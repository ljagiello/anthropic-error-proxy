package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	pb "github.com/ljagiello/fault-anthropic-plugin/proto"
)

// TLSHandler manages TLS interception for a session
//
// This handler implements a full TLS server to intercept HTTPS traffic
// and inject HTTP error responses. It works within the chunk-based architecture
// by maintaining TLS state across multiple ProcessData calls.
type TLSHandler struct {
	session *Session
	plugin  *Plugin

	// State tracking
	state             string
	handshakeComplete bool
	errorInjected     bool

	// TLS server state
	cert           *tls.Certificate
	tlsConn        *tls.Conn
	clientConn     net.Conn      // Client side of pipe
	serverConn     net.Conn      // Server side of pipe
	tlsInitialized bool
	tlsServerDone  chan error    // Signals when TLS server goroutine is done
	mutex          sync.Mutex

	// Buffers for data flow
	responseBuffer *bytes.Buffer // Buffered TLS responses to send to client
	responseMutex  sync.Mutex

	// HTTP request parsing
	httpRequest *http.Request
}

// NewTLSHandler creates a new TLS handler for a session
func NewTLSHandler(session *Session, plugin *Plugin) *TLSHandler {
	return &TLSHandler{
		session:        session,
		plugin:         plugin,
		state:          "init",
		responseBuffer: &bytes.Buffer{},
		tlsServerDone:  make(chan error, 1),
	}
}

// generateCertForHost generates a certificate for the target host signed by our CA
// This is kept for potential future use if the proxy supports full MITM mode
func (h *TLSHandler) generateCertForHost(hostname string) (*tls.Certificate, error) {
	// Check cache first
	h.plugin.certMutex.RLock()
	if cert, exists := h.plugin.certCache[hostname]; exists {
		h.plugin.certMutex.RUnlock()
		log.Printf("[TLS-Handler %s] Using cached certificate for %s", h.session.ID, hostname)
		return cert, nil
	}
	h.plugin.certMutex.RUnlock()

	log.Printf("[TLS-Handler %s] Generating new certificate for %s", h.session.ID, hostname)

	// Generate new key pair for this certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Fault Proxy"},
		},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{hostname, "*." + hostname},
	}

	// Create certificate signed by our CA
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		h.plugin.rootCA,
		&priv.PublicKey,
		h.plugin.rootKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Create TLS certificate
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	// Cache it
	h.plugin.certMutex.Lock()
	h.plugin.certCache[hostname] = cert
	h.plugin.certMutex.Unlock()

	log.Printf("[TLS-Handler %s] Generated and cached certificate for %s", h.session.ID, hostname)
	return cert, nil
}

// ProcessData is the main entry point for processing TLS data
func (h *TLSHandler) ProcessData(chunk []byte) *pb.ProcessTunnelDataResponse {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if len(chunk) == 0 {
		return passThrough(chunk)
	}

	// Initialize TLS connection on first chunk
	if !h.tlsInitialized {
		if err := h.initTLSServer(); err != nil {
			log.Printf("[TLS-Handler %s] Failed to initialize TLS server: %v", h.session.ID, err)
			return &pb.ProcessTunnelDataResponse{
				Action: &pb.ProcessTunnelDataResponse_Close{
					Close: &pb.Close{
						Reason: fmt.Sprintf("TLS initialization failed: %v", err),
					},
				},
			}
		}

		// Start the response reading goroutine
		if err := h.processTLSStateMachine(); err != nil {
			log.Printf("[TLS-Handler %s] TLS state machine error: %v", h.session.ID, err)
			return &pb.ProcessTunnelDataResponse{
				Action: &pb.ProcessTunnelDataResponse_Close{
					Close: &pb.Close{
						Reason: fmt.Sprintf("TLS error: %v", err),
					},
				},
			}
		}

		h.tlsInitialized = true
	}

	// Feed incoming chunk to the client connection (which feeds the TLS server)
	n, err := h.clientConn.Write(chunk)
	if err != nil {
		log.Printf("[TLS-Handler %s] Failed to write to client conn: %v", h.session.ID, err)
		return &pb.ProcessTunnelDataResponse{
			Action: &pb.ProcessTunnelDataResponse_Close{
				Close: &pb.Close{
					Reason: fmt.Sprintf("Write error: %v", err),
				},
			},
		}
	}
	log.Printf("[TLS-Handler %s] Fed %d bytes to TLS server", h.session.ID, n)

	// Give the TLS server goroutine time to process and generate responses
	time.Sleep(10 * time.Millisecond)

	// Check if we have response data to send
	h.responseMutex.Lock()
	if h.responseBuffer.Len() > 0 {
		responseData := h.responseBuffer.Bytes()
		h.responseBuffer.Reset()
		h.responseMutex.Unlock()

		log.Printf("[TLS-Handler %s] Sending %d bytes of TLS response", h.session.ID, len(responseData))
		return &pb.ProcessTunnelDataResponse{
			Action: &pb.ProcessTunnelDataResponse_Replace{
				Replace: &pb.Replace{
					ModifiedChunk: responseData,
				},
			},
		}
	}
	h.responseMutex.Unlock()

	// Check if TLS server is done
	select {
	case err := <-h.tlsServerDone:
		if err != nil {
			log.Printf("[TLS-Handler %s] TLS server finished with error: %v", h.session.ID, err)
		} else {
			log.Printf("[TLS-Handler %s] TLS server finished successfully", h.session.ID)
		}

		// Drain any remaining response data
		h.responseMutex.Lock()
		if h.responseBuffer.Len() > 0 {
			responseData := h.responseBuffer.Bytes()
			h.responseBuffer.Reset()
			h.responseMutex.Unlock()

			log.Printf("[TLS-Handler %s] Sending final %d bytes of TLS response", h.session.ID, len(responseData))
			return &pb.ProcessTunnelDataResponse{
				Action: &pb.ProcessTunnelDataResponse_Replace{
					Replace: &pb.Replace{
						ModifiedChunk: responseData,
					},
				},
			}
		}
		h.responseMutex.Unlock()

		// Close the connection
		return &pb.ProcessTunnelDataResponse{
			Action: &pb.ProcessTunnelDataResponse_Close{
				Close: &pb.Close{
					Reason: "TLS session complete",
				},
			},
		}
	default:
		// TLS server still processing
	}

	// Drop the original chunk since we're handling the connection
	return &pb.ProcessTunnelDataResponse{
		Action: &pb.ProcessTunnelDataResponse_Replace{
			Replace: &pb.Replace{
				ModifiedChunk: []byte{}, // Empty response, waiting for TLS processing
			},
		},
	}
}

// initTLSServer initializes the TLS server connection
func (h *TLSHandler) initTLSServer() error {
	// Generate certificate for this host
	cert, err := h.generateCertForHost(h.session.TargetHost)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}
	h.cert = cert

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	// Create a pipe: clientConn is what we feed data into, serverConn is what TLS server uses
	h.clientConn, h.serverConn = net.Pipe()

	// Create TLS server connection
	h.tlsConn = tls.Server(h.serverConn, tlsConfig)

	// Start TLS server goroutine
	go h.runTLSServer()

	log.Printf("[TLS-Handler %s] TLS server initialized for %s", h.session.ID, h.session.TargetHost)
	return nil
}

// runTLSServer runs the TLS server logic in a goroutine
func (h *TLSHandler) runTLSServer() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TLS-Handler %s] TLS server panic: %v", h.session.ID, r)
			h.tlsServerDone <- fmt.Errorf("panic: %v", r)
		}
	}()

	// Perform TLS handshake
	err := h.tlsConn.Handshake()
	if err != nil {
		log.Printf("[TLS-Handler %s] TLS handshake failed: %v", h.session.ID, err)
		h.tlsServerDone <- err
		return
	}

	log.Printf("[TLS-Handler %s] ✓ TLS handshake complete", h.session.ID)
	h.mutex.Lock()
	h.handshakeComplete = true
	h.mutex.Unlock()

	// Read HTTP request
	reader := bufio.NewReader(h.tlsConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("[TLS-Handler %s] Failed to read HTTP request: %v", h.session.ID, err)
		h.tlsServerDone <- err
		return
	}

	log.Printf("[TLS-Handler %s] Received HTTP request: %s %s", h.session.ID, req.Method, req.URL.Path)

	// Check if we should inject an error
	h.mutex.Lock()
	shouldInject := shouldInjectError(h.plugin.config.ErrorProbability)
	h.mutex.Unlock()

	if shouldInject {
		h.injectHTTPError()
	} else {
		// Pass through - but in TLS MITM mode, we'd need to proxy to real server
		// For now, just close the connection
		log.Printf("[TLS-Handler %s] Not injecting error, closing connection", h.session.ID)
	}

	h.tlsServerDone <- nil
}

// processTLSStateMachine processes the TLS state machine
func (h *TLSHandler) processTLSStateMachine() error {
	// Start a goroutine to read responses from the client side of the pipe
	// and buffer them for sending back to the actual client
	go func() {
		buf := make([]byte, 32*1024) // 32KB buffer
		for {
			n, err := h.clientConn.Read(buf)
			if n > 0 {
				h.responseMutex.Lock()
				h.responseBuffer.Write(buf[:n])
				h.responseMutex.Unlock()
				log.Printf("[TLS-Handler %s] Buffered %d bytes of response data", h.session.ID, n)
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("[TLS-Handler %s] Client conn read error: %v", h.session.ID, err)
				}
				return
			}
		}
	}()

	return nil
}

// injectHTTPError generates and sends an HTTP error response over TLS
func (h *TLSHandler) injectHTTPError() {
	h.mutex.Lock()
	h.errorInjected = true
	h.mutex.Unlock()

	log.Printf("[TLS-Handler %s] 💉 Injecting HTTP %d error over TLS", h.session.ID, h.plugin.config.StatusCode)

	// Build HTTP error response
	errorBody := h.buildErrorBody()

	response := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\n"+
			"Content-Type: application/json\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"Date: %s\r\n"+
			"\r\n"+
			"%s",
		h.plugin.config.StatusCode,
		getStatusText(h.plugin.config.StatusCode),
		len(errorBody),
		time.Now().UTC().Format(http.TimeFormat),
		errorBody,
	)

	// Write HTTP response through TLS connection
	// This will encrypt the response and send it through the pipe
	_, err := h.tlsConn.Write([]byte(response))
	if err != nil {
		log.Printf("[TLS-Handler %s] Failed to write HTTP error response: %v", h.session.ID, err)
		return
	}

	log.Printf("[TLS-Handler %s] Wrote HTTP %d error response (%d bytes plain, will be encrypted)",
		h.session.ID, h.plugin.config.StatusCode, len(response))

	// Close the TLS connection to signal we're done
	h.tlsConn.Close()
}

// buildErrorBody creates the JSON error body
func (h *TLSHandler) buildErrorBody() string {
	if h.plugin.config.ErrorBody != "" {
		return h.plugin.config.ErrorBody
	}

	errorData := map[string]interface{}{
		"type": "error",
		"error": map[string]interface{}{
			"type":    getErrorType(h.plugin.config.StatusCode),
			"message": fmt.Sprintf("Simulated error: %s", getStatusText(h.plugin.config.StatusCode)),
		},
	}

	bodyBytes, _ := json.Marshal(errorData)
	return string(bodyBytes)
}

