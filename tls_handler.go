package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	pb "github.com/ljagiello/fault-anthropic-plugin/proto"
)

// TLSHandler manages TLS interception for a session
type TLSHandler struct {
	session         *Session
	plugin          *Plugin
	state           string
	clientHello     []byte
	serverCert      *tls.Certificate
	handshakeBuffer *bytes.Buffer
	decryptBuffer   *bytes.Buffer
	encryptBuffer   *bytes.Buffer

	// Track what we've sent
	connectReplied  bool
}

// NewTLSHandler creates a new TLS handler for a session
func NewTLSHandler(session *Session, plugin *Plugin) *TLSHandler {
	return &TLSHandler{
		session:         session,
		plugin:          plugin,
		state:           "waiting_connect",
		handshakeBuffer: &bytes.Buffer{},
		decryptBuffer:   &bytes.Buffer{},
		encryptBuffer:   &bytes.Buffer{},
	}
}

// ProcessConnect handles the CONNECT request
func (h *TLSHandler) ProcessConnect(chunk []byte) *pb.ProcessTunnelDataResponse {
	log.Printf("[TLS-Handler %s] Processing CONNECT for %s", h.session.ID, h.session.TargetHost)

	// Pass through the CONNECT request first
	h.state = "connect_sent"
	return passThrough(chunk)
}

// ProcessConnectResponse handles the 200 response to CONNECT
func (h *TLSHandler) ProcessConnectResponse(chunk []byte) *pb.ProcessTunnelDataResponse {
	// Check if this is a 200 OK response
	if bytes.Contains(chunk, []byte("200")) && bytes.Contains(chunk, []byte("Connection established")) {
		log.Printf("[TLS-Handler %s] CONNECT established, waiting for ClientHello", h.session.ID)
		h.state = "waiting_client_hello"
		h.connectReplied = true
		return passThrough(chunk)
	}
	return passThrough(chunk)
}

// ProcessClientHello handles the TLS ClientHello
func (h *TLSHandler) ProcessClientHello(chunk []byte) *pb.ProcessTunnelDataResponse {
	log.Printf("[TLS-Handler %s] Processing ClientHello (%d bytes)", h.session.ID, len(chunk))

	// Store the ClientHello
	h.clientHello = chunk
	h.state = "generating_cert"

	// Generate a certificate for the target host
	cert, err := h.generateServerCert(h.session.TargetHost)
	if err != nil {
		log.Printf("[TLS-Handler %s] Failed to generate cert: %v", h.session.ID, err)
		return passThrough(chunk)
	}
	h.serverCert = cert

	// Create our ServerHello response
	serverHello := h.createServerHello()

	log.Printf("[TLS-Handler %s] Sending ServerHello (%d bytes)", h.session.ID, len(serverHello))
	h.state = "hello_sent"

	// Replace the ClientHello with our ServerHello
	return &pb.ProcessTunnelDataResponse{
		Action: &pb.ProcessTunnelDataResponse_Replace{
			Replace: &pb.Replace{
				ModifiedChunk: serverHello,
			},
		},
	}
}

// createServerHello creates a TLS ServerHello message
func (h *TLSHandler) createServerHello() []byte {
	var buf bytes.Buffer

	// TLS record header
	buf.WriteByte(0x16) // Content Type: Handshake
	buf.WriteByte(0x03) // TLS version major
	buf.WriteByte(0x03) // TLS version minor (TLS 1.2)

	// We'll write the length later
	lengthPos := buf.Len()
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	handshakeStart := buf.Len()

	// Handshake header
	buf.WriteByte(0x02) // Handshake Type: ServerHello
	// Length (3 bytes) - will fill in later
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	handshakeMsgStart := buf.Len()

	// ServerHello message
	buf.WriteByte(0x03) // TLS version major
	buf.WriteByte(0x03) // TLS version minor (TLS 1.2)

	// Random (32 bytes)
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		// Fall back to zeros if random fails (shouldn't happen)
		log.Printf("[TLS-Handler] Warning: Failed to generate random bytes: %v", err)
	}
	buf.Write(random)

	// Session ID length (0 for new session)
	buf.WriteByte(0x00)

	// Cipher suite (TLS_RSA_WITH_AES_256_GCM_SHA384)
	buf.WriteByte(0x00)
	buf.WriteByte(0x9D)

	// Compression method (null)
	buf.WriteByte(0x00)

	// Extensions length (0 for now)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	// Update handshake message length
	handshakeMsgLen := buf.Len() - handshakeMsgStart
	b := buf.Bytes()
	b[handshakeMsgStart-3] = byte(handshakeMsgLen >> 16)
	b[handshakeMsgStart-2] = byte(handshakeMsgLen >> 8)
	b[handshakeMsgStart-1] = byte(handshakeMsgLen)

	// Update record length
	recordLen := buf.Len() - handshakeStart
	b[lengthPos] = byte(recordLen >> 8)
	b[lengthPos+1] = byte(recordLen)

	// Add Certificate message
	buf.Write(h.createCertificateMessage())

	// Add ServerHelloDone message
	buf.Write(h.createServerHelloDone())

	return buf.Bytes()
}

// createCertificateMessage creates a TLS Certificate message
func (h *TLSHandler) createCertificateMessage() []byte {
	var buf bytes.Buffer

	// TLS record header
	buf.WriteByte(0x16) // Content Type: Handshake
	buf.WriteByte(0x03) // TLS version major
	buf.WriteByte(0x03) // TLS version minor

	// Placeholder for length
	lengthPos := buf.Len()
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	handshakeStart := buf.Len()

	// Handshake header
	buf.WriteByte(0x0B) // Handshake Type: Certificate

	// Placeholder for handshake length
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	certChainStart := buf.Len()

	// Certificate chain length (3 bytes) - placeholder
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	certListStart := buf.Len()

	// For each certificate in the chain
	for _, cert := range h.serverCert.Certificate {
		// Certificate length (3 bytes)
		certLen := len(cert)
		buf.WriteByte(byte(certLen >> 16))
		buf.WriteByte(byte(certLen >> 8))
		buf.WriteByte(byte(certLen))

		// Certificate data
		buf.Write(cert)
	}

	// Update certificate chain length
	certListLen := buf.Len() - certListStart
	b := buf.Bytes()
	b[certChainStart] = byte(certListLen >> 16)
	b[certChainStart+1] = byte(certListLen >> 8)
	b[certChainStart+2] = byte(certListLen)

	// Update handshake length
	handshakeLen := buf.Len() - handshakeStart - 4
	b[handshakeStart+1] = byte(handshakeLen >> 16)
	b[handshakeStart+2] = byte(handshakeLen >> 8)
	b[handshakeStart+3] = byte(handshakeLen)

	// Update record length
	recordLen := buf.Len() - handshakeStart
	b[lengthPos] = byte(recordLen >> 8)
	b[lengthPos+1] = byte(recordLen)

	return buf.Bytes()
}

// createServerHelloDone creates a ServerHelloDone message
func (h *TLSHandler) createServerHelloDone() []byte {
	return []byte{
		0x16,       // Content Type: Handshake
		0x03, 0x03, // TLS 1.2
		0x00, 0x04, // Length: 4 bytes
		0x0E,             // Handshake Type: ServerHelloDone
		0x00, 0x00, 0x00, // Length: 0
	}
}

// generateServerCert generates a certificate for the server
func (h *TLSHandler) generateServerCert(hostname string) (*tls.Certificate, error) {
	// Check cache first
	h.plugin.certMutex.RLock()
	if cert, exists := h.plugin.certCache[hostname]; exists {
		h.plugin.certMutex.RUnlock()
		log.Printf("[TLS-Handler %s] Using cached certificate for %s", h.session.ID, hostname)
		return cert, nil
	}
	h.plugin.certMutex.RUnlock()

	// Generate new key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname, "*." + hostname},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
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

	log.Printf("[TLS-Handler %s] Generated new certificate for %s", h.session.ID, hostname)
	return cert, nil
}

// ProcessHandshakeData processes TLS handshake data
func (h *TLSHandler) ProcessHandshakeData(chunk []byte) *pb.ProcessTunnelDataResponse {
	h.handshakeBuffer.Write(chunk)

	// Check what kind of handshake message this is
	if len(chunk) > 5 {
		contentType := chunk[0]
		switch contentType {
		case 0x16: // Handshake
			handshakeType := chunk[5]

			switch handshakeType {
			case 0x10: // ClientKeyExchange
				log.Printf("[TLS-Handler %s] Received ClientKeyExchange", h.session.ID)
				h.state = "key_exchanged"

			case 0x14: // Finished
				log.Printf("[TLS-Handler %s] Received Finished, handshake complete", h.session.ID)
				h.state = "established"
				h.session.TLSEstablished = true
			}
		case 0x14: // ChangeCipherSpec
			log.Printf("[TLS-Handler %s] Received ChangeCipherSpec", h.session.ID)
		}
	}

	// For now, pass through handshake data
	return passThrough(chunk)
}

// ProcessApplicationData processes encrypted application data
func (h *TLSHandler) ProcessApplicationData(chunk []byte) *pb.ProcessTunnelDataResponse {
	// This is where we would decrypt the data if we had proper TLS session
	log.Printf("[TLS-Handler %s] Processing application data (%d bytes)", h.session.ID, len(chunk))

	// For now, check if we should inject an error randomly
	if h.session.TargetHost == h.plugin.config.TargetHost {
		if shouldInjectError(h.plugin.config.ErrorProbability) {
			log.Printf("[TLS-Handler %s] 💉 ATTEMPTING to inject error (may not work without full TLS)", h.session.ID)

			// We can't properly inject without full TLS implementation
			// but we can try to close the connection with an error
			return &pb.ProcessTunnelDataResponse{
				Action: &pb.ProcessTunnelDataResponse_Close{
					Close: &pb.Close{
						Reason: fmt.Sprintf("Simulated error: %d", h.plugin.config.StatusCode),
					},
				},
			}
		}
	}

	return passThrough(chunk)
}

// ProcessData is the main entry point for processing data
func (h *TLSHandler) ProcessData(chunk []byte) *pb.ProcessTunnelDataResponse {
	// Detect TLS record type
	if len(chunk) > 0 {
		contentType := chunk[0]

		switch contentType {
		case 0x16: // Handshake
			if len(chunk) > 5 {
				handshakeType := chunk[5]
				if handshakeType == 0x01 && h.state == "waiting_client_hello" {
					// This is ClientHello
					return h.ProcessClientHello(chunk)
				}
			}
			return h.ProcessHandshakeData(chunk)

		case 0x14: // ChangeCipherSpec
			return h.ProcessHandshakeData(chunk)

		case 0x15: // Alert
			log.Printf("[TLS-Handler %s] TLS Alert received", h.session.ID)
			return passThrough(chunk)

		case 0x17: // Application Data
			return h.ProcessApplicationData(chunk)
		}
	}

	// Check for CONNECT
	if bytes.HasPrefix(chunk, []byte("CONNECT ")) {
		return h.ProcessConnect(chunk)
	}

	// Check for 200 OK response to CONNECT
	if bytes.Contains(chunk, []byte("200")) && bytes.Contains(chunk, []byte("Connection established")) {
		return h.ProcessConnectResponse(chunk)
	}

	return passThrough(chunk)
}