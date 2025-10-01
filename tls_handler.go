package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"time"

	pb "github.com/ljagiello/fault-anthropic-plugin/proto"
)

// TLSHandler manages TLS interception for a session
//
// IMPORTANT NOTE: Full TLS MITM with decryption is not possible in this plugin architecture
// because the plugin operates on data chunks flowing through the proxy and doesn't have
// direct access to network connections.
//
// This handler provides:
// 1. TLS handshake detection
// 2. Connection termination with errors for testing failure scenarios
// 3. Certificate generation (for potential future proxy-level MITM support)
type TLSHandler struct {
	session *Session
	plugin  *Plugin

	// State tracking
	state             string
	handshakeComplete bool
	errorInjected     bool

	// Certificate for this domain (generated but not used for MITM in current architecture)
	cert *tls.Certificate
}

// NewTLSHandler creates a new TLS handler for a session
func NewTLSHandler(session *Session, plugin *Plugin) *TLSHandler {
	return &TLSHandler{
		session: session,
		plugin:  plugin,
		state:   "init",
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
	// Detect what type of TLS message this is
	if len(chunk) == 0 {
		return passThrough(chunk)
	}

	// Check if this is a TLS record
	if !isTLSRecord(chunk) {
		// Not a TLS record, pass through
		return passThrough(chunk)
	}

	contentType := chunk[0]

	switch contentType {
	case 0x16: // Handshake
		return h.processHandshake(chunk)

	case 0x14: // ChangeCipherSpec
		log.Printf("[TLS-Handler %s] ChangeCipherSpec message", h.session.ID)
		h.handshakeComplete = true
		return passThrough(chunk)

	case 0x15: // Alert
		log.Printf("[TLS-Handler %s] TLS Alert message", h.session.ID)
		return passThrough(chunk)

	case 0x17: // Application Data
		return h.processApplicationData(chunk)

	default:
		log.Printf("[TLS-Handler %s] Unknown TLS content type: 0x%02x", h.session.ID, contentType)
		return passThrough(chunk)
	}
}

// processHandshake processes TLS handshake messages
func (h *TLSHandler) processHandshake(chunk []byte) *pb.ProcessTunnelDataResponse {
	if len(chunk) < 6 {
		return passThrough(chunk)
	}

	handshakeType := chunk[5]

	switch handshakeType {
	case 0x01: // ClientHello
		log.Printf("[TLS-Handler %s] ClientHello detected", h.session.ID)
		h.state = "client_hello_seen"

		// Generate certificate for potential future use
		if h.cert == nil {
			cert, err := h.generateCertForHost(h.session.TargetHost)
			if err != nil {
				log.Printf("[TLS-Handler %s] Failed to generate certificate: %v", h.session.ID, err)
			} else {
				h.cert = cert
			}
		}

		// Check if we should inject an error at handshake time
		if shouldInjectError(h.plugin.config.ErrorProbability) {
			h.errorInjected = true
			log.Printf("[TLS-Handler %s] 💉 Injecting TLS connection error", h.session.ID)

			// Close the connection with an error message
			return &pb.ProcessTunnelDataResponse{
				Action: &pb.ProcessTunnelDataResponse_Close{
					Close: &pb.Close{
						Reason: fmt.Sprintf("Simulated TLS error: HTTP %d %s",
							h.plugin.config.StatusCode,
							getStatusText(h.plugin.config.StatusCode)),
					},
				},
			}
		}

		return passThrough(chunk)

	case 0x02: // ServerHello
		log.Printf("[TLS-Handler %s] ServerHello detected", h.session.ID)
		h.state = "server_hello_seen"
		return passThrough(chunk)

	case 0x0B: // Certificate
		log.Printf("[TLS-Handler %s] Certificate message", h.session.ID)
		return passThrough(chunk)

	case 0x0C: // ServerKeyExchange
		log.Printf("[TLS-Handler %s] ServerKeyExchange message", h.session.ID)
		return passThrough(chunk)

	case 0x0E: // ServerHelloDone
		log.Printf("[TLS-Handler %s] ServerHelloDone message", h.session.ID)
		return passThrough(chunk)

	case 0x10: // ClientKeyExchange
		log.Printf("[TLS-Handler %s] ClientKeyExchange message", h.session.ID)
		return passThrough(chunk)

	case 0x14: // Finished
		log.Printf("[TLS-Handler %s] Finished message", h.session.ID)
		h.handshakeComplete = true
		return passThrough(chunk)

	default:
		log.Printf("[TLS-Handler %s] Unknown handshake type: 0x%02x", h.session.ID, handshakeType)
		return passThrough(chunk)
	}
}

// processApplicationData processes encrypted application data
// NOTE: Cannot decrypt in this architecture, but we can:
// 1. Pass through normally
// 2. Close connection to simulate errors
// 3. Buffer data (if needed for timing attacks)
func (h *TLSHandler) processApplicationData(chunk []byte) *pb.ProcessTunnelDataResponse {
	log.Printf("[TLS-Handler %s] Processing TLS application data (%d bytes)", h.session.ID, len(chunk))

	// We can't decrypt the data in this architecture, but we can simulate errors
	// by closing the connection
	if !h.errorInjected && shouldInjectError(h.plugin.config.ErrorProbability) {
		h.errorInjected = true
		log.Printf("[TLS-Handler %s] 💉 Injecting connection termination during application data", h.session.ID)

		// Determine error message based on config
		errorMsg := fmt.Sprintf("Simulated error: HTTP %d %s",
			h.plugin.config.StatusCode,
			getStatusText(h.plugin.config.StatusCode))

		// Close the connection to simulate a network/TLS error
		return &pb.ProcessTunnelDataResponse{
			Action: &pb.ProcessTunnelDataResponse_Close{
				Close: &pb.Close{
					Reason: errorMsg,
				},
			},
		}
	}

	// Normal case: pass through the encrypted data
	return passThrough(chunk)
}

// isTLSRecord checks if data looks like a TLS record
func isTLSRecord(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	// TLS record format:
	// - Content Type (1 byte): 0x14-0x18
	// - Version (2 bytes): 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2/1.3)
	// - Length (2 bytes)

	contentType := data[0]
	if contentType < 0x14 || contentType > 0x18 {
		return false
	}

	// Check version
	if data[1] != 0x03 {
		return false
	}

	if data[2] < 0x01 || data[2] > 0x04 {
		return false
	}

	return true
}

// createTLSAlert creates a TLS alert message (for potential future use)
func (h *TLSHandler) createTLSAlert(level byte, description byte) []byte {
	// TLS Alert format:
	// Record header (5 bytes) + Alert (2 bytes)
	return []byte{
		0x15,       // Content Type: Alert
		0x03, 0x03, // Version: TLS 1.2
		0x00, 0x02, // Length: 2 bytes
		level,      // Alert level (1=warning, 2=fatal)
		description, // Alert description
	}
}

// Common TLS alert descriptions (for reference)
const (
	TLSAlertCloseNotify            byte = 0
	TLSAlertUnexpectedMessage      byte = 10
	TLSAlertBadRecordMAC           byte = 20
	TLSAlertHandshakeFailure       byte = 40
	TLSAlertBadCertificate         byte = 42
	TLSAlertCertificateRevoked     byte = 44
	TLSAlertCertificateExpired     byte = 45
	TLSAlertCertificateUnknown     byte = 46
	TLSAlertIllegalParameter       byte = 47
	TLSAlertUnknownCA              byte = 48
	TLSAlertAccessDenied           byte = 49
	TLSAlertDecodeError            byte = 50
	TLSAlertDecryptError           byte = 51
	TLSAlertProtocolVersion        byte = 70
	TLSAlertInternalError          byte = 80
	TLSAlertInappropriateFallback  byte = 86
	TLSAlertUserCanceled           byte = 90
	TLSAlertUnrecognizedName       byte = 112
)
