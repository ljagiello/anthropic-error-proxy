package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	pb "github.com/ljagiello/fault-anthropic-plugin/proto"
)

// Plugin handles both TLS and non-TLS traffic transparently
type Plugin struct {
	pb.UnimplementedPluginServiceServer
	config         Config
	sessions       map[string]*Session
	sessionMutex   sync.RWMutex
	rootCA         *x509.Certificate
	rootKey        *rsa.PrivateKey
	certCache      map[string]*tls.Certificate
	certMutex      sync.RWMutex
}

// Session tracks the state of each tunnel connection
type Session struct {
	ID               string
	TargetHost       string
	Port             string
	IsHTTPS          bool
	IsTLS            bool
	ConnectSeen      bool
	HandshakeStarted bool
	TLSEstablished   bool

	// For TLS MITM
	ClientBuffer     *bytes.Buffer
	ServerBuffer     *bytes.Buffer
	DecryptedBuffer  *bytes.Buffer
	TLSClient        *tls.Conn
	TLSServer        *tls.Conn
	ClientReader     *bufio.Reader
	ServerReader     *bufio.Reader

	// State tracking
	LastErrorCheck   time.Time
	mutex            sync.Mutex
}

// NewPlugin creates a plugin that handles both TLS and non-TLS
func NewPlugin(config Config) (*Plugin, error) {
	// Load or generate CA for TLS interception
	rootCA, rootKey, err := loadOrGenerateRootCA(config.CACert, config.CAKey)
	if err != nil {
		return nil, fmt.Errorf("failed to setup CA: %w", err)
	}

	p := &Plugin{
		config:    config,
		sessions:  make(map[string]*Session),
		rootCA:    rootCA,
		rootKey:   rootKey,
		certCache: make(map[string]*tls.Certificate),
	}

	// Start session cleanup goroutine
	go p.cleanupSessions()

	return p, nil
}

// cleanupSessions removes old inactive sessions to prevent memory leaks
func (p *Plugin) cleanupSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.sessionMutex.Lock()
		now := time.Now()
		var toDelete []string

		for id, session := range p.sessions {
			session.mutex.Lock()
			// Remove sessions inactive for more than 5 minutes
			if now.Sub(session.LastErrorCheck) > 5*time.Minute {
				toDelete = append(toDelete, id)
			}
			session.mutex.Unlock()
		}

		for _, id := range toDelete {
			delete(p.sessions, id)
			log.Printf("[Session %s] Cleaned up inactive session", id)
		}
		p.sessionMutex.Unlock()

		if len(toDelete) > 0 {
			log.Printf("Cleaned up %d inactive sessions", len(toDelete))
		}
	}
}

// loadExistingCA attempts to load a CA certificate and key from files
func loadExistingCA(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Read certificate file
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Read key file
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Decode certificate PEM
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Decode key PEM
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode key PEM")
	}

	// Parse private key
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	log.Printf("Loaded existing CA from %s", certFile)
	return cert, key, nil
}

// loadOrGenerateRootCA loads or creates a CA certificate
func loadOrGenerateRootCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	var certFile, keyFile string

	if certPath != "" && keyPath != "" {
		// Use provided paths
		certFile = certPath
		keyFile = keyPath
	} else if certPath == "" && keyPath == "" {
		// Use default names for generated CA
		certFile = "fault-ca.crt"
		keyFile = "fault-ca.key"
	} else {
		// This should never happen due to validation in main, but check anyway
		return nil, nil, fmt.Errorf("both CA certificate and key paths must be provided, or neither")
	}

	// Try to load existing CA
	cert, key, err := loadExistingCA(certFile, keyFile)
	if err == nil {
		return cert, key, nil
	}

	// Generate new
	log.Println("Generating new CA for TLS interception...")
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Fault Proxy"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "Fault Proxy Root CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &newKey.PublicKey, newKey)
	if err != nil {
		return nil, nil, err
	}

	newCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	// Save for future use
	certOut, err := os.Create(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cert file: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		_ = certOut.Close()
		return nil, nil, fmt.Errorf("failed to encode certificate: %w", err)
	}
	if err := certOut.Close(); err != nil {
		return nil, nil, fmt.Errorf("failed to close cert file: %w", err)
	}

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create key file: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(newKey)}); err != nil {
		_ = keyOut.Close()
		return nil, nil, fmt.Errorf("failed to encode private key: %w", err)
	}
	if err := keyOut.Close(); err != nil {
		return nil, nil, fmt.Errorf("failed to close key file: %w", err)
	}

	log.Printf("Generated CA certificate: %s", certFile)
	return newCert, newKey, nil
}

// getOrCreateCertificate gets or creates a certificate for a host
func (p *Plugin) getOrCreateCertificate(host string) (*tls.Certificate, error) {
	p.certMutex.RLock()
	if cert, exists := p.certCache[host]; exists {
		p.certMutex.RUnlock()
		return cert, nil
	}
	p.certMutex.RUnlock()

	// Generate new certificate signed by our CA
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Fault Plugin"},
			CommonName:   host,
		},
		DNSNames:              []string{host, "*." + host},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, p.rootCA, &priv.PublicKey, p.rootKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, p.rootCA.Raw},
		PrivateKey:  priv,
	}

	p.certMutex.Lock()
	p.certCache[host] = cert
	p.certMutex.Unlock()

	return cert, nil
}

// ProcessTunnelData handles both encrypted and unencrypted tunnel data
func (p *Plugin) ProcessTunnelData(ctx context.Context, req *pb.ProcessTunnelDataRequest) (*pb.ProcessTunnelDataResponse, error) {
	session := p.getOrCreateSession(req.Id)

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Analyze the data to determine what we're dealing with
	if len(req.Chunk) == 0 {
		return passThrough(req.Chunk), nil
	}

	// Check for CONNECT request (HTTPS tunneling setup)
	if !session.ConnectSeen && bytes.HasPrefix(req.Chunk, []byte("CONNECT ")) {
		return p.handleConnect(session, req.Chunk), nil
	}

	// After CONNECT, check if it's TLS
	if session.ConnectSeen && !session.HandshakeStarted {
		if isTLSHandshake(req.Chunk) {
			session.IsTLS = true
			session.HandshakeStarted = true
			log.Printf("[Session %s] TLS handshake detected for %s", session.ID, session.TargetHost)

			// Attempt TLS MITM if this is our target host
			if session.TargetHost == p.config.TargetHost {
				return p.handleTLSInterception(session, req.Chunk), nil
			}

			// Pass through for non-target hosts
			return passThrough(req.Chunk), nil
		}
	}

	// If TLS is established, decrypt and handle
	if session.TLSEstablished {
		return p.handleDecryptedTraffic(session, req.Chunk), nil
	}

	// Check for plain HTTP request
	if isHTTPRequest(req.Chunk) {
		return p.handleHTTPRequest(session, req.Chunk), nil
	}

	// Default: pass through
	return passThrough(req.Chunk), nil
}

// handleConnect processes CONNECT requests
func (p *Plugin) handleConnect(session *Session, chunk []byte) *pb.ProcessTunnelDataResponse {
	lines := strings.Split(string(chunk), "\r\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			hostPort := parts[1]
			colonIndex := strings.LastIndex(hostPort, ":")
			if colonIndex > 0 {
				session.TargetHost = hostPort[:colonIndex]
				session.Port = hostPort[colonIndex+1:]
			} else {
				session.TargetHost = hostPort
				session.Port = "443"
			}
			session.ConnectSeen = true
			session.IsHTTPS = true

			log.Printf("[Session %s] CONNECT to %s:%s", session.ID, session.TargetHost, session.Port)

			// Check if this is our target
			if session.TargetHost == p.config.TargetHost {
				log.Printf("[Session %s] Target host detected, will intercept", session.ID)
			}
		}
	}

	// Pass through CONNECT request
	return passThrough(chunk)
}

// handleTLSInterception sets up TLS MITM
func (p *Plugin) handleTLSInterception(session *Session, chunk []byte) *pb.ProcessTunnelDataResponse {
	// Buffer the client hello
	session.ClientBuffer.Write(chunk)

	// Get certificate for this host
	cert, err := p.getOrCreateCertificate(session.TargetHost)
	if err != nil {
		log.Printf("[Session %s] Failed to create certificate: %v", session.ID, err)
		return passThrough(chunk)
	}

	// Create TLS config for server side
	// tlsConfig := &tls.Config{
	// 	Certificates: []tls.Certificate{*cert},
	// }
	_ = cert // Certificate is ready for use

	// Establish TLS with client (we act as server)
	// Note: This is simplified - in reality we'd need bidirectional communication
	// which the plugin architecture doesn't fully support
	log.Printf("[Session %s] Would establish TLS MITM for %s (not fully implemented)", session.ID, session.TargetHost)

	// For now, pass through
	return passThrough(chunk)
}

// handleDecryptedTraffic handles traffic after TLS is established
func (p *Plugin) handleDecryptedTraffic(session *Session, chunk []byte) *pb.ProcessTunnelDataResponse {
	// This would handle decrypted traffic if TLS MITM was fully implemented
	return passThrough(chunk)
}

// handleHTTPRequest handles plain HTTP requests
func (p *Plugin) handleHTTPRequest(session *Session, chunk []byte) *pb.ProcessTunnelDataResponse {
	// Parse the HTTP request
	reader := bufio.NewReader(bytes.NewReader(chunk))
	request, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("[Session %s] Failed to parse HTTP request: %v", session.ID, err)
		return passThrough(chunk)
	}

	// Extract host from request
	host := request.Host
	if host == "" {
		host = request.URL.Host
	}
	if host != "" && session.TargetHost == "" {
		session.TargetHost = strings.Split(host, ":")[0]
	}

	log.Printf("[Session %s] HTTP %s %s (host: %s)", session.ID, request.Method, request.URL.Path, session.TargetHost)

	// Check if we should inject an error (removed the ErrorInjected check to allow multiple injections)
	if session.TargetHost == p.config.TargetHost {
		// Rate limit error checks to once per second
		now := time.Now()
		if now.Sub(session.LastErrorCheck) > time.Second {
			session.LastErrorCheck = now

			if shouldInjectError(p.config.ErrorProbability) {
				log.Printf("[Session %s] 💉 Injecting HTTP error (status %d)", session.ID, p.config.StatusCode)

				errorResponse := p.createHTTPErrorResponse()
				return &pb.ProcessTunnelDataResponse{
					Action: &pb.ProcessTunnelDataResponse_Replace{
						Replace: &pb.Replace{
							ModifiedChunk: errorResponse,
						},
					},
				}
			}
		}
	}

	return passThrough(chunk)
}

// ProcessHttpRequest handles HTTP forward mode (non-tunnel)
func (p *Plugin) ProcessHttpRequest(ctx context.Context, req *pb.ProcessHttpRequestRequest) (*pb.ProcessHttpRequestResponse, error) {
	// Check host in headers
	targetHost := ""
	for _, header := range req.Request.Headers {
		if strings.ToLower(header.Name) == "host" {
			targetHost = strings.Split(header.Value, ":")[0]
			break
		}
	}

	log.Printf("[HTTP-Forward] %s %s (host: %s)", req.Request.Method, req.Request.Path, targetHost)

	// Check if we should inject error
	if targetHost == p.config.TargetHost {
		if shouldInjectError(p.config.ErrorProbability) {
			log.Printf("[HTTP-Forward] 💉 Injecting error (status %d)", p.config.StatusCode)

			body := p.config.ErrorBody
			if body == "" {
				body = fmt.Sprintf(`{"type":"error","error":{"type":"%s","message":"Simulated error: %s"}}`,
					getErrorType(p.config.StatusCode), getStatusText(p.config.StatusCode))
			}

			return &pb.ProcessHttpRequestResponse{
				Action: pb.ProcessHttpRequestResponse_ABORT,
				AbortResponse: &pb.HttpResponse{
					StatusCode: uint32(p.config.StatusCode),
					Headers: []*pb.HttpHeader{
						{Name: "Content-Type", Value: "application/json"},
					},
					Body: []byte(body),
				},
			}, nil
		}
	}

	return &pb.ProcessHttpRequestResponse{
		Action: pb.ProcessHttpRequestResponse_CONTINUE,
	}, nil
}

// ProcessHttpResponse - pass through responses
func (p *Plugin) ProcessHttpResponse(ctx context.Context, req *pb.ProcessHttpResponseRequest) (*pb.ProcessHttpResponseResponse, error) {
	return &pb.ProcessHttpResponseResponse{
		Action: pb.ProcessHttpResponseResponse_CONTINUE,
	}, nil
}

// getOrCreateSession gets or creates a session
func (p *Plugin) getOrCreateSession(id string) *Session {
	p.sessionMutex.RLock()
	if session, exists := p.sessions[id]; exists {
		p.sessionMutex.RUnlock()
		return session
	}
	p.sessionMutex.RUnlock()

	p.sessionMutex.Lock()
	defer p.sessionMutex.Unlock()

	// Double check
	if session, exists := p.sessions[id]; exists {
		return session
	}

	session := &Session{
		ID:              id,
		ClientBuffer:    &bytes.Buffer{},
		ServerBuffer:    &bytes.Buffer{},
		DecryptedBuffer: &bytes.Buffer{},
		LastErrorCheck:  time.Now(),
	}
	p.sessions[id] = session
	return session
}

// createHTTPErrorResponse creates an HTTP error response
func (p *Plugin) createHTTPErrorResponse() []byte {
	body := p.config.ErrorBody
	if body == "" {
		errorData := map[string]interface{}{
			"type": "error",
			"error": map[string]interface{}{
				"type":    getErrorType(p.config.StatusCode),
				"message": fmt.Sprintf("Simulated error: %s", getStatusText(p.config.StatusCode)),
			},
		}
		bodyBytes, _ := json.Marshal(errorData)
		body = string(bodyBytes)
	}

	var response strings.Builder
	response.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", p.config.StatusCode, getStatusText(p.config.StatusCode)))
	response.WriteString("Content-Type: application/json\r\n")
	response.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	response.WriteString("Connection: close\r\n")
	response.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(http.TimeFormat)))

	// Add custom headers
	for k, v := range p.config.Headers {
		response.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}

	response.WriteString("\r\n")
	response.WriteString(body)

	return []byte(response.String())
}

// isTLSHandshake checks if data is a TLS handshake
func isTLSHandshake(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	// TLS record: ContentType (1 byte) + Version (2 bytes) + Length (2 bytes)
	// ContentType 22 (0x16) = Handshake
	// Version 0x0301 = TLS 1.0, 0x0302 = TLS 1.1, 0x0303 = TLS 1.2/1.3
	return data[0] == 0x16 && data[1] == 0x03 && (data[2] >= 0x01 && data[2] <= 0x04)
}

// isHTTPRequest checks if data looks like an HTTP request
func isHTTPRequest(data []byte) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "TRACE "}
	for _, method := range methods {
		if bytes.HasPrefix(data, []byte(method)) {
			return true
		}
	}
	return false
}

// HealthCheck implements the health check RPC
func (p *Plugin) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{
		Healthy: true,
		Message: "Plugin is healthy - handles both TLS and non-TLS traffic",
	}, nil
}

// GetPluginInfo returns plugin metadata
func (p *Plugin) GetPluginInfo(ctx context.Context, req *pb.GetPluginInfoRequest) (*pb.GetPluginInfoResponse, error) {
	return &pb.GetPluginInfoResponse{
		Name:      "anthropic-error-plugin",
		Version:   "0.0.1",
		Author:    "Lukasz Jagiello",
		Url:       "https://github.com/ljagiello/fault-anthropic-error-plugin",
		Platform:  "linux,darwin,windows",
		Direction: pb.GetPluginInfoResponse_BOTH,
		Side:      pb.GetPluginInfoResponse_ANY,
	}, nil
}

// GetPluginCapabilities returns what the plugin can handle
func (p *Plugin) GetPluginCapabilities(ctx context.Context, req *pb.GetPluginCapabilitiesRequest) (*pb.GetPluginCapabilitiesResponse, error) {
	return &pb.GetPluginCapabilitiesResponse{
		CanHandleHttpForward: true,  // Can handle HTTP forward mode
		CanHandleTunnel:      true,  // Can handle tunnel mode
		Protocols: []pb.GetPluginCapabilitiesResponse_SupportedProtocol{
			pb.GetPluginCapabilitiesResponse_HTTP,
			pb.GetPluginCapabilitiesResponse_HTTPS,
		},
	}, nil
}