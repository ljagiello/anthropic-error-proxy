package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Proxy is an HTTP/HTTPS proxy with TLS MITM capabilities
type Proxy struct {
	listenAddr       string
	targetHost       string
	errorProbability float64
	statusCode       int
	errorBody        string
	headers          map[string]string

	// CA for signing certificates
	caCert  *tls.Certificate
	certCache map[string]*tls.Certificate
	certMutex sync.RWMutex
}

// NewProxy creates a new proxy instance
func NewProxy(config Config) (*Proxy, error) {
	// Load or generate CA
	rootCA, rootKey, err := loadOrGenerateRootCA(config.CACert, config.CAKey)
	if err != nil {
		return nil, fmt.Errorf("failed to setup CA: %w", err)
	}

	// Convert to tls.Certificate
	caCert := &tls.Certificate{
		Certificate: [][]byte{rootCA.Raw},
		PrivateKey:  rootKey,
		Leaf:        rootCA,
	}

	return &Proxy{
		listenAddr:       fmt.Sprintf(":%d", config.ProxyPort),
		targetHost:       config.TargetHost,
		errorProbability: config.ErrorProbability,
		statusCode:       config.StatusCode,
		errorBody:        config.ErrorBody,
		headers:          config.Headers,
		caCert:           caCert,
		certCache:        make(map[string]*tls.Certificate),
	}, nil
}

// Start starts the proxy server
func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.listenAddr, err)
	}

	log.Printf("🚀 Proxy listening on %s", p.listenAddr)
	log.Printf("🎯 Target host: %s", p.targetHost)
	log.Printf("🎲 Error probability: %.2f", p.errorProbability)
	log.Printf("⚠️  Status code: %d", p.statusCode)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go p.handleConnection(conn)
	}
}

// handleConnection handles an incoming connection
func (p *Proxy) handleConnection(clientConn net.Conn) {
	defer func() {
		_ = clientConn.Close()
	}()

	// Read the first line to determine if it's HTTP or CONNECT
	reader := bufio.NewReader(clientConn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		// Check if it's EOF or a real error
		if err == io.EOF {
			// Connection closed without sending data
			return
		}
		// Log only non-EOF errors to reduce noise
		if !strings.Contains(err.Error(), "malformed HTTP request \" \"") {
			log.Printf("Failed to read HTTP request: %v", err)
		}
		// Send 400 Bad Request for malformed requests
		response := "HTTP/1.1 400 Bad Request\r\nContent-Length: 15\r\n\r\nBad Request\r\n"
		_, _ = clientConn.Write([]byte(response))
		return
	}

	if request.Method == "CONNECT" {
		p.handleConnect(clientConn, request)
	} else {
		p.handleHTTP(clientConn, request)
	}
}

// handleConnect handles CONNECT requests for HTTPS
func (p *Proxy) handleConnect(clientConn net.Conn, request *http.Request) {
	host := request.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	// Extract hostname without port
	hostname := strings.Split(host, ":")[0]

	log.Printf("[CONNECT] %s", host)

	// Send 200 OK to establish tunnel
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		log.Printf("Failed to send CONNECT response: %v", err)
		return
	}

	// Check if this is our target host for MITM
	if hostname == p.targetHost {
		p.handleHTTPSWithMITM(clientConn, hostname)
	} else {
		// Pass through for non-target hosts
		p.handleHTTPSPassthrough(clientConn, host)
	}
}

// handleHTTPSWithMITM performs TLS MITM for target hosts
func (p *Proxy) handleHTTPSWithMITM(clientConn net.Conn, hostname string) {
	// Get or generate certificate for this hostname
	cert := p.getOrCreateCert(hostname)

	// Create TLS config with our certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Wrap client connection with TLS
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	defer func() {
		_ = tlsClientConn.Close()
	}()

	// Perform handshake
	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}

	log.Printf("[MITM] ✅ TLS handshake complete for %s", hostname)

	// Read HTTP request over TLS
	reader := bufio.NewReader(tlsClientConn)
	httpRequest, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("Failed to read HTTP request: %v", err)
		return
	}

	log.Printf("[MITM] %s %s", httpRequest.Method, httpRequest.URL.Path)

	// Check if we should inject an error
	if mrand.Float64() < p.errorProbability {
		log.Printf("[MITM] 💉 Injecting HTTP %d error", p.statusCode)
		p.sendErrorResponse(tlsClientConn)
	} else {
		// Forward to real server
		p.forwardToRealServer(tlsClientConn, httpRequest, hostname)
	}
}

// sendErrorResponse sends an HTTP error response
func (p *Proxy) sendErrorResponse(conn net.Conn) {
	body := p.errorBody
	if body == "" {
		errorData := map[string]interface{}{
			"type": "error",
			"error": map[string]interface{}{
				"type":    getErrorType(p.statusCode),
				"message": fmt.Sprintf("Simulated error: %s", getStatusText(p.statusCode)),
			},
		}
		bodyBytes, _ := json.Marshal(errorData)
		body = string(bodyBytes)
	}

	response := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"Date: %s\r\n",
		p.statusCode,
		getStatusText(p.statusCode),
		len(body),
		time.Now().UTC().Format(http.TimeFormat),
	)

	// Add custom headers
	for k, v := range p.headers {
		response += fmt.Sprintf("%s: %s\r\n", k, v)
	}

	response += "\r\n" + body

	if _, err := conn.Write([]byte(response)); err != nil {
		log.Printf("Failed to write error response: %v", err)
	}
}

// forwardToRealServer forwards the request to the real server
func (p *Proxy) forwardToRealServer(clientConn net.Conn, request *http.Request, hostname string) {
	// Connect to the real server
	serverConn, err := tls.Dial("tcp", hostname+":443", &tls.Config{
		ServerName: hostname,
	})
	if err != nil {
		log.Printf("Failed to connect to real server: %v", err)
		p.sendErrorResponse(clientConn)
		return
	}
	defer func() {
		_ = serverConn.Close()
	}()

	// Set the Host header
	request.Header.Set("Host", hostname)
	request.URL.Scheme = "https"
	request.URL.Host = hostname

	// Forward the request
	if err := request.Write(serverConn); err != nil {
		log.Printf("Failed to forward request: %v", err)
		return
	}

	// Read response from server
	reader := bufio.NewReader(serverConn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		log.Printf("Failed to read response: %v", err)
		return
	}
	defer func() {
		_ = response.Body.Close()
	}()

	// Forward response to client
	if err := response.Write(clientConn); err != nil {
		log.Printf("Failed to forward response to client: %v", err)
	}
}

// handleHTTPSPassthrough passes through HTTPS for non-target hosts
func (p *Proxy) handleHTTPSPassthrough(clientConn net.Conn, host string) {
	serverConn, err := net.Dial("tcp", host)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", host, err)
		return
	}
	defer func() {
		_ = serverConn.Close()
	}()

	// Bidirectional copy
	go func() {
		_, _ = io.Copy(serverConn, clientConn)
	}()
	_, _ = io.Copy(clientConn, serverConn)
}

// handleHTTP handles plain HTTP requests
func (p *Proxy) handleHTTP(clientConn net.Conn, request *http.Request) {
	log.Printf("[HTTP] %s %s", request.Method, request.URL)

	// Handle health check endpoint
	if request.URL.Path == "/health" {
		response := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nOK"
		if _, err := clientConn.Write([]byte(response)); err != nil {
			log.Printf("Failed to write health response: %v", err)
		}
		return
	}

	// Prevent proxy loops - reject requests to localhost/127.0.0.1 on our proxy port
	if strings.HasPrefix(request.Host, "localhost:") || strings.HasPrefix(request.Host, "127.0.0.1:") {
		response := "HTTP/1.1 400 Bad Request\r\nContent-Length: 23\r\n\r\nProxy loop not allowed"
		if _, err := clientConn.Write([]byte(response)); err != nil {
			log.Printf("Failed to write error response: %v", err)
		}
		return
	}

	// Parse the URL
	targetURL, err := url.Parse(request.URL.String())
	if err != nil {
		log.Printf("Failed to parse URL: %v", err)
		return
	}

	// Check if this is our target host
	if request.Host == p.targetHost && mrand.Float64() < p.errorProbability {
		log.Printf("[HTTP] 💉 Injecting error")
		p.sendErrorResponse(clientConn)
		return
	}

	// Forward the request
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create new request
	proxyReq, err := http.NewRequest(request.Method, targetURL.String(), request.Body)
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	// Copy headers
	proxyReq.Header = request.Header

	// Make the request
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("Failed to forward request: %v", err)
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Write response back
	if err := resp.Write(clientConn); err != nil {
		log.Printf("Failed to write response to client: %v", err)
	}
}

// getOrCreateCert gets or creates a certificate for a hostname
func (p *Proxy) getOrCreateCert(hostname string) *tls.Certificate {
	p.certMutex.RLock()
	if cert, exists := p.certCache[hostname]; exists {
		p.certMutex.RUnlock()
		return cert
	}
	p.certMutex.RUnlock()

	// Generate new certificate
	cert, err := generateCertForHost(hostname, p.caCert)
	if err != nil {
		log.Printf("Failed to generate certificate for %s: %v", hostname, err)
		return p.caCert
	}

	// Cache it
	p.certMutex.Lock()
	p.certCache[hostname] = cert
	p.certMutex.Unlock()

	log.Printf("[MITM] Generated certificate for %s", hostname)
	return cert
}

// generateCertForHost generates a certificate for a hostname signed by our CA
func generateCertForHost(hostname string, caCert *tls.Certificate) (*tls.Certificate, error) {
	// Generate new private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"Fault Proxy"},
			CommonName:   hostname,
		},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}

	// Sign with CA
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		caCert.Leaf,
		&priv.PublicKey,
		caCert.PrivateKey,
	)
	if err != nil {
		return nil, err
	}

	// Create TLS certificate
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	return cert, nil
}

// RunProxy runs the proxy server
func RunProxy() {
	var config Config

	// Add proxy-specific flags
	flag.IntVar(&config.ProxyPort, "proxy-port", 8080, "Proxy listening port")
	flag.StringVar(&config.TargetHost, "target-host", "api.anthropic.com", "Target host to intercept")
	flag.Float64Var(&config.ErrorProbability, "error-probability", 0.1, "Probability of error injection (0-1)")
	flag.IntVar(&config.StatusCode, "status-code", 500, "HTTP status code to return on error")
	flag.StringVar(&config.ErrorBody, "error-body", "", "Custom error response body")
	flag.StringVar(&config.CACert, "ca-cert", "", "Path to CA certificate file")
	flag.StringVar(&config.CAKey, "ca-key", "", "Path to CA private key file")

	// Custom headers flag
	var headersFlag string
	flag.StringVar(&headersFlag, "headers", "", "Custom headers as JSON")

	flag.Parse()

	// Parse headers
	if headersFlag != "" {
		if err := json.Unmarshal([]byte(headersFlag), &config.Headers); err != nil {
			log.Fatalf("Failed to parse headers: %v", err)
		}
	}

	// Validate probability
	if config.ErrorProbability < 0 || config.ErrorProbability > 1 {
		log.Fatalf("Error probability must be between 0 and 1")
	}

	// Print banner
	fmt.Println("========================================")
	fmt.Println("Anthropic Error Proxy")
	fmt.Println("========================================")
	fmt.Printf("Proxy port: %d\n", config.ProxyPort)
	fmt.Printf("Target host: %s\n", config.TargetHost)
	fmt.Printf("Error probability: %.2f\n", config.ErrorProbability)
	fmt.Printf("Status code: %d\n", config.StatusCode)
	fmt.Println("========================================")

	// Create and start proxy
	proxy, err := NewProxy(config)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	if err := proxy.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}

// loadExistingCA attempts to load an existing CA certificate and key from disk
func loadExistingCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Use tls.LoadX509KeyPair to load the certificate and key
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	// Parse the certificate to get x509.Certificate
	if len(tlsCert.Certificate) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in file")
	}

	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Extract the RSA private key
	privKey, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not an RSA key")
	}

	return cert, privKey, nil
}

// loadOrGenerateRootCA loads an existing CA or generates a new one
func loadOrGenerateRootCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Default paths if not specified
	if certPath == "" {
		certPath = "fault-ca.crt"
	}
	if keyPath == "" {
		keyPath = "fault-ca.key"
	}

	// Try to load existing CA
	if cert, key, err := loadExistingCA(certPath, keyPath); err == nil {
		log.Printf("Loaded existing CA from %s", certPath)
		return cert, key, nil
	}

	// Generate new CA
	log.Printf("Generating new CA certificate...")

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{""},
			Locality:     []string{"San Francisco"},
			Organization: []string{"Fault Proxy"},
			CommonName:   "Fault Proxy Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * 10 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	// Save certificate
	certOut, err := os.Create(certPath)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = certOut.Close()
	}()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return nil, nil, err
	}

	// Save private key
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = keyOut.Close()
	}()

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		return nil, nil, err
	}

	log.Printf("Generated new CA certificate: %s", certPath)
	return cert, privateKey, nil
}