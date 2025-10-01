package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"

	pb "github.com/ljagiello/fault-anthropic-plugin/proto"
	"google.golang.org/grpc"
)

func main() {
	var (
		port             = flag.Int("port", 50051, "gRPC plugin port")
		configFile       = flag.String("config", "", "Config file path (JSON)")
		errorProb        = flag.Float64("error-probability", 0.1, "Probability of injecting an error (0-1)")
		statusCode       = flag.Int("status-code", 500, "HTTP status code to return")
		errorBody        = flag.String("error-body", "", "Custom error response body (JSON)")
		targetHost       = flag.String("target-host", "api.anthropic.com", "Target host to intercept")
		verbose          = flag.Bool("verbose", false, "Enable verbose logging")
		exportCA         = flag.String("export-ca", "", "Export CA certificate to specified file")
		installCA        = flag.Bool("install-ca", false, "Show instructions to install CA certificate")
		caCert           = flag.String("ca-cert", "", "Path to existing CA certificate file")
		caKey            = flag.String("ca-key", "", "Path to existing CA private key file")
	)
	flag.Parse()

	// Validate CA certificate and key flags
	if (*caCert != "" && *caKey == "") || (*caCert == "" && *caKey != "") {
		log.Fatalf("Error: Both --ca-cert and --ca-key must be provided together, or neither")
	}

	// Initialize config
	config := Config{
		ErrorProbability: *errorProb,
		StatusCode:       *statusCode,
		ErrorBody:        *errorBody,
		TargetHost:       *targetHost,
		Headers:          make(map[string]string),
		CACert:           *caCert,
		CAKey:            *caKey,
	}

	// Load config from file if provided
	if *configFile != "" {
		log.Printf("Loading config from file: %s", *configFile)
		data, err := os.ReadFile(*configFile)
		if err != nil {
			log.Fatalf("Failed to read config file: %v", err)
		}
		if err := json.Unmarshal(data, &config); err != nil {
			log.Fatalf("Failed to parse config file: %v", err)
		}
	}

	// Validate config
	if config.ErrorProbability < 0 || config.ErrorProbability > 1 {
		log.Fatalf("Error probability must be between 0 and 1, got: %.2f", config.ErrorProbability)
	}

	// Set logging level
	if !*verbose {
		log.SetFlags(log.LstdFlags)
	}

	log.Printf("========================================")
	log.Printf("Anthropic Error Plugin v0.0.1")
	log.Printf("========================================")
	log.Printf("Port: %d", *port)
	log.Printf("Target host: %s", config.TargetHost)
	log.Printf("Error probability: %.2f", config.ErrorProbability)
	log.Printf("Status code: %d", config.StatusCode)
	if config.ErrorBody != "" {
		log.Printf("Custom error body: %s", config.ErrorBody)
	}
	log.Printf("========================================")
	log.Printf("Capabilities:")
	log.Printf("  ✅ HTTP traffic (plain)")
	log.Printf("  ✅ HTTPS traffic (with CONNECT)")
	log.Printf("  ✅ HTTP forward mode")
	log.Printf("  ✅ Tunnel mode")
	log.Printf("========================================")

	// Create the plugin that handles both TLS and non-TLS
	plugin, err := NewPlugin(config)
	if err != nil {
		log.Fatalf("Failed to create plugin: %v", err)
	}

	// Handle CA certificate export/installation
	if *exportCA != "" || *installCA {
		// Determine CA certificate file path
		certFile := "fault-ca.crt"
		if *caCert != "" {
			certFile = *caCert
		}

		certData, err := os.ReadFile(certFile)
		if err != nil {
			log.Fatalf("Failed to read CA certificate from %s: %v", certFile, err)
		}

		if *exportCA != "" {
			// Export to specified file
			err := os.WriteFile(*exportCA, certData, 0644)
			if err != nil {
				log.Fatalf("Failed to export CA certificate: %v", err)
			}
			fmt.Printf("CA certificate exported to: %s\n", *exportCA)
		}

		if *installCA {
			fmt.Println("\n========================================")
			fmt.Println("CA CERTIFICATE INSTALLATION INSTRUCTIONS")
			fmt.Println("========================================")

			fmt.Printf("The CA certificate is located at: %s\n\n", certFile)

			switch runtime.GOOS {
			case "darwin":
				fmt.Println("macOS Installation:")
				fmt.Println("-------------------")
				fmt.Printf("1. Export the certificate:\n")
				fmt.Printf("   ./anthropic-error-plugin --export-ca fault-proxy-ca.crt\n\n")
				fmt.Printf("2. Add to System Keychain:\n")
				fmt.Printf("   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain fault-proxy-ca.crt\n\n")
				fmt.Printf("3. Or add to Login Keychain (user only):\n")
				fmt.Printf("   security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain fault-proxy-ca.crt\n\n")
				fmt.Println("Alternative: Open Keychain Access app, drag the .crt file, and mark as 'Always Trust'")

			case "linux":
				fmt.Println("Linux Installation:")
				fmt.Println("------------------")
				fmt.Printf("1. Export the certificate:\n")
				fmt.Printf("   ./anthropic-error-plugin --export-ca fault-proxy-ca.crt\n\n")
				fmt.Printf("2. For Ubuntu/Debian:\n")
				fmt.Printf("   sudo cp fault-proxy-ca.crt /usr/local/share/ca-certificates/\n")
				fmt.Printf("   sudo update-ca-certificates\n\n")
				fmt.Printf("3. For RHEL/CentOS/Fedora:\n")
				fmt.Printf("   sudo cp fault-proxy-ca.crt /etc/pki/ca-trust/source/anchors/\n")
				fmt.Printf("   sudo update-ca-trust\n\n")

			case "windows":
				fmt.Println("Windows Installation:")
				fmt.Println("--------------------")
				fmt.Printf("1. Export the certificate:\n")
				fmt.Printf("   .\\anthropic-error-plugin.exe --export-ca fault-proxy-ca.crt\n\n")
				fmt.Printf("2. Install via Command Prompt (Admin):\n")
				fmt.Printf("   certutil -addstore -f \"ROOT\" fault-proxy-ca.crt\n\n")
				fmt.Printf("Alternative: Double-click the .crt file and follow the Certificate Import Wizard\n")
			}

			fmt.Println("\n========================================")
			fmt.Println("IMPORTANT NOTES:")
			fmt.Println("========================================")
			fmt.Println("1. Installing this CA allows the plugin to intercept HTTPS traffic")
			fmt.Println("2. Only install CAs from sources you trust")
			fmt.Println("3. The CA is valid for 10 years from generation")
			fmt.Println("4. After installation, restart your applications/browsers")
			fmt.Println("5. To verify: The CA should appear as 'Fault Proxy Root CA' in your certificate store")
			fmt.Println()

			os.Exit(0)
		}
	}

	// Start gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", *port, err)
	}

	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(10 * 1024 * 1024), // 10MB
		grpc.MaxSendMsgSize(10 * 1024 * 1024), // 10MB
	}

	s := grpc.NewServer(opts...)
	pb.RegisterPluginServiceServer(s, plugin)

	log.Printf("Plugin listening on port %d...", *port)

	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}