package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	var config Config

	// Parse flags
	flag.Float64Var(&config.ErrorProbability, "error-probability", 0.1, "Probability of error injection (0-1)")
	flag.IntVar(&config.StatusCode, "status-code", 500, "HTTP status code to return on error")
	flag.StringVar(&config.ErrorBody, "error-body", "", "Custom error response body")
	flag.StringVar(&config.TargetHost, "target-host", "api.anthropic.com", "Target host to intercept")
	flag.StringVar(&config.CACert, "ca-cert", "", "Path to CA certificate file")
	flag.StringVar(&config.CAKey, "ca-key", "", "Path to CA private key file")
	flag.IntVar(&config.ProxyPort, "proxy-port", 8080, "Proxy listening port")

	// Custom headers flag
	var headersFlag string
	flag.StringVar(&headersFlag, "headers", "", "Custom headers as JSON")

	// Config file
	var configFile string
	flag.StringVar(&configFile, "config", "", "Config file path (JSON)")

	// Export/install CA
	var exportCA string
	var installCA bool
	flag.StringVar(&exportCA, "export-ca", "", "Export CA certificate to specified file")
	flag.BoolVar(&installCA, "install-ca", false, "Show CA certificate installation instructions")

	flag.Parse()

	// Load config from file if provided
	if configFile != "" {
		log.Printf("Loading config from file: %s", configFile)
		data, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatalf("Failed to read config file: %v", err)
		}
		if err := json.Unmarshal(data, &config); err != nil {
			log.Fatalf("Failed to parse config file: %v", err)
		}
	}

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

	// Handle CA certificate export/installation
	if exportCA != "" || installCA {
		handleCAOperations(exportCA, installCA, config.CACert)
		os.Exit(0)
	}

	// Print banner
	// Define the banner using a raw string literal
	banner := `========================================
Anthropic Error Proxy
========================================
Proxy port:        %d
Target host:       %s
Error probability: %.2f
Status code:       %d
========================================
`
	// Print the banner with one call
	fmt.Printf(banner, config.ProxyPort, config.TargetHost, config.ErrorProbability, config.StatusCode)

	// Print custom error body if provided
	if config.ErrorBody != "" {
		fmt.Printf("Custom error body: %s\n========================================\n", config.ErrorBody)
	}

	// Create and start proxy
	proxy, err := NewProxy(config)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	if err := proxy.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}

func handleCAOperations(exportCA string, installCA bool, caCertPath string) {
	// Determine CA certificate file path
	certFile := "fault-ca.crt"
	if caCertPath != "" {
		certFile = caCertPath
	}

	certData, err := os.ReadFile(certFile)
	if err != nil {
		log.Fatalf("Failed to read CA certificate from %s: %v", certFile, err)
	}

	if exportCA != "" {
		// Export to specified file
		err := os.WriteFile(exportCA, certData, 0644)
		if err != nil {
			log.Fatalf("Failed to export CA certificate: %v", err)
		}
		fmt.Printf("CA certificate exported to: %s\n", exportCA)
	}

	if installCA {
		fmt.Println("\n========================================")
		fmt.Println("CA CERTIFICATE INSTALLATION INSTRUCTIONS")
		fmt.Println("========================================")
		fmt.Printf("The CA certificate is located at: %s\n\n", certFile)

		fmt.Println("macOS Installation:")
		fmt.Println("-------------------")
		fmt.Printf("sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n\n", certFile)

		fmt.Println("Linux Installation:")
		fmt.Println("------------------")
		fmt.Printf("sudo cp %s /usr/local/share/ca-certificates/\n", certFile)
		fmt.Println("sudo update-ca-certificates")

		fmt.Println("Windows Installation:")
		fmt.Println("--------------------")
		fmt.Printf("certutil -addstore -f \"ROOT\" %s\n\n", certFile)

		fmt.Println("========================================")
		fmt.Println("Note: Installing this CA allows the proxy to intercept HTTPS traffic")
		fmt.Println("Only install CAs from sources you trust")
		fmt.Println("========================================")
	}
}