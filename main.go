package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

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
	)
	flag.Parse()

	// Initialize config
	config := Config{
		ErrorProbability: *errorProb,
		StatusCode:       *statusCode,
		ErrorBody:        *errorBody,
		TargetHost:       *targetHost,
		Headers:          make(map[string]string),
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
	log.Printf("Anthropic Error Plugin v4.0.0")
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

	// Create the smart plugin that handles both TLS and non-TLS
	plugin, err := NewSmartPlugin(config)
	if err != nil {
		log.Fatalf("Failed to create plugin: %v", err)
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