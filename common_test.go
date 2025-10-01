package main

import (
	"testing"

	pb "github.com/ljagiello/fault-anthropic-plugin/proto"
)

func TestGetErrorType(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected string
	}{
		{name: "Invalid Request", code: 400, expected: "invalid_request_error"},
		{name: "Authentication Error", code: 401, expected: "authentication_error"},
		{name: "Permission Error", code: 403, expected: "permission_error"},
		{name: "Not Found", code: 404, expected: "not_found_error"},
		{name: "Request Too Large", code: 413, expected: "request_too_large"},
		{name: "Rate Limit", code: 429, expected: "rate_limit_error"},
		{name: "Internal Server Error", code: 500, expected: "api_error"},
		{name: "Overloaded", code: 529, expected: "overloaded_error"},
		{name: "Unknown Error", code: 418, expected: "error"},
		{name: "Unknown Error 2", code: 502, expected: "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getErrorType(tt.code)
			if result != tt.expected {
				t.Errorf("getErrorType(%d) = %s; want %s", tt.code, result, tt.expected)
			}
		})
	}
}

func TestGetStatusText(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected string
	}{
		{name: "Bad Request", code: 400, expected: "Bad Request"},
		{name: "Unauthorized", code: 401, expected: "Unauthorized"},
		{name: "Forbidden", code: 403, expected: "Forbidden"},
		{name: "Not Found", code: 404, expected: "Not Found"},
		{name: "Request Entity Too Large", code: 413, expected: "Request Entity Too Large"},
		{name: "Too Many Requests", code: 429, expected: "Too Many Requests"},
		{name: "Internal Server Error", code: 500, expected: "Internal Server Error"},
		{name: "Overloaded", code: 529, expected: "Overloaded"},
		{name: "Unknown Status", code: 418, expected: "Error"},
		{name: "Unknown Status 2", code: 502, expected: "Error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStatusText(tt.code)
			if result != tt.expected {
				t.Errorf("getStatusText(%d) = %s; want %s", tt.code, result, tt.expected)
			}
		})
	}
}

func TestPassThrough(t *testing.T) {
	testCases := []struct {
		name  string
		chunk []byte
	}{
		{name: "Empty chunk", chunk: []byte{}},
		{name: "Simple text", chunk: []byte("Hello, World!")},
		{name: "Binary data", chunk: []byte{0x00, 0x01, 0x02, 0xFF}},
		{name: "Large chunk", chunk: make([]byte, 1024)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := passThrough(tc.chunk)

			if result == nil {
				t.Fatal("passThrough returned nil")
			}

			// Check that it returns the correct type
			action, ok := result.Action.(*pb.ProcessTunnelDataResponse_PassThrough)
			if !ok {
				t.Fatal("passThrough did not return ProcessTunnelDataResponse_PassThrough")
			}

			if action.PassThrough == nil {
				t.Fatal("PassThrough field is nil")
			}

			// Verify the chunk is preserved
			if len(action.PassThrough.Chunk) != len(tc.chunk) {
				t.Errorf("Chunk length mismatch: got %d, want %d",
					len(action.PassThrough.Chunk), len(tc.chunk))
			}

			for i := range tc.chunk {
				if action.PassThrough.Chunk[i] != tc.chunk[i] {
					t.Errorf("Chunk content mismatch at index %d: got %v, want %v",
						i, action.PassThrough.Chunk[i], tc.chunk[i])
					break
				}
			}
		})
	}
}

func TestShouldInjectError(t *testing.T) {
	// Test deterministic cases
	deterministicTests := []struct {
		name        string
		probability float64
		expected    bool
	}{
		{name: "Zero probability", probability: 0.0, expected: false},
		{name: "Negative probability", probability: -0.5, expected: false},
		{name: "100% probability", probability: 1.0, expected: true},
		{name: "Greater than 100%", probability: 1.5, expected: true},
	}

	for _, tt := range deterministicTests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldInjectError(tt.probability)
			if result != tt.expected {
				t.Errorf("shouldInjectError(%f) = %v; want %v",
					tt.probability, result, tt.expected)
			}
		})
	}

	// Test probabilistic cases with statistical validation
	probabilisticTests := []struct {
		name        string
		probability float64
		tolerance   float64
	}{
		{name: "10% probability", probability: 0.1, tolerance: 0.05},
		{name: "25% probability", probability: 0.25, tolerance: 0.05},
		{name: "50% probability", probability: 0.5, tolerance: 0.05},
		{name: "75% probability", probability: 0.75, tolerance: 0.05},
		{name: "90% probability", probability: 0.9, tolerance: 0.05},
	}

	for _, tt := range probabilisticTests {
		t.Run(tt.name, func(t *testing.T) {
			iterations := 10000
			trueCount := 0

			for i := 0; i < iterations; i++ {
				if shouldInjectError(tt.probability) {
					trueCount++
				}
			}

			actualRate := float64(trueCount) / float64(iterations)

			if actualRate < tt.probability-tt.tolerance ||
			   actualRate > tt.probability+tt.tolerance {
				t.Errorf("shouldInjectError(%f) statistical test failed: "+
					"got rate %f (outside tolerance ±%f)",
					tt.probability, actualRate, tt.tolerance)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	// Test Config struct initialization
	config := Config{
		ErrorProbability: 0.5,
		StatusCode:       429,
		ErrorBody:        `{"error": "test"}`,
		TargetHost:       "api.example.com",
		Headers: map[string]string{
			"X-Test": "value",
		},
		CACert: "/path/to/cert",
		CAKey:  "/path/to/key",
	}

	if config.ErrorProbability != 0.5 {
		t.Errorf("ErrorProbability = %f; want 0.5", config.ErrorProbability)
	}

	if config.StatusCode != 429 {
		t.Errorf("StatusCode = %d; want 429", config.StatusCode)
	}

	if config.TargetHost != "api.example.com" {
		t.Errorf("TargetHost = %s; want api.example.com", config.TargetHost)
	}

	if len(config.Headers) != 1 {
		t.Errorf("Headers length = %d; want 1", len(config.Headers))
	}

	if config.Headers["X-Test"] != "value" {
		t.Errorf("Headers[X-Test] = %s; want value", config.Headers["X-Test"])
	}
}

func BenchmarkGetErrorType(b *testing.B) {
	codes := []int{400, 401, 403, 404, 413, 429, 500, 529, 418}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		getErrorType(codes[i%len(codes)])
	}
}

func BenchmarkGetStatusText(b *testing.B) {
	codes := []int{400, 401, 403, 404, 413, 429, 500, 529, 418}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		getStatusText(codes[i%len(codes)])
	}
}

func BenchmarkPassThrough(b *testing.B) {
	chunk := []byte("This is a test chunk of data for benchmarking")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		passThrough(chunk)
	}
}

func BenchmarkShouldInjectError(b *testing.B) {
	probabilities := []float64{0.0, 0.1, 0.5, 0.9, 1.0}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shouldInjectError(probabilities[i%len(probabilities)])
	}
}