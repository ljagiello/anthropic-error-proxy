package main

import (
	"testing"
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

func TestConfigValidation(t *testing.T) {
	// Test Config struct initialization
	config := Config{
		ProxyPort:        8080,
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

	if config.ProxyPort != 8080 {
		t.Errorf("ProxyPort = %d; want 8080", config.ProxyPort)
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