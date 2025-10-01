package main

import (
	"crypto/rand"
	"math/big"

	pb "github.com/ljagiello/fault-anthropic-plugin/proto"
)

// Config holds the plugin configuration
type Config struct {
	ErrorProbability float64           `json:"error_probability"`
	StatusCode       int               `json:"status_code"`
	ErrorBody        string            `json:"error_body"`
	TargetHost       string            `json:"target_host"`
	Headers          map[string]string `json:"headers"`
}

// getErrorType returns appropriate error type for status code
func getErrorType(code int) string {
	switch code {
	case 400:
		return "invalid_request_error"
	case 401:
		return "authentication_error"
	case 403:
		return "permission_error"
	case 404:
		return "not_found_error"
	case 429:
		return "rate_limit_error"
	case 500, 502, 503, 504:
		return "api_error"
	default:
		return "error"
	}
}

// getStatusText returns the status text for a given status code
func getStatusText(code int) string {
	statusTexts := map[int]string{
		400: "Bad Request",
		401: "Unauthorized",
		403: "Forbidden",
		404: "Not Found",
		429: "Too Many Requests",
		500: "Internal Server Error",
		502: "Bad Gateway",
		503: "Service Unavailable",
		504: "Gateway Timeout",
	}

	if text, ok := statusTexts[code]; ok {
		return text
	}
	return "Error"
}

// passThrough creates a pass-through response
func passThrough(chunk []byte) *pb.ProcessTunnelDataResponse {
	return &pb.ProcessTunnelDataResponse{
		Action: &pb.ProcessTunnelDataResponse_PassThrough{
			PassThrough: &pb.PassThrough{
				Chunk: chunk,
			},
		},
	}
}

// shouldInjectError decides whether to inject an error based on probability
func shouldInjectError(probability float64) bool {
	if probability <= 0 {
		return false
	}
	if probability >= 1 {
		return true
	}

	n, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return false
	}

	return float64(n.Int64())/10000.0 < probability
}