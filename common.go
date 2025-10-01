package main

// Config holds the proxy configuration
type Config struct {
	ProxyPort        int               `json:"proxy_port,omitempty"`
	ErrorProbability float64           `json:"error_probability"`
	StatusCode       int               `json:"status_code"`
	ErrorBody        string            `json:"error_body"`
	TargetHost       string            `json:"target_host"`
	Headers          map[string]string `json:"headers"`
	CACert           string            `json:"ca_cert,omitempty"`
	CAKey            string            `json:"ca_key,omitempty"`
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
	case 413:
		return "request_too_large"
	case 429:
		return "rate_limit_error"
	case 500:
		return "api_error"
	case 529:
		return "overloaded_error"
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
		413: "Request Entity Too Large",
		429: "Too Many Requests",
		500: "Internal Server Error",
		529: "Overloaded",
	}

	if text, ok := statusTexts[code]; ok {
		return text
	}
	return "Error"
}