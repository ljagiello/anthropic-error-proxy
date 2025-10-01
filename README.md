# Anthropic Error Proxy

A standalone HTTP/HTTPS proxy that intercepts traffic to `api.anthropic.com` and injects configurable HTTP errors with specified probability. Perfect for testing error handling in applications that use the Anthropic API.

## Features

- **Full TLS MITM**: Intercepts and decrypts HTTPS traffic using generated certificates
- **HTTP Error Injection**: Returns actual HTTP error responses (429, 500, 503, etc.) over HTTPS
- **Probabilistic error injection**: Configure the likelihood of errors (0.0 to 1.0)
- **Anthropic API specific**: Targets `api.anthropic.com` by default (configurable)
- **Pass-through mode**: Non-target traffic passes through unmodified
- **Automatic certificate generation**: Creates CA and domain certificates for TLS interception
- **Custom error responses**: Configure custom error bodies and headers

## How It Works

1. **Proxy Setup**: The proxy listens on a configured port (default 8080) for HTTP/HTTPS traffic
2. **CONNECT Handling**: When a CONNECT request is received for HTTPS:
   - For target hosts: Performs TLS MITM to intercept and potentially modify traffic
   - For other hosts: Transparently passes through the encrypted connection
3. **TLS Interception**: For target hosts (e.g., api.anthropic.com):
   - Performs TLS handshake with the client using a generated certificate
   - Decrypts the HTTPS request
   - Based on configured probability, either:
     - Injects an HTTP error response with proper status code and JSON body
     - Forwards the request to the real server (when not injecting errors)
4. **Error Injection**: When triggered:
   - Generates proper HTTP error response (429, 500, etc.)
   - Includes appropriate JSON error body matching Anthropic's error format
   - Encrypts and sends the response back to the client

## Installation

```bash
# Clone the repository
git clone https://github.com/ljagiello/anthropic-error-proxy.git
cd anthropic-error-proxy

# Build the proxy
go build -o anthropic-error-proxy .
```

## Usage

### Basic Usage

Run the proxy with default settings (10% error probability, HTTP 500):

```bash
./anthropic-error-proxy
```

### Configure Error Injection

```bash
# Always return HTTP 429 (Rate Limit) errors
./anthropic-error-proxy --error-probability 1.0 --status-code 429

# 50% chance of HTTP 503 (Service Unavailable) errors
./anthropic-error-proxy --error-probability 0.5 --status-code 503

# Custom proxy port
./anthropic-error-proxy --proxy-port 8888
```

### Using with curl

```bash
# Configure curl to use the proxy
curl -x http://localhost:8080 \
  https://api.anthropic.com/v1/messages \
  -H "x-api-key: YOUR_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hello"}]}'
```

### Using with Python

```python
import requests

proxies = {
    'http': 'http://localhost:8080',
    'https': 'http://localhost:8080',
}

# Disable SSL verification if using self-signed certificates
response = requests.post(
    'https://api.anthropic.com/v1/messages',
    proxies=proxies,
    verify=False,  # Only for testing with self-signed certificates
    headers={
        'x-api-key': 'YOUR_KEY',
        'anthropic-version': '2023-06-01',
    },
    json={
        'model': 'claude-3-5-sonnet-20241022',
        'messages': [{'role': 'user', 'content': 'Hello'}],
    }
)
```

## Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--proxy-port` | Proxy listening port | 8080 |
| `--error-probability` | Probability of error injection (0-1) | 0.1 |
| `--status-code` | HTTP status code to return | 500 |
| `--error-body` | Custom error response body JSON | Auto-generated |
| `--target-host` | Target host to intercept | api.anthropic.com |
| `--ca-cert` | Path to CA certificate file | fault-ca.crt |
| `--ca-key` | Path to CA private key file | fault-ca.key |
| `--export-ca` | Export CA certificate to specified file | - |
| `--install-ca` | Show CA installation instructions | false |
| `--config` | JSON configuration file path | - |
| `--headers` | Custom headers as JSON | - |

## Configuration File

You can use a JSON configuration file instead of command line flags:

```json
{
  "proxy_port": 8080,
  "error_probability": 0.3,
  "status_code": 429,
  "target_host": "api.anthropic.com",
  "error_body": "{\"type\":\"error\",\"error\":{\"type\":\"rate_limit_error\",\"message\":\"Rate limit exceeded\"}}",
  "headers": {
    "X-RateLimit-Limit": "1000",
    "X-RateLimit-Remaining": "0",
    "Retry-After": "60"
  }
}
```

```bash
./anthropic-error-proxy --config config.json
```

## CA Certificate Management

For HTTPS interception to work, clients need to trust the proxy's CA certificate.

### Export CA Certificate

```bash
./anthropic-error-proxy --export-ca my-ca.crt
```

### Installation Instructions

```bash
# Show platform-specific installation instructions
./anthropic-error-proxy --install-ca
```

#### macOS
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain fault-ca.crt
```

#### Linux (Ubuntu/Debian)
```bash
sudo cp fault-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

#### Windows
```powershell
certutil -addstore -f "ROOT" fault-ca.crt
```

### Security Note

Only install CA certificates from sources you trust. The CA certificate allows the proxy to decrypt HTTPS traffic.

## Error Response Examples

### Rate Limit Error (429)
```json
{
  "type": "error",
  "error": {
    "type": "rate_limit_error",
    "message": "Simulated error: Too Many Requests"
  }
}
```

### Internal Server Error (500)
```json
{
  "type": "error",
  "error": {
    "type": "api_error",
    "message": "Simulated error: Internal Server Error"
  }
}
```

### Service Unavailable (503)
```json
{
  "type": "error",
  "error": {
    "type": "api_error",
    "message": "Simulated error: Service Unavailable"
  }
}
```

## Supported Error Codes

| Code | Error Type | Description |
|------|------------|-------------|
| 400 | `invalid_request_error` | Bad Request |
| 401 | `authentication_error` | Unauthorized |
| 403 | `permission_error` | Forbidden |
| 404 | `not_found_error` | Not Found |
| 413 | `request_too_large` | Request Entity Too Large |
| 429 | `rate_limit_error` | Too Many Requests |
| 500 | `api_error` | Internal Server Error |
| 503 | `api_error` | Service Unavailable |
| 529 | `overloaded_error` | Overloaded |

## Testing

Run the included test script:

```bash
chmod +x test_standalone.sh
./test_standalone.sh
```

This will:
1. Test HTTPS interception for api.anthropic.com
2. Verify pass-through for other hosts
3. Test different error codes and probabilities

## Development

### Project Structure
```
anthropic-error-proxy/
├── main.go                # Entry point and CLI handling
├── standalone_proxy.go    # Proxy implementation
├── common.go             # Common utilities and types
├── common_test.go        # Tests for common utilities
├── go.mod                # Go module definition
└── README.md            # This file
```

### Building from Source

```bash
go build -o anthropic-error-proxy .
```

### Running Tests

```bash
go test ./...
```

## License

Apache License 2.0

## Contributing

Contributions are welcome! Please ensure:
- Code follows Go best practices
- Tests are included for new features
- Documentation is updated as needed