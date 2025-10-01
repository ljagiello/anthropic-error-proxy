# Anthropic Error Injection Plugin

A flexible HTTP/HTTPS proxy that intercepts traffic to `api.anthropic.com` and injects configurable HTTP errors with specified probability. Can run as either a Fault proxy plugin or a standalone HTTP/HTTPS proxy.

## Features

- **Standalone HTTP/HTTPS Proxy Mode**: Full-featured proxy with TLS MITM capabilities
- **Fault Plugin Mode**: gRPC-based plugin for the Fault proxy (experimental)
- **Full TLS MITM**: Intercepts and decrypts HTTPS traffic using generated certificates
- **HTTP Error Injection**: Returns actual HTTP error responses (429, 500, 503, etc.) over HTTPS
- **Probabilistic error injection**: Configure the likelihood of errors (0.0 to 1.0)
- **Anthropic API specific**: Targets `api.anthropic.com` by default (configurable)
- **Automatic certificate generation**: Creates CA and domain certificates for TLS interception
- **Pass-through mode**: Non-target traffic passes through unmodified

## How It Works

1. **TLS Detection**: When TLS ClientHello is detected for target hosts:
   - Initializes a full TLS server using Go's `crypto/tls` package
   - Uses `net.Pipe()` to bridge chunk-based data flow with TLS connection
   - Generates and signs certificates for the target domain

2. **TLS Handshake**:
   - Receives ClientHello from the actual client
   - Performs TLS handshake as the server
   - Returns ServerHello, Certificate, and other handshake messages
   - Establishes encrypted TLS session

3. **HTTP Request Processing**:
   - Decrypts incoming HTTPS request over the established TLS connection
   - Parses HTTP request from decrypted stream
   - Applies error injection based on configured probability

4. **Error Injection**: When error is triggered:
   - Generates HTTP error response (e.g., HTTP 429 with JSON body)
   - Encrypts response using established TLS session
   - Sends encrypted response back to client
   - Client receives proper HTTP 429 error, not connection failure

5. **Session Management**:
   - Runs TLS server in dedicated goroutine per session
   - Buffers responses across multiple chunk calls
   - Properly handles TLS state machine timing

### TLS MITM Implementation

The plugin implements a **full TLS man-in-the-middle** proxy that:

**✓ DOES**:
- Intercepts TLS ClientHello and becomes the TLS server
- Performs complete TLS handshake with the client
- Decrypts HTTPS traffic to read HTTP requests
- Generates and sends encrypted HTTP error responses
- Returns proper HTTP status codes (429, 500, 503, etc.) over HTTPS
- Maintains TLS session state across chunk-based data flow

**Architecture**:
- Uses `net.Pipe()` to create bidirectional connection
- Runs `tls.Server()` in goroutine to handle TLS protocol
- Feeds incoming chunks to pipe, drains encrypted responses
- Works within plugin's chunk-based processing model

**Note**: Clients must trust the plugin's CA certificate for TLS verification to succeed. Use `--export-ca` and `--install-ca` flags for CA setup.

## Building

### Prerequisites

- Go 1.25 or later
- Protocol Buffers compiler (`protoc`)
- gRPC Go plugins

### Install Dependencies

```bash
make install-deps
```

### Build the Plugin

```bash
make build
```


## Running

### Standalone Proxy Mode (Recommended)

Run as a standalone HTTP/HTTPS proxy server:

```bash
./anthropic-error-plugin \
  --standalone \
  --proxy-port 8080 \
  --error-probability 0.3 \
  --status-code 429 \
  --target-host api.anthropic.com
```

Then configure your HTTP client to use `http://localhost:8080` as the proxy:

```bash
# Using curl with the proxy
curl -k -x http://localhost:8080 \
  https://api.anthropic.com/v1/messages \
  -H "x-api-key: YOUR_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hello"}]}'
```

### Fault Plugin Mode

Run as a gRPC plugin for the Fault proxy:

```bash
# Start the plugin
./anthropic-error-plugin \
  --port 50051 \
  --error-probability 0.3 \
  --status-code 429 \
  --target-host api.anthropic.com

# Start Fault proxy with the plugin
fault run --grpc-plugin http://localhost:50051 --upstream https://api.anthropic.com
```

### Available Flags

**Common flags:**
- `--error-probability`: Probability of error injection 0-1 (default: 0.1)
- `--status-code`: HTTP status code to return (default: 500)
- `--error-body`: Custom error response body JSON
- `--target-host`: Target host to intercept (default: api.anthropic.com)
- `--config`: JSON configuration file path
- `--ca-cert`: Path to existing CA certificate file (must be used with --ca-key)
- `--ca-key`: Path to existing CA private key file (must be used with --ca-cert)
- `--export-ca`: Export CA certificate to specified file
- `--install-ca`: Show CA certificate installation instructions

**Standalone mode:**
- `--standalone`: Run as standalone HTTP/HTTPS proxy
- `--proxy-port`: Proxy listening port (default: 8080)

**Plugin mode:**
- `--port`: gRPC server port (default: 50051)

### Using Configuration File

```bash
./anthropic-error-plugin --config config.json
```

Example `config.json`:
```json
{
  "error_probability": 0.3,
  "status_code": 429,
  "target_host": "api.anthropic.com",
  "error_body": "{\"type\":\"error\",\"error\":{\"type\":\"rate_limit_error\",\"message\":\"Rate limit exceeded\"}}",
  "headers": {
    "X-RateLimit-Limit": "1000",
    "X-RateLimit-Remaining": "0",
    "Retry-After": "60"
  },
  "ca_cert": "/path/to/ca.crt",
  "ca_key": "/path/to/ca.key"
}
```

Note: `ca_cert` and `ca_key` fields are optional but must be provided together if used.


## CA Certificate Management

### CA Certificate Setup

The plugin performs full TLS MITM, which requires clients to trust the plugin's CA certificate. Without this, clients will reject the TLS connection due to certificate validation failures.

### CA Configuration Options

- `--ca-cert`: Path to existing CA certificate file
- `--ca-key`: Path to existing CA private key file
- `--export-ca`: Export CA certificate to specified file
- `--install-ca`: Show CA installation instructions

Note: Both `--ca-cert` and `--ca-key` must be provided together if using existing CA files.

### CA Setup Steps

1. **Export the CA Certificate**:
```bash
./anthropic-error-plugin --export-ca fault-ca.crt
```

2. **Install CA Certificate** (varies by platform):

**macOS**:
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain fault-ca.crt
```

**Linux (Ubuntu/Debian)**:
```bash
sudo cp fault-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

**Windows**:
```powershell
certutil -addstore -f "ROOT" fault-ca.crt
```

3. **Verify Installation**:
Run your HTTPS client and verify it accepts the plugin's certificates.

### Security Considerations

- The CA private key (`fault-ca.key`) should be kept secure
- Only install the CA certificate on systems where you control the plugin
- Remove the CA certificate when testing is complete
- Never share the CA private key

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

### Overloaded Error (529)
```json
{
  "type": "error",
  "error": {
    "type": "overloaded_error",
    "message": "Simulated error: Overloaded"
  }
}
```

### Request Too Large (413)
```json
{
  "type": "error",
  "error": {
    "type": "request_too_large",
    "message": "Simulated error: Request Entity Too Large"
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

## Integration with Fault Proxy

The plugin works with the Fault proxy to intercept HTTPS traffic and inject connection errors:

```bash
# Start the plugin
./anthropic-error-plugin \
  --port 50051 \
  --error-probability 0.3 \
  --status-code 429 \
  --target-host api.anthropic.com

# Configure Fault proxy to use the plugin
fault run \
  --mode tunnel \
  --plugin-endpoint localhost:50051 \
  --target https://api.anthropic.com
```

The plugin will monitor TLS traffic to `api.anthropic.com` and randomly terminate connections based on the configured probability, simulating various failure scenarios.

## Plugin Protocol

The plugin implements the following gRPC services:

- `HealthCheck`: Reports plugin health status
- `GetPluginInfo`: Returns plugin metadata
- `GetPluginCapabilities`: Declares tunnel handling capability
- `ProcessTunnelData`: Intercepts and potentially modifies tunnel data

## Troubleshooting

### Plugin Not Intercepting Requests
- Ensure the plugin is running and listening on the correct port
- Verify the proxy is configured to use the plugin endpoint
- Check that tunnel mode is enabled in the proxy

### Errors Not Being Injected
- Verify `error_probability` is greater than 0
- Check logs for session detection and interception messages
- Ensure target host matches the actual API hostname

### Connection Issues
- Check firewall rules for the gRPC port (default 50051)
- Verify network connectivity between proxy and plugin
- Review plugin logs for connection errors

## Development

### Project Structure
```
anthropic-error-plugin/
├── main.go                 # Entry point and CLI
├── plugin.go              # Plugin implementation
├── common.go              # Common types and utilities
├── plugin.proto           # Protocol buffer definitions
├── proto/                 # Generated protobuf code
├── Makefile              # Build automation
├── config.example.json   # Example configuration
└── README.md            # This file
```

### Making Changes

1. Modify the plugin logic in `plugin.go`
2. Update protocol buffers if needed in `plugin.proto`
3. Regenerate proto code: `make proto`
4. Build and test: `make build && make test`

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please ensure:
- Code follows Go best practices and passes `golangci-lint`
- Tests are included for new features (run `make test`)
- All CI checks pass before requesting review
- Documentation is updated as needed
- The plugin protocol is properly implemented