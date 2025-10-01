# Anthropic Error Injection Plugin

A gRPC-based plugin for the Fault proxy that intercepts HTTPS traffic to `api.anthropic.com` and injects configurable HTTP errors with specified probability.

## Features

- **TLS MITM Interception**: Intercepts and decrypts HTTPS traffic using dynamically generated certificates
- **Probabilistic error injection**: Configure the likelihood of errors (0.0 to 1.0)
- **Customizable error responses**: Set status codes, error messages, and headers
- **Anthropic API specific**: Targets `api.anthropic.com` by default (configurable)
- **Certificate generation**: Creates certificates on-the-fly signed by local CA
- **Session state tracking**: Maintains state for each tunnel connection
- **gRPC plugin architecture**: Implements the Fault proxy plugin protocol

## How It Works

1. **CONNECT Detection**: Intercepts CONNECT tunnel requests to identify target hosts
2. **TLS Interception**: When TLS handshake is detected for target hosts:
   - Generates a certificate for the target domain signed by our CA
   - Responds with ServerHello using the generated certificate
   - Establishes TLS session with the client
3. **Traffic Modification**: Decrypts HTTPS traffic and can:
   - Inject HTTP error responses based on probability
   - Modify requests or responses
   - Pass through unmodified traffic
4. **Session Management**: Tracks each connection's state through the TLS handshake

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

### Command Line Options

```bash
./anthropic-error-plugin \
  --port 50051 \
  --error-probability 0.3 \
  --status-code 429 \
  --target-host api.anthropic.com
```

### Available Flags

- `--port`: gRPC server port (default: 50051)
- `--config`: JSON configuration file path
- `--error-probability`: Probability of error injection 0-1 (default: 0.1)
- `--status-code`: HTTP status code to return (default: 500)
- `--error-body`: Custom error response body JSON
- `--target-host`: Target host to intercept (default: api.anthropic.com)
- `--ca-cert`: Path to existing CA certificate file (must be used with --ca-key)
- `--ca-key`: Path to existing CA private key file (must be used with --ca-cert)
- `--export-ca`: Export CA certificate to specified file
- `--install-ca`: Show CA certificate installation instructions

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

### Important: Install the CA Certificate

For TLS MITM to work properly, you **MUST** install the generated CA certificate in your system's trust store. Without this, clients will reject the dynamically generated certificates.

### Generating and Installing the CA

1. **Export the CA certificate**:
```bash
./anthropic-error-plugin --export-ca fault-proxy-ca.crt
```

2. **Install the CA certificate** (choose based on your OS):

#### macOS
```bash
# System-wide trust
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain fault-proxy-ca.crt

# Or user-only trust
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain fault-proxy-ca.crt
```

#### Linux
```bash
# Ubuntu/Debian
sudo cp fault-proxy-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# RHEL/CentOS/Fedora
sudo cp fault-proxy-ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

#### Windows
```powershell
# Run as Administrator
certutil -addstore -f "ROOT" fault-proxy-ca.crt
```

### CA Configuration Options

- `--ca-cert`: Path to existing CA certificate file
- `--ca-key`: Path to existing CA private key file
- `--export-ca`: Export CA certificate to specified file
- `--install-ca`: Show CA installation instructions

Note: Both `--ca-cert` and `--ca-key` must be provided together if using existing CA files.

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

The plugin works with the Fault proxy to intercept and modify HTTPS traffic:

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

**Important**: Ensure the CA certificate is installed in your system trust store before testing.

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