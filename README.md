# Anthropic Error Injection Plugin

A gRPC-based plugin for the Fault proxy that intercepts HTTPS traffic to `api.anthropic.com` and injects configurable HTTP errors with specified probability.

## Features

- **TLS Traffic Detection**: Identifies and monitors HTTPS/TLS traffic flows
- **Probabilistic error injection**: Configure the likelihood of errors (0.0 to 1.0)
- **Connection termination errors**: Simulates network failures and TLS errors
- **Anthropic API specific**: Targets `api.anthropic.com` by default (configurable)
- **Certificate generation**: Creates CA and domain certificates (for potential future MITM support)
- **Session state tracking**: Maintains state for each tunnel connection
- **gRPC plugin architecture**: Implements the Fault proxy plugin protocol

## How It Works

1. **CONNECT Detection**: Intercepts CONNECT tunnel requests to identify target hosts
2. **TLS Detection**: When TLS handshake is detected for target hosts:
   - Monitors TLS handshake messages (ClientHello, ServerHello, etc.)
   - Tracks TLS session state through handshake completion
   - Can inject errors at handshake time or during encrypted data transfer
3. **Error Injection**: Based on configured probability:
   - Terminates connections to simulate network failures
   - Closes TLS sessions with error messages
   - Simulates various HTTP status codes (429, 500, 503, etc.)
4. **Session Management**: Tracks each connection's state through the TLS lifecycle

### TLS MITM Limitations

**IMPORTANT**: Due to the plugin architecture, this plugin **cannot** perform full TLS man-in-the-middle with decryption. The plugin operates on data chunks flowing through the proxy and doesn't have direct access to network connections, which is required for TLS termination and re-encryption.

**What the plugin CAN do**:
- Detect TLS handshake messages
- Monitor TLS traffic flow
- Terminate connections at any point to simulate failures
- Inject errors during handshake or application data phases

**What the plugin CANNOT do**:
- Decrypt HTTPS traffic to read/modify HTTP requests/responses
- Perform true TLS MITM with certificate substitution
- Inspect the contents of encrypted application data

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

### Note on CA Certificates

The plugin generates a CA certificate and can create domain-specific certificates signed by this CA. However, **these certificates are not currently used for TLS MITM** due to plugin architecture limitations (see "TLS MITM Limitations" above).

The certificate generation functionality is included for:
- Future proxy-level MITM support
- Testing certificate generation
- Demonstration purposes

### CA Configuration Options (Optional)

- `--ca-cert`: Path to existing CA certificate file
- `--ca-key`: Path to existing CA private key file
- `--export-ca`: Export CA certificate to specified file
- `--install-ca`: Show CA installation instructions

Note: Both `--ca-cert` and `--ca-key` must be provided together if using existing CA files.

### If You Need Full TLS MITM

For actual HTTPS decryption and HTTP-level error injection, you would need:
1. A proxy that supports TLS MITM at the connection level (not chunk level)
2. Installation of the CA certificate in client trust stores
3. Modified plugin architecture that provides decrypted traffic to plugins

The current implementation focuses on **connection-level error injection** which is useful for testing:
- Network resilience
- Connection failure handling
- Timeout scenarios
- TLS handshake failures

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