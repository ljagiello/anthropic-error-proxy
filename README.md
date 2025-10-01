# Anthropic Error Injection Plugin

A gRPC-based plugin for the Fault proxy that can inject configurable HTTP errors with specified probability.

⚠️ **IMPORTANT LIMITATION**: This plugin currently **cannot intercept HTTPS traffic**. TLS MITM is not implemented, meaning it cannot inject errors into encrypted HTTPS requests to `api.anthropic.com`.

## Current Capabilities

### What Works ✅
- **Plain HTTP traffic**: Can inject errors into unencrypted HTTP requests
- **HTTP forward mode**: Handles direct HTTP proxy forwarding
- **CONNECT tunnel detection**: Identifies tunnel establishment for HTTPS
- **Session tracking**: Maintains state for each connection
- **Probabilistic error injection**: For plain HTTP traffic only

### What Doesn't Work ❌
- **HTTPS interception**: Cannot decrypt or modify HTTPS traffic
- **TLS MITM**: Not implemented despite CA certificate generation code
- **Anthropic API error injection**: Since the API uses HTTPS exclusively
- **Encrypted tunnel traffic**: Can detect but cannot modify

## How It Currently Works

The plugin can only handle:

1. Plain HTTP requests (non-encrypted)
2. HTTP requests in CONNECT tunnels before TLS handshake begins
3. Direct HTTP forwarding through the proxy

When HTTPS traffic is detected, the plugin:
- Logs that TLS was detected
- Passes through all encrypted data unchanged
- Cannot inject any errors

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


## CA Certificate (Currently Unused)

⚠️ **Note**: The plugin generates CA certificates but **does not use them** since TLS MITM is not implemented. The CA-related flags exist but have no practical effect on the plugin's operation.

### CA-Related Flags (Non-functional)

The following flags exist in the code but don't enable HTTPS interception:
- `--ca-cert`: Path to CA certificate file
- `--ca-key`: Path to CA private key file
- `--export-ca`: Export CA certificate
- `--install-ca`: Show CA installation instructions

These flags were intended for future TLS MITM implementation but currently serve no purpose since the plugin cannot decrypt HTTPS traffic.

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

⚠️ **LIMITATION**: This plugin cannot inject errors into HTTPS traffic to api.anthropic.com since it cannot decrypt TLS.

The plugin can only handle:
- Plain HTTP traffic (rare in production)
- HTTP requests before TLS handshake in tunnels
- Direct HTTP proxy forwarding

```bash
# Example Fault proxy configuration (adjust based on actual Fault CLI)
# Note: Will NOT work for HTTPS traffic to api.anthropic.com
fault run \
  --mode tunnel \
  --plugin-endpoint localhost:50051 \
  --target https://api.anthropic.com
```

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