# Anthropic Error Injection Plugin

A gRPC-based plugin for the Fault proxy that intercepts HTTPS requests to `api.anthropic.com` through tunneling proxies and injects configurable HTTP errors with specified probability.

## Features

- **Tunnel-based interception**: Works with HTTPS CONNECT tunneling, not just HTTP forwarding
- **Probabilistic error injection**: Configure the likelihood of errors (0.0 to 1.0)
- **Customizable error responses**: Set status codes, error messages, and headers
- **Anthropic API specific**: Targets `api.anthropic.com` by default (configurable)
- **gRPC plugin architecture**: Implements the Fault proxy plugin protocol

## How It Works

Unlike the standard HTTP error fault which only works with HTTP forwarding, this plugin:

1. Intercepts CONNECT tunnel requests to identify target hosts
2. Buffers and analyzes tunneled HTTPS traffic
3. Detects HTTP requests within the encrypted tunnel
4. Injects error responses based on configured probability
5. Maintains session state for each tunnel connection

## Building

### Prerequisites

- Go 1.24 or later
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

### Docker Build

```bash
make docker-build
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
  }
}
```

### Docker Run

```bash
docker run -p 50051:50051 anthropic-error-plugin:latest \
  --error-probability 0.5 \
  --status-code 503
```

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

This plugin is designed to work with the Fault proxy in tunneling mode. Configure the Fault proxy to use this plugin for HTTPS tunnel traffic:

```bash
# Example Fault proxy configuration (adjust based on actual Fault CLI)
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

## Testing

### Basic Test
```bash
# Start the plugin
./anthropic-error-plugin --error-probability 1.0 --status-code 500

# In another terminal, configure proxy to use the plugin
# Then make a request through the proxy
curl -x http://localhost:8080 https://api.anthropic.com/v1/messages
```

### Unit Tests
```bash
make test
```

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
├── plugin.proto           # Protocol buffer definitions
├── proto/                 # Generated protobuf code
├── generate.sh            # Proto generation script
├── Makefile              # Build automation
├── Dockerfile            # Container build
├── config.example.json   # Example configuration
└── README.md            # This file
```

### Making Changes

1. Modify the plugin logic in `plugin.go`
2. Update protocol buffers if needed in `plugin.proto`
3. Regenerate proto code: `make proto`
4. Build and test: `make build && make test`

## License

This plugin is part of the Fault project. See the main project for license information.

## Contributing

Contributions are welcome! Please ensure:
- Code follows Go best practices
- Tests are included for new features
- Documentation is updated as needed
- The plugin protocol is properly implemented