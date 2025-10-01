# Anthropic Error Injection Plugin

A gRPC-based plugin for the Fault proxy that intercepts HTTPS requests to `api.anthropic.com` through tunneling proxies and injects configurable HTTP errors with specified probability.

## Features

- **Tunnel-based interception**: Works with HTTPS CONNECT tunneling, not just HTTP forwarding
- **Probabilistic error injection**: Configure the likelihood of errors (0.0 to 1.0)
- **Customizable error responses**: Set status codes, error messages, and headers
- **Anthropic API specific**: Targets `api.anthropic.com` by default (configurable)
- **gRPC plugin architecture**: Implements the Fault proxy plugin protocol
- **Trusted CA generation**: Creates a CA certificate that can be added to system trust stores
- **TLS interception**: Intercepts HTTPS traffic with proper certificate validation

## How It Works

Unlike the standard HTTP error fault which only works with HTTP forwarding, this plugin:

1. Intercepts CONNECT tunnel requests to identify target hosts
2. Buffers and analyzes tunneled HTTPS traffic
3. Detects HTTP requests within the encrypted tunnel
4. Injects error responses based on configured probability
5. Maintains session state for each tunnel connection

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
  }
}
```


## CA Certificate Management

### Generating and Installing the CA

The plugin generates a Certificate Authority (CA) that must be trusted by your system to properly intercept HTTPS traffic without certificate errors.

### Using Custom CA Files

By default, the plugin generates and stores CA files as `fault-ca.crt` and `fault-ca.key` in the current directory. You can use existing CA files:

```bash
# Use existing CA files
./anthropic-error-plugin \
  --ca-cert /path/to/existing-ca.crt \
  --ca-key /path/to/existing-ca.key

# NOTE: Both --ca-cert and --ca-key must be provided together
# The plugin will error if only one is provided

# Export CA certificate from custom location
./anthropic-error-plugin \
  --ca-cert /path/to/my-ca.crt \
  --ca-key /path/to/my-ca.key \
  --export-ca exported-ca.crt

# Or via config file
{
  "ca_cert": "/path/to/existing-ca.crt",
  "ca_key": "/path/to/existing-ca.key",
  ...
}
```

#### CA File Requirements

- **Both or neither**: You must provide both `--ca-cert` and `--ca-key`, or neither
- **Without flags**: Plugin generates new CA files in current directory
- **With both flags**: Plugin uses the specified existing CA files
- **Invalid combinations**: Plugin will exit with an error if only one is provided

#### Export the CA Certificate
```bash
./anthropic-error-plugin --export-ca fault-proxy-ca.crt
```

#### Installation Instructions
```bash
./anthropic-error-plugin --install-ca
```

#### macOS Installation
```bash
# System-wide trust
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain fault-proxy-ca.crt

# User-only trust
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain fault-proxy-ca.crt
```

#### Linux Installation
```bash
# Ubuntu/Debian
sudo cp fault-proxy-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# RHEL/CentOS/Fedora
sudo cp fault-proxy-ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

#### Windows Installation
```powershell
# Run as Administrator
certutil -addstore -f "ROOT" fault-proxy-ca.crt
```

### Important Security Notes

- The CA is generated with a 10-year validity period
- Only install CAs from sources you trust
- The CA allows the plugin to intercept and decrypt HTTPS traffic
- After installation, the CA will appear as "Fault Proxy Root CA" in your certificate store
- Restart applications/browsers after installing the CA

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

### Run Tests with Coverage
```bash
go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
```

### Run Benchmarks
```bash
go test -bench=. ./...
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

## CI/CD

This project uses GitHub Actions for continuous integration:

- **Linting**: Runs `golangci-lint` on every PR
- **Testing**: Runs tests with race detection on Go 1.25
- **Branch Protection**: Main branch requires PR reviews and passing checks
- **Dependency Updates**: Dependabot configured for weekly updates

## Contributing

Contributions are welcome! Please ensure:
- Code follows Go best practices and passes `golangci-lint`
- Tests are included for new features (run `make test`)
- All CI checks pass before requesting review
- Documentation is updated as needed
- The plugin protocol is properly implemented

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature-name`)
3. Make your changes
4. Run tests (`make test`)
5. Run linter (`golangci-lint run`)
6. Commit your changes
7. Push to your fork
8. Create a Pull Request

All PRs require:
- Passing lint checks
- Passing tests
- At least one approving review