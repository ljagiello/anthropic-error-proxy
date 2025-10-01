# TLS Implementation Documentation

## Overview

This document describes the TLS handling implementation in the Fault Anthropic Error Plugin, including architectural constraints, design decisions, and implementation details.

## Architecture Constraints

### Plugin-Based Architecture Limitations

The Fault proxy uses a plugin architecture where plugins receive and process data chunks flowing through the proxy. This architecture has fundamental limitations for TLS MITM:

1. **No Direct Network Access**: Plugins cannot create independent network connections
2. **Chunk-Based Processing**: Data flows as discrete chunks, not continuous streams
3. **Limited Control Flow**: Plugins can only:
   - Pass through chunks unchanged
   - Replace chunks with modified data
   - Buffer chunks (with time estimate)
   - Close connections with a reason

### Why Full TLS MITM Is Not Possible

True TLS man-in-the-middle requires:

1. **Bidirectional Connection Management**:
   - Terminate TLS from client (act as server)
   - Initiate TLS to real server (act as client)
   - Maintain two separate TLS sessions simultaneously

2. **Stateful TLS Session**:
   - Complete handshake negotiation
   - Derive session keys
   - Encrypt/decrypt application data using session keys

3. **Continuous Stream Access**:
   - Read complete TLS records
   - Process handshake messages in order
   - Handle fragmented records and multi-record messages

The plugin architecture provides none of these capabilities. Plugins receive arbitrary chunks of data and must respond synchronously without maintaining external connections.

## Current Implementation

### What We've Implemented

#### 1. TLS Detection and Monitoring

File: `/Users/lcf/code/github.com/ljagiello/fault-anthropic-error-plugin/tls_handler.go`

```go
// Detects TLS records by examining:
// - Content Type (0x14-0x18 for TLS)
// - Version (0x03 0x01-0x04 for TLS 1.0-1.3)
// - Record structure

func isTLSRecord(data []byte) bool {
    if len(data) < 5 {
        return false
    }
    contentType := data[0]
    if contentType < 0x14 || contentType > 0x18 {
        return false
    }
    // ... version checks
    return true
}
```

#### 2. TLS Handshake State Tracking

The TLSHandler tracks handshake progress:

- ClientHello (0x01)
- ServerHello (0x02)
- Certificate (0x0B)
- ServerKeyExchange (0x0C)
- ServerHelloDone (0x0E)
- ClientKeyExchange (0x10)
- Finished (0x14)

This allows the plugin to understand where in the TLS lifecycle each connection is.

#### 3. Connection-Level Error Injection

The plugin can inject errors by closing connections:

```go
// During handshake
if shouldInjectError(h.plugin.config.ErrorProbability) {
    return &pb.ProcessTunnelDataResponse{
        Action: &pb.ProcessTunnelDataResponse_Close{
            Close: &pb.Close{
                Reason: fmt.Sprintf("Simulated TLS error: HTTP %d %s",
                    h.plugin.config.StatusCode,
                    getStatusText(h.plugin.config.StatusCode)),
            },
        },
    }
}

// During application data
// Similar logic for closing during encrypted data transfer
```

#### 4. Certificate Generation (Unused)

The plugin includes certificate generation for potential future use:

```go
func (h *TLSHandler) generateCertForHost(hostname string) (*tls.Certificate, error) {
    // Generate RSA key pair
    priv, err := rsa.GenerateKey(rand.Reader, 2048)

    // Create certificate template
    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            CommonName:   hostname,
            Organization: []string{"Fault Proxy"},
        },
        // ... other fields
    }

    // Sign with CA
    certDER, err := x509.CreateCertificate(
        rand.Reader,
        &template,
        h.plugin.rootCA,  // Sign with our CA
        &priv.PublicKey,
        h.plugin.rootKey,
    )

    return cert, nil
}
```

### Integration Points

#### plugin.go Integration

The main plugin integrates TLS handling at line 276-287:

```go
// After CONNECT, check if it's TLS
if session.ConnectSeen && !session.HandshakeStarted {
    if isTLSHandshake(req.Chunk) {
        session.IsTLS = true
        session.HandshakeStarted = true

        // For target host, initialize TLS handler
        if session.TargetHost == p.config.TargetHost {
            if session.TLSHandler == nil {
                session.TLSHandler = NewTLSHandler(session, p)
            }
            return session.TLSHandler.ProcessData(req.Chunk), nil
        }

        // Pass through for non-target hosts
        return passThrough(req.Chunk), nil
    }
}

// Route TLS traffic through handler
if session.IsTLS && session.TLSHandler != nil {
    return session.TLSHandler.ProcessData(req.Chunk), nil
}
```

## Capabilities and Use Cases

### What This Implementation Can Do

1. **Detect TLS Traffic**: Identify when HTTPS/TLS is being used
2. **Monitor Handshake**: Track TLS handshake progression
3. **Simulate Connection Failures**: Terminate connections at any point
4. **Test Resilience**: Verify client handling of:
   - Handshake failures
   - Connection drops during data transfer
   - Timeout scenarios
   - Network interruptions

### What This Implementation Cannot Do

1. **Decrypt HTTPS**: Cannot read HTTP requests/responses inside TLS
2. **Modify HTTP Content**: Cannot inject HTTP-level errors into HTTPS traffic
3. **Inspect Payloads**: Cannot see API request/response bodies
4. **Selective Request Modification**: Cannot modify specific API calls

### Ideal Use Cases

This implementation is well-suited for testing:

- **Network Resilience**: Connection drops, timeouts, intermittent failures
- **TLS Handshake Issues**: Simulating handshake failures
- **Load Testing**: Connection-level failures under load
- **Retry Logic**: Client retry behavior on connection failures
- **Circuit Breakers**: Testing circuit breaker patterns

## Alternative Approaches

### For True HTTPS Decryption

If you need actual HTTP-level error injection in HTTPS traffic, consider:

#### 1. Proxy-Level MITM

Use a proxy that provides TLS termination at the connection level:

```
Client → Proxy (TLS termination) → Plugin (HTTP) → Proxy (TLS to server) → Server
```

Examples:
- mitmproxy with plugin support
- Envoy proxy with Lua/WASM filters
- Custom proxy with TLS termination

#### 2. SDK/Client-Level Interception

Inject errors at the SDK level before encryption:

```python
# Python SDK wrapper
class FaultInjectedClient:
    def __init__(self, client, error_rate=0.1):
        self.client = client
        self.error_rate = error_rate

    def messages_create(self, *args, **kwargs):
        if random.random() < self.error_rate:
            raise APIError("Simulated error", status_code=429)
        return self.client.messages.create(*args, **kwargs)
```

#### 3. DNS/Routing Redirection

Route traffic to a mock server:

```
Client → DNS (mock.api.anthropic.com) → Mock Server
```

The mock server can inject errors at HTTP level without TLS complexity.

## Technical Details

### TLS Record Structure

```
+-------------+
| ContentType | 1 byte  (0x16 = Handshake, 0x17 = Application Data)
+-------------+
| Version     | 2 bytes (0x0303 = TLS 1.2)
+-------------+
| Length      | 2 bytes (length of payload)
+-------------+
| Payload     | Length bytes
+-------------+
```

### Handshake Message Types

| Type | Value | Description |
|------|-------|-------------|
| HelloRequest | 0x00 | Server requests client to start new handshake |
| ClientHello | 0x01 | Client initiates handshake |
| ServerHello | 0x02 | Server responds to ClientHello |
| Certificate | 0x0B | Certificate chain |
| ServerKeyExchange | 0x0C | Server's ephemeral key |
| CertificateRequest | 0x0D | Server requests client cert |
| ServerHelloDone | 0x0E | Server handshake messages done |
| CertificateVerify | 0x0F | Proves client has private key |
| ClientKeyExchange | 0x10 | Client's ephemeral key |
| Finished | 0x14 | Handshake verification |

### Error Injection Timing

The plugin can inject errors at these points:

1. **During Handshake** (processHandshake):
   - After ClientHello
   - During certificate exchange
   - Before handshake completion

2. **During Application Data** (processApplicationData):
   - After handshake completion
   - During encrypted data transfer
   - At any point in the session

## Code Structure

### Files

- `plugin.go`: Main plugin logic, session management, HTTP handling
- `tls_handler.go`: TLS detection, handshake tracking, error injection
- `common.go`: Shared utilities, error types, probability logic

### Key Types

```go
// Session tracking
type Session struct {
    ID               string
    TargetHost       string
    IsTLS            bool
    HandshakeStarted bool
    TLSHandler       *TLSHandler
    // ...
}

// TLS handling
type TLSHandler struct {
    session           *Session
    plugin            *Plugin
    state             string
    handshakeComplete bool
    errorInjected     bool
    cert              *tls.Certificate
}
```

### Flow Diagram

```
ProcessTunnelData
    ↓
Check for CONNECT → Extract TargetHost
    ↓
Detect TLS Handshake → Initialize TLSHandler
    ↓
TLSHandler.ProcessData
    ↓
    ├─→ processHandshake → Check probability → Close or PassThrough
    └─→ processApplicationData → Check probability → Close or PassThrough
```

## Future Enhancements

### If Proxy Architecture Changes

If the Fault proxy is enhanced to support connection-level plugins:

1. **Use Existing Certificate Generation**: Already implemented, cached
2. **Implement Full TLS Termination**: Would need:
   - Connection accept/dial capabilities
   - Stream-based I/O (not chunk-based)
   - Goroutine support for bidirectional forwarding

3. **HTTP-Level Error Injection**: With decryption:
   ```go
   // Could then do this:
   if httpRequest.Path == "/v1/messages" {
       return injectHTTPError(429, anthropicErrorBody)
   }
   ```

### Potential Plugin Protocol Extensions

```protobuf
// Hypothetical future protocol
message ProcessConnectionRequest {
    string id = 1;
    string target_host = 2;
    int32 target_port = 3;
    // Plugin gets full connection control
}

message ProcessConnectionResponse {
    oneof action {
        AcceptConnection accept = 1;  // Plugin handles connection
        PassThrough pass_through = 2;  // Proxy handles connection
    }
}
```

## Conclusion

The current implementation provides:
- ✅ TLS traffic detection and monitoring
- ✅ Connection-level error injection
- ✅ Handshake state tracking
- ✅ Certificate generation (for future use)

But cannot provide:
- ❌ HTTPS decryption
- ❌ HTTP-level request/response modification
- ❌ Selective API call interception

For the use case of testing connection resilience and simulating network failures, this implementation is fully functional and appropriate. For HTTP-level error injection in HTTPS traffic, alternative approaches (proxy-level MITM, SDK wrappers, or mock servers) would be needed.
