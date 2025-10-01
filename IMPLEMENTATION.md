# TLS MITM Implementation for Fault Proxy Plugin

## Overview

This document describes the implementation of full TLS man-in-the-middle (MITM) functionality in the Fault proxy plugin to enable HTTP error injection over HTTPS connections.

## Problem Statement

The original requirement was to return actual HTTP 429 responses for HTTPS traffic to `api.anthropic.com`, not just drop TCP connections. This required implementing a complete TLS server within the plugin's chunk-based architecture.

## Architecture Challenges

### Chunk-Based Processing

The Fault proxy plugin architecture provides data in chunks via `ProcessTunnelData` calls. Each call receives a chunk of bytes flowing through the proxy and must return an action (pass through, replace, or close).

Key constraints:
- No direct access to network connections
- Data arrives in arbitrary-sized chunks
- Must maintain state across multiple calls
- TLS requires bidirectional communication

### TLS Requirements

A TLS server needs:
1. Complete bidirectional communication channel
2. Ability to read and write at any time (not chunk-by-chunk)
3. State machine that can block waiting for data
4. Separate read/write streams

## Solution: net.Pipe() + Goroutine Architecture

### Core Components

#### 1. **net.Pipe() for Bidirectional Communication**

```go
h.clientConn, h.serverConn = net.Pipe()
h.tlsConn = tls.Server(h.serverConn, tlsConfig)
```

`net.Pipe()` creates a synchronized pair of connections:
- `clientConn`: Plugin feeds incoming chunks here
- `serverConn`: TLS server reads from here
- Writes to one end appear as reads on the other
- Fully synchronous and thread-safe

#### 2. **Dedicated TLS Server Goroutine**

```go
go h.runTLSServer()
```

Runs in background to:
- Perform TLS handshake (blocking operation)
- Read HTTP request from decrypted stream
- Generate and encrypt HTTP error response
- Signal completion via channel

#### 3. **Response Buffer with Goroutine**

```go
go func() {
    buf := make([]byte, 32*1024)
    for {
        n, err := h.clientConn.Read(buf)
        if n > 0 {
            h.responseBuffer.Write(buf[:n])
        }
    }
}()
```

Continuously reads encrypted responses from `clientConn` and buffers them for sending back to the real client.

#### 4. **ProcessData Flow**

```go
func (h *TLSHandler) ProcessData(chunk []byte) *pb.ProcessTunnelDataResponse {
    // 1. Initialize TLS server on first chunk
    if !h.tlsInitialized {
        h.initTLSServer()
        h.processTLSStateMachine()
        h.tlsInitialized = true
    }

    // 2. Feed chunk to client connection
    h.clientConn.Write(chunk)

    // 3. Wait briefly for processing
    time.Sleep(10 * time.Millisecond)

    // 4. Drain and return buffered responses
    if h.responseBuffer.Len() > 0 {
        return Replace(h.responseBuffer.Bytes())
    }

    // 5. Check if TLS server completed
    select {
    case <-h.tlsServerDone:
        return Close("TLS session complete")
    default:
        return Replace([]byte{}) // Wait for more data
    }
}
```

## Data Flow

### 1. Client → Plugin → TLS Server

```
Client sends TLS data
    ↓
ProcessTunnelData(chunk)
    ↓
clientConn.Write(chunk)
    ↓
serverConn.Read() [in TLS goroutine]
    ↓
TLS decryption
    ↓
HTTP request parsing
```

### 2. TLS Server → Plugin → Client

```
TLS server generates response
    ↓
tlsConn.Write(httpResponse)
    ↓
TLS encryption
    ↓
serverConn.Write()
    ↓
clientConn.Read() [in buffer goroutine]
    ↓
responseBuffer
    ↓
ProcessData returns Replace(responseBuffer)
    ↓
Client receives encrypted response
```

## Key Implementation Details

### Certificate Generation

```go
cert, err := h.generateCertForHost(h.session.TargetHost)
```

- Generates RSA 2048-bit certificates
- Signs with plugin's root CA
- Caches certificates per hostname
- Includes SANs for wildcard support

### TLS Handshake

```go
err := h.tlsConn.Handshake()
```

- Blocks until handshake completes
- Runs in dedicated goroutine
- Generates ServerHello, Certificate, etc.
- Establishes TLS 1.2/1.3 session

### HTTP Processing

```go
reader := bufio.NewReader(h.tlsConn)
req, err := http.ReadRequest(reader)
```

- Reads decrypted HTTP request
- Parses method, path, headers
- Applies error injection probability

### Error Injection

```go
response := fmt.Sprintf("HTTP/1.1 %d %s\r\n...", statusCode, statusText)
h.tlsConn.Write([]byte(response))
```

- Generates proper HTTP response
- Encrypts via TLS connection
- Includes JSON error body
- Sets appropriate headers

## Timing and Synchronization

### Sleep for Processing

```go
time.Sleep(10 * time.Millisecond)
```

Gives TLS server time to:
- Process incoming chunk
- Generate handshake responses
- Encrypt application data

This is necessary because:
- TLS processing is asynchronous
- Response buffer goroutine needs time to read
- Chunk calls return immediately otherwise

### Done Channel

```go
h.tlsServerDone = make(chan error, 1)
```

Signals when TLS server completes:
- Handshake failure
- HTTP processing complete
- Connection closed

Plugin uses this to know when to close the tunnel.

## Error Handling

### Handshake Failures
- Logged and reported via done channel
- Connection closed with error reason
- Client sees TLS handshake failure

### HTTP Processing Errors
- Invalid HTTP requests logged
- Connection closed gracefully
- TLS session terminated properly

### Pipe Errors
- Write errors indicate closed connection
- Read errors signal goroutine exit
- Proper cleanup on both ends

## Performance Considerations

### Goroutine Per Session
- One TLS server goroutine per session
- One response buffer goroutine per session
- Cleaned up when session ends
- Minimal overhead for short-lived connections

### Memory Buffers
- 32KB response buffer
- Certificate cache to avoid regeneration
- Efficient byte copying

### Sleep Duration
- 10ms balances responsiveness and CPU usage
- Could be reduced for lower latency
- Could be increased for lower CPU usage

## Testing Recommendations

### 1. CA Certificate Setup
```bash
./fault-anthropic-error-plugin --export-ca fault-ca.crt
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain fault-ca.crt
```

### 2. Plugin Startup
```bash
./fault-anthropic-error-plugin \
    --port 50051 \
    --error-probability 1.0 \
    --status-code 429 \
    --target-host api.anthropic.com
```

### 3. Test Client
```bash
curl -v -x http://localhost:8080 https://api.anthropic.com/v1/messages \
    -H "x-api-key: test-key" \
    -H "anthropic-version: 2023-06-01" \
    -d '{"model":"claude-3-5-sonnet-20241022","max_tokens":1024,"messages":[{"role":"user","content":"Hello"}]}'
```

Expected result:
- TLS handshake succeeds (CA trusted)
- HTTP request decrypted and logged
- HTTP 429 response returned
- Response includes proper JSON error body

## Debugging

### Enable Verbose Logging
```go
log.Printf("[TLS-Handler %s] ClientHello detected", h.session.ID)
log.Printf("[TLS-Handler %s] ✓ TLS handshake complete", h.session.ID)
log.Printf("[TLS-Handler %s] Received HTTP request: %s %s", ...)
log.Printf("[TLS-Handler %s] 💉 Injecting HTTP %d error", ...)
```

### Check Logs For
- TLS server initialization
- Handshake completion
- HTTP request details
- Response buffer activity
- Goroutine completion

## Known Limitations

### 1. No Upstream Proxying
Current implementation only injects errors. To pass through non-error requests would require:
- Opening connection to real server
- Proxying decrypted traffic
- Re-encrypting upstream responses
- Additional goroutines for bidirectional proxying

### 2. Sleep-Based Timing
Uses fixed 10ms sleep instead of proper event notification. Could be improved with:
- Condition variables
- Event channels
- Better synchronization

### 3. Single Response Mode
Each session can only inject one error response. Multiple responses would require:
- Persistent TLS connection
- Request/response loop
- Connection pooling

## Future Enhancements

### 1. Full Proxy Mode
- Add `--proxy-mode` flag
- Connect to real upstream server
- Proxy non-error requests
- Maintain long-lived connections

### 2. Request Inspection
- Parse HTTP request body
- Match on specific paths/methods
- Conditional error injection
- Request logging/metrics

### 3. Response Modification
- Modify upstream responses
- Inject delays
- Corrupt response data
- Partial response delivery

### 4. Performance Optimization
- Connection pooling
- Certificate caching
- Goroutine pool
- Zero-copy buffers

## Conclusion

This implementation successfully provides full TLS MITM capability within the Fault proxy plugin architecture. By using `net.Pipe()` and goroutines, we bridge the gap between chunk-based processing and TLS's requirements for full bidirectional communication.

The key insight is that while the plugin API is chunk-based, we can create a "virtual connection" using pipes and run the TLS protocol in a separate goroutine, then shuttle data between the plugin's chunks and the TLS connection's streams.

This allows proper HTTP 429 error responses over HTTPS, meeting the original requirement while maintaining compatibility with the plugin architecture.
