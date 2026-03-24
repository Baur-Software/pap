# PAP Transport Bindings

## Overview

The Principal Agent Protocol (PAP) is **transport-agnostic**. The protocol logic—mandate validation, signature verification, disclosure filtering, session state machine—is defined independently of the wire format or delivery mechanism.

This allows the same protocol implementation to work over HTTP, WebSocket, gRPC, Bluetooth, AMQP, or custom transports. Each transport is a separate binding that handles serialization and delivery, but all use identical cryptographic validation.

This document explains:
- How PAP separates protocol logic from transport layer
- The abstraction layer (traits and message types)
- How the default HTTP/JSON binding works
- How to implement custom transport bindings
- Real-world deployment scenarios and their transport choices

---

## Core Architecture: Protocol vs. Transport

### Protocol Layer (Cryptographic Handshake)

PAP's six-phase handshake is purely cryptographic:

1. **Phase 1:** Initiator presents a signed capability token
2. **Phase 2:** Both parties exchange ephemeral session DIDs
3. **Phase 3:** Initiator sends selective disclosures (zero or more claims)
4. **Phase 4:** Receiver executes the requested action
5. **Phase 5:** Both parties co-sign a transaction receipt
6. **Phase 6:** Session is closed and keys discarded

The protocol defines:
- Message structure (`ProtocolMessage` enum in `pap-proto`)
- Cryptographic validation rules (signatures, timestamps, replay checks)
- Session state machine (Active → Degraded → ReadOnly → Suspended)
- Security invariants (mandate scope, disclosure filtering, context minimization)

**The protocol layer is independent of how these messages are physically transmitted.**

### Transport Layer (Message Delivery)

The transport layer is responsible for:
- Converting `ProtocolMessage` to wire format (JSON, binary, etc.)
- Delivering messages between initiator and receiver
- Handling network failures and retries
- Managing TLS/encryption at the link level
- Endpoint discovery and routing

**Transport implementations must be mutually intelligible.** Different transport bindings are independent layers. A PAP orchestrator can initiate sessions with HTTP-based agents *and separately* with WebSocket-based agents. The protocol invariants (mandate validation, disclosure filtering, signature verification) remain identical across transports. Agents don't mix protocols within a single session—they match the transport their peer advertises in the DID Document service endpoint.

---

## Transport Abstraction in Rust

The PAP reference implementation uses **two traits** to achieve transport independence:

### 1. `AgentHandler` Trait (Receiver-Side Logic)

```rust
pub trait AgentHandler: Send + Sync {
    fn handle_token(&self, token: CapabilityToken)
        -> Result<(String, String), TransportError>;

    fn handle_did_exchange(&self, session_id: &str, initiator_session_did: &str)
        -> Result<(), TransportError>;

    fn handle_disclosure(&self, session_id: &str, disclosures: Vec<serde_json::Value>)
        -> Result<(), TransportError>;

    fn execute(&self, session_id: &str)
        -> Result<serde_json::Value, TransportError>;

    fn co_sign_receipt(&self, receipt: TransactionReceipt)
        -> Result<TransactionReceipt, TransportError>;

    fn handle_close(&self, session_id: &str)
        -> Result<(), TransportError>;
}
```

The `AgentHandler` is **completely transport-agnostic**. It receives structured protocol messages and returns structured responses. Whether those messages came from HTTP, WebSocket, or a file doesn't matter—the handler processes them the same way.

### 2. `ProtocolMessage` Enum (Wire Format Abstraction)

```rust
pub enum ProtocolMessage {
    TokenPresentation { token: CapabilityToken },
    TokenAccepted { session_id: String, receiver_session_did: String },
    TokenRejected { reason: String },

    SessionDidExchange { initiator_session_did: String },
    SessionDidAck { receiver_session_did: String },

    DisclosureOffer { disclosures: Vec<serde_json::Value> },
    DisclosureAccepted,

    ExecutionResult { result: serde_json::Value },

    ReceiptForCoSign { receipt: TransactionReceipt },
    ReceiptCoSigned { receipt: TransactionReceipt },

    SessionClose { reason: Option<String> },
    SessionClosed,

    Error { code: String, message: String },
}
```

`ProtocolMessage` is serializable with serde, enabling multiple wire formats (JSON, MessagePack, Protocol Buffers, etc.) with minimal code changes.

---

## Default Binding: HTTP/JSON Transport

### Architecture

The HTTP/JSON transport in `pap-transport` crate consists of:

- **`AgentClient`** (initiator-side): Makes HTTP POST requests to receiver endpoints
- **`AgentServer`** (receiver-side): Exposes REST endpoints served by Axum
- **`EndpointRegistry`**: Maps DIDs to HTTP URLs
- **TLS Support**: Optional self-signed or public CA certificates

### REST API Mapping

Each phase maps to a REST endpoint:

| Phase | Method | Endpoint | Request Message | Response Message |
|-------|--------|----------|-----------------|------------------|
| 1 | POST | `/session` | `TokenPresentation` | `TokenAccepted` \| `TokenRejected` |
| 2 | POST | `/session/{id}/did` | `SessionDidExchange` | `SessionDidAck` |
| 3 | POST | `/session/{id}/disclosure` | `DisclosureOffer` | `DisclosureAccepted` |
| 4 | POST | `/session/{id}/execute` | (empty) | `ExecutionResult` |
| 5 | POST | `/session/{id}/receipt` | `ReceiptForCoSign` | `ReceiptCoSigned` |
| 6 | POST | `/session/{id}/close` | `SessionClose` | `SessionClosed` |

### Example Usage

**Receiver (Agent B):**

```rust
use pap_transport::{AgentServer, AgentHandler};
use std::sync::Arc;

struct MyHandler;

impl AgentHandler for MyHandler {
    fn handle_token(&self, token) -> Result<(String, String), _> {
        // Validate token, return (session_id, receiver_session_did)
        Ok(("s123".into(), "did:key:receiver".into()))
    }

    fn handle_did_exchange(&self, session_id, initiator_did) -> Result<(), _> {
        // Store session state
        Ok(())
    }

    // ... implement other phases
}

let handler = Arc::new(MyHandler);
let server = AgentServer::new(handler, 8080);
server.run().await?;
```

**Initiator (Agent A):**

```rust
use pap_transport::AgentClient;

let client = AgentClient::new("http://agent-b.example.com");
let response = client.present_token(capability_token).await?;
// Proceed through remaining phases...
```

---

## Custom Transport Bindings

To implement a custom transport (e.g., WebSocket, AMQP, gRPC), follow this pattern:

### 1. Implement a Receiver Server

Create a server that:
- Accepts messages in your transport format
- Parses them into `ProtocolMessage`
- Routes each message to the appropriate `AgentHandler` method
- Serializes responses back to wire format

**Example: WebSocket Server**

```rust
use tokio_tungstenite::tungstenite::Message;
use pap_proto::ProtocolMessage;
use pap_transport::AgentHandler;

async fn handle_websocket_connection(
    ws: WebSocketStream,
    handler: Arc<dyn AgentHandler>,
) {
    while let Some(Ok(msg)) = ws.next().await {
        if let Message::Text(text) = msg {
            // Phase 1: Token presentation
            if let Ok(ProtocolMessage::TokenPresentation { token }) =
                serde_json::from_str(&text)
            {
                let (session_id, did) = handler.handle_token(token)?;
                let response = ProtocolMessage::TokenAccepted {
                    session_id,
                    receiver_session_did: did,
                };
                ws.send(Message::Text(
                    serde_json::to_string(&response)?
                )).await?;
            }
            // ... handle other phases similarly
        }
    }
}
```

### 2. Implement an Initiator Client

Create a client that:
- Takes a `ProtocolMessage` as input
- Serializes it to your transport format
- Sends it to the receiver
- Waits for and parses the response

**Example: WebSocket Client**

```rust
pub struct WebSocketClient {
    ws: WebSocketStream,
}

impl WebSocketClient {
    pub async fn present_token(
        &mut self,
        token: CapabilityToken
    ) -> Result<ProtocolMessage, Error> {
        let msg = ProtocolMessage::TokenPresentation { token };
        let json = serde_json::to_string(&msg)?;

        self.ws.send(Message::Text(json)).await?;

        if let Some(Ok(Message::Text(response))) = self.ws.next().await {
            Ok(serde_json::from_str(&response)?)
        } else {
            Err(Error::NoResponse)
        }
    }
}
```

### 3. Considerations for Custom Transports

**Serialization Format:**
- Choose based on your environment (JSON for human debugging, MessagePack for efficiency, Protocol Buffers for schema evolution)
- Implement `Serialize` and `Deserialize` for `ProtocolMessage`
- Ensure deterministic serialization for cryptographic verification

**Endpoint Discovery:**
- HTTP uses URL-based discovery
- WebSocket might use DNS + port convention
- AMQP might use queue names derived from DIDs
- Custom protocols should reference RFC 3986 for URI schemes

**Error Handling:**
- Implement protocol-specific error codes
- Map back to `TransportError` variants for consistency
- Ensure timeouts don't block mandate or capability token expiry

**TLS/Encryption:**
- HTTP/JSON uses standard TLS (rustls)
- Other transports should implement equivalent link-level encryption
- For gRPC, use mTLS
- For AMQP, use AMQP TLS features

**Testing:**
- Use the same `AgentHandler` trait for both HTTP and custom transport
- This ensures your transport doesn't introduce bugs in protocol logic
- Test against the reference HTTP transport to verify interoperability

---

## Real-World Deployment Scenarios

### Scenario 1: Cloud-Native Microservices

**Transport:** gRPC (bidirectional streaming)

**Why gRPC?**
- High-performance binary protocol
- Native support for streaming (useful for long-lived sessions)
- mTLS out of the box
- Easy service discovery via Kubernetes DNS

```proto
service PAPAgent {
    rpc EstablishSession(stream ProtocolMessage) returns (stream ProtocolMessage);
}
```

**Implementation:** Implement `AgentHandler`, wrap in gRPC service, deploy to Kubernetes.

---

### Scenario 2: IoT / Bluetooth Mesh

**Transport:** Custom binary framing over Bluetooth LE

**Why custom?**
- Bluetooth MTU (23 bytes) is small; need frame fragmentation
- BLE advertising can carry DID for discovery
- Low power requirements favor binary over JSON

**Implementation:**
- Define frame header (sequence number, type, length)
- Fragment long messages across multiple BLE packets
- Buffer partial messages on receiver
- Use MAC address for endpoint lookup (mapped to DID)

---

### Scenario 3: Offline-First Mobile App

**Transport:** SQLite local queue + HTTP sync

**Why this hybrid?**
- Build capability token requests while offline
- Queue them in SQLite
- When online, batch-send via HTTP
- Receiver treats each request independently

**Implementation:**
- `AgentHandler` writes to in-memory session state
- Mobile app persists `ProtocolMessage` to local DB
- Sync thread converts queued messages to HTTP requests
- No protocol-level changes needed

---

### Scenario 4: Email / SMTP (Asynchronous)

**Transport:** Email with JSON attachments

**Why email?**
- Works anywhere (no port restrictions)
- Inherent audit trail
- Signatures already DKIM-compatible

**Implementation:**
- Encode `ProtocolMessage` as JSON, gzip, base64
- Attach to email with subject `pap-phase-2-session-abc123`
- Receiver extracts attachment, deserializes, calls handler
- Sends response email with subject `pap-phase-2-response-abc123`

---

### Scenario 5: Federated Networks

**Transport:** HTTP over Tor / I2P

**Why anonymity networks?**
- Endpoint URLs are onion addresses
- DIDs include key material for authentication
- No DNS leakage of agent identities
- Receiver stays offline by default

**Implementation:**
- Configure `EndpointRegistry` with `.onion` URLs
- Use Tor client library (e.g., `arti`) for HTTP requests
- HTTP server listens on localhost, Tor bridges external requests
- Certificate pinning by DID key, not CA

---

## What Transport Independence Actually Means

Transport independence doesn't mean agents magically understand each other's wire formats. It means:

1. **Protocol logic is independent**: The `AgentHandler` validates mandates, checks disclosures, verifies signatures—all identically whether the message came from HTTP or WebSocket.

2. **The same handler works for any transport**: You write one `impl AgentHandler` and wrap it in HTTP, WebSocket, gRPC, etc. The protocol logic is transport-agnostic.

3. **Agents choose their transport at deployment time**: An agent publishes its endpoint URL (`https://...` or `wss://...`) in its DID Document. Initiators connect to the advertised endpoint. No protocol changes needed.

4. **Security guarantees hold across transports**: Session key signing, nonce consumption, mandate chain verification work identically regardless of how the bits move across the network.

### Example: Supporting Multiple Transports

```rust
// Same handler for both HTTP and WebSocket
struct MyAgentHandler;
impl AgentHandler for MyAgentHandler { /* ... */ }

let handler = Arc::new(MyAgentHandler);

// Publish on HTTP
let http_server = AgentServer::new(handler.clone(), 8080);
tokio::spawn(http_server.run());

// Publish on WebSocket
let ws_server = WebSocketServer::new(handler.clone(), 9000);
tokio::spawn(ws_server.run());

// Clients discover your agent's DID Document, which lists both endpoints
// They choose which one to use
```

Initiators don't care which transport you use—they just need to know your endpoint. The protocol is the same.

---

## Security Across Transports

### Transport-Layer Security

| Transport | Link Security | Notes |
|-----------|---------------|-------|
| HTTP/JSON | TLS (public CA) | Standard web PKI |
| gRPC | mTLS | Mutual authentication |
| WebSocket | TLS + WASM origin checks | Browser sandbox isolates principals |
| Bluetooth LE | AES-CCM encryption | Built-in, but limited range |
| Custom Binary | Negotiated | Implement at framing layer |

### Protocol-Level Security (Independent of Transport)

- **Signatures:** Session DIDs are verified cryptographically, regardless of transport
- **Replay Protection:** Nonce consumption and sequence numbering work across all transports
- **Context Minimization:** SD-JWT disclosure filtering is enforced by the handler, not the transport
- **Mandate Validation:** Scope and TTL checks happen in `pap-core`, before any transport interaction

**Critical rule:** The transport layer MUST NOT weaken cryptographic guarantees. If your transport cannot guarantee message integrity, use TLS or equivalent.

---

## Testing Custom Transports

### Unit Tests

```rust
#[test]
fn test_websocket_token_presentation() {
    let handler = Arc::new(MockHandler);
    let (client, receiver) = create_websocket_pair();

    // Send token
    let token = create_test_token();
    let response = client.present_token(token).await;

    // Verify response is TokenAccepted
    assert!(matches!(response, ProtocolMessage::TokenAccepted { .. }));
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_full_session_websocket() {
    let receiver = WebSocketServer::new(test_handler(), 9000);
    let handle = tokio::spawn(async move { receiver.run().await });

    let mut client = connect_websocket("ws://127.0.0.1:9000").await;

    // Run full six-phase handshake
    let (session_id, _) = client.present_token(token).await?;
    client.exchange_did(&session_id, did).await?;
    client.send_disclosures(&session_id, vec![]).await?;
    let result = client.execute(&session_id).await?;
    // ... co-sign, close

    assert_eq!(result.value, expected);
}
```

### Cross-Transport Interop Tests

```rust
#[tokio::test]
async fn test_http_to_websocket_interop() {
    // Start WebSocket receiver
    let ws_receiver = WebSocketServer::new(handler.clone(), 9001);
    tokio::spawn(ws_receiver.run());

    // Start HTTP receiver
    let http_receiver = AgentServer::new(handler.clone(), 8080);
    tokio::spawn(http_receiver.run());

    // Send request via HTTP
    let http_client = AgentClient::new("http://127.0.0.1:8080");
    let http_response = http_client.present_token(token.clone()).await?;

    // Send identical request via WebSocket
    let ws_client = WebSocketClient::connect("ws://127.0.0.1:9001").await?;
    let ws_response = ws_client.present_token(token).await?;

    // Both should produce identical handler behavior
    assert_eq!(http_response, ws_response);
}
```

---

## Roadmap: Future Transport Standards

### Planned for PAP v0.2+

1. **gRPC Binding** – Standardized `pap.proto` for Protocol Buffers
2. **AMQP Binding** – For enterprise messaging (RabbitMQ, etc.)
3. **ActivityPub Binding** – For decentralized social networks
4. **Nostr Binding** – For censorship-resistant protocols
5. **CBOR Binding** – For lightweight IoT deployments

Each binding will:
- Define endpoint discovery for that protocol
- Specify TLS/encryption strategy
- Include example implementations
- Provide conformance test suite

---

## Conclusion

PAP's transport independence is a core architectural principle. By separating the cryptographic protocol from message delivery:

✅ **Flexibility:** Deploy PAP in any networking environment
✅ **Simplicity:** Protocol logic is unchanged across transports
✅ **Security:** Cryptographic guarantees hold regardless of transport layer
✅ **Interoperability:** Different transports can coexist and interoperate
✅ **Evolution:** New transports can be added without breaking existing implementations

Start with the HTTP/JSON transport for development. Implement custom transports only when your deployment environment requires it—and PAP's abstractions make that straightforward.
