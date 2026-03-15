# Add PAP to Your Existing Agent

**Time to implement: ~18 minutes total**
**Code changes: 20 lines or less per section**

The Provider Agent Protocol (PAP) is a lightweight interoperability standard that lets your agent participate in federated marketplaces while maintaining a cryptographic audit trail of all interactions. This tutorial shows you how to add PAP compliance to your existing REST API with minimal code changes.

## Prerequisites

- An existing REST API (we'll use FastAPI for Python, Axum for Rust)
- Basic understanding of JWT tokens
- Python 3.8+ or Rust 1.70+

## What You'll Build

Your agent will gain:
- **Discovery**: A manifest endpoint describing your agent's capabilities
- **Trust**: Cryptographic handshake with disclosure tokens
- **Auditability**: Append-only log of all tool invocations
- **Marketplace access**: Registration in federated agent registries

---

## Section 1: Wrap Your REST API as a PAP Provider (5 min)

Let's add PAP compliance to an existing agent API. We'll show both Python (FastAPI) and Rust (Axum) implementations.

### Python (FastAPI)

**Before** - Your existing FastAPI agent:
```python
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class SearchRequest(BaseModel):
    query: str
    limit: int = 10

@app.post("/search")
async def search_documents(request: SearchRequest):
    # Your existing search logic
    results = perform_search(request.query, request.limit)
    return {"results": results}
```

**After** - With PAP provider wrapper:
```diff
 from fastapi import FastAPI
+from fastapi import Header, Response
 from pydantic import BaseModel
+from pap_sdk import PAPProvider, ToolSchema, Disclosure
+import os

 app = FastAPI()
+pap = PAPProvider(
+    agent_id="doc-search-agent",
+    private_key=os.getenv("PAP_PRIVATE_KEY"),
+    audit_webhook=os.getenv("PAP_AUDIT_WEBHOOK")
+)

 class SearchRequest(BaseModel):
     query: str
     limit: int = 10

+@app.get("/.well-known/pap-manifest")
+async def get_manifest():
+    return pap.manifest({
+        "name": "Document Search Agent",
+        "version": "1.0.0",
+        "tools": [
+            ToolSchema(
+                name="search",
+                description="Search internal documents",
+                parameters=SearchRequest.schema()
+            )
+        ]
+    })

 @app.post("/search")
-async def search_documents(request: SearchRequest):
+async def search_documents(
+    request: SearchRequest,
+    response: Response,
+    pap_client_id: str = Header(None),
+    pap_nonce: str = Header(None)
+):
     # Your existing search logic
     results = perform_search(request.query, request.limit)
+
+    # Generate disclosure token if PAP handshake present
+    if pap_client_id and pap_nonce:
+        disclosure = pap.create_disclosure(
+            tool="search",
+            parameters=request.dict(),
+            client_id=pap_client_id,
+            nonce=pap_nonce
+        )
+        response.headers["PAP-Disclosure-Token"] = disclosure.to_jwt()
+
     return {"results": results}
```

> **Note**: The Python `pap-sdk` package depends on issue #42 (PyO3 wrapper) and is not yet released. Use the Rust implementation for immediate deployment.

### Rust (Axum)

**Before** - Your existing Axum agent:
```rust
use axum::{Router, Json, routing::post};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct SearchRequest {
    query: String,
    limit: Option<u32>,
}

async fn search_documents(
    Json(request): Json<SearchRequest>
) -> Json<SearchResponse> {
    let results = perform_search(&request.query, request.limit);
    Json(SearchResponse { results })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/search", post(search_documents));

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

**After** - With PAP provider wrapper:
```diff
-use axum::{Router, Json, routing::post};
+use axum::{Router, Json, routing::{get, post}, response::Response, headers::HeaderMap};
 use serde::{Deserialize, Serialize};
+use pap::{Provider, ToolSchema, Disclosure, Manifest};
+use std::env;

+lazy_static::lazy_static! {
+    static ref PAP_PROVIDER: Provider = Provider::new(
+        "doc-search-agent",
+        env::var("PAP_PRIVATE_KEY").expect("PAP_PRIVATE_KEY required"),
+        env::var("PAP_AUDIT_WEBHOOK").ok()
+    );
+}

 #[derive(Deserialize)]
 struct SearchRequest {
     query: String,
     limit: Option<u32>,
 }

+async fn get_manifest() -> Json<Manifest> {
+    Json(PAP_PROVIDER.manifest(vec![
+        ToolSchema {
+            name: "search".into(),
+            description: "Search internal documents".into(),
+            parameters: serde_json::to_value(&SearchRequest::schema()).unwrap(),
+        }
+    ]))
+}

 async fn search_documents(
+    headers: HeaderMap,
     Json(request): Json<SearchRequest>
-) -> Json<SearchResponse> {
+) -> Response {
     let results = perform_search(&request.query, request.limit);
-    Json(SearchResponse { results })
+
+    let mut response = Json(SearchResponse { results }).into_response();
+
+    // Generate disclosure token if PAP handshake present
+    if let (Some(client_id), Some(nonce)) = (
+        headers.get("pap-client-id"),
+        headers.get("pap-nonce")
+    ) {
+        let disclosure = PAP_PROVIDER.create_disclosure(
+            "search",
+            &request,
+            client_id.to_str().unwrap(),
+            nonce.to_str().unwrap()
+        );
+        response.headers_mut().insert(
+            "pap-disclosure-token",
+            disclosure.to_jwt().parse().unwrap()
+        );
+    }
+
+    response
 }

 #[tokio::main]
 async fn main() {
     let app = Router::new()
+        .route("/.well-known/pap-manifest", get(get_manifest))
         .route("/search", post(search_documents));

     axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
         .serve(app.into_make_service())
         .await
         .unwrap();
 }
```

> **What just happened?**
> You added two key PAP components:
> 1. **Manifest endpoint** at `/.well-known/pap-manifest` that describes your agent's capabilities in a standardized JSON format
> 2. **Disclosure token generation** that creates a signed JWT for each tool invocation when PAP headers are present
>
> The PAP SDK automatically handles audit logging via webhook when configured. Your API remains fully backward compatible—non-PAP clients work exactly as before.

---

## Section 2: Add PAP Client Handshake to Your LLM Orchestrator (10 min)

Now let's update an LLM orchestrator to discover and call PAP-compliant agents with proper handshake.

**Before** - Standard API call without PAP:
```python
import requests
from typing import Dict, Any

class AgentOrchestrator:
    def __init__(self, agent_url: str):
        self.agent_url = agent_url

    def call_tool(self, tool_name: str, parameters: Dict[str, Any]):
        response = requests.post(
            f"{self.agent_url}/{tool_name}",
            json=parameters
        )
        return response.json()

# Usage
orchestrator = AgentOrchestrator("https://search-agent.example.com")
results = orchestrator.call_tool("search", {"query": "PAP protocol"})
```

**After** - With PAP client handshake:
```diff
 import requests
+import secrets
+import jwt
+from datetime import datetime
 from typing import Dict, Any
+from pap_sdk import PAPClient, parse_disclosure

 class AgentOrchestrator:
-    def __init__(self, agent_url: str):
+    def __init__(self, agent_url: str, client_id: str = None):
         self.agent_url = agent_url
+        self.client_id = client_id or f"orchestrator-{secrets.token_hex(8)}"
+        self.pap_client = PAPClient(self.client_id)
+        self.manifest = self._fetch_manifest()
+        self.disclosures = []
+
+    def _fetch_manifest(self):
+        response = requests.get(f"{self.agent_url}/.well-known/pap-manifest")
+        if response.status_code == 200:
+            return response.json()
+        return None

     def call_tool(self, tool_name: str, parameters: Dict[str, Any]):
+        # Generate nonce for this invocation
+        nonce = secrets.token_urlsafe(32)
+
+        headers = {
+            "PAP-Client-ID": self.client_id,
+            "PAP-Nonce": nonce
+        }
+
         response = requests.post(
             f"{self.agent_url}/{tool_name}",
-            json=parameters
+            json=parameters,
+            headers=headers
         )
+
+        # Verify and store disclosure token if present
+        if disclosure_token := response.headers.get("PAP-Disclosure-Token"):
+            disclosure = parse_disclosure(disclosure_token, self.manifest["public_key"])
+            if disclosure.verify_nonce(nonce):
+                self.disclosures.append(disclosure)
+                print(f"✓ Disclosure logged: {disclosure.tool_name} at {disclosure.timestamp}")
+
         return response.json()
+
+    def get_audit_trail(self):
+        return [d.to_dict() for d in self.disclosures]

 # Usage
-orchestrator = AgentOrchestrator("https://search-agent.example.com")
+orchestrator = AgentOrchestrator(
+    "https://search-agent.example.com",
+    client_id="my-orchestrator-v1"
+)
 results = orchestrator.call_tool("search", {"query": "PAP protocol"})
+print(f"Audit trail: {orchestrator.get_audit_trail()}")
```

> **What just happened?**
> Your orchestrator now:
> 1. **Discovers capabilities** by fetching the agent's manifest
> 2. **Generates unique nonces** for each tool invocation to prevent replay attacks
> 3. **Sends PAP headers** with client ID and nonce
> 4. **Verifies disclosure tokens** using the agent's public key from the manifest
> 5. **Maintains an audit trail** of all tool invocations with cryptographic proof

### Disclosure Token Structure

The JWT disclosure token contains:
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "doc-search-agent-2024-01"
  },
  "payload": {
    "iss": "doc-search-agent",
    "sub": "my-orchestrator-v1",
    "iat": 1710518400,
    "exp": 1710522000,
    "nonce": "aB3x9Km2...",
    "disclosure": {
      "tool": "search",
      "parameters_hash": "sha256:7d865e959b2466918c9863afca942d0f...",
      "execution_time_ms": 42,
      "success": true
    }
  },
  "signature": "..."
}
```

---

## Section 3: Register with a Marketplace (2 min)

Once your agent is PAP-compliant, register it with federated marketplaces for discovery.

### Via CLI:
```bash
# Register with the default PAP marketplace
curl -X POST https://marketplace.pap.dev/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "manifest_url": "https://search-agent.example.com/.well-known/pap-manifest",
    "categories": ["search", "documents", "enterprise"],
    "contact_email": "team@example.com",
    "signing_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqh..."
  }'

# Response:
# {
#   "agent_id": "doc-search-agent",
#   "marketplace_id": "mkt_7h3Kx9...",
#   "status": "pending_verification",
#   "verification_url": "https://marketplace.pap.dev/verify/mkt_7h3Kx9..."
# }
```

### Via Python:
```python
from pap_sdk import MarketplaceClient

marketplace = MarketplaceClient("https://marketplace.pap.dev")

registration = marketplace.register(
    manifest_url="https://search-agent.example.com/.well-known/pap-manifest",
    categories=["search", "documents", "enterprise"],
    contact_email="team@example.com",
    signing_key=open("public_key.pem").read()
)

print(f"Registered with ID: {registration.marketplace_id}")
print(f"Verification URL: {registration.verification_url}")
```

> **What just happened?**
> Your agent is now:
> 1. **Discoverable** in the marketplace catalog
> 2. **Verifiable** via its manifest and signing key
> 3. **Categorized** for easy discovery by orchestrators
> 4. **Pending verification** - the marketplace will test your manifest endpoint

---

## Section 4: View the Disclosure Audit Trail (1 min)

PAP maintains an append-only audit log of all tool invocations. View it using the PAP CLI:

```bash
# View last 10 disclosures for your agent
pap audit tail --agent-id doc-search-agent

# Output:
# 2024-03-15 10:23:45 | search      | client: orchestrator-a3b2 | 42ms  | ✓ success
# 2024-03-15 10:24:12 | search      | client: marketplace-test  | 38ms  | ✓ success
# 2024-03-15 10:25:03 | search      | client: orchestrator-x7y9 | 156ms | ✓ success

# Export full audit trail as JSON
pap audit export --agent-id doc-search-agent --format json > audit.json

# Query specific time range
pap audit query --agent-id doc-search-agent \
  --start "2024-03-15T00:00:00Z" \
  --end "2024-03-15T23:59:59Z" \
  --client-id "orchestrator-a3b2"
```

The audit trail is cryptographically signed and tamper-evident. Each entry includes:
- Timestamp (UTC)
- Tool name and parameters hash
- Client ID and nonce
- Execution time
- Success/failure status
- Disclosure token signature

> **What just happened?**
> You now have:
> 1. **Complete visibility** into who's using your agent and how
> 2. **Cryptographic proof** of each invocation via disclosure tokens
> 3. **Tamper-evident logs** that can be used for compliance and debugging
> 4. **Query capabilities** to analyze usage patterns

---

## Complete Working Examples

### Python (FastAPI) - Complete PAP Provider

```python
# agent.py
from fastapi import FastAPI, Header, Response
from pydantic import BaseModel
from pap_sdk import PAPProvider, ToolSchema
import os
from typing import Optional, List

app = FastAPI()

# Initialize PAP provider
pap = PAPProvider(
    agent_id="doc-search-agent",
    agent_name="Document Search Agent",
    version="1.0.0",
    private_key=os.getenv("PAP_PRIVATE_KEY"),
    audit_webhook=os.getenv("PAP_AUDIT_WEBHOOK")
)

# Define your tool schemas
class SearchRequest(BaseModel):
    query: str
    limit: int = 10
    filters: Optional[List[str]] = None

class SearchResponse(BaseModel):
    results: List[dict]
    total: int

# PAP manifest endpoint
@app.get("/.well-known/pap-manifest")
async def get_manifest():
    return pap.manifest({
        "tools": [
            ToolSchema(
                name="search",
                description="Search internal documents",
                parameters=SearchRequest.schema()
            )
        ],
        "categories": ["search", "documents"],
        "rate_limits": {
            "requests_per_minute": 100,
            "requests_per_hour": 5000
        }
    })

# Your existing endpoint with PAP disclosure
@app.post("/search", response_model=SearchResponse)
async def search_documents(
    request: SearchRequest,
    response: Response,
    pap_client_id: Optional[str] = Header(None),
    pap_nonce: Optional[str] = Header(None)
):
    # Your existing search logic
    results = perform_search(request.query, request.limit, request.filters)

    # Generate PAP disclosure if handshake present
    if pap_client_id and pap_nonce:
        disclosure = pap.create_disclosure(
            tool="search",
            parameters=request.dict(),
            client_id=pap_client_id,
            nonce=pap_nonce,
            success=True,
            execution_time_ms=42
        )
        response.headers["PAP-Disclosure-Token"] = disclosure.to_jwt()

    return SearchResponse(results=results, total=len(results))

def perform_search(query: str, limit: int, filters: Optional[List[str]]):
    # Your actual search implementation
    return [{"id": 1, "title": "Example", "content": "..."}]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### Rust (Axum) - Complete PAP Provider

```rust
// src/main.rs
use axum::{
    Router, Json,
    routing::{get, post},
    response::{Response, IntoResponse},
    extract::HeaderMap,
};
use serde::{Deserialize, Serialize};
use pap::{Provider, ToolSchema, Manifest};
use std::env;

lazy_static::lazy_static! {
    static ref PAP_PROVIDER: Provider = Provider::new(
        "doc-search-agent",
        "Document Search Agent",
        "1.0.0",
        env::var("PAP_PRIVATE_KEY").expect("PAP_PRIVATE_KEY required"),
        env::var("PAP_AUDIT_WEBHOOK").ok()
    );
}

#[derive(Deserialize, Serialize)]
struct SearchRequest {
    query: String,
    #[serde(default = "default_limit")]
    limit: u32,
    filters: Option<Vec<String>>,
}

fn default_limit() -> u32 { 10 }

#[derive(Serialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
    total: usize,
}

#[derive(Serialize)]
struct SearchResult {
    id: u32,
    title: String,
    content: String,
}

async fn get_manifest() -> Json<Manifest> {
    Json(PAP_PROVIDER.manifest(vec![
        ToolSchema {
            name: "search".into(),
            description: "Search internal documents".into(),
            parameters: serde_json::to_value(&SearchRequest::schema()).unwrap(),
        }
    ]))
}

async fn search_documents(
    headers: HeaderMap,
    Json(request): Json<SearchRequest>
) -> Response {
    // Your existing search logic
    let results = perform_search(&request.query, request.limit, &request.filters);
    let total = results.len();

    let mut response = Json(SearchResponse { results, total }).into_response();

    // Generate PAP disclosure if handshake present
    if let (Some(client_id), Some(nonce)) = (
        headers.get("pap-client-id"),
        headers.get("pap-nonce")
    ) {
        let disclosure = PAP_PROVIDER.create_disclosure(
            "search",
            &request,
            client_id.to_str().unwrap(),
            nonce.to_str().unwrap(),
            true,  // success
            42     // execution_time_ms
        );

        response.headers_mut().insert(
            "pap-disclosure-token",
            disclosure.to_jwt().parse().unwrap()
        );
    }

    response
}

fn perform_search(query: &str, limit: u32, filters: &Option<Vec<String>>) -> Vec<SearchResult> {
    // Your actual search implementation
    vec![SearchResult {
        id: 1,
        title: "Example".into(),
        content: "...".into(),
    }]
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/.well-known/pap-manifest", get(get_manifest))
        .route("/search", post(search_documents));

    println!("PAP-compliant agent running on http://0.0.0.0:3000");
    println!("Manifest available at http://0.0.0.0:3000/.well-known/pap-manifest");

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

### Manifest JSON Structure

Your `/.well-known/pap-manifest` endpoint returns:

```json
{
  "agent_id": "doc-search-agent",
  "name": "Document Search Agent",
  "version": "1.0.0",
  "description": "Enterprise document search with semantic understanding",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqh...",
  "tools": [
    {
      "name": "search",
      "description": "Search internal documents",
      "endpoint": "/search",
      "method": "POST",
      "parameters": {
        "type": "object",
        "properties": {
          "query": {"type": "string"},
          "limit": {"type": "integer", "default": 10},
          "filters": {
            "type": "array",
            "items": {"type": "string"}
          }
        },
        "required": ["query"]
      }
    }
  ],
  "categories": ["search", "documents", "enterprise"],
  "rate_limits": {
    "requests_per_minute": 100,
    "requests_per_hour": 5000
  },
  "contact": {
    "email": "team@example.com",
    "support_url": "https://docs.example.com/support"
  },
  "audit": {
    "webhook_configured": true,
    "retention_days": 90
  }
}
```

---

## Summary

You've successfully added PAP compliance to your agent with minimal code changes:

✅ **Manifest endpoint** for capability discovery
✅ **Cryptographic handshake** with disclosure tokens
✅ **Audit trail** of all tool invocations
✅ **Marketplace registration** for federated discovery

Your agent is now interoperable with any PAP-compliant orchestrator while maintaining complete backward compatibility with existing clients.

### Next Steps

- **Test your implementation**: Use `pap validate https://your-agent.com` to verify compliance
- **Monitor your audit logs**: Set up alerts for unusual patterns
- **Join the marketplace**: Register at https://marketplace.pap.dev
- **Implement advanced features**: Rate limiting, capability negotiation, federation

### Resources

- PAP Specification: https://github.com/pap-protocol/spec
- Python SDK: `pip install pap-sdk` (pending issue #42)
- Rust Crate: `cargo add pap`
- CLI Tools: `brew install pap-cli` or download from releases
- Community: https://discord.gg/pap-protocol

---

*Provider Agent Protocol v1.0 - Enabling trustworthy agent interoperability*