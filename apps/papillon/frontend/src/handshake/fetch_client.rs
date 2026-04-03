//! Browser-native PAP protocol client using the Fetch API.
//!
//! This is a direct port of `pap_transport::AgentClient` that uses
//! `web_sys::fetch()` instead of reqwest. It speaks the same ProtocolMessage
//! JSON protocol over the same REST endpoints, ensuring wire compatibility
//! between native and WASM handshake paths.

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_proto::ProtocolMessage;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

/// Error type for the fetch-based handshake client.
#[derive(Debug, Clone)]
pub struct FetchError(pub String);

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Browser-native PAP protocol client using the Fetch API.
///
/// Mirrors `pap_transport::AgentClient` endpoint-by-endpoint:
/// - POST /session             (Phase 1: TokenPresentation)
/// - POST /session/{id}/did    (Phase 2: SessionDidExchange)
/// - POST /session/{id}/disclosure (Phase 3: DisclosureOffer)
/// - POST /session/{id}/execute    (Phase 4: execution request)
/// - POST /session/{id}/receipt    (Phase 5: ReceiptForCoSign)
/// - POST /session/{id}/close      (Phase 6: SessionClose)
pub struct FetchClient {
    base_url: String,
}

impl FetchClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Send a POST request with JSON body and parse the response as ProtocolMessage.
    async fn post_json(&self, url: &str, body: &str) -> Result<ProtocolMessage, FetchError> {
        let opts = RequestInit::new();
        opts.set_method("POST");
        opts.set_mode(RequestMode::Cors);
        opts.set_body(&wasm_bindgen::JsValue::from_str(body));

        let request = Request::new_with_str_and_init(url, &opts)
            .map_err(|e| FetchError(format!("Request creation failed: {:?}", e)))?;

        request
            .headers()
            .set("Content-Type", "application/json")
            .map_err(|e| FetchError(format!("Header set failed: {:?}", e)))?;

        let window = web_sys::window().ok_or_else(|| FetchError("No window object".into()))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| FetchError(format!("Fetch failed: {:?}", e)))?;

        let resp: Response = resp_value
            .dyn_into()
            .map_err(|_| FetchError("Response cast failed".into()))?;

        if !resp.ok() {
            return Err(FetchError(format!("HTTP {}", resp.status())));
        }

        let text_promise = resp
            .text()
            .map_err(|e| FetchError(format!("Response text failed: {:?}", e)))?;

        let text = JsFuture::from(text_promise)
            .await
            .map_err(|e| FetchError(format!("Text await failed: {:?}", e)))?
            .as_string()
            .ok_or_else(|| FetchError("Response not a string".into()))?;

        serde_json::from_str::<ProtocolMessage>(&text)
            .map_err(|e| FetchError(format!("JSON parse failed: {}", e)))
    }

    /// Send a POST with no body (used for Phase 4: execute).
    async fn post_empty(&self, url: &str) -> Result<ProtocolMessage, FetchError> {
        let opts = RequestInit::new();
        opts.set_method("POST");
        opts.set_mode(RequestMode::Cors);

        let request = Request::new_with_str_and_init(url, &opts)
            .map_err(|e| FetchError(format!("Request creation failed: {:?}", e)))?;

        let window = web_sys::window().ok_or_else(|| FetchError("No window object".into()))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| FetchError(format!("Fetch failed: {:?}", e)))?;

        let resp: Response = resp_value
            .dyn_into()
            .map_err(|_| FetchError("Response cast failed".into()))?;

        if !resp.ok() {
            return Err(FetchError(format!("HTTP {}", resp.status())));
        }

        let text_promise = resp
            .text()
            .map_err(|e| FetchError(format!("Response text failed: {:?}", e)))?;

        let text = JsFuture::from(text_promise)
            .await
            .map_err(|e| FetchError(format!("Text await failed: {:?}", e)))?
            .as_string()
            .ok_or_else(|| FetchError("Response not a string".into()))?;

        serde_json::from_str::<ProtocolMessage>(&text)
            .map_err(|e| FetchError(format!("JSON parse failed: {}", e)))
    }

    /// Phase 1: Present a capability token. Returns ProtocolMessage::TokenAccepted
    /// with session_id and receiver_session_did on success.
    pub async fn present_token(
        &self,
        token: CapabilityToken,
    ) -> Result<ProtocolMessage, FetchError> {
        let msg = ProtocolMessage::TokenPresentation { token };
        let body = serde_json::to_string(&msg).map_err(|e| FetchError(e.to_string()))?;
        self.post_json(&format!("{}/session", self.base_url), &body)
            .await
    }

    /// Phase 2: Send the initiator's ephemeral session DID.
    pub async fn exchange_did(
        &self,
        session_id: &str,
        initiator_session_did: String,
    ) -> Result<ProtocolMessage, FetchError> {
        let msg = ProtocolMessage::SessionDidExchange {
            initiator_session_did,
        };
        let body = serde_json::to_string(&msg).map_err(|e| FetchError(e.to_string()))?;
        self.post_json(
            &format!("{}/session/{}/did", self.base_url, session_id),
            &body,
        )
        .await
    }

    /// Phase 3: Send selective disclosures (or empty vec for zero-disclosure).
    pub async fn send_disclosures(
        &self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<ProtocolMessage, FetchError> {
        let msg = ProtocolMessage::DisclosureOffer { disclosures };
        let body = serde_json::to_string(&msg).map_err(|e| FetchError(e.to_string()))?;
        self.post_json(
            &format!("{}/session/{}/disclosure", self.base_url, session_id),
            &body,
        )
        .await
    }

    /// Phase 4: Request execution and receive the result.
    pub async fn request_execution(&self, session_id: &str) -> Result<ProtocolMessage, FetchError> {
        self.post_empty(&format!("{}/session/{}/execute", self.base_url, session_id))
            .await
    }

    /// Phase 5: Send a receipt for co-signing. Returns the co-signed receipt.
    pub async fn exchange_receipt(
        &self,
        session_id: &str,
        receipt: TransactionReceipt,
    ) -> Result<ProtocolMessage, FetchError> {
        let msg = ProtocolMessage::ReceiptForCoSign { receipt };
        let body = serde_json::to_string(&msg).map_err(|e| FetchError(e.to_string()))?;
        self.post_json(
            &format!("{}/session/{}/receipt", self.base_url, session_id),
            &body,
        )
        .await
    }

    /// Phase 6: Close the session.
    pub async fn close_session(&self, session_id: &str) -> Result<ProtocolMessage, FetchError> {
        let msg = ProtocolMessage::SessionClose {
            session_id: session_id.to_string(),
        };
        let body = serde_json::to_string(&msg).map_err(|e| FetchError(e.to_string()))?;
        self.post_json(
            &format!("{}/session/{}/close", self.base_url, session_id),
            &body,
        )
        .await
    }
}
