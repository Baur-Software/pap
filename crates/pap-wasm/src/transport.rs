//! Browser-native PAP transport bindings using the Fetch API.
//!
//! [`TransportSession`] drives the 6-phase PAP handshake from JavaScript,
//! enforcing protocol phase ordering and auto-managing ephemeral session keys.
//!
//! The fetch implementation mirrors [`apps/papillon/frontend/src/handshake/fetch_client.rs`]
//! and speaks the same `ProtocolMessage` JSON wire format over the same REST
//! endpoints as `pap_transport::AgentClient`.

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use pap_proto::ProtocolMessage;

use crate::to_js_err;

// ---------------------------------------------------------------------------
// Internal: handshake phase state machine
// ---------------------------------------------------------------------------

/// Tracks which protocol phase has been completed.
/// Enforces strict forward-only transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakePhase {
    Created,
    TokenPresented,
    DidExchanged,
    DisclosureSent,
    Executed,
    ReceiptSigned,
    Closed,
}

impl HandshakePhase {
    fn can_advance_to(self, next: HandshakePhase) -> bool {
        matches!(
            (self, next),
            (HandshakePhase::Created, HandshakePhase::TokenPresented)
                | (HandshakePhase::TokenPresented, HandshakePhase::DidExchanged)
                | (HandshakePhase::DidExchanged, HandshakePhase::DisclosureSent)
                | (HandshakePhase::DisclosureSent, HandshakePhase::Executed)
                | (HandshakePhase::Executed, HandshakePhase::ReceiptSigned)
                | (HandshakePhase::ReceiptSigned, HandshakePhase::Closed)
        )
    }

    fn as_str(self) -> &'static str {
        match self {
            HandshakePhase::Created => "Created",
            HandshakePhase::TokenPresented => "TokenPresented",
            HandshakePhase::DidExchanged => "DidExchanged",
            HandshakePhase::DisclosureSent => "DisclosureSent",
            HandshakePhase::Executed => "Executed",
            HandshakePhase::ReceiptSigned => "ReceiptSigned",
            HandshakePhase::Closed => "Closed",
        }
    }
}

// ---------------------------------------------------------------------------
// Internal: fetch helpers
// ---------------------------------------------------------------------------

/// POST JSON body to `url`, parse the response as a `ProtocolMessage`.
async fn post_json(url: &str, body: &str) -> Result<ProtocolMessage, JsError> {
    let opts = web_sys::RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(web_sys::RequestMode::Cors);
    opts.set_body(&JsValue::from_str(body));

    let request = web_sys::Request::new_with_str_and_init(url, &opts)
        .map_err(|e| JsError::new(&format!("request creation failed: {e:?}")))?;

    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(|e| JsError::new(&format!("header set failed: {e:?}")))?;

    let window =
        web_sys::window().ok_or_else(|| JsError::new("no global window object"))?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| JsError::new(&format!("fetch failed: {e:?}")))?;

    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|_| JsError::new("response cast failed"))?;

    if !resp.ok() {
        return Err(JsError::new(&format!("HTTP {}", resp.status())));
    }

    let text_promise = resp
        .text()
        .map_err(|e| JsError::new(&format!("response text failed: {e:?}")))?;

    let text = JsFuture::from(text_promise)
        .await
        .map_err(|e| JsError::new(&format!("text await failed: {e:?}")))?
        .as_string()
        .ok_or_else(|| JsError::new("response body not a string"))?;

    serde_json::from_str::<ProtocolMessage>(&text)
        .map_err(|e| JsError::new(&format!("JSON parse failed: {e}")))
}

/// POST with no body (used for Phase 4: execute).
async fn post_empty(url: &str) -> Result<ProtocolMessage, JsError> {
    let opts = web_sys::RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(web_sys::RequestMode::Cors);

    let request = web_sys::Request::new_with_str_and_init(url, &opts)
        .map_err(|e| JsError::new(&format!("request creation failed: {e:?}")))?;

    let window =
        web_sys::window().ok_or_else(|| JsError::new("no global window object"))?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| JsError::new(&format!("fetch failed: {e:?}")))?;

    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|_| JsError::new("response cast failed"))?;

    if !resp.ok() {
        return Err(JsError::new(&format!("HTTP {}", resp.status())));
    }

    let text_promise = resp
        .text()
        .map_err(|e| JsError::new(&format!("response text failed: {e:?}")))?;

    let text = JsFuture::from(text_promise)
        .await
        .map_err(|e| JsError::new(&format!("text await failed: {e:?}")))?
        .as_string()
        .ok_or_else(|| JsError::new("response body not a string"))?;

    serde_json::from_str::<ProtocolMessage>(&text)
        .map_err(|e| JsError::new(&format!("JSON parse failed: {e}")))
}

/// Check for protocol-level errors in the response.
fn check_protocol_error(msg: &ProtocolMessage) -> Result<(), JsError> {
    if let ProtocolMessage::Error { code, message } = msg {
        return Err(JsError::new(&format!("protocol error {code}: {message}")));
    }
    Ok(())
}

/// Validate that a server-supplied session ID is safe for URL interpolation.
/// Rejects path traversal characters (`/`, `?`, `#`, `%`) and non-printable bytes.
fn validate_session_id(id: &str) -> Result<(), JsError> {
    if id.is_empty() {
        return Err(JsError::new("server returned empty session_id"));
    }
    if id.contains('/') || id.contains('?') || id.contains('#') || id.contains('%') {
        return Err(JsError::new(&format!(
            "server returned unsafe session_id: {id}"
        )));
    }
    if id.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(JsError::new("session_id contains control characters"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TransportSession
// ---------------------------------------------------------------------------

/// Browser-native PAP transport session.
///
/// Drives the 6-phase handshake over the Fetch API, enforcing protocol
/// phase ordering. Each method corresponds to one protocol phase and
/// must be called in sequence.
///
/// # JavaScript Example
/// ```js
/// const session = new TransportSession("https://agent.example.com");
/// const accepted = await session.presentToken(token);
/// await session.exchangeDid();
/// await session.sendDisclosures("[]");
/// const result = await session.requestExecution();
/// const receipt = await session.exchangeReceipt(receiptJson);
/// await session.closeSession();
/// ```
#[wasm_bindgen]
pub struct TransportSession {
    base_url: String,
    phase: HandshakePhase,
    session_id: Option<String>,
    receiver_session_did: Option<String>,
    session_keypair: pap_did::SessionKeypair,
    last_execution_result: Option<String>,
}

#[wasm_bindgen]
impl TransportSession {
    /// Create a new transport session targeting the given agent base URL.
    /// Automatically generates an ephemeral session keypair.
    #[wasm_bindgen(constructor)]
    pub fn new(base_url: &str) -> TransportSession {
        TransportSession {
            base_url: base_url.trim_end_matches('/').to_string(),
            phase: HandshakePhase::Created,
            session_id: None,
            receiver_session_did: None,
            session_keypair: pap_did::SessionKeypair::generate(),
            last_execution_result: None,
        }
    }

    /// The ephemeral session DID (initiator side).
    /// Available immediately after construction.
    #[wasm_bindgen(js_name = sessionDid)]
    pub fn session_did(&self) -> String {
        self.session_keypair.did()
    }

    /// Current handshake phase.
    /// One of: `"Created"`, `"TokenPresented"`, `"DidExchanged"`,
    /// `"DisclosureSent"`, `"Executed"`, `"ReceiptSigned"`, `"Closed"`.
    pub fn phase(&self) -> String {
        self.phase.as_str().to_string()
    }

    /// The session ID assigned by the receiving agent (available after Phase 1).
    #[wasm_bindgen(js_name = sessionId)]
    pub fn session_id(&self) -> Option<String> {
        self.session_id.clone()
    }

    /// The receiver's ephemeral session DID (available after Phase 1).
    #[wasm_bindgen(js_name = receiverSessionDid)]
    pub fn receiver_session_did(&self) -> Option<String> {
        self.receiver_session_did.clone()
    }

    /// The cached execution result from Phase 4 (JSON string), or `undefined`.
    #[wasm_bindgen(js_name = lastExecutionResult)]
    pub fn last_execution_result(&self) -> Option<String> {
        self.last_execution_result.clone()
    }

    // -- Phase 1: Token Presentation ------------------------------------------

    /// Phase 1: Present a capability token to the receiving agent.
    ///
    /// Returns the JSON-serialized `TokenAccepted` response on success.
    /// Stores `sessionId` and `receiverSessionDid` internally.
    ///
    /// Throws if called out of order (phase must be `Created`).
    #[wasm_bindgen(js_name = presentToken)]
    pub async fn present_token(
        &mut self,
        token: &crate::CapabilityToken,
    ) -> Result<String, JsError> {
        if !self.phase.can_advance_to(HandshakePhase::TokenPresented) {
            return Err(JsError::new(&format!(
                "cannot present token: current phase is {}, expected Created",
                self.phase.as_str()
            )));
        }

        let msg = ProtocolMessage::TokenPresentation {
            token: token.inner.clone(),
        };
        let body = serde_json::to_string(&msg).map_err(to_js_err)?;
        let resp = post_json(&format!("{}/session", self.base_url), &body).await?;

        check_protocol_error(&resp)?;

        match &resp {
            ProtocolMessage::TokenAccepted {
                session_id,
                receiver_session_did,
                ..
            } => {
                validate_session_id(session_id)?;
                let json = serde_json::to_string(&resp).map_err(to_js_err)?;
                self.session_id = Some(session_id.clone());
                self.receiver_session_did = Some(receiver_session_did.clone());
                self.phase = HandshakePhase::TokenPresented;
                Ok(json)
            }
            ProtocolMessage::TokenRejected { reason } => {
                Err(JsError::new(&format!("token rejected: {reason}")))
            }
            other => Err(JsError::new(&format!(
                "unexpected response: {}",
                other.message_type()
            ))),
        }
    }

    // -- Phase 2: Ephemeral DID Exchange --------------------------------------

    /// Phase 2: Exchange ephemeral session DIDs.
    ///
    /// Sends this session's auto-generated ephemeral DID to the receiver.
    /// Returns the JSON-serialized `SessionDidAck` response.
    ///
    /// Throws if called out of order (phase must be `TokenPresented`).
    #[wasm_bindgen(js_name = exchangeDid)]
    pub async fn exchange_did(&mut self) -> Result<String, JsError> {
        if !self.phase.can_advance_to(HandshakePhase::DidExchanged) {
            return Err(JsError::new(&format!(
                "cannot exchange DID: current phase is {}, expected TokenPresented",
                self.phase.as_str()
            )));
        }

        let session_id = self
            .session_id
            .as_ref()
            .ok_or_else(|| JsError::new("no session_id (Phase 1 not complete)"))?;

        let msg = ProtocolMessage::SessionDidExchange {
            initiator_session_did: self.session_keypair.did(),
        };
        let body = serde_json::to_string(&msg).map_err(to_js_err)?;
        let resp = post_json(
            &format!("{}/session/{}/did", self.base_url, session_id),
            &body,
        )
        .await?;

        check_protocol_error(&resp)?;

        match &resp {
            ProtocolMessage::SessionDidAck => {
                let json = serde_json::to_string(&resp).map_err(to_js_err)?;
                self.phase = HandshakePhase::DidExchanged;
                Ok(json)
            }
            other => Err(JsError::new(&format!(
                "unexpected response: {}",
                other.message_type()
            ))),
        }
    }

    // -- Phase 3: Disclosure --------------------------------------------------

    /// Phase 3: Send selective disclosures.
    ///
    /// `disclosures_json` is a JSON array of disclosure values.
    /// Pass `"[]"` for zero-disclosure sessions.
    ///
    /// Returns the JSON-serialized `DisclosureAccepted` response.
    ///
    /// Throws if called out of order (phase must be `DidExchanged`).
    #[wasm_bindgen(js_name = sendDisclosures)]
    pub async fn send_disclosures(
        &mut self,
        disclosures_json: &str,
    ) -> Result<String, JsError> {
        if !self.phase.can_advance_to(HandshakePhase::DisclosureSent) {
            return Err(JsError::new(&format!(
                "cannot send disclosures: current phase is {}, expected DidExchanged",
                self.phase.as_str()
            )));
        }

        let session_id = self
            .session_id
            .as_ref()
            .ok_or_else(|| JsError::new("no session_id"))?;

        let disclosures: Vec<serde_json::Value> =
            serde_json::from_str(disclosures_json).map_err(|e| {
                JsError::new(&format!("invalid disclosures JSON: {e}"))
            })?;

        let msg = ProtocolMessage::DisclosureOffer { disclosures };
        let body = serde_json::to_string(&msg).map_err(to_js_err)?;
        let resp = post_json(
            &format!("{}/session/{}/disclosure", self.base_url, session_id),
            &body,
        )
        .await?;

        check_protocol_error(&resp)?;

        match &resp {
            ProtocolMessage::DisclosureAccepted => {
                let json = serde_json::to_string(&resp).map_err(to_js_err)?;
                self.phase = HandshakePhase::DisclosureSent;
                Ok(json)
            }
            other => Err(JsError::new(&format!(
                "unexpected response: {}",
                other.message_type()
            ))),
        }
    }

    // -- Phase 4: Execution ---------------------------------------------------

    /// Phase 4: Request execution from the receiving agent.
    ///
    /// Returns the JSON-serialized `ExecutionResult` response.
    /// The result is also cached and accessible via `lastExecutionResult()`.
    ///
    /// Throws if called out of order (phase must be `DisclosureSent`).
    #[wasm_bindgen(js_name = requestExecution)]
    pub async fn request_execution(&mut self) -> Result<String, JsError> {
        if !self.phase.can_advance_to(HandshakePhase::Executed) {
            return Err(JsError::new(&format!(
                "cannot request execution: current phase is {}, expected DisclosureSent",
                self.phase.as_str()
            )));
        }

        let session_id = self
            .session_id
            .as_ref()
            .ok_or_else(|| JsError::new("no session_id"))?;

        let resp = post_empty(&format!(
            "{}/session/{}/execute",
            self.base_url, session_id
        ))
        .await?;

        check_protocol_error(&resp)?;

        match &resp {
            ProtocolMessage::ExecutionResult { .. } => {
                let json = serde_json::to_string(&resp).map_err(to_js_err)?;
                self.last_execution_result = Some(json.clone());
                self.phase = HandshakePhase::Executed;
                Ok(json)
            }
            other => Err(JsError::new(&format!(
                "unexpected response: {}",
                other.message_type()
            ))),
        }
    }

    // -- Phase 5: Receipt Co-signing ------------------------------------------

    /// Phase 5: Exchange receipt for co-signing.
    ///
    /// `receipt_json` is a JSON-serialized `TransactionReceipt`.
    /// The receipt is automatically co-signed with this session's ephemeral key
    /// before being sent to the receiver.
    ///
    /// Returns the JSON-serialized `ReceiptCoSigned` response.
    ///
    /// Throws if called out of order (phase must be `Executed`).
    #[wasm_bindgen(js_name = exchangeReceipt)]
    pub async fn exchange_receipt(
        &mut self,
        receipt_json: &str,
    ) -> Result<String, JsError> {
        if !self.phase.can_advance_to(HandshakePhase::ReceiptSigned) {
            return Err(JsError::new(&format!(
                "cannot exchange receipt: current phase is {}, expected Executed",
                self.phase.as_str()
            )));
        }

        let session_id = self
            .session_id
            .as_ref()
            .ok_or_else(|| JsError::new("no session_id"))?;

        let mut receipt: pap_core::receipt::TransactionReceipt =
            serde_json::from_str(receipt_json)
                .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;

        receipt.co_sign(self.session_keypair.signing_key());

        let msg = ProtocolMessage::ReceiptForCoSign { receipt };
        let body = serde_json::to_string(&msg).map_err(to_js_err)?;
        let resp = post_json(
            &format!("{}/session/{}/receipt", self.base_url, session_id),
            &body,
        )
        .await?;

        check_protocol_error(&resp)?;

        match &resp {
            ProtocolMessage::ReceiptCoSigned { .. } => {
                let json = serde_json::to_string(&resp).map_err(to_js_err)?;
                self.phase = HandshakePhase::ReceiptSigned;
                Ok(json)
            }
            other => Err(JsError::new(&format!(
                "unexpected response: {}",
                other.message_type()
            ))),
        }
    }

    // -- Phase 6: Session Close -----------------------------------------------

    /// Phase 6: Close the session.
    ///
    /// After this call, the session is complete and the ephemeral keys
    /// should be discarded.
    ///
    /// Throws if called out of order (phase must be `ReceiptSigned`).
    #[wasm_bindgen(js_name = closeSession)]
    pub async fn close_session(&mut self) -> Result<String, JsError> {
        if !self.phase.can_advance_to(HandshakePhase::Closed) {
            return Err(JsError::new(&format!(
                "cannot close session: current phase is {}, expected ReceiptSigned",
                self.phase.as_str()
            )));
        }

        let session_id = self
            .session_id
            .as_ref()
            .ok_or_else(|| JsError::new("no session_id"))?;

        let msg = ProtocolMessage::SessionClose {
            session_id: session_id.clone(),
        };
        let body = serde_json::to_string(&msg).map_err(to_js_err)?;
        let resp = post_json(
            &format!("{}/session/{}/close", self.base_url, session_id),
            &body,
        )
        .await?;

        check_protocol_error(&resp)?;

        match &resp {
            ProtocolMessage::SessionClosed => {
                let json = serde_json::to_string(&resp).map_err(to_js_err)?;
                self.phase = HandshakePhase::Closed;
                Ok(json)
            }
            other => Err(JsError::new(&format!(
                "unexpected response: {}",
                other.message_type()
            ))),
        }
    }

    // -- Convenience: full handshake ------------------------------------------

    /// Run the full 6-phase handshake in one call.
    ///
    /// `disclosures_json` — JSON array of disclosure values (or `"[]"`).
    /// `receipt_json` — JSON-serialized `TransactionReceipt`.
    ///
    /// Runs all phases through session close (Phase 6).
    /// Returns the JSON-serialized `ReceiptCoSigned` response from Phase 5.
    #[wasm_bindgen(js_name = runHandshake)]
    pub async fn run_handshake(
        &mut self,
        token: &crate::CapabilityToken,
        disclosures_json: &str,
        receipt_json: &str,
    ) -> Result<String, JsError> {
        self.present_token(token).await?;
        self.exchange_did().await?;
        self.send_disclosures(disclosures_json).await?;
        self.request_execution().await?;
        let co_signed = self.exchange_receipt(receipt_json).await?;
        self.close_session().await?;
        Ok(co_signed)
    }
}
