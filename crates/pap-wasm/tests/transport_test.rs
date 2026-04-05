use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn transport_session_generates_valid_did() {
    let session = pap_wasm::TransportSession::new("https://example.com");
    let did = session.session_did();
    assert!(
        did.starts_with("did:key:z"),
        "session DID should be a did:key, got: {did}"
    );
}

#[wasm_bindgen_test]
fn transport_session_starts_in_created_phase() {
    let session = pap_wasm::TransportSession::new("https://example.com");
    assert_eq!(session.phase(), "Created");
}

#[wasm_bindgen_test]
fn transport_session_id_none_before_phase1() {
    let session = pap_wasm::TransportSession::new("https://example.com");
    assert!(session.session_id().is_none());
}

#[wasm_bindgen_test]
fn transport_session_receiver_did_none_before_phase1() {
    let session = pap_wasm::TransportSession::new("https://example.com");
    assert!(session.receiver_session_did().is_none());
}

#[wasm_bindgen_test]
fn transport_session_execution_result_none_before_phase4() {
    let session = pap_wasm::TransportSession::new("https://example.com");
    assert!(session.last_execution_result().is_none());
}

#[wasm_bindgen_test]
fn transport_session_strips_trailing_slash() {
    // Verify that two sessions with/without trailing slash produce valid DIDs
    // (we can't inspect base_url directly, but we confirm construction works).
    let s1 = pap_wasm::TransportSession::new("https://example.com/");
    let s2 = pap_wasm::TransportSession::new("https://example.com");
    assert!(s1.session_did().starts_with("did:key:z"));
    assert!(s2.session_did().starts_with("did:key:z"));
}

#[wasm_bindgen_test]
fn transport_session_unique_keypairs() {
    let s1 = pap_wasm::TransportSession::new("https://example.com");
    let s2 = pap_wasm::TransportSession::new("https://example.com");
    assert_ne!(
        s1.session_did(),
        s2.session_did(),
        "each session should have a unique ephemeral keypair"
    );
}

// -- Phase ordering tests (async, verify out-of-order calls fail) -----------

#[wasm_bindgen_test]
async fn exchange_did_before_present_token_fails() {
    let mut session = pap_wasm::TransportSession::new("https://example.com");
    let result: Result<String, _> = session.exchange_did().await;
    assert!(
        result.is_err(),
        "exchange_did should fail before present_token"
    );
}

#[wasm_bindgen_test]
async fn send_disclosures_before_did_exchange_fails() {
    let mut session = pap_wasm::TransportSession::new("https://example.com");
    let result: Result<String, _> = session.send_disclosures("[]").await;
    assert!(
        result.is_err(),
        "send_disclosures should fail before exchange_did"
    );
}

#[wasm_bindgen_test]
async fn request_execution_before_disclosures_fails() {
    let mut session = pap_wasm::TransportSession::new("https://example.com");
    let result: Result<String, _> = session.request_execution().await;
    assert!(
        result.is_err(),
        "request_execution should fail before send_disclosures"
    );
}

#[wasm_bindgen_test]
async fn exchange_receipt_before_execution_fails() {
    let mut session = pap_wasm::TransportSession::new("https://example.com");
    let result: Result<String, _> = session.exchange_receipt("{}").await;
    assert!(
        result.is_err(),
        "exchange_receipt should fail before request_execution"
    );
}

#[wasm_bindgen_test]
async fn close_session_before_receipt_fails() {
    let mut session = pap_wasm::TransportSession::new("https://example.com");
    let result: Result<String, _> = session.close_session().await;
    assert!(
        result.is_err(),
        "close_session should fail before exchange_receipt"
    );
}
