use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::PapError;
use crate::session::Session;

/// A transaction receipt co-signed by both session parties.
/// Contains property references only — never values.
/// Auditable by both principals. Not stored by any platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Ephemeral session ID (not linked to principal)
    pub session_id: String,
    /// Schema.org action reference
    pub action: String,
    /// Ephemeral session DID of the initiating agent
    pub initiating_agent_did: String,
    /// Ephemeral session DID of the receiving agent
    pub receiving_agent_did: String,
    /// Property references disclosed by the initiator (refs only, no values)
    pub disclosed_by_initiator: Vec<String>,
    /// Property references / operator statement from receiver
    pub disclosed_by_receiver: Vec<String>,
    /// Description of what was executed
    pub executed: String,
    /// Description of what was returned
    pub returned: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Co-signatures from both session DIDs (base64-encoded)
    pub signatures: Vec<String>,
}

impl TransactionReceipt {
    /// Build a receipt from a completed session.
    pub fn from_session(
        session: &Session,
        disclosed_by_initiator: Vec<String>,
        disclosed_by_receiver: Vec<String>,
        executed: String,
        returned: String,
    ) -> Result<Self, PapError> {
        let initiator_did = session
            .initiator_session_did
            .as_ref()
            .ok_or_else(|| PapError::ReceiptError("no initiator session DID".into()))?;
        let receiver_did = session
            .receiver_session_did
            .as_ref()
            .ok_or_else(|| PapError::ReceiptError("no receiver session DID".into()))?;

        Ok(Self {
            session_id: session.id.clone(),
            action: session.action.clone(),
            initiating_agent_did: initiator_did.clone(),
            receiving_agent_did: receiver_did.clone(),
            disclosed_by_initiator,
            disclosed_by_receiver,
            executed,
            returned,
            timestamp: Utc::now(),
            signatures: vec![],
        })
    }

    /// Canonical bytes for signing (excludes signatures).
    fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "session_id": self.session_id,
            "action": self.action,
            "initiating_agent_did": self.initiating_agent_did,
            "receiving_agent_did": self.receiving_agent_did,
            "disclosed_by_initiator": self.disclosed_by_initiator,
            "disclosed_by_receiver": self.disclosed_by_receiver,
            "executed": self.executed,
            "returned": self.returned,
            "timestamp": self.timestamp.to_rfc3339(),
        });
        serde_json::to_vec(&canonical).expect("canonical serialization cannot fail")
    }

    /// Co-sign the receipt with a session key.
    pub fn co_sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        let bytes = self.canonical_bytes();
        let sig = signing_key.sign(&bytes);
        use base64::Engine;
        self.signatures.push(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        );
    }

    /// Verify a specific signature on the receipt.
    pub fn verify_signature(
        &self,
        index: usize,
        verifying_key: &VerifyingKey,
    ) -> Result<(), PapError> {
        let sig_b64 = self
            .signatures
            .get(index)
            .ok_or_else(|| PapError::ReceiptError(format!("no signature at index {index}")))?;
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| PapError::ReceiptError(format!("invalid signature encoding: {e}")))?;
        let signature = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| PapError::ReceiptError("invalid signature length".into()))?,
        );
        let bytes = self.canonical_bytes();
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| PapError::VerificationFailed)
    }

    /// Verify both co-signatures.
    pub fn verify_both(
        &self,
        initiator_key: &VerifyingKey,
        receiver_key: &VerifyingKey,
    ) -> Result<(), PapError> {
        if self.signatures.len() != 2 {
            return Err(PapError::ReceiptError(format!(
                "expected 2 signatures, found {}",
                self.signatures.len()
            )));
        }
        self.verify_signature(0, initiator_key)?;
        self.verify_signature(1, receiver_key)?;
        Ok(())
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("receipt serialization cannot fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{CapabilityToken, Session};
    use chrono::Duration;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn did_from_key(key: &SigningKey) -> String {
        pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did()
    }

    fn make_executed_session() -> Session {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        let mut token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token.sign(&issuer_key);

        let mut session =
            Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();
        session
            .open("did:key:zinit_sess".into(), "did:key:zrecv_sess".into())
            .unwrap();
        session.execute().unwrap();
        session
    }

    #[test]
    fn receipt_from_session_and_cosign() {
        let session = make_executed_session();
        let init_session_key = make_keypair();
        let recv_session_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec!["operator:search_executed".into()],
            "schema:SearchAction executed".into(),
            "schema:SearchResult returned".into(),
        )
        .unwrap();

        receipt.co_sign(&init_session_key);
        receipt.co_sign(&recv_session_key);

        assert_eq!(receipt.signatures.len(), 2);
        assert!(receipt
            .verify_both(
                &init_session_key.verifying_key(),
                &recv_session_key.verifying_key()
            )
            .is_ok());
    }

    #[test]
    fn receipt_zero_disclosure() {
        let session = make_executed_session();
        let receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec!["operator:search_executed".into()],
            "schema:SearchAction executed".into(),
            "schema:SearchResult returned".into(),
        )
        .unwrap();

        assert!(receipt.disclosed_by_initiator.is_empty());
    }

    #[test]
    fn receipt_json_roundtrip() {
        let session = make_executed_session();
        let init_key = make_keypair();
        let recv_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec!["operator:search_executed".into()],
            "schema:SearchAction executed".into(),
            "schema:SearchResult returned".into(),
        )
        .unwrap();
        receipt.co_sign(&init_key);
        receipt.co_sign(&recv_key);

        let json = receipt.to_json();
        let receipt2: TransactionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt.session_id, receipt2.session_id);
        assert_eq!(receipt.signatures.len(), receipt2.signatures.len());
    }

    #[test]
    fn wrong_key_verify_fails() {
        let session = make_executed_session();
        let init_key = make_keypair();
        let recv_key = make_keypair();
        let wrong_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();
        receipt.co_sign(&init_key);
        receipt.co_sign(&recv_key);

        assert!(receipt
            .verify_both(&wrong_key.verifying_key(), &recv_key.verifying_key())
            .is_err());
    }
}
