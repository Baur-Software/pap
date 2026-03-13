use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use pap_did::public_key_to_did;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::WebAuthnError;
use crate::signer::PrincipalSigner;

/// A mock WebAuthn credential that simulates a FIDO2/passkey registration.
///
/// In production, the credential would live on a hardware authenticator
/// or platform authenticator (TouchID, Windows Hello, YubiKey). This
/// mock uses an Ed25519 key in memory but follows the WebAuthn data
/// structures so the protocol layer exercises the right code paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    pub credential_id: Vec<u8>,
    pub public_key: [u8; 32],
    pub rp_id: String,
    pub user_handle: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

/// The authenticator's response to a `navigator.credentials.get()` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
    pub credential_id: Vec<u8>,
}

/// A mock WebAuthn signer that implements `PrincipalSigner`.
///
/// Simulates the full ceremony: registration creates the credential,
/// authentication (get_assertion) produces a response with authenticator
/// data, client data JSON, and a signature over the concatenation.
pub struct MockWebAuthnSigner {
    credential: WebAuthnCredential,
    signing_key: SigningKey,
}

impl MockWebAuthnSigner {
    /// Access the credential metadata (for display/logging).
    pub fn credential(&self) -> &WebAuthnCredential {
        &self.credential
    }
}

/// Simulate `navigator.credentials.create()` — the registration ceremony.
///
/// Returns a signer (which holds the private key) and the credential
/// (which is the relying party's view of the registered authenticator).
pub fn create_credential(rp_id: &str, _user_name: &str) -> (MockWebAuthnSigner, WebAuthnCredential) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes();

    // Credential ID: SHA-256(rp_id || public_key) — deterministic but unique
    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    hasher.update(&public_key);
    let credential_id = hasher.finalize().to_vec();

    let user_handle = Uuid::new_v4().as_bytes().to_vec();

    let credential = WebAuthnCredential {
        credential_id: credential_id.clone(),
        public_key,
        rp_id: rp_id.to_string(),
        user_handle: user_handle.clone(),
        created_at: Utc::now(),
    };

    let signer = MockWebAuthnSigner {
        credential: credential.clone(),
        signing_key,
    };

    (signer, credential)
}

/// Simulate `navigator.credentials.get()` — the authentication ceremony.
///
/// The challenge is typically provided by the relying party server.
/// The authenticator signs `authenticator_data || SHA-256(client_data_json)`.
pub fn get_assertion(
    signer: &MockWebAuthnSigner,
    challenge: &[u8],
) -> AuthenticatorAssertionResponse {
    // Authenticator data: rp_id_hash (32) + flags (1) + counter (4)
    let rp_id_hash = Sha256::digest(signer.credential.rp_id.as_bytes());
    let flags: u8 = 0x05; // UP (user present) + UV (user verified)
    let counter: u32 = 1;

    let mut authenticator_data = Vec::with_capacity(37);
    authenticator_data.extend_from_slice(&rp_id_hash);
    authenticator_data.push(flags);
    authenticator_data.extend_from_slice(&counter.to_be_bytes());

    // Client data JSON (simplified but structurally correct)
    let client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": base64_url_encode(challenge),
        "origin": format!("https://{}", signer.credential.rp_id),
        "crossOrigin": false,
    });
    let client_data_json = serde_json::to_vec(&client_data).unwrap();

    // Sign: authenticator_data || SHA-256(client_data_json)
    let client_data_hash = Sha256::digest(&client_data_json);
    let mut signed_data = authenticator_data.clone();
    signed_data.extend_from_slice(&client_data_hash);

    let signature = signer.signing_key.sign(&signed_data);

    AuthenticatorAssertionResponse {
        authenticator_data,
        client_data_json,
        signature: signature.to_bytes().to_vec(),
        credential_id: signer.credential.credential_id.clone(),
    }
}

/// Verify an assertion response against a stored credential.
///
/// This is what the relying party server does after receiving the
/// authenticator's response.
pub fn verify_assertion(
    response: &AuthenticatorAssertionResponse,
    credential: &WebAuthnCredential,
    expected_challenge: &[u8],
) -> Result<(), WebAuthnError> {
    // Check credential ID matches
    if response.credential_id != credential.credential_id {
        return Err(WebAuthnError::InvalidCredential(
            "credential ID mismatch".into(),
        ));
    }

    // Parse and verify client data
    let client_data: serde_json::Value = serde_json::from_slice(&response.client_data_json)
        .map_err(|e| WebAuthnError::CeremonyFailed(format!("invalid client data: {e}")))?;

    let challenge_b64 = client_data["challenge"]
        .as_str()
        .ok_or_else(|| WebAuthnError::CeremonyFailed("missing challenge".into()))?;

    let decoded_challenge = base64_url_decode(challenge_b64)
        .map_err(|e| WebAuthnError::CeremonyFailed(format!("bad challenge encoding: {e}")))?;

    if decoded_challenge != expected_challenge {
        return Err(WebAuthnError::ChallengeMismatch);
    }

    // Reconstruct signed data: authenticator_data || SHA-256(client_data_json)
    let client_data_hash = Sha256::digest(&response.client_data_json);
    let mut signed_data = response.authenticator_data.clone();
    signed_data.extend_from_slice(&client_data_hash);

    // Verify signature
    let verifying_key = VerifyingKey::from_bytes(&credential.public_key)
        .map_err(|e| WebAuthnError::InvalidCredential(format!("bad public key: {e}")))?;

    let signature = ed25519_dalek::Signature::from_bytes(
        response
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| WebAuthnError::VerificationFailed("invalid signature length".into()))?,
    );

    verifying_key
        .verify(&signed_data, &signature)
        .map_err(|_| WebAuthnError::VerificationFailed("signature verification failed".into()))
}

impl PrincipalSigner for MockWebAuthnSigner {
    fn did(&self) -> String {
        let verifying_key = self.signing_key.verifying_key();
        public_key_to_did(&verifying_key)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, WebAuthnError> {
        let sig = self.signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.decode(s)
}
