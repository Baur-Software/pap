//! Ed25519 JWS (JSON Web Signature) operations for DIDComm v2 signed messages.
//!
//! Implements JWS General JSON Serialization with the `EdDSA` algorithm
//! as specified in RFC 7515 and RFC 8037.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::ProtoError;

use super::types::{DIDCommPlaintext, DIDCommSigned, JwsProtectedHeader, JwsSignature};

/// Sign a DIDComm v2 plaintext message, producing a JWS General JSON Serialization.
///
/// The signing input is `ASCII(BASE64URL(header)) || '.' || ASCII(BASE64URL(payload))`
/// as defined in RFC 7515 Section 5.2.
pub fn sign_plaintext(
    plaintext: &DIDCommPlaintext,
    signing_key: &SigningKey,
) -> Result<DIDCommSigned, ProtoError> {
    let header = JwsProtectedHeader {
        typ: "application/didcomm-signed+json".into(),
        alg: "EdDSA".into(),
    };

    let header_json = serde_json::to_string(&header)
        .map_err(|e| ProtoError::DIDCommError(e.to_string()))?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

    let payload_json = serde_json::to_string(plaintext)
        .map_err(|e| ProtoError::DIDCommError(e.to_string()))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    // JWS signing input: header_b64 || '.' || payload_b64
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(DIDCommSigned {
        payload: payload_b64,
        signatures: vec![JwsSignature {
            protected_header: header_b64,
            signature: signature_b64,
        }],
    })
}

/// Verify a DIDComm v2 signed message and extract the plaintext.
///
/// Validates the first signature using the provided Ed25519 verifying key,
/// then deserializes the payload into a `DIDCommPlaintext`.
pub fn verify_signed(
    signed: &DIDCommSigned,
    verifying_key: &VerifyingKey,
) -> Result<DIDCommPlaintext, ProtoError> {
    let sig_entry = signed
        .signatures
        .first()
        .ok_or_else(|| ProtoError::DIDCommError("no signatures present".into()))?;

    // Verify the protected header declares EdDSA
    let header_bytes = URL_SAFE_NO_PAD
        .decode(&sig_entry.protected_header)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid header encoding: {e}")))?;
    let header: JwsProtectedHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid header JSON: {e}")))?;
    if header.alg != "EdDSA" {
        return Err(ProtoError::DIDCommError(format!(
            "unsupported JWS algorithm: {}",
            header.alg
        )));
    }

    // Reconstruct signing input and verify
    let signing_input = format!("{}.{}", sig_entry.protected_header, signed.payload);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&sig_entry.signature)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid signature encoding: {e}")))?;
    let signature = ed25519_dalek::Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtoError::DIDCommError("invalid signature length".into()))?,
    );

    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| ProtoError::VerificationFailed)?;

    // Decode and return the plaintext
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(&signed.payload)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid payload encoding: {e}")))?;
    serde_json::from_slice(&payload_bytes)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid plaintext JSON: {e}")))
}
