//! Ed25519 JWS (JSON Web Signature) operations for DIDComm v2 signed messages.
//!
//! Implements JWS General JSON Serialization with the `EdDSA` algorithm
//! as specified in RFC 7515 and RFC 8037.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use pap_did::SignatureAlgorithm;

use crate::error::ProtoError;

use super::types::{DIDCommPlaintext, DIDCommSigned, JwsProtectedHeader, JwsSignature};

/// Sign a DIDComm v2 plaintext message, producing a JWS General JSON Serialization.
///
/// The signing input is `ASCII(BASE64URL(header)) || '.' || ASCII(BASE64URL(payload))`
/// as defined in RFC 7515 Section 5.2.
pub fn sign_plaintext(
    plaintext: &DIDCommPlaintext,
    signing_key: &SigningKey,
    algorithm: SignatureAlgorithm,
) -> Result<DIDCommSigned, ProtoError> {
    let header = JwsProtectedHeader {
        typ: "application/didcomm-signed+json".into(),
        alg: algorithm.jws_alg().into(),
    };

    let header_json =
        serde_json::to_string(&header).map_err(|e| ProtoError::DIDCommError(e.to_string()))?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

    let payload_json =
        serde_json::to_string(plaintext).map_err(|e| ProtoError::DIDCommError(e.to_string()))?;
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
/// Dispatches to the correct verifier based on the JWS protected header `alg`
/// field. Unknown or unsupported algorithms are rejected with
/// `ProtoError::UnsupportedAlgorithm` — they never silently pass.
///
/// Per the PAP specification (Section 14.11.3), verifiers MUST reject messages
/// where the `alg` header value is not `"EdDSA"`.
pub fn verify_signed(
    signed: &DIDCommSigned,
    verifying_key: &VerifyingKey,
) -> Result<DIDCommPlaintext, ProtoError> {
    let sig_entry = signed
        .signatures
        .first()
        .ok_or_else(|| ProtoError::DIDCommError("no signatures present".into()))?;

    // Decode and parse the protected header to determine the algorithm.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(&sig_entry.protected_header)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid header encoding: {e}")))?;
    let header: JwsProtectedHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid header JSON: {e}")))?;

    // Dispatch verification on algorithm. Unknown algorithms are rejected
    // immediately — never silently passed through.
    let algorithm = match header.alg.as_str() {
        "EdDSA" => SignatureAlgorithm::Ed25519,
        other => return Err(ProtoError::UnsupportedAlgorithm(other.to_owned())),
    };

    // Reconstruct signing input and verify with the dispatched algorithm.
    let signing_input = format!("{}.{}", sig_entry.protected_header, signed.payload);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&sig_entry.signature)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid signature encoding: {e}")))?;

    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let signature = ed25519_dalek::Signature::try_from(sig_bytes.as_slice())
                .map_err(|e| ProtoError::DIDCommError(format!("invalid signature bytes: {e}")))?;
            verifying_key
                .verify_strict(signing_input.as_bytes(), &signature)
                .map_err(|_| ProtoError::VerificationFailed)?;
        }
        // SignatureAlgorithm is #[non_exhaustive]; any future variant that
        // reaches here was accepted by the header dispatch but has no verifier
        // wired up yet -- reject rather than silently pass.
        _ => return Err(ProtoError::UnsupportedAlgorithm(header.alg.clone())),
    }

    // Decode and return the plaintext.
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(&signed.payload)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid payload encoding: {e}")))?;
    serde_json::from_slice(&payload_bytes)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid plaintext JSON: {e}")))
}
