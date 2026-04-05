use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::algorithm::SignatureAlgorithm;
use crate::DidError;

/// Root keypair bound to the human principal's device.
/// In production this would be backed by WebAuthn / platform authenticator.
/// For the PoC we generate Ed25519 in software.
pub struct PrincipalKeypair {
    signing_key: SigningKey,
}

impl PrincipalKeypair {
    /// Generate a new principal keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Reconstruct from raw secret key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, DidError> {
        let signing_key = SigningKey::from_bytes(bytes);
        Ok(Self { signing_key })
    }

    /// The `did:key` identifier derived from this keypair.
    /// Format: did:key:z<base58btc(0xed01 ++ public_key_bytes)>
    pub fn did(&self) -> String {
        public_key_to_did(&self.verifying_key())
    }

    /// The raw public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }

    /// The Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// The Ed25519 signing key (for mandate/token signing).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Sign arbitrary bytes.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature against this keypair's public key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), DidError> {
        self.verifying_key()
            .verify(message, signature)
            .map_err(|_| DidError::VerificationFailed)
    }
}

/// Convert a public key to a `did:key` identifier using the specified algorithm.
pub fn public_key_to_did_for_algorithm(key_bytes: &[u8], algorithm: SignatureAlgorithm) -> String {
    let prefix = algorithm.multicodec_prefix();
    let mut prefixed = Vec::with_capacity(prefix.len() + key_bytes.len());
    prefixed.extend_from_slice(prefix);
    prefixed.extend_from_slice(key_bytes);
    let encoded = bs58::encode(&prefixed).into_string();
    format!("did:key:z{encoded}")
}

/// Convert an Ed25519 public key to a `did:key` identifier.
/// Multicodec prefix for Ed25519 public key: 0xed01
pub fn public_key_to_did(key: &VerifyingKey) -> String {
    public_key_to_did_for_algorithm(&key.to_bytes(), SignatureAlgorithm::Ed25519)
}

/// Extract public key bytes and detected algorithm from a `did:key` identifier.
pub fn did_to_public_key_bytes_with_algorithm(
    did: &str,
) -> Result<(Vec<u8>, SignatureAlgorithm), DidError> {
    let z_part = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| DidError::InvalidDid(did.to_string()))?;
    let decoded = bs58::decode(z_part)
        .into_vec()
        .map_err(|e| DidError::InvalidDid(e.to_string()))?;
    if decoded.len() < 2 {
        return Err(DidError::InvalidDid(
            "too short for multicodec prefix".into(),
        ));
    }
    let algorithm = SignatureAlgorithm::from_multicodec_prefix(&decoded[..2]).ok_or_else(|| {
        DidError::UnsupportedAlgorithm(format!(
            "unrecognized multicodec prefix: 0x{:02x}{:02x}",
            decoded[0], decoded[1]
        ))
    })?;
    let expected_len = 2 + algorithm.public_key_size();
    if decoded.len() != expected_len {
        return Err(DidError::InvalidDid(format!(
            "expected {} bytes for {}, got {}",
            expected_len,
            algorithm,
            decoded.len()
        )));
    }
    Ok((decoded[2..].to_vec(), algorithm))
}

/// Extract public key bytes from a `did:key` identifier (Ed25519 only).
pub fn did_to_public_key_bytes(did: &str) -> Result<[u8; 32], DidError> {
    let (bytes, alg) = did_to_public_key_bytes_with_algorithm(did)?;
    if alg != SignatureAlgorithm::Ed25519 {
        return Err(DidError::UnsupportedAlgorithm(format!(
            "expected Ed25519, got {}",
            alg
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Extract a VerifyingKey from a `did:key` identifier.
/// This is used to verify signatures on artifacts signed by the DID holder.
pub fn verify_key_from_did(did: &str) -> Result<VerifyingKey, DidError> {
    let bytes = did_to_public_key_bytes(did)?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| DidError::InvalidDid("invalid public key bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_sign_verify() {
        let kp = PrincipalKeypair::generate();
        let msg = b"hello principal";
        let sig = kp.sign(msg);
        assert!(kp.verify(msg, &sig).is_ok());
    }

    #[test]
    fn did_key_roundtrip() {
        let kp = PrincipalKeypair::generate();
        let did = kp.did();
        assert!(did.starts_with("did:key:z"));

        let bytes = did_to_public_key_bytes(&did).unwrap();
        assert_eq!(bytes, kp.public_key_bytes());
    }

    #[test]
    fn from_bytes_roundtrip() {
        let kp = PrincipalKeypair::generate();
        let secret = kp.signing_key.to_bytes();
        let kp2 = PrincipalKeypair::from_bytes(&secret).unwrap();
        assert_eq!(kp.did(), kp2.did());
    }

    #[test]
    fn wrong_message_fails_verify() {
        let kp = PrincipalKeypair::generate();
        let sig = kp.sign(b"correct message");
        assert!(kp.verify(b"wrong message", &sig).is_err());
    }

    #[test]
    fn algorithm_aware_did_roundtrip() {
        let kp = PrincipalKeypair::generate();
        let did =
            public_key_to_did_for_algorithm(&kp.public_key_bytes(), SignatureAlgorithm::Ed25519);
        assert_eq!(did, kp.did());

        let (bytes, alg) = did_to_public_key_bytes_with_algorithm(&did).unwrap();
        assert_eq!(alg, SignatureAlgorithm::Ed25519);
        assert_eq!(bytes.as_slice(), &kp.public_key_bytes());
    }

    #[test]
    fn unrecognized_multicodec_prefix_rejected() {
        // Fabricate a did:key with an unknown multicodec prefix
        let mut prefixed = vec![0x12, 0x00]; // not Ed25519
        prefixed.extend_from_slice(&[0u8; 32]);
        let encoded = bs58::encode(&prefixed).into_string();
        let did = format!("did:key:z{encoded}");

        let result = did_to_public_key_bytes_with_algorithm(&did);
        assert!(matches!(result, Err(DidError::UnsupportedAlgorithm(_))));
    }
}
