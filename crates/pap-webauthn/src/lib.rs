pub mod error;
pub mod mock_webauthn;
pub mod signer;
pub mod software;

pub use error::WebAuthnError;
pub use mock_webauthn::{
    create_credential, get_assertion, verify_assertion, AuthenticatorAssertionResponse,
    MockWebAuthnSigner, WebAuthnCredential,
};
pub use signer::PrincipalSigner;
pub use software::SoftwareSigner;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn software_signer_generates_valid_did() {
        let signer = SoftwareSigner::generate();
        let did = signer.did();
        assert!(did.starts_with("did:key:z"));
    }

    #[test]
    fn software_signer_sign_verify_roundtrip() {
        let signer = SoftwareSigner::generate();
        let message = b"hello PAP";
        let sig_bytes = signer.sign(message).unwrap();

        let signature = ed25519_dalek::Signature::from_bytes(
            sig_bytes.as_slice().try_into().unwrap(),
        );
        signer.verifying_key().verify(message, &signature).unwrap();
    }

    #[test]
    fn software_signer_matches_keypair() {
        let signer = SoftwareSigner::generate();
        let did_from_trait = signer.did();
        let did_from_keypair = signer.keypair().did();
        assert_eq!(did_from_trait, did_from_keypair);
    }

    #[test]
    fn mock_webauthn_create_and_verify() {
        let (signer, credential) = create_credential("example.com", "alice");

        // Credential has expected fields
        assert_eq!(credential.rp_id, "example.com");
        assert!(!credential.credential_id.is_empty());
        assert_eq!(credential.public_key, signer.verifying_key().to_bytes());

        // Signer implements PrincipalSigner
        let did = signer.did();
        assert!(did.starts_with("did:key:z"));
    }

    #[test]
    fn mock_webauthn_assertion_roundtrip() {
        let (signer, credential) = create_credential("pap.example.com", "bob");
        let challenge = b"random-challenge-from-server";

        let response = get_assertion(&signer, challenge);
        verify_assertion(&response, &credential, challenge).unwrap();
    }

    #[test]
    fn mock_webauthn_wrong_challenge_fails() {
        let (signer, credential) = create_credential("pap.example.com", "carol");
        let challenge = b"correct-challenge";
        let wrong_challenge = b"wrong-challenge";

        let response = get_assertion(&signer, challenge);
        let result = verify_assertion(&response, &credential, wrong_challenge);
        assert!(result.is_err());
    }

    #[test]
    fn mock_webauthn_wrong_credential_fails() {
        let (signer, _credential) = create_credential("pap.example.com", "dave");
        let (_other_signer, other_credential) = create_credential("pap.example.com", "eve");
        let challenge = b"a-challenge";

        let response = get_assertion(&signer, challenge);
        let result = verify_assertion(&response, &other_credential, challenge);
        assert!(result.is_err());
    }

    #[test]
    fn mock_webauthn_signer_sign_verify() {
        let (signer, _credential) = create_credential("example.com", "frank");
        let message = b"sign this with webauthn";

        let sig_bytes = signer.sign(message).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(
            sig_bytes.as_slice().try_into().unwrap(),
        );
        signer.verifying_key().verify(message, &signature).unwrap();
    }

    #[test]
    fn both_signers_interchangeable() {
        // Prove the trait is object-safe and both impls work through it
        let sw = SoftwareSigner::generate();
        let (wa, _) = create_credential("example.com", "test");

        let signers: Vec<Box<dyn PrincipalSigner>> = vec![Box::new(sw), Box::new(wa)];

        for signer in &signers {
            let did = signer.did();
            assert!(did.starts_with("did:key:z"));

            let msg = b"trait object test";
            let sig = signer.sign(msg).unwrap();
            assert_eq!(sig.len(), 64);

            let signature = ed25519_dalek::Signature::from_bytes(
                sig.as_slice().try_into().unwrap(),
            );
            signer.verifying_key().verify(msg, &signature).unwrap();
        }
    }

    #[test]
    fn credential_serialization_roundtrip() {
        let (_signer, credential) = create_credential("test.example.com", "serde");
        let json = serde_json::to_string(&credential).unwrap();
        let restored: WebAuthnCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(credential.credential_id, restored.credential_id);
        assert_eq!(credential.public_key, restored.public_key);
        assert_eq!(credential.rp_id, restored.rp_id);
    }

    #[test]
    fn assertion_response_serialization_roundtrip() {
        let (signer, _) = create_credential("test.example.com", "serde");
        let response = get_assertion(&signer, b"challenge");
        let json = serde_json::to_string(&response).unwrap();
        let restored: AuthenticatorAssertionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response.signature, restored.signature);
        assert_eq!(response.credential_id, restored.credential_id);
    }
}
