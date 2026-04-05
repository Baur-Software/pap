#![no_main]
use arbitrary::Arbitrary;
use ed25519_dalek::Verifier;
use libfuzzer_sys::fuzz_target;
use pap_did::{did_to_public_key_bytes, verify_key_from_did, DidDocument, PrincipalKeypair};

#[derive(Debug, Arbitrary)]
struct Input {
    seed: [u8; 32],
    message: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let kp = PrincipalKeypair::from_bytes(&input.seed).expect("Ed25519 accepts all 32-byte seeds");
    let pubkey_bytes = kp.public_key_bytes();
    let did = kp.did();
    let recovered_bytes = did_to_public_key_bytes(&did).unwrap();
    assert_eq!(pubkey_bytes, recovered_bytes);
    let recovered_vk = verify_key_from_did(&did).unwrap();
    assert_eq!(recovered_vk.to_bytes(), pubkey_bytes);
    let sig = kp.sign(&input.message);
    assert!(recovered_vk.verify(&input.message, &sig).is_ok());
    assert!(kp.verify(&input.message, &sig).is_ok());
    let doc = DidDocument::from_keypair(&kp);
    let json = doc.to_json();
    let doc2 = DidDocument::from_json(&json).unwrap();
    assert_eq!(doc.id, doc2.id);
    assert_eq!(
        doc.verification_method[0].public_key_multibase,
        doc2.verification_method[0].public_key_multibase,
    );
});
