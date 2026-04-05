#![no_main]
use ed25519_dalek::VerifyingKey;
use libfuzzer_sys::fuzz_target;
use pap_did::{did_to_public_key_bytes, PrincipalKeypair};

fuzz_target!(|seed: [u8; 32]| {
    let kp = PrincipalKeypair::from_bytes(&seed).expect("Ed25519 accepts all 32-byte seeds");
    let did = kp.did();
    let recovered = did_to_public_key_bytes(&did).unwrap();
    assert_eq!(kp.public_key_bytes(), recovered);
    assert!(VerifyingKey::from_bytes(&recovered).is_ok());
});
