#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pap_did::PrincipalKeypair;

#[derive(Debug, Arbitrary)]
struct Input {
    seed: [u8; 32],
    message: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let kp = PrincipalKeypair::from_bytes(&input.seed).expect("Ed25519 accepts all 32-byte seeds");
    let sig = kp.sign(&input.message);
    assert!(kp.verify(&input.message, &sig).is_ok());
});
