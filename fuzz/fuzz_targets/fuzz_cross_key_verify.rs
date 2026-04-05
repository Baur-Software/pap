#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pap_did::PrincipalKeypair;

#[derive(Debug, Arbitrary)]
struct Input {
    seed_a: [u8; 32],
    seed_b: [u8; 32],
    message: Vec<u8>,
}

fuzz_target!(|input: Input| {
    if input.seed_a == input.seed_b {
        return;
    }
    let kp_a =
        PrincipalKeypair::from_bytes(&input.seed_a).expect("Ed25519 accepts all 32-byte seeds");
    let kp_b =
        PrincipalKeypair::from_bytes(&input.seed_b).expect("Ed25519 accepts all 32-byte seeds");
    let sig = kp_a.sign(&input.message);
    assert!(kp_b.verify(&input.message, &sig).is_err());
});
