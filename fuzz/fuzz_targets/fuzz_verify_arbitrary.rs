#![no_main]
use arbitrary::Arbitrary;
use ed25519_dalek::Signature;
use libfuzzer_sys::fuzz_target;
use pap_did::PrincipalKeypair;

#[derive(Debug, Arbitrary)]
struct Input {
    seed: [u8; 32],
    message: Vec<u8>,
    sig_bytes: [u8; 64],
}

fuzz_target!(|input: Input| {
    let kp = PrincipalKeypair::from_bytes(&input.seed).unwrap();
    if let Ok(sig) = Signature::from_slice(&input.sig_bytes) {
        let _ = kp.verify(&input.message, &sig);
    }
});
