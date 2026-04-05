#![no_main]
use arbitrary::Arbitrary;
use ed25519_dalek::Signature;
use libfuzzer_sys::fuzz_target;
use pap_did::PrincipalKeypair;

#[derive(Debug, Arbitrary)]
struct Input {
    seed: [u8; 32],
    message: Vec<u8>,
    byte_index: u8,
    xor_mask: u8,
}

fuzz_target!(|input: Input| {
    if input.xor_mask == 0 {
        return;
    }
    let kp = PrincipalKeypair::from_bytes(&input.seed).unwrap();
    let sig = kp.sign(&input.message);
    let mut sig_bytes = sig.to_bytes();
    let idx = input.byte_index as usize % 64;
    sig_bytes[idx] ^= input.xor_mask;
    if let Ok(mutated_sig) = Signature::from_slice(&sig_bytes) {
        assert!(kp.verify(&input.message, &mutated_sig).is_err());
    }
});
