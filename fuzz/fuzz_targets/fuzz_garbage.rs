#![no_main]
use ed25519_dalek::Signature;
use libfuzzer_sys::fuzz_target;
use pap_did::{did_to_public_key_bytes, verify_key_from_did, DidDocument, PrincipalKeypair};

// Chaos monkey: feed arbitrary bytes to every deterministically-constructible
// entry point. Pure panic detection — no correctness assertions.
fuzz_target!(|data: &[u8]| {
    // Parser paths work on any non-empty input — no seed required
    let garbage_str = std::str::from_utf8(data).unwrap_or("");
    let _ = did_to_public_key_bytes(garbage_str);
    let _ = verify_key_from_did(garbage_str);
    let _ = DidDocument::from_json(garbage_str);

    // Keypair-dependent paths require at least 32 bytes
    if data.len() < 32 {
        return;
    }
    let seed: [u8; 32] = data[..32].try_into().expect("slice length checked above");
    let remainder = &data[32..];

    let kp = PrincipalKeypair::from_bytes(&seed).expect("Ed25519 accepts all 32-byte seeds");
    let _ = kp.did();
    let _ = kp.sign(remainder);
    if remainder.len() >= 64 {
        let sig_slice: [u8; 64] = remainder[..64]
            .try_into()
            .expect("slice length checked above");
        if let Ok(sig) = Signature::from_slice(&sig_slice) {
            let _ = kp.verify(remainder, &sig);
        }
    }
});
