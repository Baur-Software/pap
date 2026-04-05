#![no_main]
use ed25519_dalek::Signature;
use libfuzzer_sys::fuzz_target;
use pap_did::{did_to_public_key_bytes, verify_key_from_did, DidDocument, PrincipalKeypair};

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 {
        return;
    }
    let seed: [u8; 32] = data[..32].try_into().unwrap();
    let remainder = &data[32..];
    let garbage_str = std::str::from_utf8(remainder).unwrap_or("");
    let _ = did_to_public_key_bytes(garbage_str);
    let _ = verify_key_from_did(garbage_str);
    let _ = DidDocument::from_json(garbage_str);
    if let Ok(kp) = PrincipalKeypair::from_bytes(&seed) {
        let _ = kp.did();
        let _ = kp.sign(remainder);
        if remainder.len() >= 64 {
            let sig_slice: [u8; 64] = remainder[..64].try_into().unwrap();
            if let Ok(sig) = Signature::from_slice(&sig_slice) {
                let _ = kp.verify(remainder, &sig);
            }
        }
    }
});
