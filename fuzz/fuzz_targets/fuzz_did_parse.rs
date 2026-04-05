#![no_main]
use libfuzzer_sys::fuzz_target;
use pap_did::{did_to_public_key_bytes, verify_key_from_did};

fuzz_target!(|data: &[u8]| {
    let input = std::str::from_utf8(data).unwrap_or("");
    let _ = did_to_public_key_bytes(input);
    let _ = verify_key_from_did(input);
});
