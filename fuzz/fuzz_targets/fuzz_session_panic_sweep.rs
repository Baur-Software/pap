#![no_main]
use libfuzzer_sys::fuzz_target;
use pap_did::SessionKeypair;

// Panic-sweep only: SessionKeypair::generate() uses OsRng, so key space
// is not fuzzed and crash reproducibility depends on OS RNG state.
// Renamed from fuzz_session_sign_verify to set accurate expectations —
// crashes from this target cannot be minimized or reproduced.
fuzz_target!(|message: &[u8]| {
    let sk = SessionKeypair::generate();
    let sig = sk.sign(message);
    assert!(sk.verify(message, &sig).is_ok());
});
