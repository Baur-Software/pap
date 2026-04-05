#![no_main]
use libfuzzer_sys::fuzz_target;
use pap_did::SessionKeypair;

// Panic-sweep only: SessionKeypair::generate() uses OsRng, so key space
// is not fuzzed and crash reproducibility depends on OS RNG state.
fuzz_target!(|message: &[u8]| {
    let sk = SessionKeypair::generate();
    let sig = sk.sign(message);
    assert!(sk.verify(message, &sig).is_ok());
});
