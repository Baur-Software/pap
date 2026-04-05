#![no_main]
use libfuzzer_sys::fuzz_target;
use pap_did::DidDocument;

fuzz_target!(|data: &[u8]| {
    let input = std::str::from_utf8(data).unwrap_or("");
    let _ = DidDocument::from_json(input);
});
