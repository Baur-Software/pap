use crate::ipc::{decrypt, encrypt};

#[test]
fn encrypt_produces_different_output_each_time() {
    let key = [0xABu8; 32];
    let (ct1, n1) = encrypt(b"same plaintext", &key).unwrap();
    let (ct2, n2) = encrypt(b"same plaintext", &key).unwrap();
    // Nonces should differ (random), so ciphertexts differ.
    assert_ne!(n1, n2);
    assert_ne!(ct1, ct2);
}

#[test]
fn roundtrip_preserves_plaintext() {
    let key = [0x01u8; 32];
    let plaintext = b"agent query: find me a flight to NYC";
    let (ciphertext, nonce) = encrypt(plaintext, &key).unwrap();
    let recovered = decrypt(&ciphertext, &key, &nonce).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn wrong_key_fails_authentication() {
    let key1 = [0x01u8; 32];
    let key2 = [0x02u8; 32];
    let (ct, nonce) = encrypt(b"secret", &key1).unwrap();
    assert!(decrypt(&ct, &key2, &nonce).is_err());
}

#[test]
fn tampered_ciphertext_fails_authentication() {
    let key = [0x01u8; 32];
    let (mut ct, nonce) = encrypt(b"secret data", &key).unwrap();
    ct[0] ^= 0xFF; // flip bits in first byte
    assert!(decrypt(&ct, &key, &nonce).is_err());
}

#[test]
fn invalid_nonce_length_returns_error() {
    let key = [0x01u8; 32];
    let (ct, _) = encrypt(b"data", &key).unwrap();
    let bad_nonce = vec![0u8; 8]; // wrong length
    assert!(decrypt(&ct, &key, &bad_nonce).is_err());
}
