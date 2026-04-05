//! Adversarial Ed25519 tests for pap-did.
//!
//! Tests rejection behavior: malleability, bit-flips, cross-key,
//! truncation, small-order points. Complements RFC 8032 positive vectors.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use pap_did::PrincipalKeypair;

#[test]
fn cross_keypair_verify_rejected() {
    let key_a = SigningKey::from_bytes(&[1u8; 32]);
    let key_b = SigningKey::from_bytes(&[2u8; 32]);

    let message = b"cross-key test";
    let sig = key_a.sign(message);

    // Signature from A must not verify under B's public key.
    assert!(
        key_b.verifying_key().verify(message, &sig).is_err(),
        "signature from key A must be rejected by key B"
    );
}

#[test]
fn bit_flip_signature_rejected() {
    let key = SigningKey::from_bytes(&[42u8; 32]);
    let message = b"test message";
    let sig = key.sign(message);

    let mut sig_bytes = sig.to_bytes();
    sig_bytes[0] ^= 1; // flip bit 0 of byte 0

    match Signature::from_slice(&sig_bytes) {
        Ok(flipped_sig) => {
            assert!(
                key.verifying_key().verify(message, &flipped_sig).is_err(),
                "bit-flipped signature must fail verification"
            );
        }
        Err(_) => {
            // Deserialization rejection is also acceptable.
        }
    }
}

#[test]
fn bit_flip_message_rejected() {
    let key = SigningKey::from_bytes(&[42u8; 32]);
    let original = b"test message";
    let sig = key.sign(original);

    // Compute the flipped message programmatically
    let mut flipped = original.to_vec();
    flipped[0] ^= 1; // flip bit 0 of byte 0
    assert!(
        key.verifying_key().verify(&flipped, &sig).is_err(),
        "signature must not verify against bit-flipped message"
    );
}

#[test]
fn malleability_scalar_deserialization_rejected() {
    // Ed25519 curve order L = 2^252 + 27742317777372353535851937790883648493
    // Little-endian bytes per RFC 8032 Section 5.1.
    // https://www.rfc-editor.org/rfc/rfc8032#section-5.1
    const CURVE_ORDER_L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    let key = SigningKey::from_bytes(&[42u8; 32]);
    let sig = key.sign(b"malleability test");
    let sig_bytes = sig.to_bytes();

    // Add L to the S component (bytes [32..64]) with carry propagation.
    let mut malleable = sig_bytes;
    let mut carry: u16 = 0;
    for i in 32..64 {
        let sum = malleable[i] as u16 + CURVE_ORDER_L[i - 32] as u16 + carry;
        malleable[i] = sum as u8;
        carry = sum >> 8;
    }

    // ed25519-dalek may defer scalar canonicality checks to verification time.
    match Signature::from_slice(&malleable) {
        Err(_) => {
            // Rejected at deserialization — ideal.
        }
        Ok(malleable_sig) => {
            assert!(
                key.verifying_key()
                    .verify(b"malleability test", &malleable_sig)
                    .is_err(),
                "S + L must be rejected at verification if not caught at deserialization"
            );
        }
    }
}

#[test]
fn malleability_low_order_r_rejected() {
    // Identity point encoding: [1, 0, 0, ..., 0]
    let mut sig_bytes = [0u8; 64];
    sig_bytes[0] = 1; // R = identity point

    // Arbitrary valid-looking S component
    let s_bytes = [1u8; 32];
    sig_bytes[32..64].copy_from_slice(&s_bytes);

    match Signature::from_slice(&sig_bytes) {
        Ok(sig) => {
            let key = SigningKey::from_bytes(&[42u8; 32]);
            assert!(
                key.verifying_key().verify(b"low-order test", &sig).is_err(),
                "signature with identity-point R must fail verification"
            );
        }
        Err(_) => {
            // Deserialization rejection is also acceptable.
        }
    }
}

#[test]
fn truncated_signature_rejected() {
    let key = SigningKey::from_bytes(&[42u8; 32]);
    let sig = key.sign(b"truncation test");
    let sig_bytes = sig.to_bytes();

    assert!(
        Signature::from_slice(&sig_bytes[..63]).is_err(),
        "63-byte signature must be rejected"
    );
}

#[test]
fn oversized_signature_rejected() {
    let key = SigningKey::from_bytes(&[42u8; 32]);
    let sig = key.sign(b"oversize test");
    let sig_bytes = sig.to_bytes();

    let mut oversized = Vec::from(sig_bytes.as_slice());
    oversized.push(0x00);

    assert!(
        Signature::from_slice(&oversized).is_err(),
        "65-byte signature must be rejected"
    );
}

#[test]
fn zero_signature_rejected() {
    let key = SigningKey::from_bytes(&[42u8; 32]);
    let zero_sig_bytes = [0u8; 64];

    match Signature::from_slice(&zero_sig_bytes) {
        Ok(sig) => {
            assert!(
                key.verifying_key().verify(b"zero sig test", &sig).is_err(),
                "all-zero signature must fail verification"
            );
        }
        Err(_) => {
            // Deserialization rejection is also acceptable.
        }
    }
}

#[test]
fn all_ones_signature_rejected() {
    let all_ones = [0xff; 64];

    // ed25519-dalek may defer S >= L rejection to verification time.
    match Signature::from_slice(&all_ones) {
        Err(_) => {
            // Rejected at deserialization — ideal.
        }
        Ok(sig) => {
            let key = SigningKey::from_bytes(&[42u8; 32]);
            assert!(
                key.verifying_key().verify(b"all-ones test", &sig).is_err(),
                "all-0xff signature must be rejected at verification if not at deserialization"
            );
        }
    }
}

// Verify that PrincipalKeypair wrapper behaves consistently with raw dalek.
#[test]
fn principal_keypair_cross_verify_rejected() {
    let kp_a = PrincipalKeypair::from_bytes(&[1u8; 32]).unwrap();
    let kp_b = PrincipalKeypair::from_bytes(&[2u8; 32]).unwrap();

    let sig = kp_a.sign(b"cross-key via wrapper");
    assert!(
        kp_b.verify(b"cross-key via wrapper", &sig).is_err(),
        "PrincipalKeypair must reject cross-key signatures"
    );
}
