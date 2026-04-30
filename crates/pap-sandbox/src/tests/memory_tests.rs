use crate::memory::SecureBuffer;

#[test]
fn new_buffer_has_correct_length() {
    let buf = SecureBuffer::new(vec![1u8; 128]);
    assert_eq!(buf.len(), 128);
    assert!(!buf.is_empty());
}

#[test]
fn empty_buffer_does_not_panic_on_mlock_or_drop() {
    let mut buf = SecureBuffer::new(vec![]);
    let _ = buf.mlock();
    drop(buf);
}

#[test]
fn buffer_contents_readable_before_drop() {
    let data = vec![0x42u8; 16];
    let buf = SecureBuffer::new(data.clone());
    assert_eq!(buf.as_slice(), data.as_slice());
}

#[test]
fn from_string_produces_correct_bytes() {
    let buf = SecureBuffer::from("hello".to_string());
    assert_eq!(buf.as_slice(), b"hello");
}

#[test]
fn mlock_returns_bool_without_panicking() {
    let mut buf = SecureBuffer::new(vec![0u8; 256]);
    // May return false in CI sandbox environments — that's acceptable.
    let _result: bool = buf.mlock();
    // The buffer should remain valid and readable after mlock attempt.
    assert_eq!(buf.len(), 256);
}
