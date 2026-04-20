//! Size-capped `Read` adapter for bounded JSON deserialization.
//!
//! [`LimitedRead`] wraps any `Read` implementation and returns an
//! `io::ErrorKind::Other` error ("message too large") once `limit` bytes have
//! been read. When used with [`serde_json::from_reader`] the deserializer fails
//! at that point without ever allocating memory for the rest of the payload —
//! preventing allocation-based DoS via oversized server responses.

use std::io::{self, Read};

/// A `Read` adapter that caps the total number of bytes that can be read.
///
/// Once `limit` bytes have been read from the inner reader, subsequent calls to
/// [`Read::read`] return `Err(io::ErrorKind::Other)` with the message
/// `"message too large"`. This causes [`serde_json::from_reader`] to return an
/// I/O error without reading — or allocating memory for — the rest of the stream.
pub(crate) struct LimitedRead<R: Read> {
    inner: R,
    remaining: usize,
}

impl<R: Read> LimitedRead<R> {
    /// Wrap `inner` and allow at most `limit` bytes to be read.
    pub fn new(inner: R, limit: usize) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<R: Read> Read for LimitedRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "message too large"));
        }
        let to_read = buf.len().min(self.remaining);
        let n = self.inner.read(&mut buf[..to_read])?;
        self.remaining -= n;
        Ok(n)
    }
}

/// Helper: detect whether a `serde_json::Error` originated from `LimitedRead`
/// exceeding its byte cap.
///
/// Returns `true` when the error is an I/O error with kind `Other` — the
/// signature produced by [`LimitedRead`] when the limit is hit.
// Sentinel string written by LimitedRead::read() when the byte cap is hit.
// Using a module-private constant prevents false positives from other
// io::ErrorKind::Other sources that may pass through the same code paths.
pub(crate) const LIMIT_EXCEEDED_MSG: &str = "message too large";

/// Returns `true` when `e` was produced by [`LimitedRead`] exceeding its cap.
///
/// Checks both `ErrorKind::Other` (necessary) *and* the sentinel message
/// (sufficient) to avoid false positives from unrelated `Other` I/O errors.
pub(crate) fn is_limit_exceeded(e: &serde_json::Error) -> bool {
    if !e.is_io() {
        return false;
    }
    if e.io_error_kind() != Some(io::ErrorKind::Other) {
        return false;
    }
    // Downcast to confirm the sentinel string, not just the error kind.
    e.to_string().contains(LIMIT_EXCEEDED_MSG)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::*;

    /// Reading fewer bytes than the limit succeeds normally.
    #[test]
    fn limited_read_under_limit_passes() {
        let data = b"hello";
        let mut reader = LimitedRead::new(Cursor::new(data), 100);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"hello");
    }

    /// After exactly `limit` bytes have been consumed, the adapter returns
    /// `Err(Other, "message too large")` on the next call — the same error
    /// a frame one byte over would produce.  This is intentional: once the
    /// budget is spent, no further reads are allowed regardless of what the
    /// inner reader would return.
    #[test]
    fn limited_read_exactly_at_limit_returns_error_on_next_call() {
        let data = b"hello";
        let limit = data.len(); // exactly 5
        let mut reader = LimitedRead::new(Cursor::new(data), limit);
        let mut out = vec![0u8; limit];
        // Read exactly the limit — succeeds.
        let n = reader.read(&mut out).unwrap();
        assert_eq!(n, limit);
        // Next read: remaining == 0, so we return our own error, not EOF.
        let result = reader.read(&mut out);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Other);
    }

    /// Attempting to read the (limit + 1)th byte returns an `Other` I/O error.
    #[test]
    fn limited_read_over_limit_returns_io_error() {
        let data = b"hello!"; // 6 bytes
        let limit = 5;
        let mut reader = LimitedRead::new(Cursor::new(data), limit);

        let mut out = vec![0u8; 5];
        let n = reader.read(&mut out).unwrap();
        assert_eq!(n, 5);

        // Next read crosses the limit.
        let result = reader.read(&mut out);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err.to_string().contains("message too large"));
    }

    /// `serde_json::from_reader` on an oversized buffer returns an I/O error
    /// that `is_limit_exceeded` recognises.
    #[test]
    fn serde_json_from_reader_oversized_triggers_limit() {
        // Build a JSON string larger than the limit.
        let json = format!(r#"{{"key":"{}"}}"#, "x".repeat(200));
        let limit = 10; // much smaller than the json
        let reader = LimitedRead::new(Cursor::new(json.as_bytes()), limit);
        let result: Result<serde_json::Value, _> = serde_json::from_reader(reader);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            is_limit_exceeded(&err),
            "expected limit-exceeded I/O error, got: {err}"
        );
    }

    /// Well-formed JSON within the limit is deserialized successfully.
    #[test]
    fn serde_json_from_reader_within_limit_succeeds() {
        let json = br#"{"key":"value"}"#;
        let limit = 1024;
        let reader = LimitedRead::new(Cursor::new(json.as_ref()), limit);
        let result: Result<serde_json::Value, _> = serde_json::from_reader(reader);
        assert!(
            result.is_ok(),
            "unexpected error: {:?}",
            result.unwrap_err()
        );
        assert_eq!(result.unwrap()["key"], "value");
    }
}
