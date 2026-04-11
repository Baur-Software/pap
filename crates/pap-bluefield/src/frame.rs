//! Wire framing for the BlueField RDMA transport.
//!
//! Every PAP protocol message is wrapped in a simple length-prefixed frame:
//!
//! ```text
//! ┌─────────────────────┬────────────────────────────────────────────────┐
//! │  4 bytes (LE u32)   │  N bytes  (UTF-8 JSON ProtocolMessage)         │
//! │  payload length     │                                                │
//! └─────────────────────┴────────────────────────────────────────────────┘
//! ```
//!
//! The maximum payload is [`MAX_PAYLOAD`] bytes (4 MiB), which comfortably
//! exceeds any realistic PAP message size.

use pap_proto::ProtocolMessage;

use crate::error::BluefieldError;

/// Maximum JSON payload size in bytes (4 MiB).
pub const MAX_PAYLOAD: usize = 4 * 1024 * 1024;

/// Total RDMA buffer size: 4-byte header + maximum payload.
pub const FRAME_BUF_SIZE: usize = 4 + MAX_PAYLOAD;

/// Length of the length-prefix header in bytes.
pub const HEADER_LEN: usize = 4;

/// Encode `msg` into `buf` as a length-prefixed frame.
///
/// Returns the total number of bytes written (`4 + payload_len`).
/// `buf` must be at least [`FRAME_BUF_SIZE`] bytes long.
pub fn encode(msg: &ProtocolMessage, buf: &mut [u8]) -> Result<usize, BluefieldError> {
    let json = serde_json::to_vec(msg).map_err(BluefieldError::Json)?;

    if json.len() > MAX_PAYLOAD {
        return Err(BluefieldError::MessageTooLarge(json.len()));
    }

    let payload_len = json.len() as u32;
    buf[..HEADER_LEN].copy_from_slice(&payload_len.to_le_bytes());
    buf[HEADER_LEN..HEADER_LEN + json.len()].copy_from_slice(&json);

    Ok(HEADER_LEN + json.len())
}

/// Decode a [`ProtocolMessage`] from the length-prefixed frame in `buf[..total]`.
///
/// `total` is the number of bytes received from the RDMA work completion.
pub fn decode(buf: &[u8], total: usize) -> Result<ProtocolMessage, BluefieldError> {
    if total < HEADER_LEN {
        return Err(BluefieldError::FrameTruncated(format!(
            "need at least {HEADER_LEN} bytes, got {total}"
        )));
    }

    let payload_len = u32::from_le_bytes(buf[..HEADER_LEN].try_into().expect("4 bytes")) as usize;

    if HEADER_LEN + payload_len > total {
        return Err(BluefieldError::FrameTruncated(format!(
            "declared payload {payload_len} bytes but only {} available",
            total - HEADER_LEN
        )));
    }

    serde_json::from_slice(&buf[HEADER_LEN..HEADER_LEN + payload_len]).map_err(BluefieldError::Json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_session_did_ack() {
        let msg = ProtocolMessage::SessionDidAck;
        let mut buf = vec![0u8; FRAME_BUF_SIZE];
        let n = encode(&msg, &mut buf).unwrap();
        assert!(n > HEADER_LEN);
        let decoded = decode(&buf, n).unwrap();
        assert!(matches!(decoded, ProtocolMessage::SessionDidAck));
    }

    #[test]
    fn round_trip_token_accepted() {
        let msg = ProtocolMessage::TokenAccepted {
            session_id: "sess-bf-01".into(),
            receiver_session_did: "did:key:zBlueField".into(),
            attestation: None,
        };
        let mut buf = vec![0u8; FRAME_BUF_SIZE];
        let n = encode(&msg, &mut buf).unwrap();
        match decode(&buf, n).unwrap() {
            ProtocolMessage::TokenAccepted { session_id, .. } => {
                assert_eq!(session_id, "sess-bf-01");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn round_trip_execution_result() {
        let result = serde_json::json!({
            "@context": "https://schema.org",
            "@type": "SearchResultsPage",
            "name": "BlueField RDMA results"
        });
        let msg = ProtocolMessage::ExecutionResult {
            result: result.clone(),
        };
        let mut buf = vec![0u8; FRAME_BUF_SIZE];
        let n = encode(&msg, &mut buf).unwrap();
        match decode(&buf, n).unwrap() {
            ProtocolMessage::ExecutionResult { result: r } => assert_eq!(r, result),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn decode_truncated_header_returns_error() {
        let buf = [0u8; 3];
        assert!(matches!(
            decode(&buf, 3),
            Err(BluefieldError::FrameTruncated(_))
        ));
    }

    #[test]
    fn decode_truncated_payload_returns_error() {
        let mut buf = vec![0u8; FRAME_BUF_SIZE];
        // Claim 100-byte payload, but only provide the header
        buf[..HEADER_LEN].copy_from_slice(&100u32.to_le_bytes());
        assert!(matches!(
            decode(&buf, HEADER_LEN + 3), // only 3 bytes of payload
            Err(BluefieldError::FrameTruncated(_))
        ));
    }

    #[test]
    fn length_prefix_is_little_endian() {
        let msg = ProtocolMessage::SessionClosed;
        let mut buf = vec![0u8; FRAME_BUF_SIZE];
        let n = encode(&msg, &mut buf).unwrap();
        let stored_len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(HEADER_LEN + stored_len, n);
    }
}
