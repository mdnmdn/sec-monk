//! Frame codec: 4-byte big-endian unsigned length + payload (one UTF-8 JSON object).
//!
//! [`FrameCodec`] cuts and writes raw frames; [`MessageCodec`] adds [`Message`] (de)serialization. Both are
//! `tokio_util::codec` implementations: they work on byte buffers and never do I/O themselves, so the same
//! code runs over child stdio, `tokio::io::duplex` and, later, SSH or TLS streams.
//!
//! A frame longer than the limit is rejected as soon as its header is read (the body is never buffered);
//! a stream that ends inside a frame is an error, a stream that ends between frames is a clean EOF.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::error::WireError;
use crate::message::Message;
use crate::{DEFAULT_MAX_FRAME, HARD_MAX_FRAME};

/// Size of the length prefix.
pub const HEADER_LEN: usize = 4;

/// Framing failures. All of them are `protocol-error` on the wire (the connection closes).
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The announced length exceeds the limit.
    #[error("frame of {len} bytes exceeds the limit of {max} bytes")]
    Oversized {
        /// Announced length.
        len: usize,
        /// Limit in force.
        max: usize,
    },
    /// The stream ended inside a frame.
    #[error("stream ended inside a frame ({buffered} bytes buffered)")]
    Truncated {
        /// Bytes received of the incomplete frame.
        buffered: usize,
    },
    /// The payload is not a valid message.
    #[error("{0}")]
    Invalid(WireError),
    /// I/O error of the underlying stream.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

impl FrameError {
    /// The error as a wire `protocol-error` (I/O errors included: the peer is gone or broken).
    pub fn to_wire(&self) -> WireError {
        match self {
            FrameError::Invalid(e) => e.clone(),
            other => WireError::protocol(other.to_string()),
        }
    }
}

/// Raw frame codec with a size limit.
#[derive(Debug, Clone, Copy)]
pub struct FrameCodec {
    max: usize,
}

impl Default for FrameCodec {
    fn default() -> Self {
        FrameCodec::new(DEFAULT_MAX_FRAME)
    }
}

impl FrameCodec {
    /// A codec accepting frames up to `max` bytes (clamped to [`HARD_MAX_FRAME`]).
    pub fn new(max: usize) -> FrameCodec {
        FrameCodec {
            max: max.min(HARD_MAX_FRAME),
        }
    }

    /// The limit in force.
    pub fn max_frame(&self) -> usize {
        self.max
    }

    /// Change the limit (after `hello` negotiation), clamped to [`HARD_MAX_FRAME`].
    pub fn set_max_frame(&mut self, max: usize) {
        self.max = max.min(HARD_MAX_FRAME);
    }
}

impl Decoder for FrameCodec {
    type Item = Bytes;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Bytes>, FrameError> {
        if src.len() < HEADER_LEN {
            src.reserve(HEADER_LEN - src.len());
            return Ok(None);
        }
        let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;
        if len > self.max {
            return Err(FrameError::Oversized { len, max: self.max });
        }
        let total = HEADER_LEN + len;
        if src.len() < total {
            // Reserve at most what the announced (already capped) frame needs.
            src.reserve(total - src.len());
            return Ok(None);
        }
        src.advance(HEADER_LEN);
        Ok(Some(src.split_to(len).freeze()))
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Bytes>, FrameError> {
        match self.decode(src)? {
            Some(frame) => Ok(Some(frame)),
            None if src.is_empty() => Ok(None),
            None => Err(FrameError::Truncated {
                buffered: src.len(),
            }),
        }
    }
}

impl Encoder<&[u8]> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<(), FrameError> {
        if item.len() > self.max {
            return Err(FrameError::Oversized {
                len: item.len(),
                max: self.max,
            });
        }
        dst.reserve(HEADER_LEN + item.len());
        dst.put_u32(item.len() as u32);
        dst.put_slice(item);
        Ok(())
    }
}

impl Encoder<Bytes> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), FrameError> {
        Encoder::<&[u8]>::encode(self, &item, dst)
    }
}

/// [`Message`] codec on top of [`FrameCodec`].
#[derive(Debug, Clone, Copy, Default)]
pub struct MessageCodec {
    frames: FrameCodec,
}

impl MessageCodec {
    /// A codec with frame limit `max`.
    pub fn new(max: usize) -> MessageCodec {
        MessageCodec {
            frames: FrameCodec::new(max),
        }
    }

    /// The frame limit in force.
    pub fn max_frame(&self) -> usize {
        self.frames.max_frame()
    }

    /// Change the frame limit.
    pub fn set_max_frame(&mut self, max: usize) {
        self.frames.set_max_frame(max);
    }
}

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Message>, FrameError> {
        match self.frames.decode(src)? {
            Some(f) => Message::from_slice(&f)
                .map(Some)
                .map_err(FrameError::Invalid),
            None => Ok(None),
        }
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Message>, FrameError> {
        match self.frames.decode_eof(src)? {
            Some(f) => Message::from_slice(&f)
                .map(Some)
                .map_err(FrameError::Invalid),
            None => Ok(None),
        }
    }
}

impl Encoder<&Message> for MessageCodec {
    type Error = FrameError;

    fn encode(&mut self, item: &Message, dst: &mut BytesMut) -> Result<(), FrameError> {
        let payload = item.to_vec();
        self.frames.encode(payload.as_slice(), dst)
    }
}

impl Encoder<Message> for MessageCodec {
    type Error = FrameError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), FrameError> {
        Encoder::<&Message>::encode(self, &item, dst)
    }
}

/// Encode one payload as a frame (header + body) into a new buffer.
pub fn encode_frame(payload: &[u8], max: usize) -> Result<Vec<u8>, FrameError> {
    let mut b = BytesMut::new();
    FrameCodec::new(max).encode(payload, &mut b)?;
    Ok(b.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Request, Response};
    use futures_util::{SinkExt, StreamExt};
    use serde_json::json;
    use tokio_util::codec::{FramedRead, FramedWrite};

    fn req(id: u64) -> Message {
        Message::Req(Request {
            id,
            method: "echo.unary".into(),
            params: Some(json!({"n": id})),
            deadline_ms: None,
        })
    }

    /// Deterministic xorshift for fuzz-style tests (no extra dependency).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    #[test]
    fn round_trip_with_random_chunking() {
        let msgs: Vec<Message> = (1..=50).map(req).collect();
        let mut wire = BytesMut::new();
        let mut c = MessageCodec::default();
        for m in &msgs {
            c.encode(m, &mut wire).unwrap();
        }
        let wire = wire.freeze();
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..200 {
            let mut dec = MessageCodec::default();
            let mut buf = BytesMut::new();
            let mut out = Vec::new();
            let mut pos = 0;
            while pos < wire.len() {
                let n = 1 + rng.below(40).min(wire.len() - pos - 1);
                buf.extend_from_slice(&wire[pos..pos + n]);
                pos += n;
                while let Some(m) = dec.decode(&mut buf).unwrap() {
                    out.push(m);
                }
            }
            assert!(dec.decode_eof(&mut buf).unwrap().is_none());
            assert_eq!(out, msgs);
        }
    }

    #[test]
    fn truncated_frames_are_errors_at_eof() {
        let full =
            encode_frame(br#"{"type":"res","id":1,"result":null}"#, DEFAULT_MAX_FRAME).unwrap();
        for cut in 1..full.len() {
            let mut buf = BytesMut::from(&full[..cut]);
            let mut dec = MessageCodec::default();
            assert!(dec.decode(&mut buf).unwrap().is_none(), "cut {cut}");
            match dec.decode_eof(&mut buf) {
                Err(FrameError::Truncated { buffered }) => assert_eq!(buffered, cut),
                other => panic!("cut {cut}: {other:?}"),
            }
        }
        // EOF exactly between frames is clean.
        let mut empty = BytesMut::new();
        assert!(
            MessageCodec::default()
                .decode_eof(&mut empty)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn oversized_frames_are_rejected_from_the_header() {
        let mut dec = FrameCodec::new(1024);
        let mut buf = BytesMut::new();
        buf.put_u32(1025);
        match dec.decode(&mut buf) {
            Err(FrameError::Oversized {
                len: 1025,
                max: 1024,
            }) => {}
            other => panic!("{other:?}"),
        }
        // u32::MAX never allocates and is refused even with the hard cap.
        let mut dec = FrameCodec::new(usize::MAX);
        assert_eq!(dec.max_frame(), HARD_MAX_FRAME);
        let mut buf = BytesMut::from(&u32::MAX.to_be_bytes()[..]);
        assert!(matches!(
            dec.decode(&mut buf),
            Err(FrameError::Oversized { .. })
        ));
        assert!(buf.capacity() < 1024 * 1024);
        // the encoder refuses too
        let mut enc = FrameCodec::new(MIN);
        let mut out = BytesMut::new();
        assert!(enc.encode(&vec![b' '; MIN + 1][..], &mut out).is_err());
        assert!(out.is_empty());
    }
    const MIN: usize = crate::MIN_MAX_FRAME;

    #[test]
    fn invalid_payloads_are_protocol_errors() {
        let cases: [&[u8]; 9] = [
            b"\xff\xfe{}",
            b"not json",
            b"[1,2]",
            b"{}",
            br#"{"type":"bogus","id":1}"#,
            br#"{"type":"req","id":0,"method":"a.b"}"#,
            br#"{"type":"req","id":1,"method":"nodot"}"#,
            br#"{"type":"req","id":1,"method":"a.b","params":[1]}"#,
            br#"{"type":"res","id":1}"#,
        ];
        for payload in cases {
            let mut buf = BytesMut::from(&encode_frame(payload, DEFAULT_MAX_FRAME).unwrap()[..]);
            match MessageCodec::default().decode(&mut buf) {
                Err(FrameError::Invalid(e)) => {
                    assert_eq!(e.code, crate::ErrorCode::ProtocolError, "{payload:?}")
                }
                other => panic!("{:?}: {other:?}", String::from_utf8_lossy(payload)),
            }
        }
    }

    #[test]
    fn random_garbage_never_panics() {
        let mut rng = Rng(42);
        for _ in 0..2000 {
            let n = rng.below(64);
            let mut bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            if rng.below(2) == 0 && bytes.len() >= 4 {
                let len = (bytes.len() - 4) as u32;
                bytes[..4].copy_from_slice(&len.to_be_bytes());
            }
            let mut buf = BytesMut::from(&bytes[..]);
            let mut dec = MessageCodec::new(1 << 20);
            loop {
                match dec.decode(&mut buf) {
                    Ok(Some(_)) => continue,
                    Ok(None) => {
                        let _ = dec.decode_eof(&mut buf);
                        break;
                    }
                    Err(_) => break,
                }
            }
        }
    }

    #[tokio::test]
    async fn framed_stream_over_duplex() {
        let (a, b) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            let mut w = FramedWrite::new(a, MessageCodec::default());
            for i in 1..=20 {
                w.send(Message::Res(Response {
                    id: i,
                    result: json!({"i": i, "pad": "x".repeat(300)}),
                }))
                .await
                .unwrap();
            }
        });
        let mut r = FramedRead::new(b, MessageCodec::default());
        let mut n = 0;
        while let Some(m) = r.next().await {
            n += 1;
            assert_eq!(m.unwrap().id(), Some(n));
        }
        assert_eq!(n, 20);
        writer.await.unwrap();
    }
}
