//! `secmonk-wire/1`, the module protocol (`secmonk-proto`).
//!
//! - [`message`]: the envelope (`hello`, `req`, `res`, `err`, `event`, `end`, `progress`, `cancel`, `notify`);
//! - [`error`]: wire error codes and the `{code, error, hint}` body;
//! - [`methods`]: method names of the catalog (`rust/contracts/catalog/module-methods.json`);
//! - [`manifest`]: the module manifest (`secmonk-module/1`);
//! - [`codec`] (feature `codec`, default): the frame codec, 4-byte big-endian length + one JSON object.
//!
//! Spec: `rust/_docs/tech/contracts.md` (a) and (b); schemas: `rust/contracts/schemas/wire/`, `module/`.
//! No I/O and no runtime: the codec works on byte buffers (`tokio_util::codec`), the caller owns the stream.

#[cfg(feature = "codec")]
pub mod codec;
pub mod error;
pub mod manifest;
pub mod message;
pub mod methods;

pub use error::{ErrorCode, WireError};
pub use manifest::Manifest;
pub use message::{
    Cancel, CollectorInfo, DbReadGrant, End, ErrorMsg, Event, Grants, Hello, Limits, LogParams,
    Message, Notify, Progress, Provides, Request, Response, Role, SessionInfo, SourceInfo,
};

/// Protocol version string this crate speaks (`hello.protocol`).
pub const PROTOCOL: &str = "secmonk-wire/1.0";
/// Protocol family in manifests (`manifest.protocol`).
pub const PROTOCOL_FAMILY: &str = "secmonk-wire/1";
/// Major version; a peer with another major is refused.
pub const PROTOCOL_MAJOR: u32 = 1;
/// Default `max_frame` announced in `hello` (16 MiB).
pub const DEFAULT_MAX_FRAME: usize = 16 * 1024 * 1024;
/// Hard cap on any frame, whatever a peer announces (64 MiB).
pub const HARD_MAX_FRAME: usize = 64 * 1024 * 1024;
/// Smallest `max_frame` a peer may announce (64 KiB, schema minimum).
pub const MIN_MAX_FRAME: usize = 64 * 1024;
/// Largest request id (JSON-safe integer, 2^53 - 1).
pub const MAX_ID: u64 = 9_007_199_254_740_991;

/// Parse `secmonk-wire/<major>.<minor>` into `(major, minor)`.
pub fn parse_protocol(s: &str) -> Option<(u32, u32)> {
    let v = s.strip_prefix("secmonk-wire/")?;
    let (maj, min) = v.split_once('.')?;
    if maj.is_empty() || min.is_empty() || !maj.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !min.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((maj.parse().ok()?, min.parse().ok()?))
}

/// Whether a peer's `hello.protocol` is compatible (same major; minors are additive).
pub fn protocol_compatible(s: &str) -> bool {
    matches!(parse_protocol(s), Some((PROTOCOL_MAJOR, _)))
}

/// The frame limit both sides use: the smaller of the two announced values, clamped to
/// [`MIN_MAX_FRAME`]..=[`HARD_MAX_FRAME`].
pub fn negotiated_max_frame(ours: usize, theirs: usize) -> usize {
    ours.min(theirs).clamp(MIN_MAX_FRAME, HARD_MAX_FRAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_versions() {
        assert_eq!(parse_protocol("secmonk-wire/1.0"), Some((1, 0)));
        assert_eq!(parse_protocol("secmonk-wire/1.12"), Some((1, 12)));
        assert!(protocol_compatible("secmonk-wire/1.3"));
        assert!(!protocol_compatible("secmonk-wire/2.0"));
        assert!(!protocol_compatible("secmonk-wire/1"));
        assert!(!protocol_compatible("secmonk-wire/+1.0"));
        assert!(!protocol_compatible("other/1.0"));
    }

    #[test]
    fn frame_limit_negotiation() {
        assert_eq!(
            negotiated_max_frame(DEFAULT_MAX_FRAME, HARD_MAX_FRAME),
            DEFAULT_MAX_FRAME
        );
        assert_eq!(negotiated_max_frame(usize::MAX, usize::MAX), HARD_MAX_FRAME);
        assert_eq!(negotiated_max_frame(DEFAULT_MAX_FRAME, 10), MIN_MAX_FRAME);
    }
}
