//! Reading a feed document as a decompressed, capped, hashed byte stream (debian-tracker; any importer that sniffs
//! its compression): the compression from the magic bytes (gzip, plain; bzip2 and xz refused), the decompressed size
//! capped while reading, a leading UTF-8 BOM skipped (as `json.loads` of bytes), the SHA-256 of the decompressed
//! bytes (BOM included), and the first I/O error kept with its finished text so it, not the parser's, becomes the
//! run's message.

use std::fmt;
use std::io::Read;

use sha2::{Digest, Sha256};

/// An I/O error carrying a finished message (a download failure, a cap): [`io_message`] returns its text as is.
#[derive(Debug)]
pub struct Msg(pub String);

impl fmt::Display for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Msg {}

/// An I/O error whose text is `m` (see [`Msg`]).
pub fn msg_error(m: String) -> std::io::Error {
    std::io::Error::other(Msg(m))
}

/// The input compression, from the magic bytes (`_decompress` of the Python sources).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No known magic bytes.
    Plain,
    /// `1f 8b`.
    Gzip,
    /// `BZh`.
    Bzip2,
    /// `fd 37 7a 58 5a 00`.
    Xz,
}

/// The compression of a document starting with `head` (at least six bytes when there are).
pub fn sniff(head: &[u8]) -> Compression {
    if head.starts_with(b"\x1f\x8b") {
        Compression::Gzip
    } else if head.starts_with(b"BZh") {
        Compression::Bzip2
    } else if head.starts_with(b"\xfd7zXZ\x00") {
        Compression::Xz
    } else {
        Compression::Plain
    }
}

/// The texts of [`open_decoded`]'s refusals.
#[derive(Debug, Clone)]
pub struct Messages {
    /// Source name: `<source>: native importer: bzip2 input is not supported; decompress the file or use gzip`.
    pub source: &'static str,
    /// More than the cap of plain input.
    pub too_large: String,
    /// More than the cap once decompressed (gzip).
    pub too_large_gzip: String,
}

/// A reader that fails with `message` once more than `left` bytes came out of `inner`.
struct Capped<R> {
    inner: R,
    left: u64,
    message: String,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.left {
            return Err(msg_error(self.message.clone()));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// A reader that hashes what passes.
struct Hashing<R> {
    inner: R,
    hash: Sha256,
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hash.update(&buf[..n]);
        Ok(n)
    }
}

/// A reader that drops a leading UTF-8 BOM.
struct SkipBom<R> {
    inner: R,
    head: Option<Vec<u8>>,
    pos: usize,
}

impl<R: Read> Read for SkipBom<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.head.is_none() {
            let mut head = Vec::with_capacity(3);
            let mut b = [0u8; 3];
            while head.len() < 3 {
                let n = self.inner.read(&mut b[..3 - head.len()])?;
                if n == 0 {
                    break;
                }
                head.extend_from_slice(&b[..n]);
            }
            self.pos = if head == b"\xef\xbb\xbf" { 3 } else { 0 };
            self.head = Some(head);
        }
        if let Some(head) = &self.head
            && self.pos < head.len()
        {
            let n = (head.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&head[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

/// The text of an I/O error under the decoder: a [`Msg`] as is; for gzip input Python's `DecompressError` texts;
/// else `OSError: <io text>`.
pub fn io_message(e: &std::io::Error, compression: Compression) -> String {
    if let Some(m) = e.get_ref().and_then(|i| i.downcast_ref::<Msg>()) {
        return m.0.clone();
    }
    if compression == Compression::Gzip {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return "DecompressError: truncated gz data (no end-of-stream marker)".into();
        }
        return format!("DecompressError: corrupt gz data: {e}");
    }
    format!("OSError: {e}")
}

/// The first `n` bytes of `r` (fewer at its end), and `r` with them put back in front.
fn peek<R: Read>(mut r: R, n: usize) -> std::io::Result<(Vec<u8>, impl Read)> {
    let mut head = Vec::with_capacity(n);
    let mut b = vec![0u8; n];
    while head.len() < n {
        match r.read(&mut b[..n - head.len()]) {
            Ok(0) => break,
            Ok(k) => head.extend_from_slice(&b[..k]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok((head.clone(), std::io::Cursor::new(head).chain(r)))
}

/// Lower-case hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A decoded document: read it (the decompressed bytes without a leading BOM), then [`Decoded::sha256`].
pub struct Decoded<'a> {
    reader: SkipBom<Hashing<Box<dyn Read + 'a>>>,
    error: Option<String>,
    compression: Compression,
}

impl fmt::Debug for Decoded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoded")
            .field("compression", &self.compression)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl Decoded<'_> {
    /// The compression found.
    pub fn compression(&self) -> Compression {
        self.compression
    }

    /// The text of the first I/O error seen while reading (a cap, a download failure, corrupt gzip), taken.
    pub fn take_error(&mut self) -> Option<String> {
        self.error.take()
    }

    /// The text of `e`, an error of this reader ([`io_message`]).
    pub fn message(&self, e: &std::io::Error) -> String {
        io_message(e, self.compression)
    }

    /// SHA-256 (lower-case hex) of the decompressed bytes read so far, a leading BOM included.
    pub fn sha256(&self) -> String {
        hex(&self.reader.inner.hash.clone().finalize())
    }
}

impl Read for Decoded<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.reader.read(buf) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Err(e),
            Err(e) => {
                if self.error.is_none() {
                    self.error = Some(io_message(&e, self.compression));
                }
                Err(e)
            }
            ok => ok,
        }
    }
}

/// Open `r` for reading as a decoded document: compression from the first six bytes, at most `cap` decompressed
/// bytes (`messages.too_large` / `too_large_gzip` beyond), bzip2 and xz refused. Gzip: one member, trailing bytes
/// ignored (as zlib in the Python sources).
pub fn open_decoded<'a, R: Read + 'a>(
    r: R,
    cap: u64,
    messages: &Messages,
) -> Result<Decoded<'a>, String> {
    let (head, r) = peek(r, 6).map_err(|e| io_message(&e, Compression::Plain))?;
    let compression = sniff(&head);
    let inner: Box<dyn Read + 'a> = match compression {
        Compression::Plain => Box::new(Capped {
            inner: r,
            left: cap,
            message: messages.too_large.clone(),
        }),
        Compression::Gzip => Box::new(Capped {
            inner: flate2::read::GzDecoder::new(r),
            left: cap,
            message: messages.too_large_gzip.clone(),
        }),
        Compression::Bzip2 | Compression::Xz => {
            let what = if compression == Compression::Bzip2 {
                "bzip2"
            } else {
                "xz"
            };
            return Err(format!(
                "{}: native importer: {what} input is not supported; decompress the file or use gzip",
                messages.source
            ));
        }
    };
    Ok(Decoded {
        reader: SkipBom {
            inner: Hashing {
                inner,
                hash: Sha256::new(),
            },
            head: None,
            pos: 0,
        },
        error: None,
        compression,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn messages() -> Messages {
        Messages {
            source: "x",
            too_large: "plain too large".into(),
            too_large_gzip: "gzip too large".into(),
        }
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn read_all(input: &[u8], cap: u64) -> Result<(Vec<u8>, String, Compression), String> {
        let mut d = open_decoded(input, cap, &messages())?;
        let mut out = Vec::new();
        // in small reads, so the BOM step sees reads shorter than the BOM
        let mut buf = [0u8; 2];
        loop {
            match d.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) => return Err(d.take_error().unwrap_or_else(|| d.message(&e))),
            }
        }
        Ok((out, d.sha256(), d.compression()))
    }

    #[test]
    fn documents_decode_with_bom_hash_and_caps() {
        let doc = b"{\"a\": 1}";
        let (out, plain_hash, c) = read_all(doc, 100).unwrap();
        assert_eq!((out.as_slice(), c), (&doc[..], Compression::Plain));
        assert_eq!(plain_hash, hex(&Sha256::digest(doc)));
        let mut bom = b"\xef\xbb\xbf".to_vec();
        bom.extend_from_slice(doc);
        let (out, bom_hash, _) = read_all(&bom, 100).unwrap();
        assert_eq!(out, doc, "BOM skipped");
        assert_eq!(bom_hash, hex(&Sha256::digest(&bom)), "BOM hashed");
        let (out, gz_hash, c) = read_all(&gz(doc), 100).unwrap();
        assert_eq!((out.as_slice(), c), (&doc[..], Compression::Gzip));
        assert_eq!(gz_hash, plain_hash, "the decompressed bytes are hashed");
        assert_eq!(
            read_all(b"\xef\xbb", 100).unwrap().0,
            b"\xef\xbb",
            "a short input"
        );
        assert_eq!(read_all(doc, 3).unwrap_err(), "plain too large");
        assert_eq!(read_all(&gz(doc), 3).unwrap_err(), "gzip too large");
        let z = gz(doc);
        assert_eq!(
            read_all(&z[..z.len() - 12], 100).unwrap_err(),
            "DecompressError: truncated gz data (no end-of-stream marker)"
        );
        assert_eq!(
            read_all(b"BZh91AY", 100).unwrap_err(),
            "x: native importer: bzip2 input is not supported; decompress the file or use gzip"
        );
        assert_eq!(sniff(b"\xfd7zXZ\x00"), Compression::Xz);
    }

    #[test]
    fn a_finished_message_passes_through() {
        struct Fails;
        impl Read for Fails {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(msg_error("download failed".into()))
            }
        }
        assert_eq!(
            open_decoded(Fails, 10, &messages()).unwrap_err(),
            "download failed"
        );
        let e = std::io::Error::other("boom");
        assert_eq!(io_message(&e, Compression::Plain), "OSError: boom");
    }
}
