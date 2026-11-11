//! Reads below a boundary (`base.resolve_within` / `base.read_within`): a scanned tree or a served
//! directory is untrusted, a symlink inside it may point anywhere.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Failure of a bounded read.
#[derive(Debug)]
pub enum WithinError {
    /// The path resolves outside the boundary.
    Escapes(PathBuf),
    /// Not a regular file.
    NotRegular(PathBuf),
    /// Larger than the cap.
    TooLarge(PathBuf, u64),
    /// I/O error.
    Io(std::io::Error),
}

impl std::fmt::Display for WithinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WithinError::Escapes(p) => write!(f, "{} resolves outside the boundary", p.display()),
            WithinError::NotRegular(p) => write!(f, "{} is not a regular file", p.display()),
            WithinError::TooLarge(p, cap) => {
                write!(f, "{} is larger than {cap} bytes", p.display())
            }
            WithinError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WithinError {}

impl From<std::io::Error> for WithinError {
    fn from(e: std::io::Error) -> Self {
        WithinError::Io(e)
    }
}

/// `path` resolved (symlinks followed) and checked to be `boundary` itself or below it.
pub fn resolve_within(path: &Path, boundary: &Path) -> Result<PathBuf, WithinError> {
    let b = boundary.canonicalize()?;
    let r = path.canonicalize()?;
    if r != b && !r.starts_with(&b) {
        return Err(WithinError::Escapes(path.to_path_buf()));
    }
    Ok(r)
}

/// Read a regular file below `boundary` (following only symlinks that stay inside), at most `cap` bytes.
///
/// The file type is checked **before** opening (`symlink_metadata` of the resolved path): opening a FIFO in a
/// scanned tree would block forever, a device could have side effects. The open itself is non-blocking and does
/// not follow a final symlink (POSIX: `O_NONBLOCK | O_NOFOLLOW`), and the handle is checked again (`fstat`: still a
/// regular file, the same inode), so a swap between the check and the open is refused instead of read.
pub fn read_within(path: &Path, boundary: &Path, cap: u64) -> Result<Vec<u8>, WithinError> {
    let r = resolve_within(path, boundary)?;
    let before = std::fs::symlink_metadata(&r)?;
    if !before.is_file() {
        return Err(WithinError::NotRegular(path.to_path_buf()));
    }
    if before.len() > cap {
        return Err(WithinError::TooLarge(path.to_path_buf(), cap));
    }
    let f = open_regular(&r)?;
    let md = f.metadata()?;
    if !md.is_file() || !same_file(&before, &md) {
        return Err(WithinError::NotRegular(path.to_path_buf()));
    }
    if md.len() > cap {
        return Err(WithinError::TooLarge(path.to_path_buf(), cap));
    }
    let mut buf = Vec::with_capacity(md.len() as usize);
    f.take(cap).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Open for reading without blocking on a FIFO and without following a final symlink.
fn open_regular(p: &Path) -> std::io::Result<File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let flags = rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOFOLLOW;
        o.custom_flags(flags.bits() as i32);
    }
    o.open(p)
}

#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_: &std::fs::Metadata, _: &std::fs::Metadata) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_escapes_and_caps() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("a"), b"hello").unwrap();
        std::fs::write(d.path().join("outside"), b"secret").unwrap();
        assert_eq!(read_within(&root.join("a"), &root, 10).unwrap(), b"hello");
        assert!(matches!(
            read_within(&root.join("a"), &root, 3),
            Err(WithinError::TooLarge(..))
        ));
        assert!(matches!(
            read_within(&root.join("../outside"), &root, 10),
            Err(WithinError::Escapes(_))
        ));
        assert!(matches!(
            read_within(&root, &root, 10),
            Err(WithinError::NotRegular(_))
        ));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(d.path().join("outside"), root.join("link")).unwrap();
            assert!(matches!(
                read_within(&root.join("link"), &root, 10),
                Err(WithinError::Escapes(_))
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn fifo_is_refused_without_blocking() {
        // regression: the file was opened before its type was checked, so a FIFO hung the read
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("pipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let (tx, rx) = std::sync::mpsc::channel();
        let (f, root) = (fifo.clone(), d.path().to_path_buf());
        std::thread::spawn(move || {
            let _ = tx.send(read_within(&f, &root, 10));
        });
        let res = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("read_within blocked on a FIFO");
        assert!(matches!(res, Err(WithinError::NotRegular(_))), "{res:?}");
    }
}
