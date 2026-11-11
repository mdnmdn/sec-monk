//! uv release asset selection: target triple from OS, architecture and (Linux) libc.

use std::path::Path;

/// C library of a Linux host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Libc {
    /// glibc.
    Gnu,
    /// musl (Alpine).
    Musl,
}

/// Archive format of a release asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    /// `.tar.gz` (`uv-<triple>/uv`).
    TarGz,
    /// `.zip` (flat, `uv.exe` at the root).
    Zip,
}

/// A uv release asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UvAsset {
    /// Target triple.
    pub triple: &'static str,
    /// File name (`uv-aarch64-apple-darwin.tar.gz`).
    pub name: String,
    /// Format.
    pub kind: ArchiveKind,
}

/// The release triple for `os` / `arch` (`std::env::consts` values) and, on Linux, `libc`.
pub fn target_triple(os: &str, arch: &str, libc: Libc) -> Option<&'static str> {
    Some(match (os, arch, libc) {
        ("macos", "aarch64", _) => "aarch64-apple-darwin",
        ("macos", "x86_64", _) => "x86_64-apple-darwin",
        ("linux", "x86_64", Libc::Gnu) => "x86_64-unknown-linux-gnu",
        ("linux", "x86_64", Libc::Musl) => "x86_64-unknown-linux-musl",
        ("linux", "aarch64", Libc::Gnu) => "aarch64-unknown-linux-gnu",
        ("linux", "aarch64", Libc::Musl) => "aarch64-unknown-linux-musl",
        ("windows", "x86_64", _) => "x86_64-pc-windows-msvc",
        ("windows", "aarch64", _) => "aarch64-pc-windows-msvc",
        _ => return None,
    })
}

/// The asset for a triple.
pub fn asset_for(triple: &'static str) -> UvAsset {
    let kind = if triple.contains("windows") {
        ArchiveKind::Zip
    } else {
        ArchiveKind::TarGz
    };
    let ext = match kind {
        ArchiveKind::Zip => "zip",
        ArchiveKind::TarGz => "tar.gz",
    };
    UvAsset {
        triple,
        name: format!("uv-{triple}.{ext}"),
        kind,
    }
}

/// Follow the symlinks of `p` inside the fake root `root` (absolute targets are re-rooted), at most 8 hops.
/// The final path, if it exists.
fn resolve_in_root(root: &Path, p: &Path) -> Option<std::path::PathBuf> {
    let mut cur = p.to_path_buf();
    for _ in 0..8 {
        let md = std::fs::symlink_metadata(&cur).ok()?;
        if !md.file_type().is_symlink() {
            return Some(cur);
        }
        let t = std::fs::read_link(&cur).ok()?;
        cur = if t.is_absolute() {
            root.join(t.strip_prefix("/").ok()?)
        } else {
            cur.parent()?.join(t)
        };
    }
    None
}

/// Whether a glibc loader / `libc.so.6` entry is the real glibc: it resolves to an existing file whose name is
/// not musl's loader or gcompat's shim (Alpine's `gcompat` installs `ld-linux-*.so.2` as a link to
/// `ld-musl-*.so.1`, and `libgcompat.so.0`).
fn is_real_glibc(root: &Path, entry: &Path) -> bool {
    let Some(target) = resolve_in_root(root, entry) else {
        return false;
    };
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    target.is_file() && !name.starts_with("ld-musl-") && !name.starts_with("libgcompat")
}

/// Detect the libc of a Linux system rooted at `root` (`/` in production). musl when a musl loader exists and no
/// *real* glibc loader or `libc.so.6` does; a glibc name that resolves to musl's loader or to gcompat (Alpine with
/// `gcompat`) does not count, because gcompat cannot run the gnu uv build. A binary built for musl always answers
/// musl.
pub fn detect_libc(root: &Path) -> Libc {
    if cfg!(target_env = "musl") {
        return Libc::Musl;
    }
    let entries = |dir: &str, prefix: &str| -> Vec<std::path::PathBuf> {
        std::fs::read_dir(root.join(dir))
            .map(|rd| {
                rd.flatten()
                    .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
                    .map(|e| e.path())
                    .collect()
            })
            .unwrap_or_default()
    };
    let musl = !entries("lib", "ld-musl-").is_empty();
    let gcompat = !entries("lib", "libgcompat").is_empty();
    let glibc = [
        ("lib", "ld-linux"),
        ("lib64", "ld-linux"),
        ("lib", "libc.so.6"),
        ("lib/x86_64-linux-gnu", "libc.so.6"),
        ("lib/aarch64-linux-gnu", "libc.so.6"),
        ("usr/lib", "libc.so.6"),
    ]
    .iter()
    .flat_map(|(d, p)| entries(d, p))
    .any(|e| {
        is_real_glibc(root, &e)
            // gcompat with a loader that is a plain file (not a link): still not glibc unless libc.so.6 is real
            && !(gcompat && musl && e.file_name().is_some_and(|n| n.to_string_lossy().starts_with("ld-linux")))
    });
    if musl && !glibc {
        Libc::Musl
    } else {
        Libc::Gnu
    }
}

/// The asset of the running host.
pub fn host_asset() -> Option<UvAsset> {
    let libc = if std::env::consts::OS == "linux" {
        detect_libc(Path::new("/"))
    } else {
        Libc::Gnu
    };
    target_triple(std::env::consts::OS, std::env::consts::ARCH, libc).map(asset_for)
}

/// File names kept from the archive.
pub fn uv_binaries(kind: ArchiveKind) -> &'static [&'static str] {
    match kind {
        ArchiveKind::TarGz => &["uv", "uvx"],
        ArchiveKind::Zip => &["uv.exe", "uvx.exe"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pinned_target_has_an_asset() {
        let combos = [
            (
                "macos",
                "aarch64",
                Libc::Gnu,
                "uv-aarch64-apple-darwin.tar.gz",
            ),
            (
                "macos",
                "x86_64",
                Libc::Musl,
                "uv-x86_64-apple-darwin.tar.gz",
            ),
            (
                "linux",
                "x86_64",
                Libc::Gnu,
                "uv-x86_64-unknown-linux-gnu.tar.gz",
            ),
            (
                "linux",
                "x86_64",
                Libc::Musl,
                "uv-x86_64-unknown-linux-musl.tar.gz",
            ),
            (
                "linux",
                "aarch64",
                Libc::Gnu,
                "uv-aarch64-unknown-linux-gnu.tar.gz",
            ),
            (
                "linux",
                "aarch64",
                Libc::Musl,
                "uv-aarch64-unknown-linux-musl.tar.gz",
            ),
            (
                "windows",
                "x86_64",
                Libc::Gnu,
                "uv-x86_64-pc-windows-msvc.zip",
            ),
            (
                "windows",
                "aarch64",
                Libc::Gnu,
                "uv-aarch64-pc-windows-msvc.zip",
            ),
        ];
        for (os, arch, libc, name) in combos {
            let t = target_triple(os, arch, libc).unwrap();
            assert_eq!(asset_for(t).name, name);
            assert!(crate::pins::builtin_sha256(t).is_some(), "{t}");
        }
        assert_eq!(target_triple("freebsd", "x86_64", Libc::Gnu), None);
        assert_eq!(target_triple("linux", "riscv64", Libc::Gnu), None);
        assert_eq!(asset_for("x86_64-pc-windows-msvc").kind, ArchiveKind::Zip);
    }

    #[test]
    fn libc_detection_on_fake_roots() {
        if cfg!(target_env = "musl") {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let alpine = d.path().join("alpine");
        std::fs::create_dir_all(alpine.join("lib")).unwrap();
        std::fs::write(alpine.join("lib/ld-musl-x86_64.so.1"), b"").unwrap();
        assert_eq!(detect_libc(&alpine), Libc::Musl);
        let debian = d.path().join("debian");
        std::fs::create_dir_all(debian.join("lib64")).unwrap();
        std::fs::write(debian.join("lib64/ld-linux-x86-64.so.2"), b"").unwrap();
        assert_eq!(detect_libc(&debian), Libc::Gnu);
        // both loaders as real files (musl-tools installed on Debian): glibc wins
        std::fs::create_dir_all(debian.join("lib")).unwrap();
        std::fs::write(debian.join("lib/ld-musl-x86_64.so.1"), b"").unwrap();
        assert_eq!(detect_libc(&debian), Libc::Gnu);
        assert_eq!(detect_libc(&d.path().join("empty")), Libc::Gnu);
    }

    #[cfg(unix)]
    #[test]
    fn alpine_with_gcompat_is_musl() {
        // regression: gcompat's ld-linux name made Alpine look like glibc, so the gnu uv build was chosen
        if cfg!(target_env = "musl") {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let alpine = d.path().join("alpine");
        std::fs::create_dir_all(alpine.join("lib")).unwrap();
        std::fs::create_dir_all(alpine.join("lib64")).unwrap();
        std::fs::write(alpine.join("lib/ld-musl-x86_64.so.1"), b"").unwrap();
        std::fs::write(alpine.join("lib/libgcompat.so.0"), b"").unwrap();
        // gcompat: absolute and relative links to musl's loader
        std::os::unix::fs::symlink(
            "/lib/ld-musl-x86_64.so.1",
            alpine.join("lib/ld-linux-x86-64.so.2"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../lib/ld-musl-x86_64.so.1",
            alpine.join("lib64/ld-linux-x86-64.so.2"),
        )
        .unwrap();
        assert_eq!(detect_libc(&alpine), Libc::Musl);
        // a dangling glibc link does not count either
        std::os::unix::fs::symlink("/nowhere/libc.so.6", alpine.join("lib/libc.so.6")).unwrap();
        assert_eq!(detect_libc(&alpine), Libc::Musl);
        // a real glibc next to musl (glibc installed for real): gnu
        let both = d.path().join("both");
        std::fs::create_dir_all(both.join("lib/x86_64-linux-gnu")).unwrap();
        std::fs::write(both.join("lib/ld-musl-x86_64.so.1"), b"").unwrap();
        std::fs::write(both.join("lib/x86_64-linux-gnu/libc.so.6"), b"").unwrap();
        assert_eq!(detect_libc(&both), Libc::Gnu);
    }
}
