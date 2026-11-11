//! Safe extraction of a uv release archive: only the expected file names (`uv`, `uvx` / `uv.exe`,
//! `uvx.exe`), regular files only, no path from the archive is ever used (file names only, and entries with
//! `..` or absolute paths are refused), size-capped, written 0700 with `create_new` into a fresh directory.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path};

use crate::platform::{ArchiveKind, uv_binaries};
use crate::{RuntimeError, RuntimeResult};

/// Largest binary accepted from the archive.
pub const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
/// Most entries looked at (a uv archive has a handful).
pub const MAX_ENTRIES: usize = 64;

/// Extract the uv binaries of `archive` into `dest` (an empty directory). Returns the extracted names.
pub fn extract_uv(archive: &Path, kind: ArchiveKind, dest: &Path) -> RuntimeResult<Vec<String>> {
    let wanted = uv_binaries(kind);
    let mut got: Vec<String> = Vec::new();
    let f = File::open(archive).map_err(|e| RuntimeError::io(archive, e))?;
    match kind {
        ArchiveKind::TarGz => {
            let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(f));
            let entries = ar
                .entries()
                .map_err(|e| RuntimeError::BadArchive(e.to_string()))?;
            for (i, e) in entries.enumerate() {
                if i >= MAX_ENTRIES {
                    return Err(RuntimeError::BadArchive("too many entries".into()));
                }
                let mut e = e.map_err(|e| RuntimeError::BadArchive(e.to_string()))?;
                let path = e
                    .path()
                    .map_err(|e| RuntimeError::BadArchive(e.to_string()))?
                    .into_owned();
                let Some(name) = accept(&path, wanted)? else {
                    continue;
                };
                if !e.header().entry_type().is_file() {
                    continue;
                }
                if e.size() > MAX_ENTRY_BYTES {
                    return Err(RuntimeError::BadArchive(format!(
                        "{name} is larger than {MAX_ENTRY_BYTES} bytes"
                    )));
                }
                write_binary(&mut e, &dest.join(&name), &mut got, name)?;
            }
        }
        ArchiveKind::Zip => {
            let mut z =
                zip::ZipArchive::new(f).map_err(|e| RuntimeError::BadArchive(e.to_string()))?;
            if z.len() > MAX_ENTRIES {
                return Err(RuntimeError::BadArchive("too many entries".into()));
            }
            for i in 0..z.len() {
                let mut e = z
                    .by_index(i)
                    .map_err(|e| RuntimeError::BadArchive(e.to_string()))?;
                let path = std::path::PathBuf::from(
                    e.name()
                        .map_err(|e| RuntimeError::BadArchive(e.to_string()))?
                        .as_ref(),
                );
                let Some(name) = accept(&path, wanted)? else {
                    continue;
                };
                if !e.is_file() {
                    continue;
                }
                if e.size() > MAX_ENTRY_BYTES {
                    return Err(RuntimeError::BadArchive(format!(
                        "{name} is larger than {MAX_ENTRY_BYTES} bytes"
                    )));
                }
                write_binary(&mut e, &dest.join(&name), &mut got, name)?;
            }
        }
    }
    let main = wanted[0];
    if !got.iter().any(|n| n == main) {
        return Err(RuntimeError::BadArchive(format!(
            "{main} not found in the archive"
        )));
    }
    Ok(got)
}

/// The file name to extract, or `None` to skip. Refuses absolute paths and `..` anywhere.
fn accept(path: &Path, wanted: &[&str]) -> RuntimeResult<Option<String>> {
    let mut depth = 0;
    for c in path.components() {
        match c {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            _ => {
                return Err(RuntimeError::BadArchive(format!(
                    "unsafe path {}",
                    path.display()
                )));
            }
        }
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // uv-<triple>/uv in tarballs, uv.exe at the root of zips
    Ok((depth <= 2 && wanted.contains(&name.as_str())).then_some(name))
}

fn write_binary(
    r: &mut dyn Read,
    to: &Path,
    got: &mut Vec<String>,
    name: String,
) -> RuntimeResult<()> {
    if got.contains(&name) {
        return Err(RuntimeError::BadArchive(format!("{name} appears twice")));
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o700);
    }
    let mut out = o.open(to).map_err(|e| RuntimeError::io(to, e))?;
    let n = std::io::copy(&mut r.take(MAX_ENTRY_BYTES + 1), &mut out)
        .map_err(|e| RuntimeError::io(to, e))?;
    if n > MAX_ENTRY_BYTES {
        return Err(RuntimeError::BadArchive(format!(
            "{name} is larger than {MAX_ENTRY_BYTES} bytes"
        )));
    }
    out.flush().map_err(|e| RuntimeError::io(to, e))?;
    got.push(name);
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A tar.gz with raw (unchecked) entry names.
    pub(crate) fn targz(entries: &[(&str, &[u8], tar::EntryType)]) -> Vec<u8> {
        let mut b = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (name, data, ty) in entries {
            let mut h = tar::Header::new_gnu();
            {
                let raw = &mut h.as_old_mut().name;
                raw.fill(0);
                raw[..name.len()].copy_from_slice(name.as_bytes());
            }
            h.set_entry_type(*ty);
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            if *ty == tar::EntryType::Symlink {
                h.set_link_name("outside-target").unwrap();
            }
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn keeps_only_the_binaries() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("uv.tar.gz");
        std::fs::write(
            &a,
            targz(&[
                ("uv-x/uv", b"UV", tar::EntryType::Regular),
                ("uv-x/uvx", b"UVX", tar::EntryType::Regular),
                ("uv-x/README", b"no", tar::EntryType::Regular),
                ("uv-x/a/b/uv", b"deep", tar::EntryType::Regular),
            ]),
        )
        .unwrap();
        let dest = d.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        let mut got = extract_uv(&a, ArchiveKind::TarGz, &dest).unwrap();
        got.sort();
        assert_eq!(got, vec!["uv", "uvx"]);
        assert_eq!(std::fs::read(dest.join("uv")).unwrap(), b"UV");
        assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(dest.join("uv"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn refuses_path_escapes() {
        let d = tempfile::tempdir().unwrap();
        for evil in ["../uv", "uv-x/../../uv", "/tmp/uv"] {
            let a = d.path().join("evil.tar.gz");
            std::fs::write(&a, targz(&[(evil, b"X", tar::EntryType::Regular)])).unwrap();
            let dest = d.path().join(format!("out{}", evil.len()));
            std::fs::create_dir(&dest).unwrap();
            let err = extract_uv(&a, ArchiveKind::TarGz, &dest).unwrap_err();
            assert!(matches!(err, RuntimeError::BadArchive(_)), "{evil}: {err}");
            assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 0);
        }
        assert!(!d.path().join("uv").exists());
    }

    #[test]
    fn skips_links_and_requires_uv() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("link.tar.gz");
        std::fs::write(&a, targz(&[("uv-x/uv", b"", tar::EntryType::Symlink)])).unwrap();
        let dest = d.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        assert!(matches!(
            extract_uv(&a, ArchiveKind::TarGz, &dest),
            Err(RuntimeError::BadArchive(_))
        ));
        assert!(std::fs::symlink_metadata(dest.join("uv")).is_err());
    }

    #[test]
    fn zip_flat_layout() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("uv.zip");
        {
            let mut z = zip::ZipWriter::new(File::create(&a).unwrap());
            let o = zip::write::SimpleFileOptions::default();
            z.start_file("uv.exe", o).unwrap();
            z.write_all(b"MZ").unwrap();
            z.start_file("uvw.exe", o).unwrap();
            z.write_all(b"MZ").unwrap();
            z.start_file("../uvx.exe", o).unwrap();
            z.write_all(b"MZ").unwrap();
            z.finish().unwrap();
        }
        let dest = d.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        assert!(matches!(
            extract_uv(&a, ArchiveKind::Zip, &dest),
            Err(RuntimeError::BadArchive(_))
        ));
        assert!(!d.path().join("uvx.exe").exists());
    }
}
