//! Integrity of the Python module project: `lock_sha256` (the project's `uv.lock`) and `tree_sha256` (the module
//! sources), compared with `[modules.pins]` in `trust = "pinned"` mode (configuration.md § Module integrity).
//!
//! **Tree hash** (`secmonk-tree/1`): the files of the tree are `pyproject.toml` and every regular file below
//! `src/`, except directories named in [`EXCLUDED_DIRS`] and files named in [`EXCLUDED_FILES`] or ending in
//! `.pyc` / `.pyo`. Manifests (`modules/*.toml`) are outside the tree: they carry the pins themselves. For each
//! file, sorted by its relative path (`/` separators, byte order), one line `<sha256 of the content>  <path>\n`
//! (the `sha256sum` format); `tree_sha256` is the sha256 of the concatenated lines. A symlink anywhere in the tree
//! is an error (it could point anywhere); so is a tree of more than [`MAX_FILES`] files or a file above
//! [`MAX_FILE_BYTES`]. The same algorithm is `rust/python/scripts/pins.py` (cross-checked by a shared test vector).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{RuntimeError, RuntimeResult};
use secmonk_config::{ModulePin, TrustMode};

/// Directory names skipped at any depth.
pub const EXCLUDED_DIRS: [&str; 8] = [
    "__pycache__",
    ".venv",
    ".git",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    "node_modules",
];

/// File names skipped (besides `*.pyc`, `*.pyo`).
pub const EXCLUDED_FILES: [&str; 2] = [".DS_Store", "Thumbs.db"];

/// Most files hashed.
pub const MAX_FILES: usize = 50_000;

/// Largest file hashed.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The digests of a module project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeDigest {
    /// sha256 of `<project>/uv.lock`.
    pub lock_sha256: String,
    /// `secmonk-tree/1` hash of the sources.
    pub tree_sha256: String,
    /// Files in the tree hash.
    pub files: usize,
}

fn hex_sha256_reader(path: &Path) -> RuntimeResult<String> {
    let f = std::fs::File::open(path).map_err(|e| RuntimeError::io(path, e))?;
    let md = f.metadata().map_err(|e| RuntimeError::io(path, e))?;
    if !md.is_file() {
        return Err(RuntimeError::Integrity(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if md.len() > MAX_FILE_BYTES {
        return Err(RuntimeError::Integrity(format!(
            "{} is larger than {MAX_FILE_BYTES} bytes",
            path.display()
        )));
    }
    let mut h = Sha256::new();
    let mut r = f.take(MAX_FILE_BYTES);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf).map_err(|e| RuntimeError::io(path, e))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn excluded_file(name: &str) -> bool {
    EXCLUDED_FILES.contains(&name) || name.ends_with(".pyc") || name.ends_with(".pyo")
}

fn walk(
    root: &Path,
    rel: &str,
    dir: &Path,
    out: &mut BTreeMap<String, String>,
) -> RuntimeResult<()> {
    let rd = std::fs::read_dir(dir).map_err(|e| RuntimeError::io(dir, e))?;
    for e in rd {
        let e = e.map_err(|e| RuntimeError::io(dir, e))?;
        let name = e.file_name();
        let name = name.to_str().ok_or_else(|| {
            RuntimeError::Integrity(format!("non UTF-8 file name in {}", dir.display()))
        })?;
        let p = e.path();
        let ft = e.file_type().map_err(|e| RuntimeError::io(&p, e))?;
        let r = format!("{rel}/{name}");
        if ft.is_symlink() {
            return Err(RuntimeError::Integrity(format!(
                "symlink in the module tree: {r}"
            )));
        }
        if ft.is_dir() {
            if !EXCLUDED_DIRS.contains(&name) {
                walk(root, &r, &p, out)?;
            }
        } else if ft.is_file() {
            if !excluded_file(name) {
                if out.len() >= MAX_FILES {
                    return Err(RuntimeError::Integrity(format!(
                        "more than {MAX_FILES} files in {}",
                        root.display()
                    )));
                }
                out.insert(r, hex_sha256_reader(&p)?);
            }
        } else {
            return Err(RuntimeError::Integrity(format!(
                "not a regular file in the module tree: {r}"
            )));
        }
    }
    Ok(())
}

/// The `secmonk-tree/1` hash of `project` and the number of files in it (module docs above).
pub fn tree_sha256(project: &Path) -> RuntimeResult<(String, usize)> {
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    let py = project.join("pyproject.toml");
    let md = std::fs::symlink_metadata(&py).map_err(|e| RuntimeError::io(&py, e))?;
    if !md.is_file() {
        return Err(RuntimeError::Integrity(format!(
            "{} is not a regular file",
            py.display()
        )));
    }
    files.insert("pyproject.toml".into(), hex_sha256_reader(&py)?);
    let src = project.join("src");
    match std::fs::symlink_metadata(&src) {
        Ok(m) if m.is_dir() => walk(project, "src", &src, &mut files)?,
        Ok(_) => {
            return Err(RuntimeError::Integrity(format!(
                "{} is not a directory",
                src.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(RuntimeError::io(&src, e)),
    }
    let mut h = Sha256::new();
    for (path, sum) in &files {
        h.update(format!("{sum}  {path}\n").as_bytes());
    }
    Ok((hex::encode(h.finalize()), files.len()))
}

/// Both digests of `project` (no comparison).
pub fn module_digest(project: &Path) -> RuntimeResult<TreeDigest> {
    let lock_sha256 = hex_sha256_reader(&project.join("uv.lock"))?;
    let (tree_sha256, files) = tree_sha256(project)?;
    Ok(TreeDigest {
        lock_sha256,
        tree_sha256,
        files,
    })
}

fn compare(module: &str, what: &str, pin: Option<&String>, actual: &str) -> RuntimeResult<()> {
    match pin {
        None => Err(RuntimeError::PinMismatch {
            module: module.into(),
            what: what.into(),
            expected: "(no pin)".into(),
            actual: actual.into(),
        }),
        Some(p) if !p.eq_ignore_ascii_case(actual) => Err(RuntimeError::PinMismatch {
            module: module.into(),
            what: what.into(),
            expected: p.to_ascii_lowercase(),
            actual: actual.into(),
        }),
        Some(_) => Ok(()),
    }
}

/// Hash the module project on disk and, in `pinned` mode, compare with the pin of `module`: a missing pin, a
/// missing hash in it or a different hash is [`RuntimeError::PinMismatch`]. In `dev` mode nothing is compared;
/// the digest is returned so the caller can record it. Call it before every module start.
pub fn verify_module_tree(
    project: &Path,
    module: &str,
    pin: Option<&ModulePin>,
    trust: TrustMode,
) -> RuntimeResult<TreeDigest> {
    let d = module_digest(project)?;
    if trust == TrustMode::Pinned {
        compare(
            module,
            "lock_sha256",
            pin.and_then(|p| p.lock_sha256.as_ref()),
            &d.lock_sha256,
        )?;
        compare(
            module,
            "tree_sha256",
            pin.and_then(|p| p.tree_sha256.as_ref()),
            &d.tree_sha256,
        )?;
    }
    Ok(d)
}

/// [`verify_module_tree`] against every pin in `pins` (the enabled modules sharing `project`). Pinned mode with
/// no pin at all is refused.
pub fn verify_project_pins(
    project: &Path,
    pins: &BTreeMap<String, ModulePin>,
    trust: TrustMode,
) -> RuntimeResult<TreeDigest> {
    let d = module_digest(project)?;
    if trust == TrustMode::Pinned {
        if pins.is_empty() {
            return Err(RuntimeError::PinMismatch {
                module: "*".into(),
                what: "[modules.pins]".into(),
                expected: "(no pin)".into(),
                actual: d.tree_sha256,
            });
        }
        for (name, pin) in pins {
            compare(
                name,
                "lock_sha256",
                pin.lock_sha256.as_ref(),
                &d.lock_sha256,
            )?;
            compare(
                name,
                "tree_sha256",
                pin.tree_sha256.as_ref(),
                &d.tree_sha256,
            )?;
        }
    }
    Ok(d)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The shared test vector (`rust/python/tests/test_pins.py` builds the same tree).
    pub(crate) fn vector_tree(root: &Path) {
        let w = |rel: &str, data: &[u8]| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, data).unwrap();
        };
        w("pyproject.toml", b"[project]\nname = \"x\"\n");
        w("uv.lock", b"version = 1\n");
        w("src/pkg/__init__.py", b"");
        w("src/pkg/mod.py", b"print('hi')\n");
        w("src/pkg/B.txt", b"upper sorts first\n");
        w("src/pkg/__pycache__/mod.cpython-313.pyc", b"junk");
        w("src/pkg/old.pyc", b"junk");
        w("src/.DS_Store", b"junk");
        w("modules/py-x.toml", b"not in the tree\n");
        w("tests/test_x.py", b"not in the tree\n");
    }

    pub(crate) const VECTOR_TREE_SHA256: &str =
        "8f3e1c253c9ae6335fc57147a349301c3ab39b49b07a109db6dddbb470fbd7bc";

    #[test]
    fn tree_hash_is_deterministic_and_skips_caches() {
        let d = tempfile::tempdir().unwrap();
        vector_tree(d.path());
        let (h, n) = tree_sha256(d.path()).unwrap();
        assert_eq!(n, 4, "pyproject + 3 sources");
        assert_eq!(h, VECTOR_TREE_SHA256);
        // caches, tests and manifests do not change it; a source does
        std::fs::write(d.path().join("src/pkg/__pycache__/x.pyc"), b"y").unwrap();
        std::fs::write(d.path().join("modules/py-x.toml"), b"changed").unwrap();
        assert_eq!(tree_sha256(d.path()).unwrap().0, h);
        std::fs::write(d.path().join("src/pkg/mod.py"), b"print('evil')\n").unwrap();
        assert_ne!(tree_sha256(d.path()).unwrap().0, h);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_in_tree_is_refused() {
        let d = tempfile::tempdir().unwrap();
        vector_tree(d.path());
        std::os::unix::fs::symlink("/etc/hosts", d.path().join("src/pkg/link.py")).unwrap();
        assert!(matches!(
            tree_sha256(d.path()),
            Err(RuntimeError::Integrity(_))
        ));
    }

    #[test]
    fn pinned_mode_compares_lock_and_tree() {
        let d = tempfile::tempdir().unwrap();
        vector_tree(d.path());
        let dig = module_digest(d.path()).unwrap();
        let good = ModulePin {
            lock_sha256: Some(dig.lock_sha256.clone()),
            tree_sha256: Some(dig.tree_sha256.clone()),
        };
        let p = d.path();
        assert_eq!(
            verify_module_tree(p, "py-x", Some(&good), TrustMode::Pinned).unwrap(),
            dig
        );
        // dev: no pin needed, the digest is still computed
        assert_eq!(
            verify_module_tree(p, "py-x", None, TrustMode::Dev).unwrap(),
            dig
        );
        let err = verify_module_tree(p, "py-x", None, TrustMode::Pinned).unwrap_err();
        assert!(
            matches!(&err, RuntimeError::PinMismatch { what, .. } if what == "lock_sha256"),
            "{err}"
        );
        let bad_lock = ModulePin {
            lock_sha256: Some("0".repeat(64)),
            ..good.clone()
        };
        assert!(matches!(
            verify_module_tree(p, "py-x", Some(&bad_lock), TrustMode::Pinned),
            Err(RuntimeError::PinMismatch { what, .. }) if what == "lock_sha256"
        ));
        // a changed source after pinning is refused
        std::fs::write(p.join("src/pkg/mod.py"), b"print('evil')\n").unwrap();
        assert!(matches!(
            verify_module_tree(p, "py-x", Some(&good), TrustMode::Pinned),
            Err(RuntimeError::PinMismatch { what, .. }) if what == "tree_sha256"
        ));
        let mut pins = BTreeMap::new();
        assert!(verify_project_pins(p, &pins, TrustMode::Pinned).is_err());
        assert!(verify_project_pins(p, &pins, TrustMode::Dev).is_ok());
        pins.insert("py-x".to_string(), good);
        assert!(matches!(
            verify_project_pins(p, &pins, TrustMode::Pinned),
            Err(RuntimeError::PinMismatch { .. })
        ));
    }
}
