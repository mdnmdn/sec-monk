//! Getting the archive: download (rustls) or copy of a local file, hashed while written to
//! `tools/downloads/<asset>.part`, size-capped; then compared with the pin.

use std::path::{Path, PathBuf};

use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::{RuntimeError, RuntimeResult};

/// Largest archive accepted.
pub const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

/// sha256 hex of a file.
pub fn sha256_file(path: &Path) -> RuntimeResult<String> {
    let mut f = std::fs::File::open(path).map_err(|e| RuntimeError::io(path, e))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut f, &mut buf).map_err(|e| RuntimeError::io(path, e))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Write `url` (or copy `local`) to `part`, returning the sha256 of the bytes.
pub async fn fetch_to(
    url: &str,
    local: Option<&Path>,
    part: &Path,
    offline: bool,
) -> RuntimeResult<String> {
    let _ = tokio::fs::remove_file(part).await;
    let mut out = tokio::fs::File::create(part)
        .await
        .map_err(|e| RuntimeError::io(part, e))?;
    let mut h = Sha256::new();
    let mut total: u64 = 0;
    let mut push = |chunk: &[u8], total: &mut u64| -> RuntimeResult<()> {
        *total += chunk.len() as u64;
        if *total > MAX_ARCHIVE_BYTES {
            return Err(RuntimeError::BadArchive(format!(
                "archive larger than {MAX_ARCHIVE_BYTES} bytes"
            )));
        }
        h.update(chunk);
        Ok(())
    };
    if let Some(src) = local {
        let mut f = tokio::fs::File::open(src)
            .await
            .map_err(|e| RuntimeError::io(src, e))?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut f, &mut buf)
                .await
                .map_err(|e| RuntimeError::io(src, e))?;
            if n == 0 {
                break;
            }
            push(&buf[..n], &mut total)?;
            out.write_all(&buf[..n])
                .await
                .map_err(|e| RuntimeError::io(part, e))?;
        }
    } else {
        if offline {
            return Err(RuntimeError::Offline(format!(
                "uv is not installed and no [uv] archive is set ({url})"
            )));
        }
        let err = |m: String| RuntimeError::Download {
            url: url.to_string(),
            message: m,
        };
        let client = reqwest::Client::builder()
            .user_agent(concat!("secmonk-desktop/", env!("CARGO_PKG_VERSION")))
            .https_only(true)
            .build()
            .map_err(|e| err(e.to_string()))?;
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| err(e.to_string()))?;
        let resp = resp.error_for_status().map_err(|e| err(e.to_string()))?;
        let mut body = resp.bytes_stream();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|e| err(e.to_string()))?;
            push(&chunk, &mut total)?;
            out.write_all(&chunk)
                .await
                .map_err(|e| RuntimeError::io(part, e))?;
        }
    }
    out.flush().await.map_err(|e| RuntimeError::io(part, e))?;
    Ok(hex::encode(h.finalize()))
}

/// The URL of an asset from the template (`{version}`, `{asset}`).
pub fn asset_url(template: &str, version: &str, asset: &str) -> String {
    template
        .replace("{version}", version)
        .replace("{asset}", asset)
}

/// `tools/downloads/<asset>.part`.
pub fn part_path(downloads: &Path, asset: &str) -> PathBuf {
    downloads.join(format!("{asset}.part"))
}
