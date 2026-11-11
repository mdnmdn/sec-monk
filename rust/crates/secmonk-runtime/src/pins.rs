//! Compiled-in uv pins: version and sha256 of each release archive. `[uv]` in the config may override them;
//! a different version requires config checksums (fail closed).
//!
//! Source: the `.sha256` files of the uv 0.13.7 GitHub release, copied on 2026-11-11 (same values as
//! `rust/sec-monk.toml`). Check them against `sha256.sum` and GitHub attestations before a release build
//! (**verify**).

/// Pinned uv version.
pub const UV_VERSION: &str = "0.13.7";

/// Default download URL template.
pub const UV_URL: &str = "https://github.com/astral-sh/uv/releases/download/{version}/{asset}";

/// target triple -> sha256 of `uv-<triple>.(tar.gz|zip)` for [`UV_VERSION`].
pub const UV_SHA256: [(&str, &str); 8] = [
    (
        "aarch64-apple-darwin",
        "81b811b57e4624df7ed3aac148e0359100d9962f3d9dce00aec533dc2e086731",
    ),
    (
        "x86_64-apple-darwin",
        "20c47e4c1f630b8abaff8c291fa9b9aa300fef92c4fbff95adf198b55287cda7",
    ),
    (
        "x86_64-unknown-linux-gnu",
        "c5221ff41b7892bfc223543883600125f6a47fe845093e0f5bdff4f359196d83",
    ),
    (
        "aarch64-unknown-linux-gnu",
        "71279f8d3c67241e807b9d8db872d1bf541579fb9f08b7d1eb1682196d1e57dc",
    ),
    (
        "x86_64-unknown-linux-musl",
        "287491da03f2a785c70fa75b13e1f849918c2f2b5415fe84876b8214eeb792f9",
    ),
    (
        "aarch64-unknown-linux-musl",
        "2d3ec076a0c4c0e8250bb6418c44080828b544f1a3be0b6e46adf9fb6923de45",
    ),
    (
        "x86_64-pc-windows-msvc",
        "0cdc5b38fe5a8168ed6a25814f5ba43c21d313dd3187314fccb37b7cec46e021",
    ),
    (
        "aarch64-pc-windows-msvc",
        "505d9e65e7692bac3ddf98c66754aa26c5050c409c184af30a881a0a72cc85e3",
    ),
];

/// The compiled-in pin of `triple` for [`UV_VERSION`].
pub fn builtin_sha256(triple: &str) -> Option<&'static str> {
    UV_SHA256
        .iter()
        .find(|(t, _)| *t == triple)
        .map(|(_, s)| *s)
}
