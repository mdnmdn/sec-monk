//! The headless server: the same command line and server mode as `secmonk-server` ([`crate::cli`]), kept under its
//! old name for the Linux dev workflow and the Node UI harness.
//!
//! ```text
//! secmonk-headless [serve] [--config FILE] [--listen 127.0.0.1:8765] [--set key=value] ...
//! ```
//!
//! Nothing here is specific any more: [`run`] is `cli::main_named("secmonk-headless", ..)`. [`listen_addr`] (a
//! loopback address only) stays for the desktop app's optional dev binding (`[ui] http_listen`).

use std::net::SocketAddr;

pub use crate::serve::DEFAULT_LISTEN;

/// A loopback listen address with a non-zero port (the desktop dev binding has no login).
pub fn listen_addr(value: &str) -> Result<SocketAddr, String> {
    let addr = crate::serve::parse_listen(value)?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "listen address {value:?}: only loopback addresses are accepted here (no login on this binding)"
        ));
    }
    Ok(addr)
}

/// Run the command line; returns the process exit code (0 ok, 1 runtime error, 2 usage).
pub fn run(args: &[String]) -> i32 {
    crate::cli::main_named("secmonk-headless", args)
}
