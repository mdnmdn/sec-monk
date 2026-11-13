//! `secmonk-server`: the server mode (API and UI over HTTP(S) with API-key authentication) and its admin commands
//! (`apikey`, `config show`); see `secmonk_host::cli`.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(secmonk_host::cli::main(&args));
}
