//! `secmonk-headless`: the same command line as `secmonk-server` (kept for the Linux dev workflow and the Node UI
//! harness; see `secmonk_host::cli`).

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(secmonk_host::headless::run(&args));
}
