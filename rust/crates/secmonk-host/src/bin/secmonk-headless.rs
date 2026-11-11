//! `secmonk-headless`: the API and the UI on loopback, without a window (see `secmonk_host::headless`).

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(secmonk_host::headless::run(&args));
}
