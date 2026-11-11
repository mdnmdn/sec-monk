// Tauri's convention: no console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    std::process::exit(secmonk_desktop_lib::run());
}
