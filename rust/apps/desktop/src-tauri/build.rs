// Tauri's build step (icons, capabilities, context) only runs with the `ui` feature: a headless Linux build has no
// tauri-build in its dependency graph at all.
fn main() {
    if std::env::var_os("CARGO_FEATURE_UI").is_some() {
        generate_tauri_context();
    }
}

#[cfg(feature = "ui")]
fn generate_tauri_context() {
    tauri_build::build();
}

#[cfg(not(feature = "ui"))]
fn generate_tauri_context() {}
