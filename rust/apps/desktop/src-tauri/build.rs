// Tauri's build step (icons, capabilities, context) only runs with the `ui` feature: a headless Linux build has no
// tauri-build in its dependency graph at all.
fn main() {
    if std::env::var_os("CARGO_FEATURE_UI").is_some() {
        generate_tauri_context();
    }
}

// The app's one IPC command gets the permissions `allow-secmonk-api` / `deny-secmonk-api`; the capability
// `capabilities/main.json` grants the first to the `main` window and nothing else.
#[cfg(feature = "ui")]
fn generate_tauri_context() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&["secmonk_api"])),
    )
    .expect("failed to run the Tauri build step");
}

#[cfg(not(feature = "ui"))]
fn generate_tauri_context() {}
