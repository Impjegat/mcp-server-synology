fn main() {
    // Every command the local control window may call is listed here, so each needs
    // an explicit permission in capabilities/default.json. The broker's own window
    // is a remote page and has no capability at all: it can call none of them.
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(&[
            "get_status",
            "start_broker",
            "stop_broker",
            "open_broker",
            "quit_app",
        ])),
    )
    .expect("failed to run the Tauri build script");
}
