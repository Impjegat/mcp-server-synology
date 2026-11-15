use std::process::Command;

/// The commit this app is built from: the version "Update Broker" brings the broker to.
/// `BROKER_COMMIT` in the environment overrides it; with neither, the app has no update
/// to offer and says so.
fn broker_commit() -> String {
    if let Ok(given) = std::env::var("BROKER_COMMIT") {
        return given.trim().to_string();
    }
    Command::new("git")
        // The repository may sit on a share that git does not take to be the user's own.
        .args(["-c", "safe.directory=*", "rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default()
}

fn main() {
    println!("cargo:rerun-if-env-changed=BROKER_COMMIT");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/logs/HEAD");
    println!("cargo:rustc-env=BROKER_COMMIT={}", broker_commit());

    // Every command the app's own view may call is listed here, so each needs an
    // explicit permission in capabilities/default.json. The view that shows the
    // broker's page is a remote page and has no capability at all: it can call none
    // of them.
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(&[
            "get_status",
            "start_broker",
            "stop_broker",
            "open_broker",
            "place_page",
            "hide_page",
            "trust_certificate",
            "prepare_update",
        ])),
    )
    .expect("failed to run the Tauri build script");
}
