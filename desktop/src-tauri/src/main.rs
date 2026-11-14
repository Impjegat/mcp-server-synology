// The Synology broker's desktop shell: starts the broker, shows its private login in a
// window of its own, and tells you from the tray when a client is waiting.
//
// It never sees the NAS password, the one-time code or a session: those are typed into
// the broker's own page. The only secret it handles is the broker's Windows account
// password, for the instant it takes to start the broker.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod alerts;
mod commands;
mod config;
mod launch;
mod monitor;
mod state;
mod tray;

use std::path::PathBuf;
use std::time::Duration;

use tauri::{AppHandle, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent};

use config::Config;
use state::AppState;

/// The folder the .exe is in: the settings file and the browser data live beside it, so
/// the whole app is one folder that can be copied or deleted.
fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Where the windows keep their browser data. `None` if it cannot be made there, in
/// which case Windows' usual per-user place is used instead.
pub fn data_dir() -> Option<PathBuf> {
    let dir = exe_dir().join("synology-broker-data");
    std::fs::create_dir_all(&dir).ok().map(|_| dir)
}

pub fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn main() {
    let (config, config_error) = match Config::load(&exe_dir()) {
        Ok(config) => (config, None),
        Err(error) => (Config::default(), Some(error)),
    };
    // The broker is on this computer: never through a proxy, and a bounded wait.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("the HTTP client could not be built");

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_notification::init())
        .manage(AppState::new(config, config_error, client))
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::start_broker,
            commands::stop_broker,
            commands::open_broker,
            commands::quit_app,
        ])
        .on_window_event(|window, event| {
            // Closing the control window hides it to the tray; Quit really quits.
            if window.label() == "main" {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .setup(|app| {
            let mut builder =
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .title("Synology Broker")
                    .inner_size(480.0, 600.0)
                    .resizable(false)
                    .center();
            if let Some(dir) = data_dir() {
                builder = builder.data_directory(dir);
            }
            builder.build()?;
            tray::build(app.handle())?;
            monitor::spawn(app.handle().clone());
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("the app could not be built")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                // Quitting ends a broker this app started, if the settings say so. (The
                // job object does it as well if the app is killed.)
                let state = app.state::<AppState>();
                if state.config.stop_broker_on_quit {
                    let owned = state
                        .inner
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .owned
                        .take();
                    if let Some(owned) = owned {
                        let _ = owned.terminate();
                    }
                }
            }
        });
}
