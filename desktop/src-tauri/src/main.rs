// The Synology broker's desktop shell: starts the broker, shows its private pages in the
// same window, and tells you from the tray when a client is waiting.
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
mod trust;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Where the app's own view keeps its browser data. `None` if it cannot be made there,
/// in which case Windows' usual per-user place is used instead.
pub fn data_dir() -> Option<PathBuf> {
    let dir = exe_dir().join("synology-broker-data");
    std::fs::create_dir_all(&dir).ok().map(|_| dir)
}

/// Where the view that shows the broker's page keeps its own (see `commands::show_page`).
pub fn page_data_dir() -> Option<PathBuf> {
    let dir = data_dir()?.join("page");
    std::fs::create_dir_all(&dir).ok().map(|_| dir)
}

pub fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// The CA certificate named by `ca_file`: PEM, or DER if it is not PEM. A relative path
/// is read from the folder the .exe is in. Given back both as the HTTP client takes it
/// and as the bytes Windows' certificate store takes.
fn load_ca(path: &str) -> Result<(reqwest::Certificate, Vec<u8>), String> {
    let path = PathBuf::from(path);
    let path = if path.is_absolute() { path } else { exe_dir().join(path) };
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("ca_file: cannot read {}: {error}", path.display()))?;
    let not_one = || format!("ca_file: {} is not a certificate (PEM or DER)", path.display());
    let der = trust::ca_file_der(&bytes).map_err(|error| match error {
        trust::CaFileError::NotACertificate => not_one(),
        trust::CaFileError::MoreThanOne => format!(
            "ca_file: {} holds more than one certificate or key. It must hold only the CA \
             certificate that signed the broker's.",
            path.display()
        ),
    })?;
    let certificate = reqwest::Certificate::from_der(&der).map_err(|_| not_one())?;
    Ok((certificate, der))
}

/// The broker is on this computer: never through a proxy, and a bounded wait.
fn http_client(
    ca: Option<reqwest::Certificate>,
    check_certificate: bool,
) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .danger_accept_invalid_certs(!check_certificate);
    if let Some(ca) = ca {
        builder = builder.add_root_certificate(ca);
    }
    builder.build().expect("the HTTP client could not be built")
}

/// One confirmation at a time, however often the close button is pressed.
static CONFIRMING: AtomicBool = AtomicBool::new(false);

/// Ask, in a box owned by the app's window, whether to end the broker with the app.
#[cfg(windows)]
fn confirm_close(owner: Option<isize>) -> bool {
    use windows::core::w;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, IDYES, MB_ICONQUESTION, MB_YESNO};

    let owner = owner.map(|raw| HWND(raw as *mut core::ffi::c_void));
    unsafe {
        MessageBoxW(
            owner,
            w!("Stop the broker and close?"),
            w!("Synology Broker"),
            MB_YESNO | MB_ICONQUESTION,
        ) == IDYES
    }
}

fn main() {
    let (config, mut config_error) = match Config::load(&exe_dir()) {
        Ok(config) => (config, None),
        Err(error) => (Config::default(), Some(error)),
    };
    let (ca, ca_der) = match config.ca_file.as_deref().map(load_ca) {
        Some(Ok((ca, der))) => (Some(ca), Some(der)),
        Some(Err(error)) => {
            config_error.get_or_insert(error);
            (None, None)
        }
        None => (None, None),
    };
    let client = http_client(ca, true);
    // What a window sees: Windows' own store, without the `ca_file`.
    let system_client = http_client(None, true);
    // Only for telling "down" from "up, but its certificate is not trusted" (see
    // `monitor::probe`): it reads /healthz and nothing else.
    let diagnostic_client = http_client(None, false);

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_notification::init())
        .manage(AppState::new(
            config,
            config_error,
            client,
            system_client,
            diagnostic_client,
            ca_der,
        ))
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::start_broker,
            commands::stop_broker,
            commands::open_broker,
            commands::place_page,
            commands::hide_page,
            commands::trust_certificate,
            commands::prepare_update,
        ])
        .on_window_event(|window, event| {
            // The window's close button closes the app, and the broker with it
            // if this app started it. That is worth one question: every client would
            // have to be signed in to the NAS again.
            if window.label() != "main" {
                return;
            }
            if let WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle().clone();
                if !commands::close_needs_confirmation(&app) {
                    app.exit(0);
                    return;
                }
                api.prevent_close();
                if CONFIRMING.swap(true, Ordering::SeqCst) {
                    return;
                }
                let owner = window.hwnd().ok().map(|hwnd| hwnd.0 as isize);
                // Not on this thread: the box waits for an answer, and this one runs
                // the windows.
                std::thread::spawn(move || {
                    let close = confirm_close(owner);
                    CONFIRMING.store(false, Ordering::SeqCst);
                    if close {
                        app.exit(0);
                    }
                });
            }
        })
        .setup(|app| {
            let mut builder =
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .title("Synology Broker")
                    // The title bar is the app's own (menu, back and forward, the status dot,
                    // the window buttons), drawn in the page; so Windows draws none.
                    .decorations(false)
                    .inner_size(1000.0, 700.0)
                    .min_inner_size(760.0, 520.0)
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
                // Closing the app ends a broker this app started, if the settings say
                // so. (The job object does it as well if the app is killed.)
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
