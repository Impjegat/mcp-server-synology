//! What the local control window can ask the app to do.
//!
//! Each command is also listed in build.rs and granted by capabilities/default.json,
//! so only the `main` window can call it. Each checks that itself as well: the
//! broker's own window is a remote page and must never be able to start or stop
//! anything.

use std::time::Instant;

use tauri::{AppHandle, Emitter, Manager, State, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use zeroize::Zeroizing;

use crate::launch;
use crate::state::{AppState, Phase, Status};
use crate::tray;

/// The only places on the broker's page the app opens. Anything else is refused.
const PAGES: [&str; 4] = ["/", "/login-all", "/log", "/settings"];

fn require_main(window: &WebviewWindow) -> Result<(), String> {
    if window.label() == "main" {
        Ok(())
    } else {
        Err("Not allowed from this window.".to_string())
    }
}

fn publish(app: &AppHandle) {
    let state = app.state::<AppState>();
    let status = state.status();
    tray::update(app, status.phase == Phase::Running, status.attention.as_ref());
    let _ = app.emit("broker-status", status);
}

#[tauri::command]
pub fn get_status(window: WebviewWindow, state: State<'_, AppState>) -> Result<Status, String> {
    require_main(&window)?;
    Ok(state.status())
}

/// Start the broker as its own Windows account. The password is wiped as soon as
/// Windows has used it.
#[tauri::command]
pub async fn start_broker(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    require_main(&window)?;
    let password = Zeroizing::new(password);
    if let Some(error) = &state.config_error {
        return Err(error.clone());
    }
    if password.is_empty() {
        return Err("Enter the password for the broker's Windows account.".to_string());
    }
    {
        let mut inner = state.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(inner.phase, Phase::Starting | Phase::Running) {
            return Err("The broker is already running.".to_string());
        }
        inner.phase = Phase::Starting;
        inner.message = "Starting the broker...".to_string();
        inner.starting_since = Some(Instant::now());
        inner.misses = 0;
        inner.attention = None;
    }
    publish(&app);

    let config = state.config.clone();
    let launched = tauri::async_runtime::spawn_blocking(move || {
        launch::spawn(
            &config.account,
            &password,
            &config.start_command,
            config.stop_broker_on_quit,
        )
    })
    .await
    .map_err(|error| format!("The start did not finish: {error}"))?;

    let outcome = {
        let mut inner = state.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match launched {
            Ok(owned) => {
                inner.owned = Some(owned);
                Ok(())
            }
            Err(message) => {
                inner.phase = Phase::Error;
                inner.message = message.clone();
                inner.starting_since = None;
                Err(message)
            }
        }
    };
    publish(&app);
    outcome
}

/// End a broker this app started. See `Owned::terminate` for what that does to its
/// NAS sessions.
pub fn stop(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    let result = {
        let mut inner = state.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match inner.owned.take() {
            None if inner.phase == Phase::Running => Err(
                "This broker was not started by the app, so the app cannot stop it.".to_string(),
            ),
            None => Ok(()),
            Some(owned) => {
                let ended = owned.terminate();
                if ended.is_ok() {
                    inner.phase = Phase::Stopped;
                    inner.message = "The broker was stopped.".to_string();
                    inner.attention = None;
                    inner.alerts.reset();
                } else {
                    inner.owned = Some(owned);
                }
                ended
            }
        }
    };
    publish(app);
    result
}

#[tauri::command]
pub fn stop_broker(window: WebviewWindow, app: AppHandle) -> Result<(), String> {
    require_main(&window)?;
    stop(&app)
}

pub fn spawn_stop(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = stop(&app);
    });
}

/// Show the broker's page in its own window. That window loads a remote page and has
/// no capability: it cannot call anything in this app, and it cannot leave the
/// broker's address.
pub async fn open(app: &AppHandle, path: &str) -> Result<(), String> {
    if !PAGES.contains(&path) {
        return Err("That page is not one the app opens.".to_string());
    }
    let state = app.state::<AppState>();
    let target = Url::parse(&format!("{}{}", state.config.broker_url, path))
        .map_err(|error| format!("The broker's address is not valid: {error}"))?;
    let origin = target.origin();

    if let Some(existing) = app.get_webview_window("broker") {
        existing.navigate(target).map_err(|error| error.to_string())?;
        let _ = existing.show();
        let _ = existing.set_focus();
        return Ok(());
    }
    let mut builder = WebviewWindowBuilder::new(app, "broker", WebviewUrl::External(target))
        .title("Synology broker")
        .inner_size(1000.0, 780.0)
        .center()
        .on_navigation(move |next| next.origin() == origin);
    if let Some(dir) = crate::data_dir() {
        builder = builder.data_directory(dir);
    }
    builder.build().map_err(|error| error.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn open_broker(
    window: WebviewWindow,
    app: AppHandle,
    path: Option<String>,
) -> Result<(), String> {
    require_main(&window)?;
    open(&app, path.as_deref().unwrap_or("/")).await
}

pub fn spawn_open(app: &AppHandle, path: &'static str) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = open(&app, path).await;
    });
}

pub fn quit(app: &AppHandle) {
    app.exit(0);
}

#[tauri::command]
pub fn quit_app(window: WebviewWindow, app: AppHandle) -> Result<(), String> {
    require_main(&window)?;
    quit(&app);
    Ok(())
}
