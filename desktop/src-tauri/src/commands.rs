//! What the local control window can ask the app to do.
//!
//! Each command is also listed in build.rs and granted by capabilities/default.json,
//! so only the `main` window can call it. Each checks that itself as well: the
//! broker's own window is a remote page and must never be able to start or stop
//! anything.

use std::time::Instant;

use tauri::{AppHandle, Emitter, Manager, State, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use zeroize::Zeroizing;

use crate::launch::{self, Owned, UpdateError};
use crate::state::{AppState, Phase, Stage, Status, BROKER_COMMIT};
use crate::{monitor, tray, trust};

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

/// How an attempt to start the broker ended.
enum Attempt {
    Launched(Owned),
    /// Windows ran nothing as the account (a wrong password, say). A pending update is
    /// still pending.
    NotStarted(String),
    /// The update ran and failed. It is dropped, so the next start is a plain one.
    UpdateFailed(String),
    /// The update, if any, is done; the broker itself could not be started.
    LaunchFailed(String),
}

/// Start the broker as its own Windows account, after bringing its code to this app's
/// version if an update is pending. The password is wiped as soon as Windows has used it.
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
    let updating = {
        let mut inner = state.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(inner.phase, Phase::Starting | Phase::Running) {
            return Err("The broker is already running.".to_string());
        }
        let updating = inner.update_pending;
        inner.phase = Phase::Starting;
        inner.stage = Some(if updating { Stage::Updating } else { Stage::Launching });
        inner.message.clear();
        // The time the broker has to answer is counted from when it is launched, not
        // from here: an update comes first and takes as long as it takes.
        inner.starting_since = None;
        inner.misses = 0;
        inner.attention = None;
        updating
    };
    publish(&app);

    let config = state.config.clone();
    let worker = app.clone();
    let attempt = tauri::async_runtime::spawn_blocking(move || {
        if updating {
            match launch::update(&config.account, &password, &config.broker_checkout, BROKER_COMMIT) {
                Ok(()) => {}
                Err(UpdateError::NotStarted(message)) => return Attempt::NotStarted(message),
                Err(UpdateError::Failed(message)) => return Attempt::UpdateFailed(message),
            }
            {
                let state = worker.state::<AppState>();
                let mut inner = state.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                inner.update_pending = false;
                inner.stage = Some(Stage::Launching);
            }
            publish(&worker);
        }
        match launch::spawn(
            &config.account,
            &password,
            &config.start_command,
            config.stop_broker_on_quit,
        ) {
            Ok(owned) => Attempt::Launched(owned),
            Err(message) if updating => Attempt::LaunchFailed(message),
            Err(message) => Attempt::NotStarted(message),
        }
    })
    .await
    .map_err(|error| format!("The start did not finish: {error}"));

    {
        let mut inner = state.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let failure = match attempt {
            Ok(Attempt::Launched(owned)) => {
                inner.owned = Some(owned);
                inner.stage = Some(Stage::Waiting);
                inner.starting_since = Some(Instant::now());
                None
            }
            Ok(Attempt::NotStarted(message)) | Ok(Attempt::LaunchFailed(message)) => Some(message),
            Ok(Attempt::UpdateFailed(message)) => {
                inner.update_pending = false;
                Some(message)
            }
            Err(message) => Some(message),
        };
        // A failure is told through the status, which the window shows as a notice:
        // answering the command with it as well would show the same sentence twice.
        if let Some(message) = failure {
            inner.phase = Phase::Error;
            inner.stage = None;
            inner.message = message;
            inner.starting_since = None;
        }
    }
    publish(&app);
    Ok(())
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
                    inner.stage = None;
                    inner.message.clear();
                    inner.attention = None;
                    inner.alerts.reset();
                } else {
                    inner.owned = Some(owned);
                }
                ended
            }
        }
    };
    if result.is_ok() {
        // Its page is gone with it.
        if let Some(page) = app.get_webview_window("broker") {
            let _ = page.close();
        }
    }
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

/// Stop the broker and mark the next start as one that first brings the broker's code
/// to this app's version. The password is asked for then, as for any start.
#[tauri::command]
pub fn prepare_update(window: WebviewWindow, app: AppHandle) -> Result<(), String> {
    require_main(&window)?;
    if !launch::commit_ok(BROKER_COMMIT) {
        return Err("This build of the app does not know which broker version to fetch.".to_string());
    }
    let state = app.state::<AppState>();
    {
        let inner = state.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match inner.phase {
            Phase::Starting => return Err("Wait for the broker to finish starting.".to_string()),
            Phase::Running if inner.owned.is_none() => {
                return Err(
                    "This broker was started outside the app. Stop it there, then start it here to update it."
                        .to_string(),
                )
            }
            _ => {}
        }
    }
    stop(&app)?;
    state.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).update_pending = true;
    publish(&app);
    Ok(())
}

/// Offer the `ca_file` certificate to Windows' Root store for this Windows account.
/// Windows asks the person to confirm in a dialog of its own; this returns when they
/// have answered, and then looks at the broker again at once.
#[tauri::command]
pub async fn trust_certificate(window: WebviewWindow, app: AppHandle) -> Result<(), String> {
    require_main(&window)?;
    let der = {
        let state = app.state::<AppState>();
        if !state.status().can_trust {
            return Err("There is no certificate to trust right now.".to_string());
        }
        state.ca_der.clone().ok_or("Set \"ca_file\" in synology-broker-app.json first.")?
    };
    tauri::async_runtime::spawn_blocking(move || trust::add_to_user_roots(&der))
        .await
        .map_err(|error| format!("The request did not finish: {error}"))??;
    monitor::tick(&app).await;
    Ok(())
}

fn broker_page(app: &AppHandle, path: &str) -> Result<Url, String> {
    if !PAGES.contains(&path) {
        return Err("That page is not one the app opens.".to_string());
    }
    let state = app.state::<AppState>();
    Url::parse(&format!("{}{}", state.config.broker_url, path))
        .map_err(|error| format!("The broker's address is not valid: {error}"))
}

/// Show the broker's page in its own window. That window loads a remote page and has
/// no capability: it cannot call anything in this app, and it cannot leave the
/// broker's address.
///
/// A window is a browser engine and takes its trust from Windows' own store (the
/// `ca_file` does not count: a window cannot use it). Until Windows trusts the broker's
/// certificate the page would not load, so nothing is opened and the control window
/// offers to trust it instead.
pub async fn open(app: &AppHandle, path: &str) -> Result<(), String> {
    let target = broker_page(app, path)?;
    let status = app.state::<AppState>().status();
    if status.phase != Phase::Running {
        return Err("The broker is not running.".to_string());
    }
    if status.window_untrusted {
        return Err("Windows does not trust the broker's certificate yet.".to_string());
    }
    let origin = target.origin();

    if let Some(existing) = app.get_webview_window("broker") {
        existing.navigate(target).map_err(|error| error.to_string())?;
        let _ = existing.show();
        let _ = existing.unminimize();
        let _ = existing.set_focus();
        return Ok(());
    }
    let mut builder = WebviewWindowBuilder::new(app, "broker", WebviewUrl::External(target))
        .title("Synology Broker private page")
        .inner_size(1000.0, 780.0)
        .center()
        .on_navigation(move |next| next.origin() == origin);
    // Its own browser data, apart from the control window's: the engine that shows the
    // remote page is then a separate one, and it is always started after Windows came
    // to trust the certificate, so it never holds an older answer about that.
    if let Some(dir) = crate::page_data_dir() {
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

/// Open a page from the tray or after a start. If it cannot be opened, the control
/// window is shown instead: it says why.
pub fn spawn_open(app: &AppHandle, path: &'static str) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if open(&app, path).await.is_err() {
            crate::show_main(&app);
        }
    });
}

/// Whether closing the control window now would end a broker (see
/// `state::close_needs_confirmation`).
pub fn close_needs_confirmation(app: &AppHandle) -> bool {
    let state = app.state::<AppState>();
    let inner = state.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    crate::state::close_needs_confirmation(
        inner.phase,
        inner.owned.is_some(),
        state.config.stop_broker_on_quit,
    )
}
