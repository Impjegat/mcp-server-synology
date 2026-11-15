//! What the app's own view can ask the app to do.
//!
//! The window holds two views: the app's own (the title bar, the card, the sidebar),
//! labelled `main`, and beside it the broker's page, labelled `broker`. Each command is
//! also listed in build.rs and granted by capabilities/default.json, so only the `main`
//! view can call it. Each checks that itself as well: the broker's page is a remote page
//! and must never be able to start or stop anything.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use serde::Deserialize;
use tauri::webview::WebviewBuilder;
use tauri::{
    AppHandle, Emitter, LogicalPosition, LogicalSize, Manager, Rect, State, Url, Webview, WebviewUrl,
};
use zeroize::Zeroizing;

use crate::launch::{self, Owned, UpdateError};
use crate::state::{AppState, Phase, Stage, Status, BROKER_COMMIT};
use crate::{monitor, tray, trust};

/// The only places on the broker's page the app opens. Anything else is refused.
const PAGES: [&str; 3] = ["/", "/log", "/settings"];

/// The label of the view that shows the broker's page.
const PAGE_LABEL: &str = "broker";

/// What that view calls itself. The broker reads it to know its pages are shown in the
/// app: they then leave out their own navigation and ask for the passkey by themselves.
/// It changes how a page looks and nothing the broker allows.
const PAGE_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
    (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0 SynologyBrokerApp/1";

/// One view is made at a time, however many places it is asked for at once.
static PAGE_LOCK: Mutex<()> = Mutex::new(());

/// The view is kept, blank and out of sight, when the broker stops (see `retire_page`),
/// and the next time the page is shown it is pointed at the broker again.
static PAGE_RETIRED: AtomicBool = AtomicBool::new(false);

const BLANK: &str = "about:blank";

/// Take the broker's page away when the broker stops: hide its view and blank it.
///
/// The view is not closed. A page that is asking for a passkey has a Windows prompt open,
/// and closing the view while that prompt is up froze the whole app until the prompt was
/// dismissed (seen with a debug build on Windows 11). Going to a blank page ends the
/// request without that, and the same view serves the next start.
fn retire_page(page: &Webview) {
    PAGE_RETIRED.store(true, Ordering::SeqCst);
    let _ = page.hide();
    if let Ok(blank) = Url::parse(BLANK) {
        let _ = page.navigate(blank);
    }
}

/// The view a command was called from must be the app's own. Not the window: the window
/// holds the broker's page as well, and what is asked is which of the two is asking.
fn require_main(webview: &Webview) -> Result<(), String> {
    if webview.label() == "main" {
        Ok(())
    } else {
        Err("Not allowed from this view.".to_string())
    }
}

fn publish(app: &AppHandle) {
    let state = app.state::<AppState>();
    let status = state.status();
    tray::update(app, status.phase == Phase::Running, status.attention.as_ref());
    // To the app's own view only: not to the view that shows the broker's page.
    let _ = app.emit_to("main", "broker-status", status);
}

#[tauri::command]
pub fn get_status(webview: Webview, state: State<'_, AppState>) -> Result<Status, String> {
    require_main(&webview)?;
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
    webview: Webview,
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    require_main(&webview)?;
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
        if let Some(page) = app.get_webview(PAGE_LABEL) {
            retire_page(&page);
        }
    }
    publish(app);
    result
}

#[tauri::command]
pub fn stop_broker(webview: Webview, app: AppHandle) -> Result<(), String> {
    require_main(&webview)?;
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
pub fn prepare_update(webview: Webview, app: AppHandle) -> Result<(), String> {
    require_main(&webview)?;
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
pub async fn trust_certificate(webview: Webview, app: AppHandle) -> Result<(), String> {
    require_main(&webview)?;
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

/// Where the app's own view wants the broker's page: a box inside the window, in the
/// view's own (logical) pixels.
#[derive(Debug, Deserialize)]
pub struct Bounds {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

impl Bounds {
    /// A real box: finite, inside the window's corner, and neither empty nor absurd.
    fn is_sane(&self) -> bool {
        [self.x, self.y, self.width, self.height].iter().all(|value| value.is_finite())
            && self.x >= 0.0
            && self.y >= 0.0
            && (1.0..=20_000.0).contains(&self.width)
            && (1.0..=20_000.0).contains(&self.height)
    }

    fn rect(&self) -> Rect {
        Rect {
            position: LogicalPosition::new(self.x, self.y).into(),
            size: LogicalSize::new(self.width, self.height).into(),
        }
    }
}

/// Show the broker's page in `bounds`, making its view first if there is none.
///
/// The view loads a remote page and has no capability: it cannot call anything in this
/// app, and it cannot leave the broker's address. It has its own browser data, apart
/// from the app's own view, so that its engine is a separate one, and it is only ever
/// made after Windows came to trust the broker's certificate, so it never holds an
/// older answer about that.
///
/// A view is a browser engine and takes its trust from Windows' own store (the
/// `ca_file` does not count: a view cannot use it). Until Windows trusts the broker's
/// certificate the page would not load, so nothing is made and the app's own view
/// offers to trust it instead.
pub fn show_page(app: &AppHandle, bounds: &Bounds, path: &str) -> Result<(), String> {
    if !bounds.is_sane() {
        return Err("The page cannot be shown there.".to_string());
    }
    let status = app.state::<AppState>().status();
    if status.phase != Phase::Running {
        return Err("The broker is not running.".to_string());
    }
    if status.window_untrusted {
        return Err("Windows does not trust the broker's certificate yet.".to_string());
    }
    let _one_at_a_time = PAGE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(page) = app.get_webview(PAGE_LABEL) {
        if PAGE_RETIRED.swap(false, Ordering::SeqCst) {
            // Left blank when the broker stopped: point it at the broker again.
            page.navigate(broker_page(app, path)?).map_err(|error| error.to_string())?;
        }
        page.set_bounds(bounds.rect()).map_err(|error| error.to_string())?;
        page.show().map_err(|error| error.to_string())?;
        let _ = page.set_focus();
        return Ok(());
    }

    let target = broker_page(app, path)?;
    let origin = target.origin();
    let window = app.get_window("main").ok_or("The window is gone.")?;
    let on_route = app.clone();
    let on_title = app.clone();
    let mut builder = WebviewBuilder::new(PAGE_LABEL, WebviewUrl::External(target))
        .user_agent(PAGE_USER_AGENT)
        // It cannot leave the broker's address. What it moves to is told to the app's own
        // view, which only uses it to know which page is shown.
        .on_navigation(move |next| {
            if next.as_str() == BLANK {
                return true;
            }
            if next.origin() != origin {
                return false;
            }
            let _ = on_route.emit_to("main", "page-route", next.path().to_string());
            true
        })
        .on_document_title_changed(move |_, title| {
            let _ = on_title.emit_to("main", "page-title", title);
        });
    if let Some(dir) = crate::page_data_dir() {
        builder = builder.data_directory(dir);
    }
    let page = window
        .add_child(builder, LogicalPosition::new(bounds.x, bounds.y), LogicalSize::new(bounds.width, bounds.height))
        .map_err(|error| error.to_string())?;
    // The passkey is asked for by the page, and Windows asks only a window that has focus.
    let _ = page.set_focus();
    Ok(())
}

#[tauri::command]
pub async fn place_page(
    webview: Webview,
    app: AppHandle,
    bounds: Bounds,
    path: Option<String>,
) -> Result<(), String> {
    require_main(&webview)?;
    show_page(&app, &bounds, path.as_deref().unwrap_or("/"))
}

/// Take the broker's page out of sight: for when the app's own view is not showing it.
#[tauri::command]
pub async fn hide_page(webview: Webview, app: AppHandle) -> Result<(), String> {
    require_main(&webview)?;
    if let Some(page) = app.get_webview(PAGE_LABEL) {
        let _ = page.hide();
    }
    Ok(())
}

/// Move the broker's page to another page of the broker's.
#[tauri::command]
pub async fn open_broker(
    webview: Webview,
    app: AppHandle,
    path: Option<String>,
) -> Result<(), String> {
    require_main(&webview)?;
    let target = broker_page(&app, path.as_deref().unwrap_or("/"))?;
    let page = app.get_webview(PAGE_LABEL).ok_or("The broker's page is not shown.")?;
    page.navigate(target).map_err(|error| error.to_string())
}

/// Ask the app's own view to show a page, from the tray: the window comes forward, and
/// the view moves the broker's page if it is showing it.
pub fn spawn_open(app: &AppHandle, path: &'static str) {
    crate::show_main(app);
    let _ = app.emit_to("main", "open-page", path);
}

/// Whether closing the window now would end a broker (see
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

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds(x: f64, y: f64, width: f64, height: f64) -> Bounds {
        Bounds { x, y, width, height }
    }

    #[test]
    fn only_a_real_box_inside_the_window_is_placed() {
        assert!(bounds(228.0, 37.0, 772.0, 600.0).is_sane());
        assert!(bounds(0.0, 0.0, 1.0, 1.0).is_sane());
        assert!(!bounds(-1.0, 0.0, 100.0, 100.0).is_sane());
        assert!(!bounds(0.0, -0.5, 100.0, 100.0).is_sane());
        assert!(!bounds(0.0, 0.0, 0.0, 100.0).is_sane());
        assert!(!bounds(0.0, 0.0, 100.0, 0.5).is_sane());
        assert!(!bounds(0.0, 0.0, 20_001.0, 100.0).is_sane());
        assert!(!bounds(f64::NAN, 0.0, 100.0, 100.0).is_sane());
        assert!(!bounds(0.0, 0.0, f64::INFINITY, 100.0).is_sane());
    }

    #[test]
    fn the_app_opens_three_pages_and_the_page_calls_itself_by_the_name_the_broker_reads() {
        assert_eq!(PAGES, ["/", "/log", "/settings"]);
        // The broker's `APP_USER_AGENT` (src/private_auth/app.py): desktop/tests/release.test.js
        // checks the two agree.
        assert!(PAGE_USER_AGENT.contains("SynologyBrokerApp/"));
    }
}
