//! What the app knows about the broker, shared between the window, the tray and the
//! background monitor.

use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;

use crate::alerts::{AlertState, Attention};
use crate::config::Config;
use crate::launch::{self, Owned};
use crate::trust;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Stopped,
    Starting,
    Running,
    Error,
}

/// How far a start has got, for the progress bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    /// Bringing the broker's code to this app's version, before starting it.
    Updating,
    /// Asking Windows to start the broker as its account.
    Launching,
    /// The broker's process exists; waiting for it to answer.
    Waiting,
}

/// How long the broker has to answer after it is started.
pub const START_DEADLINE_SECONDS: u64 = 60;

/// The lowest `level` (what the broker's `/healthz` reports) whose private page has
/// everything this app opens and reads. A broker that reports less, or none, is older.
pub const REQUIRED_LEVEL: u32 = 1;

/// The commit this app was built from: the broker version "Update Broker" fetches.
pub const BROKER_COMMIT: &str = env!("BROKER_COMMIT");

/// Whether a broker that reports `level` is older than this app needs. `None` is a
/// broker whose level could not be read (its certificate did not verify): unknown is
/// not "older".
pub fn is_outdated(level: Option<u32>) -> bool {
    level.is_some_and(|level| level < REQUIRED_LEVEL)
}

/// Whether closing the window should first ask: only when it would end a broker, which
/// is one this app started (and is set to end) that is running or on its way up.
pub fn close_needs_confirmation(phase: Phase, owned: bool, stop_on_quit: bool) -> bool {
    owned && stop_on_quit && matches!(phase, Phase::Starting | Phase::Running)
}

pub struct Inner {
    pub phase: Phase,
    pub stage: Option<Stage>,
    pub message: String,
    /// The broker this app started, if it did. A broker that was already running is not owned.
    pub owned: Option<Owned>,
    pub attention: Option<Attention>,
    pub alerts: AlertState,
    pub starting_since: Option<Instant>,
    /// Consecutive failed health checks while running.
    pub misses: u32,
    /// The broker answers, but only if its certificate is not checked: neither Windows
    /// nor the `ca_file`, if any, trusts the CA that signed it.
    pub cert_untrusted: bool,
    /// Windows' own trust store accepts the broker's certificate. A window (a browser
    /// engine) needs this to open the page at all; the `ca_file` does not count for it.
    pub windows_trusts: bool,
    /// The level the broker reported, when its certificate verified.
    pub level: Option<u32>,
    /// The next start first brings the broker's code to this app's version.
    pub update_pending: bool,
}

pub struct AppState {
    pub config: Config,
    /// Set when the settings file is unusable: the app then refuses to start a broker.
    pub config_error: Option<String>,
    pub inner: Mutex<Inner>,
    /// Checks the broker's certificate against Windows' store and the `ca_file`. The only
    /// client that fetches anything but `/healthz`.
    pub client: reqwest::Client,
    /// Checks it against Windows' store alone: what a window would see.
    pub system_client: reqwest::Client,
    /// Used only to find out whether the broker is up when `client` could not verify its
    /// certificate, so the window can say "running, but not trusted" instead of "down".
    /// It reads `/healthz` and nothing else, and what it reads decides only a message.
    pub diagnostic_client: reqwest::Client,
    /// The `ca_file` certificate as DER: what "Trust certificate" offers to Windows.
    pub ca_der: Option<Vec<u8>>,
}

/// What the window is told. Names and numbers only: never a password.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub phase: Phase,
    pub stage: Option<Stage>,
    pub message: String,
    /// Running, but not started by this app, so this app cannot stop it.
    pub external: bool,
    pub attention: Option<Attention>,
    pub account: String,
    pub start_command: String,
    pub broker_url: String,
    pub config_error: Option<String>,
    /// Running, but nothing trusts the broker's certificate (not even the `ca_file`).
    pub cert_untrusted: bool,
    /// Running, but Windows does not trust the certificate, so a window cannot open the
    /// page. True too when only the `ca_file` makes it verify.
    pub window_untrusted: bool,
    /// The `ca_file` is what verifies the certificate, so it can be offered to Windows.
    pub can_trust: bool,
    /// Running, and older than this app needs.
    pub outdated: bool,
    /// This build knows which version to fetch.
    pub can_update: bool,
    pub update_pending: bool,
}

impl AppState {
    pub fn new(
        config: Config,
        config_error: Option<String>,
        client: reqwest::Client,
        system_client: reqwest::Client,
        diagnostic_client: reqwest::Client,
        ca_der: Option<Vec<u8>>,
    ) -> Self {
        AppState {
            config,
            config_error,
            client,
            system_client,
            diagnostic_client,
            ca_der,
            inner: Mutex::new(Inner {
                phase: Phase::Stopped,
                stage: None,
                message: String::new(),
                owned: None,
                attention: None,
                alerts: AlertState::default(),
                starting_since: None,
                misses: 0,
                cert_untrusted: false,
                windows_trusts: false,
                level: None,
                update_pending: false,
            }),
        }
    }

    pub fn status(&self) -> Status {
        let inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let running = inner.phase == Phase::Running;
        Status {
            phase: inner.phase,
            stage: inner.stage,
            message: inner.message.clone(),
            external: running && inner.owned.is_none(),
            attention: inner.attention,
            account: self.config.account.clone(),
            start_command: self.config.start_command.clone(),
            broker_url: self.config.broker_url.clone(),
            config_error: self.config_error.clone(),
            cert_untrusted: running && inner.cert_untrusted,
            window_untrusted: running && !inner.windows_trusts,
            can_trust: trust::worth_offering(
                running,
                self.ca_der.is_some(),
                !inner.cert_untrusted,
                inner.windows_trusts,
            ),
            outdated: running && is_outdated(inner.level),
            can_update: launch::commit_ok(BROKER_COMMIT),
            update_pending: inner.update_pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broker_below_the_required_level_is_older_and_an_unknown_one_is_not() {
        assert!(is_outdated(Some(0)));
        assert!(!is_outdated(Some(REQUIRED_LEVEL)));
        assert!(!is_outdated(Some(REQUIRED_LEVEL + 1)));
        assert!(!is_outdated(None));
    }

    #[test]
    fn closing_asks_only_when_it_would_end_a_broker() {
        assert!(close_needs_confirmation(Phase::Running, true, true));
        assert!(close_needs_confirmation(Phase::Starting, true, true));
        // Nothing running, a broker started elsewhere, or one set to outlive the app.
        assert!(!close_needs_confirmation(Phase::Stopped, false, true));
        assert!(!close_needs_confirmation(Phase::Error, false, true));
        assert!(!close_needs_confirmation(Phase::Running, false, true));
        assert!(!close_needs_confirmation(Phase::Running, true, false));
    }

    #[test]
    fn the_build_carries_a_commit_or_none_at_all() {
        assert!(BROKER_COMMIT.is_empty() || launch::commit_ok(BROKER_COMMIT), "{BROKER_COMMIT:?}");
    }
}
