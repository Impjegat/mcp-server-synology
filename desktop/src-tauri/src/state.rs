//! What the app knows about the broker, shared between the window, the tray and the
//! background monitor.

use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;

use crate::alerts::{AlertState, Attention};
use crate::config::Config;
use crate::launch::Owned;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Stopped,
    Starting,
    Running,
    Error,
}

/// How long the broker has to answer after it is started.
pub const START_DEADLINE_SECONDS: u64 = 60;

pub struct Inner {
    pub phase: Phase,
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
    /// engine) needs this to offer a passkey; the `ca_file` does not count for it.
    pub windows_trusts: bool,
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
}

/// What the window is told. Names and numbers only: never a password.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub phase: Phase,
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
    /// Running, but Windows does not trust the certificate, so a window cannot do
    /// passkeys. True too when only the `ca_file` makes it verify.
    pub window_untrusted: bool,
}

impl AppState {
    pub fn new(
        config: Config,
        config_error: Option<String>,
        client: reqwest::Client,
        system_client: reqwest::Client,
        diagnostic_client: reqwest::Client,
    ) -> Self {
        AppState {
            config,
            config_error,
            client,
            system_client,
            diagnostic_client,
            inner: Mutex::new(Inner {
                phase: Phase::Stopped,
                message: String::new(),
                owned: None,
                attention: None,
                alerts: AlertState::default(),
                starting_since: None,
                misses: 0,
                cert_untrusted: false,
                windows_trusts: false,
            }),
        }
    }

    pub fn status(&self) -> Status {
        let inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        Status {
            phase: inner.phase,
            message: inner.message.clone(),
            external: inner.phase == Phase::Running && inner.owned.is_none(),
            attention: inner.attention,
            account: self.config.account.clone(),
            start_command: self.config.start_command.clone(),
            broker_url: self.config.broker_url.clone(),
            config_error: self.config_error.clone(),
            cert_untrusted: inner.phase == Phase::Running && inner.cert_untrusted,
            window_untrusted: inner.phase == Phase::Running && !inner.windows_trusts,
        }
    }
}
