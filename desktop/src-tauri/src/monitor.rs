//! Watches the broker in the background: is it up, and does anything need you?
//!
//! It asks two public endpoints on the broker's private port: `/healthz` (is it
//! running) and `/attention` (counts only). Neither needs, or reveals, anything
//! secret. The certificate is checked against Windows' own store and the settings'
//! `ca_file`; a broker that answers only when it is not checked is reported as
//! running with an untrusted certificate, and its counts are not read.

use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

use crate::alerts::Attention;
use crate::state::{AppState, Phase, START_DEADLINE_SECONDS};
use crate::tray;

/// Misses in a row before a running broker is called stopped, so one slow reply is not.
const MISSES_BEFORE_STOPPED: u32 = 3;

pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            let delay = tick(&app).await;
            tokio::time::sleep(delay).await;
        }
    });
}

/// What a look at the broker found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// Answers, and its certificate is trusted.
    Trusted,
    /// Answers, but only when its certificate is not checked.
    Untrusted,
    Down,
}

async fn healthy(client: &reqwest::Client, base: &str) -> bool {
    let url = format!("{base}/healthz");
    matches!(client.get(url).send().await, Ok(reply) if reply.status().is_success())
}

async fn probe(state: &AppState) -> Probe {
    if healthy(&state.client, &state.config.broker_url).await {
        Probe::Trusted
    } else if healthy(&state.diagnostic_client, &state.config.broker_url).await {
        Probe::Untrusted
    } else {
        Probe::Down
    }
}

async fn fetch_attention(state: &AppState) -> Option<Attention> {
    let url = format!("{}/attention", state.config.broker_url);
    let reply = state.client.get(url).send().await.ok()?;
    if !reply.status().is_success() {
        return None;
    }
    reply.json::<Attention>().await.ok()
}

/// One round of checking. Returns how long to wait before the next.
async fn tick(app: &AppHandle) -> Duration {
    let state = app.state::<AppState>();
    let found = probe(&state).await;
    let up = found != Probe::Down;
    // The counts are only read over a connection whose certificate was verified.
    let attention = if found == Probe::Trusted { fetch_attention(&state).await } else { None };

    let mut alerts = Vec::new();
    let (phase, snapshot) = {
        let mut inner = state.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.cert_untrusted = found == Probe::Untrusted;
        if found == Probe::Untrusted {
            // Nothing to read counts from: the last ones would be stale.
            inner.attention = None;
        }
        match inner.phase {
            Phase::Starting => {
                if up {
                    inner.phase = Phase::Running;
                    inner.message.clear();
                    inner.starting_since = None;
                    inner.misses = 0;
                    inner.alerts.reset();
                } else if let Some(code) = inner.owned.as_ref().and_then(|o| o.exit_code()) {
                    // A script that starts the broker elsewhere and ends with 0 is fine:
                    // keep waiting. A failure is not.
                    if code != 0 {
                        inner.phase = Phase::Error;
                        inner.message =
                            format!("The start command ended with error code {code} before the broker answered.");
                        inner.owned = None;
                        inner.starting_since = None;
                    }
                }
                if inner.phase == Phase::Starting
                    && inner
                        .starting_since
                        .is_some_and(|t| t.elapsed() > Duration::from_secs(START_DEADLINE_SECONDS))
                {
                    inner.phase = Phase::Error;
                    inner.message = format!(
                        "The broker did not answer at {} within {START_DEADLINE_SECONDS} seconds.",
                        state.config.broker_url
                    );
                    inner.starting_since = None;
                }
            }
            Phase::Running => {
                if up {
                    inner.misses = 0;
                } else {
                    inner.misses += 1;
                    if inner.misses >= MISSES_BEFORE_STOPPED {
                        inner.phase = Phase::Stopped;
                        inner.message = "The broker stopped.".to_string();
                        inner.owned = None;
                        inner.attention = None;
                        inner.alerts.reset();
                    }
                }
            }
            Phase::Stopped | Phase::Error => {
                if up {
                    // Started some other way (the old shortcut, say): adopt it.
                    inner.phase = Phase::Running;
                    inner.message.clear();
                    inner.misses = 0;
                    inner.alerts.reset();
                }
            }
        }
        if inner.phase == Phase::Running {
            if let Some(now) = attention {
                alerts = inner.alerts.update(now);
                inner.attention = Some(now);
            }
        }
        (inner.phase, inner.attention)
    };

    for alert in alerts {
        let _ = app.notification().builder().title(alert.title()).body(alert.body()).show();
    }
    tray::update(app, phase == Phase::Running, snapshot.as_ref());
    let _ = app.emit("broker-status", state.status());

    if phase == Phase::Starting {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(state.config.poll_seconds)
    }
}
