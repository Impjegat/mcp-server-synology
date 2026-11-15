//! Watches the broker in the background: is it up, and does anything need you?
//!
//! It asks two public endpoints on the broker's private port: `/healthz` (is it
//! running, and how new is it) and `/attention` (counts only). Neither needs, or
//! reveals, anything secret. The certificate is checked against Windows' own store and
//! the settings' `ca_file`; a broker that answers only when it is not checked is
//! reported as running with an untrusted certificate, and nothing else is read from it.

use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

use crate::alerts::Attention;
use crate::commands;
use crate::state::{is_outdated, AppState, Phase, Stage, START_DEADLINE_SECONDS};
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
    /// Answers, and its certificate verifies (against Windows' store, or the `ca_file`).
    /// `windows` is whether Windows' store alone accepts it, which is what a window sees.
    /// `level` is how new the broker says it is (0 if it does not say).
    Trusted { windows: bool, level: u32 },
    /// Answers, but only when its certificate is not checked.
    Untrusted,
    Down,
}

/// The level in a `/healthz` body: `{"status": "ok", "level": 1}`. A broker from before
/// levels says only that it is up, and anything else that is not this JSON object is
/// treated the same way: level 0, which is all that is known about it.
fn level_of(body: &[u8]) -> u32 {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|health| health.as_object()?.get("level")?.as_u64())
        .and_then(|level| u32::try_from(level).ok())
        .unwrap_or(0)
}

/// The broker's level if it answers `/healthz` over a connection `client` accepts.
async fn health(client: &reqwest::Client, base: &str) -> Option<u32> {
    let reply = client.get(format!("{base}/healthz")).send().await.ok()?;
    if !reply.status().is_success() {
        return None;
    }
    Some(reply.bytes().await.map(|body| level_of(&body)).unwrap_or(0))
}

/// A look that checks the certificate. `None` if the broker does not answer one.
async fn verified(state: &AppState) -> Option<Probe> {
    let base = &state.config.broker_url;
    let level = health(&state.client, base).await?;
    // Without a `ca_file` the two clients check the same thing. With one, the
    // `ca_file` may be what makes it verify, and a window has only Windows' store.
    let windows = state.config.ca_file.is_none()
        || health(&state.system_client, base).await.is_some()
        || dev_assume_windows_trusts();
    Some(Probe::Trusted { windows, level })
}

async fn probe(state: &AppState) -> Probe {
    if let Some(found) = verified(state).await {
        return found;
    }
    if health(&state.diagnostic_client, &state.config.broker_url).await.is_none() {
        return Probe::Down;
    }
    // It answers when its certificate is not checked. That is "untrusted" only if it
    // still fails a checked look now: a broker that came up between the two looks
    // above would otherwise be called untrusted until the next round.
    verified(state).await.unwrap_or(Probe::Untrusted)
}

/// Debug builds only, and only when this is set in the environment: carry on as if
/// Windows trusted a certificate that the `ca_file` verifies. It exists so that opening
/// the broker's page can be exercised on a development machine without adding anything
/// to Windows' certificate store. A release build has no such path.
#[cfg(debug_assertions)]
fn dev_assume_windows_trusts() -> bool {
    std::env::var_os("SYNOLOGY_BROKER_DEV_ASSUME_TRUSTED").is_some()
}

#[cfg(not(debug_assertions))]
fn dev_assume_windows_trusts() -> bool {
    false
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
pub async fn tick(app: &AppHandle) -> Duration {
    let state = app.state::<AppState>();
    let found = probe(&state).await;
    let up = found != Probe::Down;
    // The counts are only read over a connection whose certificate was verified.
    let attention = if matches!(found, Probe::Trusted { .. }) {
        fetch_attention(&state).await
    } else {
        None
    };

    let mut alerts = Vec::new();
    // A broker this app has just started opens its page by itself.
    let mut just_started = false;
    let (phase, snapshot) = {
        let mut inner = state.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.cert_untrusted = found == Probe::Untrusted;
        inner.windows_trusts = matches!(found, Probe::Trusted { windows: true, .. });
        inner.level = match found {
            Probe::Trusted { level, .. } => Some(level),
            Probe::Untrusted | Probe::Down => None,
        };
        if found == Probe::Untrusted {
            // Nothing to read counts from: the last ones would be stale.
            inner.attention = None;
        }
        match inner.phase {
            // While the update runs the old broker is stopped and nothing is waited for
            // here: `commands::start_broker` moves the start on, or ends it.
            Phase::Starting if inner.stage == Some(Stage::Updating) => {}
            Phase::Starting => {
                if up {
                    inner.phase = Phase::Running;
                    inner.stage = None;
                    inner.message.clear();
                    inner.starting_since = None;
                    inner.misses = 0;
                    inner.alerts.reset();
                    just_started = inner.owned.is_some();
                } else if let Some(code) = inner.owned.as_ref().and_then(|o| o.exit_code()) {
                    // A script that starts the broker elsewhere and ends with 0 is fine:
                    // keep waiting. A failure is not.
                    if code != 0 {
                        inner.phase = Phase::Error;
                        inner.stage = None;
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
                    inner.stage = None;
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
                        inner.message = "The broker stopped by itself.".to_string();
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
        just_started = just_started && inner.windows_trusts && !is_outdated(inner.level);
        (inner.phase, inner.attention)
    };

    for alert in alerts {
        let _ = app.notification().builder().title(alert.title()).body(alert.body()).show();
    }
    tray::update(app, phase == Phase::Running, snapshot.as_ref());
    let _ = app.emit_to("main", "broker-status", state.status());
    if just_started {
        commands::spawn_open(app, "/");
    }

    if phase == Phase::Starting {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(state.config.poll_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_level_is_read_from_healthz_and_an_old_broker_has_none() {
        assert_eq!(level_of(br#"{"status": "ok", "level": 1}"#), 1);
        assert_eq!(level_of(br#"{"level": 7, "status": "ok", "more": [1, 2]}"#), 7);
        // A broker from before levels, and anything that is not what is expected.
        assert_eq!(level_of(br#"{"status": "ok"}"#), 0);
        assert_eq!(level_of(b"ok"), 0);
        assert_eq!(level_of(b""), 0);
        assert_eq!(level_of(br#"{"level": "new"}"#), 0);
        assert_eq!(level_of(br#"{"level": -1}"#), 0);
        assert_eq!(level_of(br#"[1]"#), 0);
        assert_eq!(level_of(br#"{"level": 99999999999}"#), 0);
        assert_eq!(level_of(br#"{"level": 1.5}"#), 0);
    }
}
