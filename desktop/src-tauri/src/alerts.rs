//! Turns the broker's `/attention` counts into notifications and a tray state.
//!
//! The counts name nobody and nothing: how many sign-ins are waiting, how many
//! sessions are live, how many end soon, how many client grants need renewing.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Attention {
    pub waiting: u32,
    pub connected: u32,
    pub sessions_ending_soon: u32,
    pub grants_ending_soon: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alert {
    /// A client asked for a NAS sign-in and is waiting for you.
    Waiting,
    /// This many sessions reach their absolute deadline within minutes.
    SessionsEnding(u32),
    /// This many clients' grants have ended or end within two weeks.
    GrantsEnding(u32),
}

impl Alert {
    pub fn title(&self) -> &'static str {
        match self {
            Alert::Waiting => "An AI client is waiting",
            Alert::SessionsEnding(_) => "A NAS session is about to end",
            Alert::GrantsEnding(_) => "A client's access needs renewing",
        }
    }

    pub fn body(&self) -> String {
        match self {
            Alert::Waiting => "Open the broker and sign in to the NAS.".to_string(),
            Alert::SessionsEnding(n) => format!(
                "{n} session{} will reach {} time limit within minutes. Sign in again afterwards.",
                if *n == 1 { "" } else { "s" },
                if *n == 1 { "its" } else { "their" },
            ),
            Alert::GrantsEnding(n) => format!(
                "{n} client{} ha{} ended or end{} within two weeks. Renew in the broker's policy.",
                if *n == 1 { "" } else { "s" },
                if *n == 1 { "s" } else { "ve" },
                if *n == 1 { "s" } else { "" },
            ),
        }
    }
}

/// Remembers the last counts so that each change is announced once.
#[derive(Debug, Default)]
pub struct AlertState {
    last: Option<Attention>,
    grants_told: bool,
}

impl AlertState {
    /// The alerts that `now` adds to what was already known.
    pub fn update(&mut self, now: Attention) -> Vec<Alert> {
        let before = self.last.unwrap_or_default();
        let mut alerts = Vec::new();
        if now.waiting > 0 && before.waiting == 0 {
            alerts.push(Alert::Waiting);
        }
        if now.sessions_ending_soon > before.sessions_ending_soon {
            alerts.push(Alert::SessionsEnding(now.sessions_ending_soon));
        }
        // Once per run of the app: it is a reminder to renew, not a thing to nag about.
        if now.grants_ending_soon > 0 && !self.grants_told {
            self.grants_told = true;
            alerts.push(Alert::GrantsEnding(now.grants_ending_soon));
        }
        self.last = Some(now);
        alerts
    }

    /// The broker stopped: whatever it reports next is news again.
    pub fn reset(&mut self) {
        self.last = None;
        self.grants_told = false;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    Stopped,
    Running,
    Attention,
}

pub fn tray_state(running: bool, attention: Option<&Attention>) -> TrayState {
    match (running, attention) {
        (false, _) => TrayState::Stopped,
        (true, Some(a)) if a.waiting > 0 => TrayState::Attention,
        (true, _) => TrayState::Running,
    }
}

pub fn tooltip(running: bool, attention: Option<&Attention>) -> String {
    if !running {
        return "Synology broker: stopped".to_string();
    }
    match attention {
        None => "Synology broker: running".to_string(),
        Some(a) => {
            let mut text = format!("Synology broker: {} connected", a.connected);
            if a.waiting > 0 {
                text.push_str(&format!(", {} waiting for you", a.waiting));
            }
            if a.grants_ending_soon > 0 {
                text.push_str(&format!(", {} grant(s) to renew", a.grants_ending_soon));
            }
            text
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(waiting: u32, connected: u32, ending: u32, grants: u32) -> Attention {
        Attention { waiting, connected, sessions_ending_soon: ending, grants_ending_soon: grants }
    }

    #[test]
    fn a_waiting_client_is_announced_once_until_it_clears() {
        let mut state = AlertState::default();
        assert_eq!(state.update(counts(0, 0, 0, 0)), vec![]);
        assert_eq!(state.update(counts(1, 0, 0, 0)), vec![Alert::Waiting]);
        assert_eq!(state.update(counts(1, 0, 0, 0)), vec![]);
        assert_eq!(state.update(counts(2, 0, 0, 0)), vec![]);
        assert_eq!(state.update(counts(0, 2, 0, 0)), vec![]);
        assert_eq!(state.update(counts(1, 2, 0, 0)), vec![Alert::Waiting]);
    }

    #[test]
    fn the_first_reading_counts_as_news() {
        let mut state = AlertState::default();
        assert_eq!(state.update(counts(1, 0, 0, 0)), vec![Alert::Waiting]);
    }

    #[test]
    fn sessions_ending_are_announced_when_the_number_grows() {
        let mut state = AlertState::default();
        state.update(counts(0, 3, 0, 0));
        assert_eq!(state.update(counts(0, 3, 1, 0)), vec![Alert::SessionsEnding(1)]);
        assert_eq!(state.update(counts(0, 3, 1, 0)), vec![]);
        assert_eq!(state.update(counts(0, 3, 3, 0)), vec![Alert::SessionsEnding(3)]);
        assert_eq!(state.update(counts(0, 0, 0, 0)), vec![]);
    }

    #[test]
    fn grants_are_mentioned_once_per_run_and_again_after_a_restart() {
        let mut state = AlertState::default();
        assert_eq!(state.update(counts(0, 0, 0, 2)), vec![Alert::GrantsEnding(2)]);
        assert_eq!(state.update(counts(0, 0, 0, 2)), vec![]);
        state.reset();
        assert_eq!(state.update(counts(0, 0, 0, 2)), vec![Alert::GrantsEnding(2)]);
    }

    #[test]
    fn several_changes_arrive_together() {
        let mut state = AlertState::default();
        let alerts = state.update(counts(1, 1, 1, 1));
        assert_eq!(
            alerts,
            vec![Alert::Waiting, Alert::SessionsEnding(1), Alert::GrantsEnding(1)]
        );
    }

    #[test]
    fn the_tray_shows_stopped_running_or_attention() {
        assert_eq!(tray_state(false, None), TrayState::Stopped);
        assert_eq!(tray_state(false, Some(&counts(5, 0, 0, 0))), TrayState::Stopped);
        assert_eq!(tray_state(true, None), TrayState::Running);
        assert_eq!(tray_state(true, Some(&counts(0, 2, 0, 3))), TrayState::Running);
        assert_eq!(tray_state(true, Some(&counts(1, 0, 0, 0))), TrayState::Attention);
    }

    #[test]
    fn the_tooltip_says_what_is_going_on() {
        assert_eq!(tooltip(false, None), "Synology broker: stopped");
        assert_eq!(tooltip(true, None), "Synology broker: running");
        assert_eq!(
            tooltip(true, Some(&counts(1, 2, 0, 1))),
            "Synology broker: 2 connected, 1 waiting for you, 1 grant(s) to renew"
        );
    }

    #[test]
    fn the_wording_agrees_with_the_number() {
        assert!(Alert::SessionsEnding(1).body().starts_with("1 session will reach its"));
        assert!(Alert::SessionsEnding(2).body().starts_with("2 sessions will reach their"));
        assert!(Alert::GrantsEnding(1).body().starts_with("1 client has ended or ends"));
        assert!(Alert::GrantsEnding(2).body().starts_with("2 clients have ended or end "));
    }

    #[test]
    fn the_broker_s_json_is_read_even_with_a_field_missing() {
        let a: Attention = serde_json::from_str(r#"{"waiting":2,"connected":1}"#).unwrap();
        assert_eq!((a.waiting, a.connected, a.sessions_ending_soon), (2, 1, 0));
    }
}
