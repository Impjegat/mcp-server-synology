//! The app's own settings: a JSON file beside the .exe. It holds no secret.

use std::path::Path;

use serde::Deserialize;
use url::Url;

pub const FILE_NAME: &str = "synology-broker-app.json";

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The Windows account the broker runs as, e.g. `BERNARD-PC\synbroker`.
    pub account: String,
    /// The script or program that starts the broker as that account.
    pub start_command: String,
    /// Where the broker's private login is. Must be HTTPS on this computer.
    pub broker_url: String,
    /// Seconds between checks of the broker while it runs (3 to 300).
    pub poll_seconds: u64,
    /// End the broker when the app quits (only if this app started it).
    pub stop_broker_on_quit: bool,
}

impl Default for Config {
    fn default() -> Self {
        let computer = std::env::var("COMPUTERNAME").unwrap_or_else(|_| ".".to_string());
        Config {
            account: format!("{computer}\\synbroker"),
            start_command: r"C:\SynologyBroker\start-broker.cmd".to_string(),
            broker_url: "https://localhost:8444".to_string(),
            poll_seconds: 10,
            stop_broker_on_quit: true,
        }
    }
}

impl Config {
    /// Read `dir`/`synology-broker-app.json`. No file means the defaults; a file that
    /// cannot be read or is not valid is an error the window shows, never silently
    /// replaced by defaults, because this decides which account a password is used for.
    pub fn load(dir: &Path) -> Result<Config, String> {
        let path = dir.join(FILE_NAME);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Config::default().checked();
            }
            Err(error) => return Err(format!("Cannot read {FILE_NAME}: {error}")),
        };
        Config::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let config: Config =
            serde_json::from_str(text).map_err(|error| format!("{FILE_NAME} is not valid: {error}"))?;
        config.checked()
    }

    fn checked(mut self) -> Result<Config, String> {
        if self.account.trim().is_empty() {
            return Err(format!("{FILE_NAME}: account is empty"));
        }
        if self.start_command.trim().is_empty() {
            return Err(format!("{FILE_NAME}: start_command is empty"));
        }
        let url = Url::parse(&self.broker_url)
            .map_err(|_| format!("{FILE_NAME}: broker_url is not a web address"))?;
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if url.scheme() != "https" || !loopback {
            return Err(format!(
                "{FILE_NAME}: broker_url must be https on this computer (localhost or 127.0.0.1)"
            ));
        }
        if url.username() != "" || url.password().is_some() {
            return Err(format!("{FILE_NAME}: broker_url must not carry a user name or password"));
        }
        self.broker_url = url.as_str().trim_end_matches('/').to_string();
        self.poll_seconds = self.poll_seconds.clamp(3, 300);
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_object_gives_the_defaults() {
        let config = Config::parse("{}").unwrap();
        assert_eq!(config.broker_url, "https://localhost:8444");
        assert_eq!(config.poll_seconds, 10);
        assert!(config.stop_broker_on_quit);
        assert!(config.account.ends_with("\\synbroker"));
    }

    #[test]
    fn settings_override_the_defaults() {
        let config = Config::parse(
            r#"{"account":"PC\\broker","start_command":"D:\\b.cmd","poll_seconds":30,"stop_broker_on_quit":false}"#,
        )
        .unwrap();
        assert_eq!(config.account, "PC\\broker");
        assert_eq!(config.start_command, "D:\\b.cmd");
        assert_eq!(config.poll_seconds, 30);
        assert!(!config.stop_broker_on_quit);
    }

    #[test]
    fn an_unknown_setting_is_refused_not_ignored() {
        let error = Config::parse(r#"{"passwrod":"x"}"#).unwrap_err();
        assert!(error.contains("not valid"), "{error}");
    }

    #[test]
    fn the_poll_interval_is_kept_within_bounds() {
        assert_eq!(Config::parse(r#"{"poll_seconds":0}"#).unwrap().poll_seconds, 3);
        assert_eq!(Config::parse(r#"{"poll_seconds":99999}"#).unwrap().poll_seconds, 300);
    }

    #[test]
    fn the_broker_must_be_https_on_this_computer() {
        for bad in [
            "http://localhost:8444",
            "https://broker.example:8444",
            "https://user:pw@localhost:8444",
            "not a url",
        ] {
            let text = format!(r#"{{"broker_url":"{bad}"}}"#);
            assert!(Config::parse(&text).is_err(), "{bad} was accepted");
        }
        for good in ["https://localhost:8444", "https://127.0.0.1:9000/"] {
            let text = format!(r#"{{"broker_url":"{good}"}}"#);
            assert!(Config::parse(&text).is_ok(), "{good} was refused");
        }
    }

    #[test]
    fn a_trailing_slash_is_dropped() {
        let config = Config::parse(r#"{"broker_url":"https://localhost:8444/"}"#).unwrap();
        assert_eq!(config.broker_url, "https://localhost:8444");
    }

    #[test]
    fn blank_account_or_command_is_refused() {
        assert!(Config::parse(r#"{"account":" "}"#).is_err());
        assert!(Config::parse(r#"{"start_command":""}"#).is_err());
    }
}
