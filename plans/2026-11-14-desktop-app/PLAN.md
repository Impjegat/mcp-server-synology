# Desktop app for the broker, and the private page features behind it

## Why

Connecting an AI client to the NAS took five hops across three programs: a desktop shortcut (`cmd /k runas /user:<PC>\synbroker C:\SynologyBroker\start-broker.cmd`), the account password pasted into a terminal, a second terminal, a browser at `https://localhost:8444`, a passkey, and then the NAS password typed once per client (Claude Code, Claude Desktop, Codex).

Goal: one portable app (single `.exe`, no installer) that starts the broker, shows the sign-in in its own window, signs every client in from one password entry, and adds a tray icon, alerts, a session dashboard, a log, grant-expiry reminders and a settings page.

## Decisions

| Topic | Decision |
|---|---|
| Stack | Tauri 2 (Rust shell, plain HTML/JS control window), WebView2 from Windows 11 |
| Broker start | The app asks for the broker account's Windows password at each start; nothing is stored |
| Passkey | Try 1Password as a Windows passkey provider in the embedded window; otherwise enrol a Windows Hello passkey (`enroll new-code --add-device`) |
| NAS password | Entered once, signs in every ticked client; the NAS account uses a one-time code |
| Settings | Session times (owner page and NAS sessions), folders, write access, all on the broker's page behind a fresh passkey |

## Principle: the app is a shell, the broker stays the authority

The broker runs as its own account so that nothing running as the user (where AI tools run) can read its secrets or change its policy. The app runs as the user too, so it **never sees the NAS password, code or a session** (they are typed into the broker's page, shown in a window with no Tauri capability), and **settings are edited on the broker's passkey-gated page**, never by the app.

## What shipped on this branch

**Broker (`src/`):** `/login-all` and `/api/login-all/step`; dashboard time-left, grant dates, Disconnect all; `/attention` (counts only); `/log` from `private_auth/logbuffer.py`; `/settings` with `private_auth/settings.py` (change logic, `SettingsService`), `broker/policy_store.py` (validate, atomic write, `.previous`, changed-on-disk check), `BrokerRuntime.apply_policy`, `SessionManager.set_policy`, `OwnerSessions.set_limits`, `PasskeyOwnerAuth.begin/finish_confirmation`; policy keys `session.owner_idle_seconds`, `session.owner_absolute_seconds`, `restricted_mode`; `WRITE_TOOLS` and `DELETE_TOOLS`.

**App (`desktop/`):** start screen, launch as the broker account (`launch.rs`), health and `/attention` monitor (`monitor.rs`), alert rules (`alerts.rs`), tray (`tray.rs`), settings file (`config.rs`), per-command capabilities (`build.rs`, `capabilities/default.json`).

## Where it differs from the first draft

- **Plain HTML/JS control window, no Vite or npm build**: it has one screen, and a CSP of `script-src 'self'` is easier to hold without a bundler.
- **NAS sessions are kept when settings change** (the draft ended affected clients' sessions): a session is not an authorization, which is judged on every call, so a narrower folder list or a removed tool takes effect on the next call without a sign-out.
- **The policy carries `restricted_mode`**, instead of the page also editing `settings.json`: one file, validated by one parser.
- **Two owner-session keys** (idle and absolute), mirroring the NAS session pair, rather than one.
- **"Write access" means file changes only** (create, rename, move), with delete separate. Containers, downloads, sharing and accounts are not offered by the page.
- **Stop is a hard stop for now.** A broker ended from outside cannot log its NAS sessions out. Follow-up: a graceful stop (an owner-gated `/shutdown`, triggered from the app's window when an owner session is open, with the hard stop as the fallback).

## Checked, and not yet

Checked: the full Python suite (`pytest`, 1769 passed) and lint; `cargo test` (alert rules, config, launch parsing) and `clippy`; the release build; the app starts, hides to the tray on close, and its control window talks to the Rust side (status, validation, refusals, CSP) driven over the DevTools protocol.

Not yet, because they need the real broker account, certificate and passkey (all the user's): starting the broker as its own account and whether Windows lets the app end it; the passkey inside the app's window; whether DSM accepts one code for several sign-ins; the remote page being refused the app's commands (defended in depth, not exercised).

## Things only the user does

- Type the broker account's Windows password, the passkey, the NAS password and code. Never given to an assistant.
- Deploy the updated broker code to `C:\SynologyBroker` as the broker account, and (if the 1Password passkey does not appear in the app) run `enroll new-code --add-device` there.
