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
- **A `ca_file` setting, and the browser as a fallback** (not in the first draft; see "Found on the first real run").
- **Stop is a hard stop for now.** A broker ended from outside cannot log its NAS sessions out. Follow-up: a graceful stop (an owner-gated `/shutdown`, triggered from the app's window when an owner session is open, with the hard stop as the fallback).

## Found on the first real run

The broker's certificate comes from a private CA that Windows does not trust (the user's browser trusts it by other means). The app's strict health check therefore failed against a broker that was running, and reported "did not answer within 60 seconds". Also, a browser engine refuses passkeys on a site with a certificate error, so the app's own window could never have offered one.

What changed: a `ca_file` setting (the CA's public certificate, used for the app's own checks only; nothing is added to Windows), a distinct "running, but the certificate is not trusted" state, and a default-browser fallback (**Open in browser**). The window opens only when Windows' own store trusts the certificate, since the `ca_file` does not count for a window. The optional per-user trust import (`certutil -user -addstore Root`) is described in `desktop/README.md` with the reason the CA's private key matters.

## Checked, and not yet

Checked: the Python suite (1912 passed) and lint; `cargo test` and `clippy`; the release build, which runs, hides to the tray and keeps its data beside itself; the control window driven over the DevTools protocol (IPC, validation, refusals, CSP); certificate handling against a fake broker on a throwaway CA (no `ca_file`, the right one, a missing one). On the real machine with the **old** broker: started as the broker account, verified through the `ca_file`, and **Open in browser** with the 1Password passkey signed in.

Not yet, because they need the real broker, its host and the user's passkey: any of the new broker pages against the real broker (it still ran the old code); whether Windows lets the app end the broker it started; whether DSM accepts one verification code for several sign-ins; the passkey inside the app's own window (needs Windows to trust the CA); the remote page being refused the app's commands (defended in depth, not exercised).

## Things only the user does

- Type the broker account's Windows password, the passkey, the NAS password and code. Never given to an assistant.
- Deploy the updated broker code to `C:\SynologyBroker` as the broker account, and (if the 1Password passkey does not appear in the app) run `enroll new-code --add-device` there.
