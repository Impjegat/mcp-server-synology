# Desktop app, second round: lean window, pages in the app, update, trust

Status: implemented on branch `desktop-app/round-2`
Initiated: 2026-11-14
Follows: [`2026-11-14-desktop-app`](../shipped/2026-11-14-desktop-app/PLAN.md) (merged as #34 to #36)

## Why

The first real use of the app showed that it did not do its main job:

- **Log, Sign in all and Settings said "Not Found".** The broker on the host was still the code from before #34. Only the broker's account can write its folder, so nothing had been deployed, and the app opened pages the broker did not have.
- **Settings looked missing.** They exist on the broker's `/settings` page, but the app had no Settings button.
- **Open broker launched the browser**, because Windows did not trust the broker's certificate and a window cannot load the page without that.
- The window had too much text, no progress bar, a Quit link, and warnings at the top.

## Decisions (with the owner, 2026-11-14)

| Topic | Decision |
|---|---|
| Close button | Closes the app and the broker it started, after one question while a broker runs. Minimise goes to the taskbar; no maximise. No Quit link, and none in the tray menu |
| Broker code | An **Update Broker** button in the app, not a command to paste |
| Passkey in the window | Build **Add a passkey** on the settings page now, so a passkey kept in a password manager can get a Windows Hello companion without a terminal |
| Certificate | Windows is made to trust the CA by the person, from a button, through Windows' own confirmation. The app adds nothing by itself |

## What changed

### The window (`desktop/ui/`, `desktop/src-tauri/src/main.rs`, `tray.rs`)

- Stopped: title "Synology Broker", status, "Windows password for the Synbroker account", **Start Broker**. Nothing else; the command and account are a hover on the label.
- Starting: a progress bar and no password box. It moves through stages (updating, launching, waiting) and never reaches the end before the broker answers.
- Running: **Open Broker**, **Sign in all clients**, **Settings**, **Log**, **Stop Broker**. After a start from the app the dashboard opens by itself.
- Every message is a card at the bottom with an ×. A dismissal is forgotten when its cause goes away.
- `ui/view.js` holds all of that as pure functions; `app.js` only applies them.
- The window is 460 by 460, cannot be resized or maximised. Its close button exits the app (`close_needs_confirmation` in `state.rs` decides whether to ask first).
- **No browser**: `open_browser`, `open_in_browser`, the `rundll32` call and `quit_app` are gone, with their permissions.

### Updating the broker (`launch.rs`, `commands.rs`, `state.rs`, `build.rs`; `src/private_auth/app.py`)

- The broker's private `/healthz` reports `level` (`PRIVATE_PAGE_LEVEL`, now 1). The app needs `REQUIRED_LEVEL`; a broker that reports less, or nothing, is older.
- The app is built with the commit it was made from (`BROKER_COMMIT`). **Update Broker** stops the broker and marks the next start as an update; with the password, `launch::update` runs one line as the broker's account and waits for it: fetch exactly that commit from `origin`, then switch to it, in the `broker_checkout` folder. Each of the three values on that line is refused unless it is plainly a path, a path and a 40-digit commit.
- Failures are told apart by exit code (not downloaded, not switched to) and said in words. A failed update is dropped, so the next start is a plain one; a wrong password keeps it pending.

### Trusting the certificate (`trust.rs`, `monitor.rs`)

- **Trust certificate** is offered only while the broker runs and the `ca_file` is what verifies its certificate. It adds that certificate to the current user's Root store with `CertAddEncodedCertificateToStore`; Windows shows its own confirmation.
- The page window has its own browser data folder (`synology-broker-data\page`).
- Found while testing, and fixed: a broker that came up between the monitor's two looks was called "untrusted" until the next poll.

### Add a passkey (`src/private_auth/owner.py`, `app.py`)

- `/api/passkeys/begin`, `/confirm`, `/finish`, the Passkeys section of the settings page and `/static/passkeys.js`.
- The confirmation is the existing `confirm` challenge bound to `ADD_PASSKEY_BINDING`; `passkeys_confirm` refuses any other binding, and `settings_commit` cannot spend this one. The new passkey goes through the existing enrollment (`begin_additional_enrollment` makes a one-time code that is used at once and never shown), so it is single-use under the same rules as one enrolled from the host.

## Where it differs from the plan

- **Two development switches in debug builds** (`SYNOLOGY_BROKER_DEV_RUN_AS_SELF`, `SYNOLOGY_BROKER_DEV_ASSUME_TRUSTED`), absent from release builds. Without them the start, update, stop and page-opening paths could only be tested with someone's Windows password and a changed certificate store.
- The page window is titled "Synology Broker private page", so the two windows can be told apart.
- CI runs the window's view tests (`node --test`); the app's Rust tests stay local, as before.

## Verification

- `pytest -m "not real_nas"`: 1956 passed, 30 skipped (35 new in `tests/test_private_passkeys.py` and `test_private_settings.py`). ruff, black and the tool catalog check are clean.
- `cargo test`: 40 passed (was 22), including the update line run against real git repositories (updated; unknown commit; a checkout with its own changes is left alone; not a checkout) and the certificate call on a store that exists only in memory. clippy is clean with `-D warnings`.
- `node --test desktop/tests/view.test.js`: 21 passed.
- **A debug copy of the app driven over DevTools against a stand-in broker in a throwaway git repository: 85 of 85 checks.** The stopped window's text is exactly the four items; no maximise box and a title-bar double-click does not maximise; the bar rises and the password box is gone while starting; notices sit at the bottom with the × in the corner and stay dismissed; an older broker with an untrusted certificate shows both notices and opens nothing; Update Broker brings the checkout to the built-in commit and the notice goes; a failed update says why and the next start is plain; with trust, the dashboard opens by itself in an app window and each button shows its page in that same window; the page cannot call any app command or leave the broker's address; the X asks once, No keeps everything running, Yes ends the app and the broker; a sign-in Windows refuses is a red notice and the typed password is nowhere on the page.

## Left for the owner (cannot be done from here)

1. Push this branch, so the commit the app is built from exists on GitHub; then run the app and press **Update Broker** with the broker account's password. This is the first run of the update under the real account.
2. Press **Trust certificate** and answer Windows' dialog.
3. Sign in with the passkey in the app's window. If Windows does not offer it: from the usual browser, Settings, **Add a passkey**, choose Windows Hello.
4. Sign in all, change a setting, read the log, close with the X.
