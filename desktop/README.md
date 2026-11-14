# Synology Broker (desktop)

A small portable Windows app that replaces the shortcut, the two terminals and the browser tab you use to connect an AI client to the NAS through the [broker](../docs/MANUAL_AUTHENTICATION.md).

One `.exe` (about 4 MB), no installer. It:

- **starts the broker** as its own Windows account with no console window (you type that account's Windows password once; it is used for the instant it takes to start the broker and is not kept);
- **shows the broker's private page** (passkey, dashboard, *Sign in all*, settings, log) in a window of its own;
- sits in the **tray** (grey stopped, green running, amber a client is waiting for you) and sends **notifications** when a client is waiting, a session is about to reach its limit, or a client's grant needs renewing;
- lets you **stop** the broker from the tray and **quit**.

It is a shell around the broker, not a second authority. It never sees your NAS password, one-time code or a NAS session: those are typed into the broker's own page. Settings (session times, folders, write access) are changed on that page and need your passkey again; the app has no way to change them.

## Using it

1. Copy `synology-broker.exe` to a folder you keep (it makes `synology-broker-data/` beside itself for the browser's data, so the folder is the whole app) and run it.
2. Type the Windows password of the broker's account and press **Start broker**. The window shows *Running* when the broker answers.
3. **Open broker**, sign in with your passkey, then **Sign in all clients**: tick the clients, type the NAS password (and a code if the account uses one) once.
4. Closing the window hides it to the tray. **Quit** from the tray or the window ends the broker too, if this app started it.

If the broker is already running (started the old way), the app finds it and shows *Running*, but it cannot stop a broker it did not start.

## Settings file

Optional, `synology-broker-app.json` beside the `.exe`. Everything has a default and there is no secret in it:

```json
{
  "account": "BERNARD-PC\\synbroker",
  "start_command": "C:\\SynologyBroker\\start-broker.cmd",
  "broker_url": "https://localhost:8444",
  "poll_seconds": 10,
  "stop_broker_on_quit": true
}
```

- `account` defaults to `<this computer>\synbroker`; `start_command` to `C:\SynologyBroker\start-broker.cmd` (a `.cmd`/`.bat` runs through `cmd.exe`, anything else directly).
- `broker_url` must be `https` on this computer. The app checks the broker's certificate against Windows' own store, exactly as the browser would.
- An unknown or invalid setting is an error shown in the window, not ignored, because this file decides which account your password is used for.

## What this does and does not protect

- The broker's page is a **remote page in its own window with no capability**: it cannot call anything in the app, and it cannot navigate away from the broker's address. The app's commands are each granted to the local control window only.
- The app runs as **you**, like the AI tools you use. The broker is protected from them by running as a different account. The app does not change that, but it does mean a program that can **edit this app, its settings file or the start script** could make the app launch something else as the broker's account when you type that password. Keep this folder, and the broker's start script, somewhere an AI tool cannot write; the window shows the command and the account just above the password box so you can see what you are about to start.
- **Stop is a hard stop.** The broker cannot log its NAS sessions out when it is ended this way, so they linger on the NAS until its own timeout. Press **Disconnect all** on the dashboard first if that matters. (A graceful stop from the app is a known follow-up.)
- A **new broker** is needed for the dashboard, *Sign in all*, settings, log and the tray's notifications (`/attention`). An older broker still starts, stops and opens in the window, but the tray cannot tell you a client is waiting.

## Not yet checked on the real broker

These depend on the broker's account, its certificate and your passkey, so they were not exercised in development:

- starting the broker as its own account (and whether Windows lets the app end it afterwards);
- the passkey inside the app's window. A passkey kept only in 1Password's browser extension will not appear there, because extensions do not load in an embedded window. If it does not work, add a second passkey with Windows Hello (`broker_main.py enroll new-code --add-device` on the broker host) and use that; the 1Password one keeps working in your browser;
- whether DSM accepts one verification code for several sign-ins in a row (if not, *Sign in all* asks for the next code and carries on).

## Building

Needs Rust (`rustup`, stable MSVC), the Visual Studio *C++ build tools* and Node. From this folder:

```bash
npm install
npx tauri build --no-bundle      # synology-broker.exe in src-tauri/target/release/
cd src-tauri && cargo test       # config, alert rules and launch parsing
```

If the repository is on a network share, set `CARGO_TARGET_DIR` to a local folder first: building on a share is slow and can fail.

```
desktop/
  ui/         the control window (plain HTML, CSS and JS; no framework, no build step)
  src-tauri/
    src/      main.rs (windows, tray), commands.rs, launch.rs (CreateProcessWithLogonW),
              monitor.rs (health and /attention), alerts.rs, tray.rs, config.rs, state.rs
    icons/    app icon and the three tray icons
```
