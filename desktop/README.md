# Synology Broker (desktop)

A small portable Windows app that replaces the shortcut, the two terminals and the browser tab you use to connect an AI client to the NAS through the [broker](../docs/MANUAL_AUTHENTICATION.md).

One `.exe` (about 4 MB), no installer. It:

- **starts the broker** as its own Windows account with no console window (you type that account's Windows password once; it is used for the instant it takes to start the broker and is not kept);
- **shows the broker's private page** (passkey, dashboard, *Sign in all*, settings, log) in a window of its own, never in your browser;
- **updates the broker's code** to the version the app was built from, when the broker is older;
- sits in the **tray** as a status light (grey stopped, green running, amber a client is waiting for you) and sends **notifications** when a client is waiting, a session is about to reach its limit, or a client's grant needs renewing.

It is a shell around the broker, not a second authority. It never sees your NAS password, one-time code or a NAS session: those are typed into the broker's own page. Settings (session times, folders, write access) are changed on that page and need your passkey again; the app has no way to change them.

## Using it

1. Copy `synology-broker.exe` to a folder you keep (it makes `synology-broker-data/` beside itself for the browser's data, so the folder is the whole app) and run it.
2. Type the Windows password of the broker's account and press **Start Broker**. A progress bar shows until the broker answers; then the window shows *Running* and the broker's dashboard opens in a window of the app.
3. Sign in there with your passkey, then use **Sign in all clients**, **Settings** and **Log** from the app's window (or from the links at the top of the page).
4. **The X closes the app, and the broker with it** if this app started it. Because that disconnects every client, the app asks first while a broker is running. Minimise sends the app to the taskbar. The window cannot be maximised.

Anything the app has to tell you is a card at the bottom of the window with an **×** to dismiss it. A dismissed card stays away until its cause goes and comes back. Two of them have a button, and you will meet both the first time:

- **"This broker is an older version"** with **Update Broker**: see [Updating the broker](#updating-the-broker).
- **"Windows does not trust the broker's certificate yet"** with **Trust certificate**: see [The broker's certificate](#the-brokers-certificate). Until then the page buttons are greyed out, because the page cannot load in a window.

The tray icon has no Quit: its menu opens the broker's pages and stops the broker, and a click shows the window.

If the broker is already running (started the old way), the app finds it and shows *Running*, but it cannot stop or update a broker it did not start.

## Settings file

Optional, `synology-broker-app.json` beside the `.exe`. Everything has a default and there is no secret in it:

```json
{
  "account": "BERNARD-PC\\synbroker",
  "start_command": "C:\\SynologyBroker\\start-broker.cmd",
  "broker_url": "https://localhost:8444",
  "ca_file": "C:\\path\\to\\broker-ca.pem",
  "broker_checkout": "C:\\SynologyBroker\\app\\mcp-server-synology",
  "poll_seconds": 10,
  "stop_broker_on_quit": true
}
```

- `account` defaults to `<this computer>\synbroker`; `start_command` to `C:\SynologyBroker\start-broker.cmd` (a `.cmd`/`.bat` runs through `cmd.exe`, anything else directly). The window does not print them, to stay uncluttered: **hover over the password label** to see exactly which command will be started as which account.
- `broker_url` must be `https` on this computer.
- `ca_file` is the **public** certificate of the CA that signed the broker's certificate: the same file your adapter calls `ca_file`. It must hold that one certificate and no other: a bundle of several is refused, because this is the certificate **Trust certificate** offers to Windows and which one that is must not depend on the order of a file. See [The broker's certificate](#the-brokers-certificate). Leave it out if Windows already trusts the broker's certificate.
- `broker_checkout` is the folder that holds the broker's code as a git checkout. It must be a full path, and it is refused if it holds a character a command line could misread (`" % & | < > ^ !`).
- An unknown or invalid setting is an error shown in the window, not ignored, because this file decides which account your password is used for.

## The broker's certificate

The broker serves HTTPS with a certificate from a private CA, which Windows does not know. Two things follow:

- **The app's own checks** (is the broker up, how new is it, does anything need you) verify that certificate. Without `ca_file` they cannot, and the window says the certificate is not trusted. With `ca_file` set they verify against that CA, and only for these checks: that alone adds nothing to Windows.
- **The app's window** is a browser engine, and a browser engine takes its trust from Windows, not from the `ca_file`. So for the broker's page to open in the app, Windows itself must trust the CA.

**Trust certificate** does that. It offers the `ca_file` certificate to the *Trusted Root Certification Authorities* store of **your Windows account only** (not the whole computer). **Windows then shows its own confirmation**, naming the certificate and its thumbprint, and adds it only if you answer Yes there; the app never adds anything by itself. The button is offered only while the broker is running and the `ca_file` is what verifies its certificate, so the certificate you are asked about is the one the broker really uses. Hovering over the button says what it does, and Windows' dialog says it again: a trusted root is trusted for **every** site that CA signs a certificate for, not only the broker.

Say Yes only if the CA's **private key** is out of reach of anything an AI tool can read: anyone holding it could mint a certificate that Edge and Chrome on your account would then trust. A CA made only to sign `localhost` for the broker, whose key was deleted once the broker's certificate existed (or that is limited to `localhost` with name constraints), is safe to trust. To undo it later:

```bash
certutil -user -delstore Root "Name of your broker CA"
```

## Updating the broker

The broker's code lives in a folder that only the broker's account can write, so an AI tool running as you cannot change it. The app can update it because you type that account's password.

The broker says how new it is (`level` in `/healthz`). When that is less than this app needs, the window says *This broker is an older version*, greys out the pages the broker lacks, and offers **Update Broker**. Pressing it stops the broker and returns to the password box, whose button now reads **Update and Start Broker**. With the password, the app runs one line as the broker's account, hidden, and then starts the broker as usual:

```text
git -C <broker_checkout> fetch origin <commit>   and then   git -C <broker_checkout> checkout --detach <commit>
```

`<commit>` is the exact commit this app was built from, compiled into the `.exe`; nothing else is fetched and no branch is followed. If a step fails, the window says which (not downloaded: the PC is offline, Git is not installed for that account, or the app was built from a commit that is not on GitHub; not switched to: the folder has changes of its own), nothing is half-applied, and the next start is a plain one with the broker that is there.

What it needs, and does not do:

- **Git for Windows**, installed for all users, and a checkout whose `origin` is the repository on GitHub.
- An app **built from a commit that is on GitHub**. A build from a commit that was never pushed has nothing to fetch.
- It does not install Python packages. No release so far has needed that; if one adds a dependency, its notes will say so and the broker's virtual environment needs `pip install -r requirements.txt` as the broker's account, once.

## The passkey in the app's window

The window asks Windows for the passkey, as any app does. What it is offered depends on where your passkey lives:

- **Windows Hello** or a **security key**: offered directly.
- **A password manager** (1Password, Bitwarden): offered only if that manager is switched on as a passkey provider in Windows (*Settings > Accounts > Passkeys > Advanced options*, Windows 11 with the November 2025 update or later). A passkey held only by a browser extension is not offered, because extensions do not load in an app's window.

If yours is not offered, add one that is, once: open the broker's page in your usual browser, sign in, go to **Settings > Add a passkey**, confirm with the passkey you have, and when asked where to keep the new one choose *Windows Hello* (in a password manager's pop-up, the option to use the device instead). From then on the app's window signs in with Windows Hello. See [Adding a passkey from the private page](../docs/MANUAL_AUTHENTICATION.md#adding-a-passkey-from-the-private-page).

## What this does and does not protect

- The broker's page is a **remote page in its own window with no capability**: it cannot call anything in the app, and it cannot navigate away from the broker's address. It also has its own browser data folder, so it does not share an engine with the control window. The app's commands are each granted to the local control window only.
- The app runs as **you**, like the AI tools you use. The broker is protected from them by running as a different account. The app does not change that, but it does mean a program that can **edit this app, its settings file or the start script** could make the app launch something else as the broker's account when you type that password. Keep this folder, and the broker's start script, somewhere an AI tool cannot write, and hover over the password label when in doubt.
- **Stop, and closing the app, are hard stops.** The broker cannot log its NAS sessions out when it is ended this way, so they linger on the NAS until its own timeout. Press **Disconnect all** on the dashboard first if that matters. (A graceful stop from the app is a known follow-up.)
- **Trusting the CA** is a change to your Windows account that outlives the app: see above for when it is safe and how to undo it.

## Not yet checked on the real broker

These need the broker's account, its certificate and your passkey, so they were exercised only against a stand-in:

- **Update Broker** as the broker's account. The update line itself is tested against real git repositories, and the whole flow against a stand-in broker run as the developer's own account; what has not run is that line under the real account, with its own Git and network access.
- **Trust certificate** against Windows' real store. The call is tested on a store that exists only in memory; pressing the button and answering Windows' dialog is yours.
- **The passkey inside the app's window** (above).
- Whether DSM accepts one verification code for several sign-ins in a row (if not, *Sign in all* asks for the next code and carries on).

## Building

Needs Rust (`rustup`, stable MSVC), the Visual Studio *C++ build tools*, Node and git. From this folder:

```bash
npm install
npx tauri build --no-bundle      # synology-broker.exe in src-tauri/target/release/
node --test tests/view.test.js   # what the window shows for each status
cd src-tauri && cargo test       # config, alerts, launch and update lines, trust, levels
```

The build compiles in the commit it is made from (`git rev-parse HEAD`, or `BROKER_COMMIT` if that is set): that is the version **Update Broker** fetches, so make a release build from a commit that is on GitHub. If the repository is on a network share, set `CARGO_TARGET_DIR` to a local folder first: building on a share is slow and can fail.

A **debug** build (`npx tauri build --debug --no-bundle`) has two switches that a release build does not contain, for exercising the app end to end on a development machine: `SYNOLOGY_BROKER_DEV_RUN_AS_SELF` runs the start and update commands as your own account with no sign-in, and `SYNOLOGY_BROKER_DEV_ASSUME_TRUSTED` carries on as if Windows trusted a certificate that the `ca_file` verifies.

```
desktop/
  ui/         the control window (plain HTML, CSS and JS; no framework, no build step):
              view.js decides what to show for a status, app.js puts it on the page
  tests/      view.test.js (node --test)
  src-tauri/
    src/      main.rs (windows, close), commands.rs, launch.rs (CreateProcessWithLogonW,
              the update line), trust.rs (Windows' certificate store), monitor.rs (health,
              level and /attention), alerts.rs, tray.rs, config.rs, state.rs
    icons/    app icon and the three tray icons
```
