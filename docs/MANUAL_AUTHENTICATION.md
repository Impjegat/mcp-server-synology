# Manual authentication

How to use this server so that **your NAS password and one-time code never pass through an AI application**. You type them yourself, on a page only you can open, and the AI is told only whether the NAS is connected.

This is the recommended way to run the server. The older mode, where the server logs in with a password it is given in `.env` or `settings.json`, still exists and is described under [Legacy mode](#legacy-mode).

## What changes

| | Legacy mode | Manual authentication |
|---|---|---|
| Where the NAS password is | In `.env` or `settings.json`, readable by whatever can read that file | Nowhere on disk. You type it into a private page; it is used once to sign in and then forgotten |
| What the AI application launches | The full server, with the password in its environment or files | A small adapter that holds no NAS credential and cannot sign in |
| Who holds the NAS session | The server process the AI application started | A separate **broker** the AI application cannot reach except through the adapter |
| What happens when a session expires | The server logs in again by itself | The AI is told `AUTHENTICATION_REQUIRED`; you sign in again, privately |
| Tool that takes a password | `synology_login` | None. It does not exist in this mode |

## The three pieces

```
  AI application ──stdio──▶ adapter ──HTTPS + client token──▶ broker ──HTTPS──▶ NAS
   (Claude, ...)         holds no NAS             holds the DSM sessions,
                          credential              enforces the policy
                                                       ▲
                                  you, on a trusted device: passkey, then NAS password (+ code)
                                              (the private login page)
```

- **The adapter** (`adapter_main.py`) is what an AI application starts. It forwards the tool list and tool calls to the broker with this application's own *client token* and returns the answer. It has no NAS password, no session, no fallback and no way to sign in. If the broker is down, the model is told so.
- **The broker** (`broker_main.py`) holds the DSM sessions in memory only. It decides, per client, which NAS units, which tools and which folders are allowed, and it ends sessions on a timer.
- **The private login** is a separate page on the broker, on its own port. You open it with a passkey on a device you trust, see who is asking for what, and only then type your NAS password and code. A short-lived worker process uses them to sign in and exits.

Two different things authorize two different things:

| | What it allows | Who may hold it |
|---|---|---|
| Client token | Calling the tools the policy allows, for the NAS units and folders it allows | The AI application's adapter. It is *not* a login: it cannot sign in, read a session or open the private page |
| Your passkey, then your NAS password and code | Signing in to the NAS | You, and nobody else. Never an AI application |

## Who does what

Most of this guide is things **you** do, on purpose, because they are the steps an AI must not take for you.

| Step | You | The software |
|---|---|---|
| Choose and prepare the broker host | ✔ | |
| Create the NAS account for the integration, and its settings file | ✔ | |
| Make the TLS certificate | ✔ | |
| Make client tokens, write the policy | ✔ | `broker_main.py new-token` prints a token and its digest |
| Start the broker | ✔ | Refuses to start without TLS and a valid policy |
| Enrol your passkey | ✔ (needs a code made on the broker host) | One-time code, single use, expires |
| Register the adapter in each AI application | ✔ | The adapter refuses to start if a NAS credential is in its environment |
| Sign in to the NAS | ✔ (private page) | The AI is told `AUTHENTICATION_REQUIRED` until you have |
| Rotate the old password, enrol one-time codes | ✔ | |
| Hold the session, enforce folders and tools, expire sessions | | ✔ |

An AI assistant helping you with this can write files and explain steps. It should **not** be given the new password or a one-time code, and it should not run the commands on the broker host that print codes or tokens.

## Where the broker runs

This decides whether the whole thing is worth anything, so read it before you enter a real password anywhere.

The broker is only protected from the AI application if the AI application **cannot**:

- read the broker's files, memory, configuration, logs or the private login's state;
- edit the broker's code, dependencies, start-up command, policy, TLS setup or login page;
- administer the broker's host: over SSH, Docker, a mounted socket, a management API, remote execution, shared folders, backups or another connected tool;
- use your private device, its password manager, its authenticator or your recovery material;
- get the broker to run changes from a repository the AI application can edit.

**A separate machine** that the AI application's account has no access to is the straightforward answer. A broker on the NAS itself, or on the computer the AI application runs on, is acceptable only after you have shown that the account the AI application acts as (and every tool it has: file shares, SSH, container management) cannot reach the broker's files or administer it. **A container is packaging, not proof of that.** If you cannot show it, do not describe the password as out of the AI's reach, and do not enter or rotate a real password into that design.

Quick checks, from the AI application's side, using a dummy file: put a file with a recognisable dummy value where the broker keeps its config and state, and confirm that the AI application's tools (file browsing, search, container logs, anything with a shell) cannot find or read it.

## Setting it up

Everything below runs on the broker host unless it says otherwise. Example names (`broker.example.lan`, `nas1`) are placeholders.

### 1. An account and folders for the broker

Create an account that nothing the AI application runs as can use, and three directories it owns, mode `0700`:

```
/opt/synology-broker/synology-mcp   settings.json and broker-policy.json (mode 0600)
/opt/synology-broker/tls            cert.pem and key.pem
/opt/synology-broker/state          written by the broker: owner.json (your public passkey)
```

The broker looks for `settings.json` in `$XDG_CONFIG_HOME/synology-mcp/`, so running it directly means `XDG_CONFIG_HOME=/opt/synology-broker`. The container template mounts the first directory at `/config/synology-mcp` and sets that for you.

### 2. The NAS account and `settings.json`

Use a **dedicated NAS account for this server**, not your own. DSM's monitoring APIs generally need an administrator, so decide with eyes open: with an administrator account, the tools you allow and the folders in the policy are the limit on what the AI can do, because DSM itself will let that account do more. Give the account only the DSM application privileges it needs.

`settings.json` says where the NAS is and which account to sign in as. **It holds no password** and the broker refuses it if it does (naming the setting, never the value). See [`config/settings.broker.example.json`](../config/settings.broker.example.json):

```json
{
  "synology": {
    "nas1": { "host": "nas.example.lan", "port": 5001, "username": "mcp-reader", "note": "Primary NAS" }
  },
  "server": { "restricted_mode": true, "verify_ssl": true }
}
```

Put it in the first directory above, mode `0600`, owned by the broker's account (the broker refuses a settings file another account owns or others can read). Connections are HTTPS only, and the NAS's certificate is always verified: `verify_ssl` must be `true` (the default) or, for a NAS with a private certificate, the path of the CA bundle that signed it (a file or a directory, and it must exist). The broker refuses to start with `false`, an empty value or a CA path that is not there, because your password and code travel over that connection. The broker also refuses to follow a redirect from the NAS, so a wrong address or port is an error, not a detour.

### 3. A TLS certificate for the broker

The adapters talk to the broker over HTTPS, and your browser talks to the private page over HTTPS, so the broker needs a certificate valid for the exact name they use (`BROKER_HOST`). Use a certificate from a CA your devices already trust, or make a small private CA and give its *public* certificate to each adapter (`ca_file`). Keep the broker's private key (`key.pem`) readable only by the broker's account.

The broker will not start without TLS. (`--allow-plain-http-loopback` exists for local testing on `127.0.0.1` only.)

### 4. A token for each AI application

Make one token per application, so each can be revoked and scoped on its own:

```bash
python broker_main.py new-token
```

It prints the token, to hand to that application's adapter **once, over a private channel**, and its SHA-256 digest, which is all that goes in the broker's policy. The broker never stores a token.

### 5. The policy

One file, read at start-up, never writable by the AI. See [`config/broker.example.json`](../config/broker.example.json):

| Setting | Meaning |
|---|---|
| `clients.<name>.token_sha256` | The digest from step 4 |
| `clients.<name>.nas` | The NAS units (names from `settings.json`) this client may use |
| `clients.<name>.tools` | The tools it may call. Omit it for the default set: browsing, file reading and monitoring ([`TOOL_CATALOG.md`](TOOL_CATALOG.md), "On by default") |
| `clients.<name>.folders` | Per NAS, the folders it may reach. Anything outside is refused, including through symbolic links |
| `clients.<name>.disconnect` | Whether it may end a session (default `true`) |
| `deny_paths` | Folders refused for every client |
| `session` | `idle_seconds` (default 900), `absolute_seconds` (default 28800, never extended by use) and `pending_seconds` (default 300) |

Two things worth knowing:

- The broker applies **restricted mode as well as the policy**. To give a client a tool that changes things you need both the tool in its entry and `RESTRICTED_MODE=false` on the broker. Restricted mode is the better default.
- `synology_login` can never be granted, and the account, group and permission tools are off by default.

### 6. Start the broker

With the container template (see [`deploy/broker/`](../deploy/broker/)):

```bash
cd deploy/broker
cp broker.env.example broker.env       # host name, uid/gid, bind addresses, directories
docker compose --env-file broker.env up -d --build
```

Or directly:

```bash
XDG_CONFIG_HOME=/opt/synology-broker \
python broker_main.py serve --policy /opt/synology-broker/synology-mcp/broker-policy.json \
  --host 0.0.0.0 --port 8443 --allowed-host broker.example.lan:8443 \
  --tls-cert /opt/synology-broker/tls/cert.pem --tls-key /opt/synology-broker/tls/key.pem \
  --private-origin https://broker.example.lan:8444 --private-port 8444 \
  --private-allowed-host broker.example.lan:8444 --rp-id broker.example.lan \
  --owner-store /opt/synology-broker/state/owner.json
```

The private page is on its own port. Publish it only to the devices you will sign in from; the MCP port is the one the adapters reach.

A broker nobody has signed in to is *ready*, not unhealthy: `/healthz` and `/readyz` say nothing about the NAS, the clients or any session.

### 7. Enrol your passkey

Do this once, from a device you trust (a phone or computer with a passkey you control):

1. On the broker host, run `python broker_main.py enroll --owner-store /opt/synology-broker/state/owner.json new-code`. It prints a one-time code, valid for ten minutes, usable once. With the container: `docker compose --env-file broker.env exec broker python broker_main.py enroll --owner-store /state/owner.json new-code`.
2. On your trusted device open `https://broker.example.lan:8444/enroll`, type the code, and create the passkey.

The code can only be made on the broker host, which is why an AI application elsewhere cannot enrol itself. To add a second device later, run `new-code --add-device`. `enroll list` shows the enrolled passkeys and `enroll revoke ID` removes one. The broker stores only public keys.

### 8. Register the adapter in each AI application

Write the adapter's settings, for example `~/.config/synology-mcp/adapter.json` ([`config/adapter.example.json`](../config/adapter.example.json)):

```json
{
  "broker_url": "https://broker.example.lan:8443/mcp",
  "token_file": "~/.config/synology-mcp/broker.token",
  "ca_file": "/etc/synology-mcp/broker-ca.pem"
}
```

- `token_file` holds this application's token (from step 4) and is read on every call, so replacing it needs no restart. Make it readable only by you; the adapter warns at start-up if other accounts can read it. Or use `token_env` to name an environment variable instead.
- `ca_file` is the CA that signed the broker's certificate, only if your devices do not already trust it.
- There is no setting for a NAS credential. The adapter refuses a setting named like a password, token or session, and **it will not start if `SYNOLOGY_PASSWORD`, `SYNOLOGY_OTP_CODE` or `SYNOLOGY_DEVICE_ID` is in its environment**, because a registration that still carries a password is exactly what this removes.

Then point each application at the adapter. **Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "synology": {
      "command": "python",
      "args": ["/path/to/mcp-server-synology/adapter_main.py", "--config", "/path/to/adapter.json"]
    }
  }
}
```

**Claude Code:**

```bash
claude mcp add --scope user synology -- python /path/to/mcp-server-synology/adapter_main.py --config /path/to/adapter.json
```

Any other application that launches a stdio MCP server works the same way. With Docker, run the adapter image (`docker build --target adapter`) with the config and token mounted read-only:

```json
{
  "command": "docker",
  "args": ["run", "--rm", "-i",
           "-v", "/path/to/adapter.json:/config/adapter.json:ro",
           "-v", "/path/to/broker.token:/run/secrets/broker-token:ro",
           "-v", "/path/to/broker-ca.pem:/config/broker-ca.pem:ro",
           "synology-mcp-adapter", "--config", "/config/adapter.json"]
}
```

(set `token_file` to `/run/secrets/broker-token` and `ca_file` to `/config/broker-ca.pem` in that config).

Restart the application. It should list the tools straight away, even before you have signed in, and `synology_status` should say it is waiting for you.

## Using it

1. Ask the AI something that needs the NAS. The first call that needs a session is answered `AUTHENTICATION_REQUIRED`, and the AI tells you to sign in. It **does not and must not** ask you for your password: this server gives it nowhere to put one.
2. Open the private page on your trusted device and sign in with your passkey. You see a table of clients and NAS units; the one waiting says so.
3. Choose **Sign in** (or **Continue**). Before you type anything, the page shows which NAS and account it is for, which client asked, how many tools it gets and which folders it can reach. Check that it is what you expect.
4. Type your NAS password, and the verification code if the account uses one. Submit. The worker signs in, hands the session to the broker and exits; the password is not kept.
5. Ask the AI again.

**How long it lasts.** A session ends after 15 minutes without use or 8 hours in all, whichever comes first (the policy can change both; use never extends the 8 hours). Restarting the AI application does not extend it and does not end it. The page's **Disconnect** button, or the `synology_logout` tool if the client may use it, ends it at once and logs out of the NAS. Either also withdraws a sign-in that is still being made, and so does cancelling the request from the front page, or letting it expire: a password you have just submitted cannot complete a connection you have just ended, and a session the NAS opened for it is logged out again, never used. Submit once; a second submit while the first is still running is told to wait.

**If you mistype.** Three wrong answers in five minutes lock that sign-in for ten, well inside what DSM's own auto-block tolerates, and a locked sign-in does not contact the NAS. Asking for a code, an unreachable NAS and a certificate problem do not count against you.

## Turning on one-time codes (OTP)

Enrolling a code changes your NAS account, so you do it yourself, privately, after the sign-in above works. The server can describe the steps but must never see the authenticator's seed or your recovery material.

1. Decide which account this is and check that you have a working way back in if the code device is lost. Administrator and ordinary-user recovery differ; do not assume an email reset exists.
2. On your trusted device, sign in to DSM, open that account's security / two-step verification settings, scan the QR code with your authenticator and finish the check.
3. Keep the QR code, the seed and any recovery codes out of chat, files, shares and logs.
4. **Do not tick "trust this device".** The broker asks DSM for no reusable device token and takes a fresh code at each sign-in. The code is needed to sign in, not for every tool call.
5. Test with a few controlled attempts: a correct password and code signs in; a wrong or missing code does not.

If you use a password manager, use it on your trusted device only; do not give an AI application, or this server, access to your vault.

## Moving from the old setup

The old setup left your password in places an AI application can read. Cutting over means **removing it everywhere and then changing it**. In this order:

1. Bring the broker up and prove the checks in [Where the broker runs](#where-the-broker-runs), using dummy values.
2. Stop every old server: the containers, background processes and scheduled launchers. Their cached passwords and sessions must not survive.
3. Register the adapter in **every** application that started the old server. They are easy to miss: Claude Desktop's config, Claude Code's (`claude mcp list`), and any other launcher you installed.
4. Delete the old credentials: `.env` in the repository, `password`, `otp_code` and `device_id` in `settings.json`, and `SYNOLOGY_PASSWORD` or similar in any application's environment. Look in backups and history too; changing the password makes any copy useless but does not erase it.
5. Check from the AI application's side that it can see the tool list and status while disconnected, and cannot read or change the broker's files.
6. Only then, **change the NAS password in DSM yourself**, on your trusted device. Do not tell the new one to an AI application.
7. Sign out the old sessions and trusted devices in DSM. A password change does not necessarily end them.
8. Enrol one-time codes (above), sign in through the private page, and run a read-only health check, a folder check, a disconnect and an expiry check.

**Rollback.** If the new setup fails: stop the broker, let its sessions go, and leave the adapter disconnected. Restore a reviewed previous broker release if you have one. Do **not** put the old password-based server back as the automatic fallback, switch off TLS or codes, widen the folders, or turn off restricted mode to get things working.

## When something is wrong

What the AI reports, and what it means:

| Code | Meaning | What to do |
|---|---|---|
| `AUTHENTICATION_REQUIRED` | The NAS has no session | Sign in on the private page |
| `AUTHORIZATION_DENIED` | The policy does not allow that tool, NAS or folder | Check the client's entry; this is by design |
| `BROKER_UNAVAILABLE` | The adapter cannot reach the broker | Is it running? Is `broker_url` right? Is the port reachable from here? |
| `BROKER_TIMEOUT` | The broker did not answer in time | Check the broker and the network; long searches are bounded |
| `BROKER_CERTIFICATE_ERROR` | The adapter does not trust the broker's certificate | Set `ca_file`, or fix the certificate's name |
| `BROKER_TOKEN_MISSING` | No token was found | Check `token_file` or `token_env` |
| `BROKER_TOKEN_INVALID` | The token is not shaped like one | It is too short, or has spaces or line breaks in it |
| `BROKER_UNAUTHORIZED` | The broker does not accept this token | Is its digest in the policy? Was it rotated? |
| `BROKER_REFUSED`, `BROKER_BUSY`, `BROKER_ERROR`, `BROKER_PROTOCOL_ERROR` | The broker refused, was busy, or answered unexpectedly | Look at the broker's log |

Other things people hit:

- **The adapter will not start and names `SYNOLOGY_PASSWORD`.** A registration still passes a credential. Remove it.
- **The broker will not start and names a setting.** The policy or `settings.json` is wrong, or `settings.json` contains a password. Messages name the setting, never a value.
- **"No owner enrolled" on the private page.** Run the enrol steps (step 7).
- **The passkey prompt does not appear.** The page must be opened at exactly the address in `--private-origin`, over HTTPS, and the certificate must be trusted by that device.
- **The NAS says the address is blocked.** DSM's auto-block caught repeated failures. Wait, or unblock it in DSM, and see the lockout above.

## What this protects, and what it does not

It protects **the password and one-time code** from an AI application and from anything an AI application can read: they are entered once on a page it does not control and are not stored. It limits **what an AI can do on the NAS** to the tools, units and folders in the policy, whatever the NAS account itself could do.

It does **not**:

- stop the AI from seeing what the allowed tools return. File contents and logs it reads go to the AI application and its provider. The [tool catalog](TOOL_CATALOG.md) marks those tools.
- help if the broker's host is not really out of the AI's reach. That is the whole assumption.
- stop someone who holds your trusted device and its passkey, or who can watch you type.
- remove the old password from backups and history. Changing it makes them useless.
- make an administrator NAS account less powerful than it is.

## Legacy mode

The single-process server that logs in with a stored password still works, for a machine you alone use: `main.py`, `docker-compose.yml` at the top of the repository, and `.env` or `settings.json` with `password`. It is a separate entry point, not a fallback: the adapter cannot start it, and the broker never reads a `.env`. If you keep it, understand that the password is readable by whatever can read those files.

## Reference

| File | What it is |
|---|---|
| `adapter_main.py`, `src/adapter/` | The adapter |
| `broker_main.py`, `src/broker/`, `src/private_auth/` | The broker and the private login |
| `config/adapter.example.json` | Adapter settings |
| `config/broker.example.json` | Broker policy |
| `config/settings.broker.example.json` | NAS endpoints for the broker |
| `deploy/broker/` | Container template for the broker |
| `Dockerfile` | `--target adapter`, `--target broker`, and `legacy` |
| [`TOOL_CATALOG.md`](TOOL_CATALOG.md) | Every tool, in plain language |
| `plans/2026-10-06-manual-authentication/PLAN.md` | The design and its reasoning |
