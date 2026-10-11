# Auth & multi-NAS targeting

## Two ways the server is set up, and how to tell which

| | Manual authentication (recommended) | Legacy |
|---|---|---|
| Who signs in to the NAS | **The user**, privately, on a page you cannot open | The server, with a stored password |
| `synology_login` | Does not exist. It is not in your tool list | Exists when auto-login is off or failed |
| When there is no session | A tool answers `AUTHENTICATION_REQUIRED` | A tool answers a session error |

You can tell from your tool list: **no `synology_login` means manual authentication.** The calls below work the same way in both.

## The one rule: never ask for a NAS password or one-time code

Whatever the mode, do not ask the user to type or paste their NAS password, one-time code, session id or device token into the chat, and do not put one into a tool call. In manual authentication there is nowhere to put one, and the point of that mode is that the secret never passes through you. If a user offers a password in the chat, tell them not to share it, and that signing in is done on the private page.

## Tools

| Tool | What it does |
|------|--------------|
| `synology_status` | Show which sessions are active across all configured NAS units |
| `synology_list_nas` | List configured NAS units (name, URL, connection status) |
| `synology_login` | **Legacy mode only.** Log in to a NAS. Absent with manual authentication |
| `synology_logout` | End a session — almost never needed in normal use |

`synology_status` and `synology_list_nas` work with nobody signed in. They are how you find out what is wrong.

## Manual authentication: what to do when there is no session

A tool that needs the NAS answers with an error that starts `AUTHENTICATION_REQUIRED`. That means the user has not signed in, or the session ended (it expires after a period of no use and after a fixed total time, and the user can disconnect it).

1. **Stop.** Do not retry in a loop, and do not look for another tool that gets around it.
2. Tell the user, in plain words, that the NAS needs them to sign in, and that they do it themselves on their private sign-in page, with their passkey and then their NAS password (and code, if their account uses one). You cannot do it for them and you will not see what they type.
3. Wait. When they say they have signed in, repeat the call you were making.

Say it once, briefly. For example: "The NAS isn't signed in. Could you sign in on your private sign-in page? I can't do that part, and I won't see your password. Tell me when you're done and I'll carry on."

`AUTHORIZATION_DENIED` is different: the server's policy does not allow that tool, NAS or folder for this application. It is by design. Tell the user what was refused; do not look for a workaround. If they want it allowed, that is a change to the broker's policy, which only they can make.

If `synology_status` itself fails with a `BROKER_...` code, the adapter cannot reach the broker (or does not trust its certificate, or has no valid token). Report the code; the user's guide lists what each one means.

## Legacy mode: the auth state machine

The server logs in automatically at startup for every NAS configured in `~/.config/synology-mcp/settings.json` (or the legacy `.env`). Sessions persist for the server's lifetime. So:

- **Default state**: every configured NAS is already authenticated. You can call file/download/health tools immediately.
- **If a tool returns an auth error**: call `synology_status` to see what's wrong. The session may have timed out or the credentials may be invalid.
- **If status confirms no active session**: then — and only then — `synology_login` is the tool for it. Its `password` is a secret the user would have to type into this conversation, which is exactly what you should avoid: prefer asking the user to fix the server's configuration (or to move to manual authentication) over asking for a password here.

Don't preface a workflow with `synology_login`. It's noise 99% of the time and confuses users who expect the server to "just be connected."

## Multi-NAS targeting

Every operational tool accepts:

- `nas_name` — the identifier from settings.json (e.g., `"nas1"`, `"backup"`). Preferred.
- `base_url` — full HTTPS URL like `"https://192.168.1.100:5001"`. Fallback when the NAS isn't configured. Plain `http://` is rejected. With manual authentication, only a configured NAS is accepted.

In restricted mode (the default), once any NAS is configured, `synology_login` (legacy) refuses a `base_url` that isn't one of the configured NAS units — so a one-off login to an unconfigured NAS needs `RESTRICTED_MODE=false`.

### Picking a target

1. Call `synology_list_nas` to see what's configured.
2. If the user named a NAS by note/identifier, match it to a `nas_name`.
3. If only one NAS is configured, you can omit the target argument entirely.
4. If multiple are configured and the user is ambiguous, **ask** which one. Don't guess based on alphabetical order or "the first one".

### When to use base_url instead

`base_url` is for one-off connections to a NAS that isn't in settings.json — e.g., the user is testing a new device or troubleshooting from a different network. For everything else, prefer `nas_name`: it's shorter and survives IP changes.

## settings.json — what to know

Lives at `~/.config/synology-mcp/settings.json` (XDG standard) on the machine that runs the server (the **broker**'s host in manual authentication). The file requires `chmod 600` permissions and to be owned by the account running the server; the server will refuse to load it otherwise. Schema (abridged):

```json
{
  "synology": {
    "nas1": { "host": "192.168.1.100", "port": 5001, "username": "...", "note": "Primary" },
    "nas2": { "host": "192.168.1.200", "port": 5001, "username": "...", "note": "Backup" }
  }
}
```

**With manual authentication this file holds no password, one-time code or device token, and the server refuses to start if it does** (naming the setting, never the value). Legacy mode additionally reads `password`, `otp_code` and `device_id` per NAS from it.

Every connection is HTTPS-only regardless of port — there is no HTTP fallback. 5001 is DSM's default HTTPS port (and the default here when `port` is omitted); a custom port still connects over HTTPS. The `note` is for the user's reference — surface it when listing NAS units to a user, since human-readable notes ("primary", "backup") are easier to reason about than `nas1`/`nas2`.

The same file has a `"server"` block for the server's own options: `verify_ssl` (`true`, or a CA bundle file path for a private CA; legacy mode also accepts `false`, manual mode never does), `restricted_mode` (default `true`), `max_file_content_size`, `session_timeout`, `log_level` and `debug` (and, in legacy mode, `auto_login`).

## Gotchas

- **Failures are errors**: a failed login or logout, or a call with no active session, comes back as a result with `isError: true`. An argument of the wrong type is refused with a message that names the field but never repeats the value, so a mistyped password is not echoed back.
- **Session expiry**: long-idle sessions end (the policy sets the limits in manual authentication; DSM can also invalidate them). In manual authentication, expiry looks exactly like never having signed in: `AUTHENTICATION_REQUIRED`, and the user signs in again. Don't loop on retry — diagnose with `synology_status` first.
- **Two-factor accounts**: with manual authentication the user types the one-time code on the private page each time they sign in, and nothing is stored. (Legacy mode can instead hold a trusted-device token; do not try to retrieve or handle one.)
- **Old `secrets.json` wording**: older builds of the MCP said "from secrets.json" in some tool descriptions, and a `synology_list_nas` message told users to create `~/.config/synology-mcp/secrets.json`. The actual file has always been `settings.json`; there is nothing to recreate.

## Workflow examples

### "Am I connected?"

```
synology_status
```

Returns connection state for each configured NAS. If everything is green, you're done. If it says a NAS is waiting for the user to sign in, tell them (once) to sign in on their private page.

### "List my NASes"

```
synology_list_nas
```

Returns names, URLs, notes, and connection status. Surface the `note` field to the user — it's the human label.

### "Log out of nas2"

```
synology_logout(base_url="https://nas2.example:5001")
```

(`base_url` is the NAS's address from `synology_list_nas`; this tool does not take `nas_name`.) Almost never needed in normal use, but available for cleanup. With manual authentication it may not be offered to this application at all; the user can disconnect from their private page.
