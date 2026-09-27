# Auth & multi-NAS targeting

## Tools

| Tool | What it does |
|------|--------------|
| `synology_status` | Show which sessions are active across all configured NAS units |
| `synology_list_nas` | List configured NAS units (name, URL, connection status) |
| `synology_login` | Manually log in to a NAS — only needed when auto-login is off or has failed |
| `synology_logout` | End a session — almost never needed in normal use |

## The auth state machine

The MCP server logs in automatically at startup for every NAS configured in `~/.config/synology-mcp/settings.json` (or the legacy `.env`). Sessions persist for the server's lifetime. So:

- **Default state**: every configured NAS is already authenticated. You can call file/download/health tools immediately.
- **If a tool returns an auth error**: call `synology_status` to see what's wrong. The session may have timed out or the credentials may be invalid.
- **If status confirms no active session**: then — and only then — call `synology_login` with the relevant `nas_name`.

Don't preface a workflow with `synology_login`. It's noise 99% of the time and confuses users who expect the server to "just be connected."

## Multi-NAS targeting

Every operational tool accepts:

- `nas_name` — the identifier from settings.json (e.g., `"nas1"`, `"backup"`). Preferred.
- `base_url` — full HTTPS URL like `"https://192.168.1.100:5001"`. Fallback when the NAS isn't configured. Plain `http://` is rejected.

### Picking a target

1. Call `synology_list_nas` to see what's configured.
2. If the user named a NAS by note/identifier, match it to a `nas_name`.
3. If only one NAS is configured, you can omit the target argument entirely.
4. If multiple are configured and the user is ambiguous, **ask** which one. Don't guess based on alphabetical order or "the first one".

### When to use base_url instead

`base_url` is for one-off connections to a NAS that isn't in settings.json — e.g., the user is testing a new device or troubleshooting from a different network. For everything else, prefer `nas_name`: it's shorter, picks up credentials automatically, and survives IP changes.

## settings.json — what to know

Lives at `~/.config/synology-mcp/settings.json` (XDG standard). The file requires `chmod 600` permissions; the server will refuse to load it otherwise. Schema (abridged):

```json
{
  "synology": {
    "nas1": {
      "host": "192.168.1.100", "port": 5001,
      "username": "...", "password": "...",
      "note": "Primary",
      "otp_code": "123456",
      "device_id": "did_returned_by_dsm"
    },
    "nas2": { "host": "192.168.1.200", "port": 5001, "username": "...", "password": "...", "note": "Backup" }
  }
}
```

`otp_code` and `device_id` are both optional. `device_id` wins over `otp_code`. Workflow: set `otp_code` once → start the server with auto-login enabled → on the first successful login the server saves the device token into `settings.json` itself (it's never logged or returned, per the credential-handling policy — there's nothing to copy by hand) → `otp_code` is now redundant and can be deleted. From then on, OTP is no longer needed.

Every connection is HTTPS-only regardless of port — there is no HTTP fallback. 5001 is DSM's default HTTPS port (and the default here when `port` is omitted); a custom port still connects over HTTPS. The `note` is for the user's reference — surface it when listing NAS units to a user, since human-readable notes ("primary", "backup") are easier to reason about than `nas1`/`nas2`.

## Gotchas

- **2FA / OTP**: the server supports DSM accounts with 2FA enabled. Two ways to log in:
  - Interactive (one-shot): call `synology_login` with an `otp_code` argument. DSM issues a device token on success, but the tool never returns, logs, or persists it (credential-handling policy) — there's no way to retrieve it from this call, so don't retry expecting one. Every future interactive login needs a fresh OTP code.
  - Persistent: store `device_id` (long-lived trusted-device token) per-NAS in `settings.json`. Auto-login then skips OTP, and silent re-login after DSM error 119 also uses the device token. When `device_id` is set, `otp_code` is ignored.
  For `.env` legacy single-NAS, `SYNOLOGY_OTP_CODE` is honored as a one-shot code on first login; for ongoing reuse, migrate to `settings.json`.
- **Session expiry**: long-idle sessions can be invalidated by DSM. If a tool returns a session error, re-running after a `synology_login` usually fixes it. Don't loop on retry — diagnose with `synology_status` first.
- **Stale `secrets.json` references**: some tool descriptions still say "from secrets.json". The actual file is `settings.json`. This is a docs bug in the MCP, not a config you need to recreate.

## Workflow examples

### "Am I connected?"

```
synology_status
```

Returns connection state for each configured NAS. If everything is green, you're done.

### "List my NASes"

```
synology_list_nas
```

Returns names, URLs, notes, and connection status. Surface the `note` field to the user — it's the human label.

### "Log out of nas2"

```
synology_logout(nas_name="nas2")
```

Almost never needed in normal use, but available for cleanup or when rotating credentials.
