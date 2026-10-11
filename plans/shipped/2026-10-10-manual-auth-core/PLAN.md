# Manual authentication core: config modes, no stored secrets, typed session loss

**Written:** 10 October 2026
**Roadmap:** [`../2026-10-10-manual-auth-roadmap/PLAN.md`](../2026-10-10-manual-auth-roadmap/PLAN.md), PR 1
**Source plan:** §2, §4.3, §6.1 and §7.1 of [`../2026-10-06-manual-authentication/PLAN.md`](../2026-10-06-manual-authentication/PLAN.md)

## What this changes

A new `SYNOLOGY_AUTH_MODE=broker` mode (default `legacy`, unchanged). In it the process holds no NAS password, one-time code or trusted-device token, never signs in by itself, and never renews a lost session from a stored secret. A lost session becomes a typed `AuthenticationRequired` error instead of a raw DSM code.

| Area | Change |
|---|---|
| `src/config.py` | `auth_mode`; NAS endpoints load without a password; stored credentials and auto-login rejected by setting name, never value; no `.env`; `save_device_id` refuses; a bare `SYNOLOGY_URL` becomes the `default` endpoint |
| `main.py` | No `load_dotenv()` in broker mode |
| `src/auth/synology_auth.py` | `manual_mode`: no `_credentials`, no `enable_device_token`, no `did` kept or returned, `device_id` refused, `relogin()` never signs in, `logout()` always clears local state |
| `src/broker/errors.py` (new) | `AuthenticationRequired`, `AuthorizationDenied`, `is_session_lost` (106, 107, 119) |
| `src/utils/synology_api.py` | Shared client raises `AuthenticationRequired`; `raise_if_authentication_required` and `recover_session` for modules that make their own calls |
| `src/filestation/...`, `src/downloadstation/...` | Lost session raises in broker mode, including download and hand-built requests. Legacy mode now renews once on 119 and repeats a read, never a write. Download Station's default-value fallbacks no longer hide a lost session |
| `src/mcp_server.py` | No `synology_login` in broker mode (registry, discovery, validators); starts disconnected; `install_session()`; `_require_session`; only a configured NAS as `base_url`; typed errors become flagged results; logout works for an installed session |

## Left for later PRs

- Excluding secret-bearing container fields (environment, mounts, logs) from the default tool set belongs with the broker policy in PR 2 (`allowed_tools`), because it is a tool-scope decision, not a session one.
- A real private login that calls `install_session` is PR 3. Until then a broker-mode server is disconnected unless something installs a session.

## Acceptance criteria

- Legacy mode behaves as before: the existing hermetic suite passes unchanged (387 passed, 2 skipped).
- Broker mode rejects every stored-credential setting by name and never echoes a value.
- No tool schema in broker mode has a `password`, `otp_code` or `device_id` property, and calling `synology_login` is a protocol error.
- A lost session (106, 107, 119) is `AUTHENTICATION_REQUIRED` from the shared client, File Station and Download Station; a permission error (105) is not.
- Nothing in broker mode makes a login request on its own.

## Verification

`tests/test_manual_auth.py` (56 tests, fake endpoints and dummy values only). Breaking the code on purpose makes it fail: with the shared client's check disabled 12 tests fail, with the stored-credential check disabled 8 fail, and with the manual-login guard disabled 1 fails. `pytest -m "not real_nas"`, `ruff` and `black` are clean.
