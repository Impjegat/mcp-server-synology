# PR 1: Credential-and-session-leak hardening

Status: Implemented
Initiated: 2026-09-27
GitHub PR: [Impjegat/mcp-server-synology#2](https://github.com/Impjegat/mcp-server-synology/pull/2)
Implements: `REMEDIATION_PLAN.md` §1 (Remove credentials and tokens from output), plus the timeout/retry-rule portion of §4 that's specific to `src/auth/synology_auth.py`.

## Why

The remediation review (see repo root `REMEDIATION_PLAN.md`) found that DSM session IDs, SynoTokens, trusted-device tokens, and (via exception text) passwords can all reach MCP tool output and process logs today. Login also sends the password/OTP/device-token in a URL query string, and its API-version-fallback retry treats several genuine authentication-outcome errors (disabled account, IP auto-blocked, 2FA required) as reasons to keep retrying, which resubmits the password each time. This PR closes those paths before any of the other remediation work (restricted mode, connection defaults, packaging) lands, since the account this server runs as is a dedicated NAS administrator — leaking its credentials or session is the highest-severity failure mode in scope.

## Changes

1. **New `src/utils/redact.py`**: a `redact()` function that masks known live secrets (current session IDs, SynoTokens, device IDs, configured passwords) plus pattern-masks `_sid=`, `passwd=`, `password=`, `SynoToken=`, `device_id=`, `otp_code=` wherever they appear in text. Includes a `logging.Filter` wrapper for use on the process's log handlers.
2. **`main.py`**: attach the redacting log filter to the handler `logging.basicConfig` creates.
3. **`src/mcp_server.py`**: redact the text of every tool response at the single point `handle_call_tool` returns it, and stop logging the full trusted-device token — log only that one was issued and where it's stored.
4. **`src/auth/synology_auth.py`**:
   - Login switches from `requests.get(..., params=payload)` to `requests.post(..., data=payload)`.
   - Both login and logout get bounded timeouts.
   - The API-version-fallback retry now stops immediately on any DSM auth-outcome error code, and only falls back to another version on an API/version-unsupported error or a transport exception.
5. **`src/utils/synology_api.py`, `src/downloadstation/synology_downloadstation.py`, `src/filestation/synology_filestation.py`**: redact exception text before it's returned/re-raised; catch previously-uncaught `requests` exceptions in FileStation; fix two call sites (`create_file`'s hand-built URL, the upload method's `params=`) that put `_sid` in the query string even though nothing required it to be there.
6. **`src/config.py`**: best-effort Windows ACL restriction on `settings.json`/token storage; atomic (`temp file + os.replace`) writes that preserve untouched keys.
7. **`src/utils/logger.py`**: removed — unused (no importer anywhere in the repo); logging setup already lives in `main.py`.

## Acceptance criteria

- Tests with recognizable dummy secrets confirm no leak in successful responses, failed responses, or captured logs, across auth, filestation, downloadstation, and the shared API client.
- A test confirms the login request sends its password via POST body, not URL query string.
- The retry-rule tests confirm an auth-outcome error code does not trigger a second API-version attempt, while an API/version-unsupported code does.
- Existing 2FA / device-token-reuse / session-renewal / logout regression tests still pass unchanged.

## Verification

- `pytest -m "not real_nas"` — full non-live suite, including new/updated tests in `tests/test_auth.py`, `tests/test_download_station.py`, `tests/test_file_station.py`, and a new `tests/test_redact.py`. Result: 79 passed, 3 skipped (real_nas-gated fixtures, no credentials in this environment), 2 pre-existing failures in `tests/test_config.py` confirmed unrelated (reproduce identically on the unmodified pre-PR1 code — a test-isolation bug where a `monkeypatch.delattr(os, "getuid")` in one test bleeds into a later test's fresh module import; not touched by this PR, left for whoever picks up PR 4's test-isolation work).
- Manual check: ran `python main.py` against a NAS entry pointing at an unreachable host (`10.255.255.1`) with a recognizable dummy password. Confirmed the process's stderr contains no trace of the password, and that it fails within the new auth timeout rather than hanging.
- Manual read-through of the diff confirming every changed `requests.*` call site's `params=`/`data=` split matches intent (a `params=` dict on a POST still leaks into the URL, as `_make_upload_request`'s bug demonstrated).
- `ruff check` and `black --check` both clean on every changed file.

## Scope note: one test deferred to PR 3

The original design listed an `omitted port defaults to 5001` test under this PR's tests. That fix (`config.py`'s `port = nas_info.get("port", 5000)` → `5001`) is `REMEDIATION_PLAN.md` §4 scope, assigned to PR 3 (`connection-defaults-and-bounds`), not this one — PR1 doesn't touch the port default. Adding the test here without the fix would ship a deliberately red test, so it's deferred to land together with its fix in PR 3.

## Review round 1 (GitHub PR review, `@claude review this`)

Two real findings, both fixed and pushed (commit `c13d6ff`):

- `logout()` (`src/auth/synology_auth.py`) still sent `_sid` via a GET query string — the PR gave `login()` the POST fix and only a timeout/redaction backstop to `logout()`, missing the actual source fix. Switched to POST.
- `_atomic_write_settings()` (`src/config.py`) created its temp file via `write_text()` (default umask) and `chmod`'d it to 0600 only afterward, leaving a brief window where the full settings file — every configured NAS's password — sat at ambient-umask permissions. Now creates the temp file already restricted via `os.open(..., 0o600)`.

Also folded in a non-blocking nit from the same review: `redact.py`'s `_PARAM_PATTERN` now anchors to a key-name boundary so an unrelated key merely ending in `_sid` etc. isn't over-redacted.

New tests: `test_logout_sends_session_id_via_post_not_url`, a boundary-anchoring case in `test_redact.py`, and `save_device_id()` gets test coverage for the first time (permission + field-preservation). Full suite: 83 passed, 3 skipped, same 2 pre-existing unrelated failures.

## Result

All changes above are implemented, tested, and committed. See the top-level `REMEDIATION_PLAN.md` for how this fits into the overall roadmap.

## Out of scope (tracked separately)

- The tool registry / restricted-mode work (`REMEDIATION_PLAN.md` §3) — separate PR, since it's a larger, independent surface (dispatch unification, deny-by-default enforcement).
- Port defaults, CA-bundle support, `search_files`/`get_file_content` bounds (§4 remainder) — separate PR.
- Docker/packaging and test-isolation-ordering fixes (§2, §5) — separate PR.
