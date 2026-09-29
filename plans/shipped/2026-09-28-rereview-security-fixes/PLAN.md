# PR: Rereview security fixes

Status: Shipped — PR #9
Initiated: 2026-09-28
GitHub PR: [Impjegat/mcp-server-synology#9](https://github.com/Impjegat/mcp-server-synology/pull/9)
Implements: findings 1, 2, 3 from [`REVIEW_REPORT.md`](../2026-09-28-rereview-followups/REVIEW_REPORT.md) — see [the follow-ups plan](../2026-09-28-rereview-followups/PLAN.md) for the full verdict table

## Why

Three findings from an independent rereview of the merged remediation roadmap, done first because they're security-relevant:

1. **`RESTRICTED_MODE` parsing fails open** (`src/config.py:114`) — only the literal string `true` is treated as "on"; `1`, `yes`, and `true ` (trailing space) all silently disable restricted mode, which is the only thing stopping the admin account from taking write actions.
2. **Log redaction misses exception objects, tracebacks, and configured-but-not-yet-live secrets** (`src/utils/redact.py`) — the filter only redacts string messages and string `%s` args; a chained exception's traceback (logged at DEBUG via `exc_info=True`) can still carry `_sid=`.
3. **A failed Windows ACL restriction doesn't stop the settings write** (`src/config.py:211`) — `_atomic_write_settings` reports success even when `_restrict_file_permissions` failed, so the device-token save can leave `settings.json` world-readable on Windows.

## Changes

### Finding 3 — `src/config.py`

- New `_parse_restricted_mode(value) -> bool`, reusing the existing `_VERIFY_SSL_TRUTHY`/`_VERIFY_SSL_FALSY` sets (`config.py:31-32`). Only an explicit false value (`false`/`0`/`no`/`off`, case/whitespace-insensitive) disables restricted mode; anything else — including a value the parser doesn't recognize — leaves it **on** and logs a warning naming the unrecognized value.
- Apply it at both existing read sites: the `RESTRICTED_MODE` env var (`:114`) and `settings.json`'s `restricted_mode` key (`:374`). For `settings.json`, a JSON boolean passes straight through; a string goes through the same parser; anything else (e.g. `null`) leaves restricted mode on with a warning.

### Finding 1 — `src/utils/redact.py`, `src/config.py`, `main.py`, `src/mcp_server.py`

- `RedactingFilter.filter`: use `record.getMessage()` to get the fully-formatted string (handles exception objects and non-string args passed via `%s`), redact it, assign to `record.msg`, and clear `record.args`. Fall back to today's per-arg redaction if `getMessage()` raises.
- When `record.exc_info` is set, pre-render the traceback via `logging.Formatter().formatException(record.exc_info)` (which includes chained exceptions), redact it, and store the result in `record.exc_text` — the stdlib formatter uses a pre-filled `exc_text` instead of re-rendering. Same treatment for `record.stack_info`.
- New `config.iter_configured_secrets()`: yields every configured password, `device_id`, and `otp_code` across all NAS units (settings.json and the legacy `.env` path), so secrets are masked even before a session exists to make them "live".
- Chain it into the existing `iter_live_secrets()` call sites: `main.py:53` (the logging filter) and `src/mcp_server.py:622`/`:635` (tool-response redaction).

### Finding 2 — `src/config.py:178-239`

- `_restrict_file_permissions` returns `bool` instead of `None`.
- `_atomic_write_settings`: create the temp file via `tempfile.mkstemp(dir=CONFIG_DIR)` (unique name, avoids concurrent-writer collisions on the current fixed `settings.json.tmp`), restrict its permissions immediately while it's still empty, and only then write the secret-bearing content. If restriction fails, delete the temp file, leave the existing `settings.json` untouched, and return `False`. Wrap the whole body in `try/finally` so the temp file is never left behind on any exit path.
- `save_device_id`'s existing handling of a `False` return (log a warning, ask for OTP again next time, never fall back to printing the token) is unchanged — this PR only makes the return value trustworthy.

## Tests

- `tests/test_config.py`: parametrized `_parse_restricted_mode` cases — restricted for `1`, `yes`, `true `, `TRUE`, `garbage`; unrestricted for `false`, `0`, `no`, ` Off `; `settings.json` cases for `null`, `"false"`, `false`.
- `tests/test_config.py`: `_atomic_write_settings` returns `False` and leaves the original file untouched when permission-restriction fails (mock `_restrict_file_permissions` to return `False`); no stray temp files remain afterward.
- New `tests/test_redact.py` additions (or extend the existing redaction tests): an exception object passed through `%s` gets redacted; a chained `RequestException` logged with `exc_info=True` has `_sid=` scrubbed from its rendered traceback; a configured-but-unused password is redacted via `iter_configured_secrets()`.

## Verification

- `pytest -m "not real_nas"` and the full suite, both clean.
- `ruff check` / `black --check` clean.
- Manual probe: `RESTRICTED_MODE=1 python -c "from config import config; print(config.restricted_mode)"` prints `True`.
