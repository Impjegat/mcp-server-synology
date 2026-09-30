# PR: Follow-up review fixes (validation echo, health summary, polling budgets)

Status: Shipped — pushed to `claude/vibrant-mccarthy-mpyaus` (no pull request opened yet)
Initiated: 2026-09-30
Implements: the three open findings in `REVIEW_FOLLOWUP_2026-09-29.md` (a follow-up review of `main` at `587dcfc`; the document lives outside this repository)

## Why

The follow-up review confirmed the migration, the Docker image and the missing-file fix, and reproduced three findings that the earlier PRs had left open. Each was reproduced again against `587dcfc` before any change was made:

1. **P1 — newly submitted credentials are echoed.** `_validate_arguments` returned jsonschema's own message, which quotes the rejected value. A `password`, `device_id` or `otp_code` of the wrong type came back in the tool result (`['…'] is not of type 'string'`) and in DEBUG logs. The redactor only knows configured and session secrets, so a value that has just been typed in is unknown to it.
2. **P2 — a failed health summary reports success.** `health_summary()` dropped every failed check and always returned `success: true`, so an unreachable NAS came back as `{"success": true, "data": {}}` with `isError: false`.
3. **P2 — polling limits overrun.** The wall-clock deadline was only checked *before* each status request, and each request still had a fixed 15 s timeout: a request started with 4 s left ran for 14 s, and a 120 s search was reported at 130.5 s. The request that starts the task, fetching results and cleanup had no budget at all, and a `requests` timeout limits each read, not the whole exchange.

## Changes

### 1. Value-free validation messages; this call's credentials are secrets (`src/mcp_server.py`, `src/auth/synology_auth.py`)

- `_describe_validation_error` builds the message from the schema alone — field from the schema path, constraint from `validator_value` — and never reads the submitted value: `password must be of type 'string'`. A missing required property keeps jsonschema's wording (`'path' is a required property`), which names a property from the schema.
- `request_secrets()` (a `ContextVar` context manager beside `iter_all_secrets`) registers values for the length of one call; `iter_all_secrets()` yields them, so the tool-response redaction and the process-wide log filter both pick them up with no other change. `_call_tool` registers every string under a `password` or `device_id` key, at any depth, before anything else runs — so even a well-typed password that a later failure quotes is masked before any login has taught the redactor about it.
- **`otp_code` is deliberately not registered.** `config.iter_configured_secrets` already documents why: masking a 6-digit code as a substring corrupts unrelated output, and it is one-shot. The OTP echo the review reproduced is closed at the source, by the message no longer quoting values. (This differs from the first draft of this plan, which registered it.)
- Checked: the mcp 2.x SDK does not log raw `tools/call` parameters at DEBUG, so `_PARAM_PATTERN` needed no change.

### 2. A health summary that says how complete it is (`src/health/synology_health.py`)

`health_summary()` runs the seven checks from one table and reports:

| Outcome | Result |
|---|---|
| all succeeded | `success: true`, `status: "complete"`, `data` |
| some failed | `success: true`, `status: "partial"`, `message: "Some health checks could not be completed."`, `failed_checks`, `data` |
| all failed | `success: false`, error `health_checks_failed` carrying `failed_checks` → `isError: true` via the existing `_dsm_result` |

The tool description and README tell the assistant that a partial result is not confirmation that the NAS is healthy.

### 3. Every request bounded by the time left (`src/filestation/synology_filestation.py`)

- `_make_request(..., deadline=)`: nothing is sent when no time is left; the timeout is `min(15, remaining)`; and the call runs in a daemon thread that is given up on at the deadline (`_run_within`), because a `requests` timeout alone does not bound a server that trickles bytes. A timeout that was cut down to the time left is reported as the deadline, not as a network error.
- One `_wait_for_task` replaces the three copies of the poll loop; it checks the deadline again after each response. One `_stop_task` replaces the three cleanup blocks and bounds them.
- The limit now covers the request that starts the task (and, for `delete`, the initial path lookup — if that runs out of time nothing is started). Fetching search results and stopping the task have their own allowances, so the longest a call can take is **140 s** (search: 120 + 15 + 5), **125 s** (delete: 120 + 5) and **65 s** (move: 60 + 5). Documented in the method docstrings, the README ("Time limits") and the CHANGELOG.
- Design note: a response that has already arrived is not discarded for being a few milliseconds late — the hard stop at the deadline is what makes the bound strict, and discarding a finished `delete` would report a timeout for an operation that succeeded. A request that was abandoned at the deadline may still complete on the NAS; the README says so.

## Tests

- `tests/test_tool_calls.py`: value-free messages (including a sweep of **every property of every tool** with a sentinel that nothing registers with the redactor); mistyped `password` / `device_id` / `otp_code` never echoed, in the result or at DEBUG; a credential quoted by a later failure or a successful result is masked; request secrets are forgotten when the call ends and are not shared between concurrent calls; health summary through the tool boundary (all failed, partial, complete).
- `tests/test_stdio_protocol.py`: against the real server at `LOG_LEVEL=DEBUG`, wrong-typed and well-typed credentials appear neither in any result nor anywhere in the log.
- `tests/test_health.py`: aggregation (all failed — exactly the 11 underlying requests the review counted — partial, complete, failure with no error detail).
- `tests/test_file_station.py`: the old polling test is replaced by one that drives the real `_make_request` with a fake `requests.get` and clock, for search/delete/move, with an instant and a 14 s start request — asserting the limit is reported at the limit, no request outlives it, and the documented maximum holds; a real-time test that a request that never answers is abandoned at the limit; results get their own allowance; a real network timeout is still a network error; `delete` starts nothing if the lookup runs out of time.

## Verification

- All three findings were reproduced before the fixes (password echoed and logged; health `isError: false`; search reported at 130.5 s) and are fixed afterwards (no echo; `isError: true`; 120.0 s).
- The new tests were run against the pre-fix code, one area at a time, and fail there: the mistyped-credential, sweep and later-failure tests, the DEBUG-log stdio test, every health aggregation test, and all the new polling-budget tests except one. That one (a real network timeout is still reported as a network error) is a regression guard for behaviour that must not change. All pass after the fix.
- `pytest -m "not real_nas"`, `ruff check` and `black --check` clean.

## Not done here

- **Authenticated check of the user's real client against the NAS** (including authenticated Docker startup) — needs the NAS and its credentials.
- **Whether Dependabot version updates are enabled** in the repository settings — a GitHub setting; `.github/dependabot.yml` and the `mcp<3` bound are in place.
- **Optional approved-folder allowlist and credential-file exclusions** — still deferred, as in the earlier plans; a separate feature that needs its own design.
