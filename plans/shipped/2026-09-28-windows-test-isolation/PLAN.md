# PR: Windows test isolation

Status: Shipped — PR #11
Initiated: 2026-09-29
GitHub PR: [Impjegat/mcp-server-synology#11](https://github.com/Impjegat/mcp-server-synology/pull/11)
Implements: finding 7 from [`REVIEW_REPORT.md`](../2026-09-28-rereview-followups/REVIEW_REPORT.md) — see [the follow-ups plan](../2026-09-28-rereview-followups/PLAN.md) for the full verdict table

## Why

The test isolation added by the remediation roadmap works on Linux but breaks the suite on Windows, where the project is developed (the report saw 26 failures and 10 setup errors). Three separate causes:

1. **The socket guard blocks asyncio's own sockets.** `tests/conftest.py` makes every `socket.connect()` raise in tests not marked `real_nas`. On Windows, asyncio builds its event loop's self-pipe as a pair of connected loopback sockets (`socket.socketpair()` is emulated with a listener plus a `connect()` there), so every async test failed during setup, before reaching the code under test.
2. **Config tests strip the home directory.** 33 calls of `patch.dict(os.environ, {...}, clear=True)` remove `USERPROFILE`, and each is followed by a fresh import of `config`, whose module-level `os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")` evaluates `Path.home()` even when `XDG_CONFIG_HOME` is set. On Windows `Path.home()` needs `USERPROFILE` (or `HOMEDRIVE` + `HOMEPATH`), so the import raised. POSIX falls back to the password database and never noticed.
3. **A permission test assumes POSIX.** `test_permission_warning_for_open_permissions` chmods a file to `0o644` and expects a warning about open permissions. Windows has no mode bits and no `os.getuid()`, so the server skips that check there — the test only passed by accident, because the "skipping file-permission check" warning also contains the word "permission".

Nothing verified these on Windows automatically, since the repo's only workflows are the AI-review ones. This PR adds the first test CI.

## Changes

### Socket guard — `tests/conftest.py`, `tests/socket_guard.py`

- `connect` and `connect_ex` are guarded rather than blanket-blocked: an address that is positively local (a loopback IP anywhere in 127.0.0.0/8 or `::1`, `localhost`, or an AF_UNIX path) goes to the real implementation, kept from before the patch; anything else raises the same `RuntimeError` as before. Anything that can't be classified counts as remote, so the guard fails closed. The classifier lives in `tests/socket_guard.py` so the guard's tests can import it.
- **A second block, one level up, closes the hole the exemption would open.** `requests` honors `HTTP(S)_PROXY`, and a proxy running on the same machine — a local dev proxy, or the forwarder in this sandbox — is a loopback address, so an unmocked request would now connect to it and be tunnelled out. This showed up while working on the PR: an existing test that calls an unmocked `https://nas.example.com` went from 1 s to 19 s because it reached the sandbox's proxy. HTTP requests are therefore also blocked in `urllib3.HTTPConnectionPool.urlopen`, whatever the proxy settings. That point is below `HTTPAdapter.cert_verify` (an existing `test_auth` test relies on `cert_verify` raising first, so blocking `HTTPAdapter.send` would have broken it) and above any connection attempt.

### Config tests — `tests/test_config.py`

- New `clean_env(overrides)`: `patch.dict(os.environ, ..., clear=True)` that keeps `XDG_CONFIG_HOME`, `HOME`, `USERPROFILE`, `HOMEDRIVE` and `HOMEPATH`. All 33 calls use it. Keeping `XDG_CONFIG_HOME` also leaves the settings lookup pointed at the throwaway directory `tests/conftest.py` sets up rather than the real `~/.config`.
- `test_permission_warning_for_open_permissions` is skipped where `os.getuid()` doesn't exist.

### CI — `.github/workflows/tests.yml` (new)

- `pytest -m "not real_nas"` on `ubuntu-latest` and `windows-latest`, Python 3.13 (what the reviewer ran on Windows), `fail-fast: false` so one OS failing doesn't hide the other.
- `ruff check` and `black --check` once, on Linux, with both tools pinned (`black==26.5.1`, `ruff==0.16.9`, the versions `main` was verified clean against) so a release of either can't turn an unrelated PR red. Bumping them is a deliberate step.
- Triggers: pull requests and pushes to `main`. No secrets, read-only token, 15-minute job timeout.
- Not included: Python versions other than 3.13 (the code targets 3.9+; a version matrix is a follow-up if wanted).

## Tests

- `tests/test_network_guard.py` (new): address classification (local, remote, and unparseable-counts-as-remote cases); remote `connect`/`connect_ex` and a bare hostname are blocked; loopback IPv4, IPv6 and Unix-socket connections work; an HTTP request is blocked, including one configured to go through a loopback proxy that never receives a connection; asyncio can create and close an event loop (the case that failed on Windows).
- `tests/test_config.py`, `TestCleanEnv`: it keeps exactly the home variables and clears the rest, restoring them afterwards; an override beats a kept variable; and a Windows-shaped `Path.home()` (reads `USERPROFILE`, raises without it) lets `config` import under `clean_env()` while the plain `clear=True` form raises.

## Verification

- `pytest`, `ruff check`, `black --check` clean on Linux.
- Without the fixes: the loopback and Unix-socket guard tests fail against the old `conftest.py`; the HTTP-block tests fail if the `urlopen` block is removed (and the suite's unmocked-request NFS test slows from 1 s to ~19 s); the Windows-shaped home test fails if `USERPROFILE` isn't kept.
- The Windows behavior itself can't be run in this Linux container. The new workflow's `windows-latest` job is the check, and any further Windows-only failure it shows is fixed in this PR until both operating systems pass.
