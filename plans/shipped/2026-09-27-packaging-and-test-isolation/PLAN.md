# PR 4: Packaging and test isolation

Status: In progress
Initiated: 2026-09-27
Implements: `REMEDIATION_PLAN.md` §2 (Keep credentials out of Docker images) and §5 (Validate and prepare installation)

## Why

The last roadmap PR. §2 stops the Docker build from being able to bake local credentials into the image; §5 makes the test suite itself hermetic (no dependence on whatever happens to be on the machine running it) and fixes the two tests that have been failing since before this whole roadmap started — deferred here explicitly from PRs 1-3's plan docs each time, since their actual root cause (test-authoring bugs interacting with `config.py`'s module-level singleton, not the "monkeypatch bleed" originally assumed) belongs to this PR's test-isolation scope.

## Changes

1. **Stop copying credentials into the image** (`Dockerfile`): removed `COPY .env* ./` — credentials come from a runtime mount or env vars now, never baked into a layer.
2. **`.dockerignore`**: added `.env`, `.env.*`, `settings*.json` — defense in depth so these can never reach the build context even if a future `COPY` becomes broader than the current targeted `src/`+`main.py` copies.
3. **`docker-compose.yml`**: removed `tty: true` (wrong for a process speaking JSON-RPC over stdin/stdout — every client config in the README launches this via `docker-compose run --rm`, not an interactive terminal) and `restart: unless-stopped` (a restart policy is for a long-running service started with `up`, not a one-off `--rm` container tied to a client's process lifetime).
4. **Fixed the two pre-existing test failures** (`tests/test_config.py`), root-caused properly instead of continuing to defer them:
   - `test_env_rejects_http_url`: `config.py` constructs a module-level `config = SynologyConfig()` singleton at import time. The test's `patch("config.SETTINGS_FILE", ...)` uses a string target, which itself triggers a fresh import (via `mock`'s own target-resolution) — outside the `pytest.raises` block, since `_load_env_settings()` (which validates `SYNOLOGY_URL` and is what actually raises) runs before `_load_settings()` (which is what `SETTINGS_FILE` is even for). Restructured to wrap the triggering import directly, matching on `ValueError` (stable identity) rather than `InsecureURLError` (a brand-new class object on every reimport) and asserting the class name for precision.
   - `test_permission_check_skips_without_getuid`: deleting `os.getuid()` to simulate "no os.getuid on this platform" (i.e. Windows) also broke `config.py`'s own unrelated module-level `Path.home()` call (used to default `XDG_CONFIG_HOME`), since `posixpath.expanduser()` needs `getuid()` on this POSIX test runner — a dependency real Windows's `ntpath.expanduser()` doesn't have at all. Fixed by also patching `Path.home` to a safe stub for the duration of this specific test, isolating the simulation to the code path it's actually meant to exercise.
5. **Test-session isolation** (`tests/conftest.py`), per the plan's explicit ask:
   - `XDG_CONFIG_HOME` is pointed at a fresh temp directory (via `setdefault`, so an explicit override is still respected) *before* `config` is ever imported — an ambient `~/.config/synology-mcp/settings.json` on the machine running the tests can no longer make collection itself non-hermetic or crash outright. The legacy `.env`-based credentials `real_nas` tests use are unaffected either way, since `config.py` reads those from `os.environ`/`.env` directly, not through `XDG_CONFIG_HOME`.
   - A new autouse fixture blocks `socket.socket.connect`/`connect_ex` for every test *not* marked `real_nas` — defense in depth against an accidental live network call, on top of (not instead of) marker-based skipping.
6. **Documentation**:
   - New "Windows Installation" README section (previously just a config-path mention in the Claude Desktop client-setup snippet) — local Python setup on Windows, where `settings.json` actually resolves to by default (`%USERPROFILE%\.config\synology-mcp\settings.json`) and how to override it, the `icacls`-based permission handling, and a Docker Desktop note.
   - Corrected `skills/synology-nas/references/auth.md`'s "port 5001 enables HTTPS; anything else uses HTTP" statement — every connection is HTTPS-only regardless of port; there's no HTTP fallback.
   - Fixed the README Quick Start's `docker-compose up -d` (a background-service invocation) to `docker-compose build`, consistent with the `run --rm` per-client-session pattern the rest of the README (and the `docker-compose.yml` changes above) actually use.

## Explicitly out of scope

- Refactoring `config.py`'s module-level singleton itself (e.g. lazy-loading) — the plan's ask was test isolation and the two specific test bugs, not an architecture change to how `config` is constructed. Fixed the tests to work correctly with the existing design instead.
- Adding `pytest-socket` as a dependency — a manual autouse fixture accomplishes the same "block sockets outside real_nas tests" goal without a new third-party dependency for a security-hardening PR.

## Verification

- `pytest` (full suite, including `real_nas`-marked tests, which gracefully skip without credentials): **185 passed, 40 skipped, 0 failed** — the first fully green run across this entire remediation effort; previously 2 tests failed on every run, including on unmodified `hardening`.
- `pytest -m "not real_nas"`: 185 passed, 3 skipped, 37 deselected, 0 failed.
- `ruff check` and `black --check` clean on every changed file.
- `docker-compose.yml` validated as parseable YAML after the edits.
