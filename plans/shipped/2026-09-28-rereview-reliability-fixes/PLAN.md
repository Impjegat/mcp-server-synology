# PR: Rereview reliability fixes

Status: Shipped — PR #10
Initiated: 2026-09-29
GitHub PR: [Impjegat/mcp-server-synology#10](https://github.com/Impjegat/mcp-server-synology/pull/10)
Implements: findings 4, 5, 6 from [`REVIEW_REPORT.md`](../../2026-09-28-rereview-followups/REVIEW_REPORT.md) — see [the follow-ups plan](../../2026-09-28-rereview-followups/PLAN.md) for the full verdict table

## Why

Three findings from an independent rereview of the merged remediation roadmap. None is a security hole; each is a way the server stops doing what its own documentation or limits say:

4. **The Docker quick start no longer gets credentials.** PR #6 stopped copying `.env` into the image (`.dockerignore` now excludes it), but nothing hands `.env` to the container at runtime, while the README still tells users to create one.
5. **A JSON download bypasses the size cap** (`get_file_content`). A response with a JSON Content-Type went through `response.json()`, which reads the whole body into memory before the byte limit is looked at. The same branch also misclassified a real `.json` file as a DSM error, so such files could not be read at all.
6. **Polling deadlines count only sleep time** (`search_files`, and the same bug in `delete` and `move_file`, which the report didn't mention). The loops added 0.5 s per poll and stopped at 120 s (60 s for move) — but each status request can itself take up to its 15 s timeout, which the counter never sees. Worst case was about an hour, not two minutes.

## Changes

### Finding 4 — `docker-compose.yml`, `README.md`

- Add an optional `env_file` entry (`path: .env`, `required: false`) so Compose passes `.env` to the container **when it starts**. It stays out of the image; the `:ro` `settings.json` mount is unchanged, so both configuration routes keep working, and `required: false` means a `settings.json`-only setup doesn't break.
- README Docker quick start now says how `.env` is read (at container start, not built in, no rebuild after editing), that this needs Docker Compose v2.24 or later, and that a `$` in a `.env` value must be single-quoted. That last point came out of checking the compose output: Compose expands `$name` in `.env` values, so `SYNOLOGY_PASSWORD=pa$word` reaches the container as `pa` — a silent mangling that the old baked-in `.env` (read by python-dotenv, which leaves a bare `$` alone) never had.

### Finding 5 — `src/filestation/synology_filestation.py` (`get_file_content`)

- Always read the body through the bounded `iter_content` loop first, so the cap applies to every response whatever its Content-Type.
- Then, only if the Content-Type is JSON, classify the collected bytes with the new `_dsm_download_error_code()`: it is a DSM error only if the body is a JSON object whose `success` is `false` and which has an `error` key. Anything else — a list, a scalar, malformed JSON, a deeply nested file that overflows the parser, an object without those keys — is the file's own content and is returned as text.
- Hold the response in `with response:` so the connection is closed on every exit path (oversize abort, DSM error, a stream that fails midway, success), not only the one that called `close()` by hand.

### Finding 6 — `src/filestation/synology_filestation.py` (`search_files`, `delete`, `move_file`)

- Replace the sleep counter (`wait_time += 0.5`) with a `time.monotonic()` deadline in all three loops. Worst case is now the limit plus one request (15 s). The limits (120 s / 120 s / 60 s) and the existing stop-task cleanup on timeout are unchanged.
- `import time` moves from inside the three `try` blocks to the top of the module, so tests can substitute a clock for it.

## Tests

- `tests/test_file_station.py`:
  - A `_FakeClock` replaces `time` in the module. The existing `search_files` timeout test uses it (it used to rely on a no-op `sleep`, which a wall-clock deadline would spin against for real).
  - New, parametrized over all three methods: with every status request taking 14 s, the loop times out after exactly `ceil(limit / 14.5)` polls (9, 9 and 5) instead of 240, 240 and 120, and still sends the stop request.
  - New `_FakeStreamingResponse` that, like a real streamed response, pulls chunks from the wire one at a time for `iter_content()` but drains everything for `.json()`. Tests: an oversized JSON body is rejected after reading two chunks, not all fifty; real `.json` files (object, list, string, `null`, `success: true`, `success: false` with no `error`) come back as text; unparseable JSON-typed bodies (malformed, not text, deeply nested, empty) come back as text; DSM error bodies still raise with the right code, under either spelling of the Content-Type; the same bytes under a non-JSON Content-Type are just the file; and the response is closed after success, after a DSM error, and after a mid-stream failure.
- No compose test: parsing the file needs a YAML library the project doesn't depend on. The compose change was checked with `docker compose config` instead — it parses with and without a `.env` present, and the values from `.env` reach the container's environment.

## Verification

- `pytest`, `ruff check` and `black --check` clean.
- The new tests were run against the pre-fix code (with only the module-level `import time` added, so the fake clock could drive the old counter): 22 of them fail there, and pass after the fix.
- `docker compose config` with and without a `.env` file in place.
