# PR 3: Connection defaults and bounds

Status: Shipped — PR #5
Initiated: 2026-09-27
Implements: [remediation roadmap](../2026-09-27-remediation-roadmap/PLAN.md) §4 (remainder — the auth-specific timeout/retry-rule portion already shipped in PR 1)

## Why

§4's timeouts and DSM-error-code retry rule landed in PR 1. What's left: the wrong port default, no CA-bundle support (only a bare `verify_ssl` bool), `search_files` polling with no deadline, `get_file_content` with no size cap, and login failures that all collapse into a generic "Authentication failed" regardless of whether the real problem was a bad certificate, an unreachable host, or actually-wrong credentials.

## Changes

1. **Port default fix** (`src/config.py`): `nas_info.get("port", 5000)` → `5001`. 5000 is DSM's HTTP-only port; combined with the existing HTTPS-only `base_url` construction, the old default silently produced a connection that could never succeed.
2. **CA-bundle support** (`src/config.py`): `VERIFY_SSL` (env var and `settings.json`'s `server.verify_ssl`) now accepts `true`/`false` as before, or any other string as a CA bundle file path — passed straight through to `requests`' own `verify=` parameter, which already accepts either form. New `_parse_verify_ssl()` helper. `REQUESTS_CA_BUNDLE` already worked as a global override; this is the equivalent per-server setting, documented in the README alongside a note that Windows `requests` doesn't use the OS trust store.
3. **`search_files` timeout** (`src/filestation/synology_filestation.py`): the `while True` polling loop (no deadline at all) is now bounded the same way `delete()`/`move_file()` already are — 120s, then a clear timeout exception instead of hanging against an unresponsive NAS.
4. **`get_file_content` size cap** (`src/filestation/synology_filestation.py`, `src/config.py`, `src/mcp_server.py`): new `config.max_file_content_size` (env var `MAX_FILE_CONTENT_SIZE` / `settings.json`'s `server.max_file_content_size`, default 1,000,000 bytes). Enforced via `get_file_info()`'s size field *before* the download request is made, not after reading the whole file into memory — file contents are sent to the MCP client's AI provider, and this tool stays enabled even in restricted mode.
5. **Distinguished login errors** (`src/auth/synology_auth.py`): `login_with_session`'s per-API-version loop now catches `requests.exceptions.SSLError`, `ConnectionError`, and `Timeout` specifically and stops immediately (a transport-level failure isn't fixed by retrying with a different API version payload — the same host is unreachable/untrusted regardless). Each gets its own error code (`certificate_error`, `connection_error`, `connection_timeout`) and a specific, sanitized message; a truly unrecognized exception keeps the previous fall-through-to-next-version behavior. Only reachable-and-answering-but-still-rejected credentials fall through to the generic `"Authentication failed"`.
6. **Missing test from PR 1's deferral**: `tests/test_config.py`'s "omitted port defaults to 5001" case, explicitly deferred here in PR 1's plan doc.

## Explicitly out of scope

- §2 (Docker/`.dockerignore`/compose) and §5 (conftest isolation ordering, Windows install docs, the `skills/synology-nas/references/auth.md` port-5001 correction) — PR 4.
- `logout()`'s error handling is left as-is: PR 1 already added redaction and `RequestException` handling there, and §4's "distinguish unreachable/certificate/auth failures" language is about the login/startup path, not session teardown.

## Verification

- `pytest -m "not real_nas"`: 165 passed, 3 skipped, the same 2 pre-existing unrelated failures (test-isolation bug in `test_config.py`, deferred to PR 4).
- New tests: `test_omitted_port_defaults_to_5001`, `test_verify_ssl_env_var_accepts_ca_bundle_path` / `test_verify_ssl_settings_json_accepts_ca_bundle_path`, `test_max_file_content_size_env_var_override` / `test_max_file_content_size_settings_json_overrides_env` (`tests/test_config.py`); `test_search_files_times_out_instead_of_polling_forever` / `test_search_files_still_returns_results_when_it_finishes_in_time`, `test_get_file_content_rejects_oversized_file_before_downloading` / `test_get_file_content_allows_file_within_size_cap` (`tests/test_file_station.py`); `test_certificate_error_stops_immediately_with_a_specific_message`, `test_connection_error_stops_immediately_with_a_specific_message`, `test_timeout_error_stops_immediately_with_a_specific_message`, `test_unexpected_transport_exception_still_retries_other_versions` (`tests/test_auth.py`).
- `ruff check` clean; `black --check` clean on every changed file (aside from the same pre-existing, unrelated formatting issue in `test_file_station.py` noted in PRs 1 and 2).
