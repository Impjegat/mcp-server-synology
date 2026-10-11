# Fix: NAS transport (review findings R03, R04, R08)

**Written:** 11 October 2026
**Roadmap:** [`../2026-10-10-manual-auth-roadmap/PLAN.md`](../2026-10-10-manual-auth-roadmap/PLAN.md), Remediation, fix PR 1
**Review:** [`IMPLEMENTATION_REVIEW_2026-10-11.md`](../2026-10-10-manual-auth-roadmap/IMPLEMENTATION_REVIEW_2026-10-11.md)
**Builds on:** everything merged through #26.

## What the review found, and what was checked

All three findings are High or Medium problems in how the server talks to the NAS. Each was reproduced against `main` (`9a5e3ed`) before any change, with a test that fails on that code.

| ID | Finding | Reproduced as |
|---|---|---|
| R03 | A NAS answer that redirects makes `requests` repeat the request at the new address, body and custom headers included. A login would send the password and one-time code; any other call, the session id and `X-SYNO-TOKEN` | A fake transport answers 307 to another host. On `main` login, the shared client and the file download each made a second request to `other.example.test` |
| R04 | Broker mode accepted `VERIFY_SSL=false`, an empty value (which `requests` reads as "do not verify"), and a CA path that does not exist. The worker accepted any boolean and passed it on | The config and `SynologyAuth` built with each value on `main`: no error. The worker's acceptance of any boolean is read from its code (`validate`) and covered by the new tests |
| R08 | `server.verify_ssl` in settings.json is applied after each NAS entry was built from `VERIFY_SSL`, so the entries kept the old value. The private login reads the entry; the services read the global | A server-level CA bundle reached `cfg.verify_ssl` but not `cfg.nas_configs[...]`, and so not the worker's payload |

## What changes

| Piece | Files | What it does |
|---|---|---|
| No redirects | `src/utils/synology_api.py`, `src/auth/synology_auth.py`, `src/filestation/synology_filestation.py`, `src/downloadstation/synology_downloadstation.py` | Every NAS request is sent with `allow_redirects=False` and checked by `refuse_redirect()` before its answer is read. A 3xx ends the request |
| The typed error | `src/broker/errors.py` | `RedirectRefused`, code `REDIRECT_REFUSED`, with a fixed message that never repeats where the NAS tried to send the request |
| Sign-in | `src/private_auth/login.py` | `redirect_refused` has its own sentence and does not count towards the attempt limit |
| One TLS setting | `src/config.py` | After both sources are read, every NAS entry gets the final `verify_ssl` |
| Verification required | `src/config.py`, `src/private_auth/worker.py`, `src/auth/synology_auth.py` | `true` or an existing CA bundle, checked at startup, at the worker boundary, and when a manual-mode `SynologyAuth` is built |
| Documents | `docs/MANUAL_AUTHENTICATION.md`, `deploy/broker/`, `skills/synology-nas/references/auth.md`, `README.md`, `CHANGELOG.md` | Say that `false` is refused in manual mode and that redirects are not followed |

## Design choices worth knowing

- **Both halves of "no redirects" are needed.** `allow_redirects=False` makes `requests` hand the 3xx back, but `raise_for_status()` does not treat a 3xx as an error, so without the explicit check the empty body would surface as a confusing JSON error. `refuse_redirect()` is that check, and it ignores a response whose status is not an integer, so test doubles with no status are not mistaken for redirects.
- **The error is the same everywhere, and says nothing the NAS chose.** Login returns the code `redirect_refused`, the shared client returns the same code in its error dictionary, and File Station and Download Station raise `RedirectRefused`. None repeats `Location`. Download Station's fallbacks (`get_info`, `list_tasks`, `get_config`, `get_statistics`, `create_task`) used to turn any failure into a default answer; a redirect now passes through them, as `AuthenticationRequired` already did.
- **A test fails when a call is added without the guard.** An AST scan covers every `requests.<verb>(...)` call and every `<session>.<verb>(..., verify=...)` call in the four modules that talk to the NAS, and a second test fails if a fifth module starts importing `requests`.
- **There is one TLS setting, not one per NAS.** No setting exists for a per-NAS certificate, so the global value is the single authority and the entries are made to agree with it.
- **An empty string is refused as well as `false`.** `requests` reads `verify=""` as falsy, which switches verification off, so an empty `VERIFY_SSL` is the same mistake in a quieter form. A CA bundle may be a file or a directory, as `requests` allows.
- **A path that does not exist is refused at startup.** It could only fail at the first sign-in, in front of the person typing a password. The message names the setting and never the value.
- **Legacy mode is unchanged**, except that it no longer follows redirects either. Disabling verification there still works.

## Acceptance criteria

- A redirect from the NAS never causes a second request, in login, logout, the shared client, File Station (including upload and download) or Download Station; the secrets in the first request go nowhere else.
- Disabled, empty, mistyped or missing verification settings stop the broker before any request, and are refused again by the worker and by `SynologyAuth`. A real CA bundle works.
- A CA bundle set in settings.json reaches the request the worker receives.

## Verification

`pytest -m "not real_nas"`, ruff and black over `src/`, the entry points, `scripts/`, `docker/` and `tests/`, and `python scripts/generate_tool_catalog.py --check`.

New: `tests/test_nas_redirects.py` (37 tests, most through `requests`' real redirect engine), and additions to `tests/test_manual_auth.py`, `tests/test_login_worker.py`, `tests/test_login_service.py` and `tests/test_packaging.py`.

Result: 1460 passed, 29 skipped (the 13 that need a POSIX filesystem and the 16 image tests that need Docker, as before); 1375 passed before this PR. Ruff, Black and the catalog check are clean.

The redirect tests and the config and `SynologyAuth` tests were run against the unfixed code before any fix. Of the 33 redirect tests written first, 32 failed (the one that passed checks that the list of modules is complete), and the failures show the leak the reviewer described, a second request to `other.example.test` from login, the shared client and the download, not a fault in the fake. The config and `SynologyAuth` tests that assert a refusal or a corrected value failed with "did not raise" or the stale value; the ones that assert what must keep working (a real CA bundle, `true`, legacy mode) passed before and after, by design. The worker, sign-in message and packaging tests were added alongside or after the fix and are checked by the mutations below.

Fifty faults were then put into the code and the template one at a time, to confirm the tests can fail: a call without `allow_redirects=False` (login, logout, each File Station and Download Station request, the shared client), a call without the status check, a retry on another API version after a redirect, the fallbacks swallowing a redirect, each end of the `300 <= status < 400` boundary, a refused redirect counting as a wrong password, the final TLS setting not applied (or applied to one entry), verification accepted when `false` or empty or missing or a directory-only or file-only CA, the startup check removed, the CA path echoed, the worker and `SynologyAuth` accepting what they should refuse, the template defaulting to `false`, and the guide losing its sentence. Forty-seven were caught the first time. Three were not, and each was a weak test rather than an equivalent change: `create_file` only asserted that some error occurred (a JSON error satisfied it), an empty `VERIFY_SSL` was still refused but with the wrong message, and the guide check matched an unrelated sentence. All three tests were tightened and all fifty are now caught.

## Not yet verified

- **A real DSM.** The tests use a fake transport and a fake worker. DSM's own behaviour on a redirect (for example an HTTP-to-HTTPS or port redirect from a mistyped address) has not been observed.
- **The other nine findings.** They are fixed in fix PRs 2 to 4.
