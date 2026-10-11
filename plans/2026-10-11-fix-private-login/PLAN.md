# Fix: the private login (review findings R01 and R05)

**Written:** 11 October 2026
**Roadmap:** [`../2026-10-10-manual-auth-roadmap/PLAN.md`](../2026-10-10-manual-auth-roadmap/PLAN.md), Remediation, fix PR 2
**Review:** [`IMPLEMENTATION_REVIEW_2026-10-11.md`](../2026-10-10-manual-auth-roadmap/IMPLEMENTATION_REVIEW_2026-10-11.md)
**Builds on:** the private login (#21) and the NAS transport fixes (#27).

## What the review found, and what was checked

Both findings are High, both are in the private login, and both were reproduced against `main` (`e6eb5aa`) before any change, with tests that fail on that code.

| ID | Finding | Reproduced as |
|---|---|---|
| R01 | Sign-in and enrollment shared one challenge table without recording what each challenge was for, and enrollment completion accepted a challenge made for an ordinary sign-in. While an additional-device code is open, anyone who can reach the page can enrol a passkey without knowing the code, and then sign in with it | Through the real app and the real passkey check: `POST /auth/begin` (it needs no sign-in), a software authenticator creating a passkey over that challenge, `POST /enroll/finish` answered **200**, and the attacker's own passkey then signed in (**200**) |
| R05 | The pending request is checked before the worker starts, but a session the worker returns is installed afterwards without checking again | A paused worker; the request cancelled, expired, replaced or its client disconnected while it ran; the outcome was still `connected`, with a session installed. Through the page, `/pending/cancel` during a submission still ended in `/?m=connected` |

## What changes

| Piece | Files | What it does |
|---|---|---|
| Purpose on every challenge | `src/private_auth/owner.py` | A challenge is made for `sign-in` or `enroll` and redeemable only for that. A state is spent even when it is presented for the wrong purpose |
| Enrollment bound to its code | `src/private_auth/owner.py` | `begin_enrollment` keeps the digest of the code it was given (`match_enrollment_code`); `add_credential_consuming_code` takes that digest, **required**, and under the store's lock checks that this same code is still the open one before it adds the passkey and uses the code up |
| Sign-in attempts | `src/broker/sessions.py` | `begin_attempt` claims a pending request for one sign-in (`started`, `expired` or `in_progress`); `install_for_attempt` adopts a session in one step under the lock, only if the request is still the live one and the attempt still holds it; `release_attempt` frees a claim |
| Withdrawing a request | `src/broker/sessions.py` | Cancelling, expiry, a disconnect (`revoke`, which the page's button and the client's `synology_logout` both use), shutdown, and installing a session another way each withdraw the request, and with it the attempt |
| Adoption | `src/broker/runtime.py`, `src/private_auth/login.py` | `LoginService.attempt` claims the request first and releases the claim on every way out; a refused adoption is never installed, and the session the NAS opened for it is ended there (`end_unadopted_session`) |
| The page | `src/private_auth/app.py` | A withdrawn sign-in goes back to the front page with a fixed sentence (`?m=withdrawn`); a second submission while one runs gets a 409 and is told to wait |
| Documents | `docs/MANUAL_AUTHENTICATION.md`, `CHANGELOG.md` | Say that disconnecting, cancelling and expiry withdraw a sign-in that is still being made |

## Design choices worth knowing

- **The binding is the code's digest, not a flag.** A boolean "this was an enrollment challenge" would have stopped the reviewer's attack but not an enrollment begun under a code that has since been replaced: it would finish against whichever code is open now. Holding the digest closes both, and `code_sha256` has no default, so a caller that does not say which code it holds cannot add a passkey.
- **One lock decides adoption.** Checking the request, checking the claim, installing the session and settling the request are a single step in `install_for_attempt`. The earlier shape (check, await the worker, install) left the whole worker time in between.
- **A claim lives and dies with its request.** Whatever removes a pending request removes the attempt holding it, so a result that arrives late finds nothing to adopt it, and a stale claim can never make the next request for the same owner and NAS unclaimable. The request id and the attempt id are both checked on adoption; each is redundant while that invariant holds, which is deliberate defence in depth, and only removing both is observable.
- **Disconnect means no connection.** `SessionManager.revoke` used to remove sessions only. It now also withdraws the pending request for the same owner and NAS (or all of the owner's), because a password submitted a moment before a disconnect must not complete the connection that was just ended. The client's own `synology_logout` goes through the same call.
- **A withdrawn login is not a wrong password.** The NAS accepted it, so it does not count towards the attempt limit, and neither does a second submission that was told to wait.
- **The session the NAS opened is not left open.** It is logged out in the background with the same bounded logout used everywhere else, and it is never in the session manager, so no tool can reach it and it is not in the redaction list.

## Acceptance criteria

- A sign-in challenge cannot complete enrollment, and an enrollment challenge cannot complete a sign-in. A wrong, absent, expired, replaced or consumed code cannot add a passkey. Concurrent completions cannot reuse one code. First-device and additional-device enrollment still work, over HTTP as well.
- Cancelling, expiry, replacement, a page disconnect or the client's `synology_logout` during a sign-in leaves no session, and the NAS session is ended once. Concurrent submissions cannot start two workers, and an older result cannot replace a newer session.

## Verification

`pytest -m "not real_nas"`, ruff and black over `src/`, the entry points, `scripts/`, `docker/` and `tests/`, and `python scripts/generate_tool_catalog.py --check`.

New or changed: `tests/test_owner_passkeys.py` (the binding, with the four enrollment-atomicity tests now naming the code they hold), `tests/test_broker_sessions.py` (`TestLoginAttempts`), `tests/test_login_service.py` (a worker that pauses, so the request can be changed while the NAS is thinking) and `tests/test_private_app.py` (the same through the page, and the reviewer's enrollment attack through the real passkey check).

Result: 1517 passed, 29 skipped (the 13 that need a POSIX filesystem and the 16 image tests that need Docker, as before); 1460 passed before this PR. Ruff, Black and the catalog check are clean.

The tests written first were run against the unfixed code: 50 failed. (Four tests were added after that run, for the client's own `synology_logout`, a NAS the client may not use, and two claims that must not outlive a session; they are covered by the mutations below.) The failures are the bug itself, not a fault in the harness: the HTTP enrollment attack answered 200 and the attacker then signed in with their passkey, and a cancelled sign-in ended as `connected`. The session-manager tests failed because the claim and adopt methods did not exist yet, and four existing enrollment-atomicity tests failed because they were changed to name the code they hold. Three of my own tests would have hung on the unfixed code (a second worker waiting for a release that comes after it returns), so those waits are bounded and fail in seconds.

Thirty faults were then put into the code one at a time to confirm the tests can fail: a challenge redeemable for any purpose, a wrong-purpose state kept rather than spent, an enrollment no longer bound to its code, the store ignoring which code was held or code expiry, sign-in and enrollment each redeeming the other's challenges, a wrong code still getting options, adoption not checking the request or not expiring stale ones, a disconnect, a cancel, an expiry, a new login or a shutdown that did not withdraw a sign-in, two claims on one request, one attempt releasing another's claim, a failed attempt keeping its claim, a withdrawn login adopted anyway or left open on the NAS, the client's NAS check skipped, and the page and its notices saying something else. Twenty-nine were caught the first time. One was not: nothing checked that a claim does not outlive the session it made (the service always releases its own claim, which hid it), so two manager-level tests were added and all thirty are now caught.

## Not yet verified

- **A real browser and a real passkey.** The tests use a software authenticator and an in-process app. The reviewer's attack is reproduced and refused there; the actual WebAuthn ceremony in a browser has not been run.
- **A real DSM.** The worker is a fake that pauses. A session that a real NAS opens for a withdrawn login, and its logout, have not been observed.
- **The other seven findings.** They are fixed in fix PRs 3 and 4.
