# The private login: owner passkey, login page and short-lived worker

**Written:** 10 October 2026
**Roadmap:** [`../2026-10-10-manual-auth-roadmap/PLAN.md`](../2026-10-10-manual-auth-roadmap/PLAN.md), PR 3
**Source plan:** §3.2, §4.1, §5.1 and §5.2 of [`../2026-10-06-manual-authentication/PLAN.md`](../2026-10-06-manual-authentication/PLAN.md)
**Builds on:** the broker (#20), whose `BrokerRuntime.install_login` and pending sign-in requests this uses.

## What this adds

The way a person signs in to the NAS so that the password never passes through an AI client. After this PR the broker can actually be signed in to: the owner proves who they are with a passkey, sees which client is waiting, checks which NAS, account and access are involved, and types the password on a page the model cannot reach.

| Piece | File | What it does |
|---|---|---|
| Owner proof | `src/private_auth/owner.py` | Passkey (WebAuthn) sign-in, user verification required, single-use two-minute challenges, a counter that must advance. A store of public keys only. Enrolment by a one-time code made on the broker host |
| The page | `src/private_auth/app.py` | Pages, passkey endpoints, CSRF and Origin checks, secure cookies, security headers on every response, attempt limits. Own address, port and TLS |
| Security primitives | `src/private_auth/security.py` | Rate limiter, owner sessions (idle and absolute deadlines), Origin check, header set |
| Sign-in service | `src/private_auth/login.py` | Runs one sign-in: pending check, attempt limit, worker, install the session. Fixed value-free messages |
| Worker | `src/private_auth/worker.py` | Short-lived subprocess: secrets on stdin only, one line out (a session or an error code), no device token, no core dump, no traceback |
| Wiring | `broker_main.py` | `--private-origin` and friends start the private listener in a thread; `enroll new-code / list / revoke` |
| Request hook | `src/broker/runtime.py` | A call that needs a session leaves one de-duplicated pending request for the owner. The reply to the model is unchanged |

New dependency: `webauthn>=3.0.1,<4`, imported only inside `private_auth`, so the single-process server runs without it.

## Design choices worth knowing

- **Isolation, not erasure.** Python strings cannot be wiped. What protects the password is that the worker lives for seconds, holds one copy, writes nothing to disk and exits. The web front end necessarily holds a copy while it parses the form; that is documented, not hidden. A host administrator can still read the process.
- **Enrolment needs the host.** The one-time code is printed on the broker host, so enrolling cannot be done from an AI application elsewhere. Once a passkey exists no other can be added without running that command again with `--add-device`.
- **The order of checks matters.** Origin, then owner session, then the (bounded) body, then CSRF. An unauthenticated request is refused before anything is read.
- **The account is not the model's or the browser's to choose.** It comes from the broker's configuration. Only when none is configured does the owner type it.
- **Attempts are counted so a typo cannot get the NAS account locked.** Failures that did not burn a DSM attempt (asking for a code, an unreachable NAS, a certificate that did not verify) are not counted.
- **One DSM session per sign-in.** Download Station may need a separate session type; those tools are not in the default scope, so this is left as a documented limitation rather than a second private login.

## Acceptance criteria

- The password, code and session never appear in a response body, header, cookie, redirect, URL, log line, process argument or environment; the worker receives them on standard input only.
- Only the owner reaches the login page; an MCP client's token opens nothing there, and the MCP listener serves none of the private pages.
- Every state-changing request needs the owner session, a CSRF token and the right Origin; every response carries the security headers; the page has no inline script or style and loads nothing from elsewhere.
- Passkey sign-in refuses a replayed, expired, wrong-origin, wrong-site, unverified, unknown-device or counter-regressing response, and enrolment is single-use.
- A wrong password, a missing or wrong code, a certificate that does not verify, an unreachable NAS and a locked account each produce a fixed sentence and nothing else.
- A model gets `AUTHENTICATION_REQUIRED` and nothing it could use to sign in.

## Verification

`pytest -m "not real_nas"`: 983 passed, 3 skipped (717 before this PR, plus 266 new). New files: `test_private_security`, `test_owner_passkeys` and `test_private_passkey_flow` (the real WebAuthn library against a software authenticator), `test_login_service`, `test_login_worker` (the real worker as a subprocess, including against a fake DSM over real TLS with certificate verification on), `test_private_app` (in-process, every property above) and additions to `test_broker_main` (refusals, the `enroll` command, and a real start in which a passkey enrols and signs in over loopback HTTP, a model's call leaves a waiting request, and a real worker is run with a password that must appear nowhere afterwards).

Twenty-two behaviours were broken on purpose to confirm the tests can fail (Origin, CSRF, owner session, cookie flags, headers, body limit, host names, worker environment and isolated mode, worker output, device token, attempt limit, account substitution, expired requests, user verification, single-use challenge, sign counter, enrolment code and its race, and the pending-request hook). All were caught. One was missed at first: a reusable challenge was masked by the counter and code checks that also stop a replay, so tests now isolate it.

## Bugs found by the tests while writing this

- Every request to the private listener was refused: Starlette compares the Host header without its port, so names configured with one never matched. Only the real-process test saw it.
- `config.py` raised in a process with a minimal environment (`Path.home()` evaluated even when `XDG_CONFIG_HOME` was set).
- Importing `broker_main` set the process into broker mode; collection imports every test module, so the whole session ran that way.
- An oversized body was parsed before the request was authenticated.

## Not yet verified

- A real browser and a real authenticator. The tests use a software authenticator speaking the same protocol; the page's JavaScript (`/static/passkey.js`) has not been run in a browser. This is the main thing for live acceptance, together with the platform's own crash-dump settings for the worker on Windows.
- TLS with a real certificate on the private listener.
- A `webauthn` relying-party id that is an IP address is accepted by the library but not by browsers; use a host name for the real deployment.

## For PR 4

The adapter forwards to `/mcp` with a client token and needs nothing from this package.
