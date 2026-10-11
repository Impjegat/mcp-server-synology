# Fix: client grants and service errors (review findings R12, R09, R10 and R11)

**Written:** 11 October 2026
**Roadmap:** [`../2026-10-10-manual-auth-roadmap/PLAN.md`](../2026-10-10-manual-auth-roadmap/PLAN.md), Remediation, fix PR 4
**Review:** [`IMPLEMENTATION_REVIEW_2026-10-11.md`](../2026-10-10-manual-auth-roadmap/IMPLEMENTATION_REVIEW_2026-10-11.md)
**Builds on:** the broker's policy (#19, #20) and the three fix PRs before this one (#27, #28, #29).

## What the review found, and what was checked

All four are Medium. Each has tests written before the fix and run against the code before the change; the scenarios below are those tests' and the review's.

| ID | Finding | Scenario |
|---|---|---|
| R12 | A client's token never stops working: the policy has no expiry, and `PolicyTokenVerifier` returns `expires_at=None`. The source plan says to validate expiry; a stolen or forgotten token lives until someone edits the policy by hand | A grant written with no expiry was accepted at start-up, and a token was accepted at any later time |
| R09 | `create_task` fell back to the older create form after *any* error, including a timeout or a lost connection, and again after DSM refused the destination. The first request may already have created the download | A timeout on the first create produced a second create request; a 402 produced a second one too; a network error naming `10.0.0.102` started the task-list fallback because the code searched the error text for `102` |
| R10 | `AUTHENTICATION_REQUIRED` and a refused redirect were swallowed by broad `except` clauses on the way out: an upload that found the session gone raised a generic upload error, Download Station turned it into an empty task list, zeroed statistics or a generic create failure | Each path scripted with 106, 107 or 119 (and a redirect) returned the wrong thing |
| R11 | After a lost session was renewed from the stored login (legacy mode), File Station repeated any GET (a rename, the start of a delete or a move and a new folder are all GETs), Download Station repeated delete, pause and resume, and the shared client repeated any request that failed with 119, POSTs included, while every container call is a POST read | A rename, a delete, a pause and a POST change each sent two requests |

## What changes

| Piece | Files | What it does |
|---|---|---|
| Grant expiry | `src/broker/policy.py`, `src/broker/server.py`, `broker_main.py`, `config/broker.example.json` | A required `expires` per client (date or datetime with a time zone, at most 366 days after the policy is loaded). The token verifier refuses an ended grant and tells the SDK when it ends. Start-up logs a warning for an ended grant and for one within 14 days of ending. `new-token` prints a suggested `expires` line |
| Typed Download Station errors | `src/downloadstation/synology_downloadstation.py` | `DownloadStationAPIError` (DSM answered, with its code) and `DownloadStationNetworkError` (the request may not have arrived). Fallbacks are chosen by type and code, never by searching text |
| One create | the same | The older create form is tried only after DSM answers 102, 103 or 104, which means the first form did nothing. After any network error exactly one create has been sent, and the error says it is unclear whether it was created |
| Errors reach the caller | `src/filestation/synology_filestation.py`, `src/downloadstation/synology_downloadstation.py` | An upload with 106, 107 or 119 raises `AuthenticationRequired`; every fallback lets `AuthenticationRequired`, `RedirectRefused` and `SessionRenewedNotRepeated` through |
| Replay by operation | `src/utils/synology_api.py`, `src/broker/errors.py`, both service modules | `READ_ONLY_METHODS` names the methods that only read. After a renewal only those are repeated, once. Anything else (including a method nobody listed) fails with `SessionRenewedNotRepeated`, code `SESSION_RENEWED`; the shared client raises it too (it first returned an error result; see Follow-up after review) |
| Documents | `docs/MANUAL_AUTHENTICATION.md`, `README.md`, `skills/synology-nas/references/auth.md`, `CHANGELOG.md` | The `expires` setting, "Renewing or revoking a client", and what the legacy server now does after an expired session |
| Test support | `tests/network_support.py` | `ScriptedNas`: a script of DSM answers per `(api, method)` on the real `HTTPAdapter.send`, so every request is counted and nothing opens a socket. `tests/test_nas_redirects.py` uses it too |

## Design choices worth knowing

- **Expiry is required, and bounded.** Decided with the owner. A date means *through the end of that day, UTC*; a datetime must carry a time zone (a naive one is refused, because it would silently mean a different moment on each host). More than 366 days ahead is refused at load time, so "never expires" cannot be written by picking a far date. The bound is measured from when the policy is loaded, so editing it again is how a grant is renewed, and the guide says so.
- **An ended grant does not stop the broker.** The other clients keep working. The ended one is refused on every request, and start-up names it in a warning so it is not mistaken for a broken token. The SDK's own bearer middleware enforces the same time (`AccessToken.expires_at`), so the check holds even for a request that is already past the first verification. The clock is injectable (`create_broker_app(..., clock=...)`, `PolicyTokenVerifier(clock=...)`), which is what lets the tests cross the boundary without sleeping.
- **A renewal does not extend a session.** Editing the policy and restarting the broker drops every DSM session, because they live only in memory. The guide says this, so nobody expects a renewal to keep someone signed in.
- **A refusal and an unknown outcome are different things.** DSM answering with an error code means the request was received and not carried out. A timeout means nothing is known. Treating both as "try something else" is what made R09 possible, so the two are different exception types and a fallback has to name which it handles. 102, 103 and 104 are "the API, method or version is not supported", the only answers that mean "this form does nothing, try the other".
- **The task-list fallback uses the code, not the text.** An empty list is returned only when *both* forms say they are unsupported. An older form that fails for any other reason is an error, not "no tasks", because an empty list reads as "nothing is downloading".
- **What counts as a read is a list, and the list fails closed.** `READ_ONLY_METHODS` is `get`, `getconfig`, `getinfo`, `get_smart_info`, `info`, `list`, `list_by_user`, `list_share`, `load_info`, `search`, `status` and `tags`. A method that is not on it is treated as a change. That choice is the reason this is a list of reads and not a list of writes: forgetting to add a new read costs one extra "run it again", forgetting to add a new write would cost a repeated change. The verb does not matter in either direction.
- **A change still renews the session.** Before this PR a failed write over POST left the session dead until the next read. Now the session is renewed and the caller is told ("run it again if it is still wanted"), so the caller's own retry works, and it is the caller, not the server, that decides. This changed one existing test, `test_legacy_file_station_never_repeats_a_write`: it expected the raw DSM 119 error and no renewal, which encoded the old behaviour.
- **Manual mode is unchanged.** It never renews and never repeats; it reports `AUTHENTICATION_REQUIRED` and the session is dropped at once, so the next call leaves the owner a sign-in request. R10 is about making that true from every fallback.
- **The audit of broad `except` clauses.** Every `except Exception` in the service modules was checked for whether it can hide `AuthenticationRequired`, `RedirectRefused` or `SessionRenewedNotRepeated`. The places that could are fixed (the upload error, Download Station's list, statistics and create fallbacks, and File Station's delete classification, which swallowed a redirect). The remaining ones either already re-raise those types or only wrap errors that are not about the session.

## Breaking change

**A policy file without `expires` on every client is refused at start-up.** This is on purpose (R12 asked for it) and the error says what to add and gives an example date. `config/broker.example.json`, `broker_main.py new-token` and the guide all show it. Anyone with a policy written before this PR has to add the line before restarting the broker. The three client tokens then need renewing at least once a year.

## Acceptance criteria

- A policy with a missing, unparseable, naive or too-distant `expires` is refused at start-up; a valid one is accepted.
- A token whose grant has ended is refused (`BROKER_UNAUTHORIZED` at the adapter); other clients are unaffected; start-up and `new-token` say so.
- A timeout or lost connection while creating a download sends one create request and says it is unclear whether it was created; a definite refusal sends one; 102, 103 and 104 fall back once to the older form, and a failure of that form is not retried.
- A lost session reaches the caller as `AUTHENTICATION_REQUIRED` from an upload and from every Download Station fallback; a redirect reaches the caller from File Station's delete.
- In legacy mode a rename, delete, move, new folder, download create, pause, resume or POST change is sent once after a session loss, renews the session and says to run it again; a read is repeated once.

## Verification

`pytest -m "not real_nas"`, ruff and black over `src/`, the entry points, `scripts/`, `docker/` and `tests/`, and `python scripts/generate_tool_catalog.py --check`.

New or changed: `tests/test_broker_policy.py` (grant expiry), `tests/test_broker_http.py` (a grant that ends), `tests/test_broker_main.py` (`new-token` and a real broker process refusing an ended grant), `tests/test_packaging.py` (the example parses with a fixed clock; the guide names the setting), `tests/test_tool_catalog.py`, `tests/broker_support.py`, the new `tests/network_support.py` and `tests/test_service_errors.py` (R09, R10 and R11 together, 88 cases), and `tests/test_manual_auth.py` (one test changed, see above).

Result: 1709 passed, 29 skipped (the 13 that need a POSIX filesystem and the 16 image tests that need Docker, as before); 1581 passed before this PR. Ruff, Black and the catalog check are clean.

**Mutation checks.** Faults were put into the code one at a time, and a fault counts as caught only when a test fails. Both sets were run again on the final code.

- *R12, 19 of 19 caught:* a grant with no expiry accepted; the one-year limit off by one second and twice as long; a date ending at the start of its day; a datetime without a time zone accepted; the policy judged against the wrong "now"; a grant still good at the instant it ends; a grant with no expiry trusted by the verifier; the answer not carrying when the grant ends; the verifier and the app each ignoring the clock they were given; start-up silent about ended grants; the 14-day warning shortened to 13; a token digest in a warning; `new-token` suggesting no expiry or one past the limit; the guide and the example each losing the setting.
- *R09 to R11, 32 of 32 caught:* a create repeated after any refusal and after a network failure; 103 not read as unsupported and 400 read as unsupported; the uncertain-outcome sentence lost; a network failure in the older form called a refusal; the older form tried again from itself; the task list falling back on any refusal, and an older list refused for another reason returned as empty; the two Download Station error types no longer typed; an upload, the statistics fallback, the older create form and File Station's delete classification each hiding a lost session or a redirect; a Download Station read not repeated; a change treated as a read, and six reads (polling, smart info, config, share list, registry search and tags, user shares) treated as changes; the shared client repeating every request or reporting a different code; a File Station or Download Station change repeated, or not renewed; the renewed-but-not-repeated error losing its code or its advice.

All 32 were caught the first time they were run. The R12 results are from the final run; whether some of those 19 needed a test tightened along the way is not recorded here.

## Observed, not changed

- **Download Station judges a destination by its name only, and `list_downloaded_files` is unfiltered.** Unchanged from the note in fix PR 3: none of the `ds_*` tools is in a broker client's default grant and the review does not name them. It is worth a fix before anyone grants them.
- **`check_enrollment_code` is now used only by tests** (from fix PR 2). Left in place; removing it is a separate clean-up.
- **A grant can be renewed only by editing the policy and restarting the broker.** There is no command for it. The guide documents the steps; automating them is a feature, not part of this review.

## Not yet verified

- **A real DSM.** Every NAS answer in the tests is scripted. How a real Download Station answers an unsupported API (the exact code on each DSM version), and whether 106/107/119 come back for an upload in the shape the tests use, has not been observed here. The codes follow Synology's published lists.
- **A long-lived broker.** The clock is injected in the tests; an ended grant on a broker that has been running for months has been checked only by crossing the boundary with a fake clock, and once with a real broker process started with a grant that had already ended.
- **The deployed setup.** The live servers still run the code from before these fixes. Nothing here changes them until the user redeploys.

## Follow-up after review (#30)

The bot's review of #30 had no blocking issues and four notes. They were checked against the code before anything changed, and two turned out different from how they were put.

| Note | What was found | Change |
|---|---|---|
| `ends.timestamp()` sits outside the `try`, so an extreme datetime could raise | It cannot: for a datetime with a time zone, `timestamp()` is a subtraction of two aware datetimes and does not overflow, for year 1 or 9999 in any zone (probed). But the probe found a **real** bug next to it: an `expires` before 1970 is accepted, and start-up then writes a note for the ended grant with `datetime.fromtimestamp(negative)`, which raises `OSError` on Windows. `expires: "1969-12-30"` stopped the broker with a traceback | An `expires` that ends before the start of the year 2000 is refused at load time with a message naming the setting. The `timestamp()` call also moved inside the `try`, which no test can tell apart (it cannot raise); a test shows that extreme dates only ever give a `PolicyError` |
| Check every read method the tools call is in `READ_ONLY_METHODS` | The services were read for every method they send. One gap: `start` is a change for a delete and a move but a **read for a search**, so a search that found the session gone was told to run it again | `READ_ONLY_CALLS` lists the `(API, method)` pairs that read although the name changes things elsewhere; `is_read_only(api, method)` decides and its three callers pass the API. A test reads the service modules, collects every method they send, and fails when one is in neither `READ_ONLY_METHODS` nor an explicit list of changes (and when a list names a method nobody sends), so the next added method is decided deliberately |
| The shared client returns a `session_renewed` result while File Station and Download Station raise | Confirmed, and visible to the client: a container call gave a JSON dump, a File Station call gave "Error executing ...: ..." | The shared client raises `SessionRenewedNotRepeated` too, and `_call_tool` answers it with the one fixed sentence and keeps the session (unlike a lost one). The `session_renewed` result shape no longer exists |
| `AccessToken.expires_at` is `int(...)`, which truncates | True, and the safe direction: the SDK's own check can only refuse up to a second early, never accept late. The broker's exact check is the one that decides | Kept, with a comment saying why and a test (fractional seconds) that fails if it were rounded up |

**Verification.** The new tests were run against the code before the changes: 24 failed, for the findings themselves (the floor, the search, the shared client, the tool layer); the rest are pins on behaviour that already held (the SDK second, the extreme dates, the audit of method names). On the final code, 15 faults were put in one at a time and all 15 were caught: the floor gone, off by a second either way, echoing the value, the SDK's second rounded up or to nearest, no read by API, a delete read by API, the API ignored, the shared client repeating a change again, File Station forgetting the API, the tool layer without an answer, the tool layer dropping a session that was only renewed, a read renamed where the services send it, and a read leaving the list. Moving `timestamp()` back out of the `try` is not on the list because no test can observe it.

**Not changed.** The server's own session table still holds the session id from before a service renewed its copy (the instances renew themselves). That is how legacy mode has always worked and is not part of the review.
