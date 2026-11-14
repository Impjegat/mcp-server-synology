# Synology MCP Server — Follow-up Review

Initial review date: 2026-09-29. Last revalidated: 2026-10-06.

Current reviewed source: `63ec02bafc6e2e11fbc2c67f15fb83a8e362165b` plus the local credential-serialization fix applied on 2026-10-06. The installed copy includes that fix; it has not been committed or pushed.

Original review baseline: `9cf8cc8c631981623b44f08128624535d58f5d74` (PRs #13 and #14).

Previous revalidation: `587dcfcb141d94a5c187e20a60cf26d65c43b834`, reviewed on 2026-09-30.

Local and remote `main` remain at `63ec02b`. The working tree now contains the masking fix and its regression tests in three files. Installation validation used a separate local runtime, isolated automated tests, and verified-HTTPS read-only calls to the real NAS. The original `REVIEW_REPORT.md` remains unchanged.

## Assessment

The three specific findings from the previous revalidation are resolved: invalid arguments no longer echo submitted credentials; a completely failed health summary is an error, with partial results clearly identified; and task requests are bounded by the remaining time budget.

The selected behaviour is implemented: partial health results retain successful data and name failed checks, while search/delete/move use a shared start-and-polling budget plus documented bounded extras.

The additional credential-redaction gap identified on 2026-10-01 is now fixed in the local and installed copies. The shared redactor masks raw strings and JSON-escaped spellings, including quotes, backslashes, control characters, and Unicode. Sixteen new regression cases cover known-secret response/log filtering and newly supplied credentials in successful and failed tool results. Remote `main` still needs this local fix to be committed and merged.

The final local suite passes with the installed MCP 2.3.0 runtime: 387 passed, 2 skipped, 40 deselected. Formatting and lint checks pass for the changed files. The earlier remote CI results below apply to the unmodified `63ec02b` baseline, not to the new uncommitted patch.

## Resolved findings

### 1. Invalid argument validation no longer exposes submitted values

The server now builds validation messages from trusted schema information instead of returning the validator's raw value-containing error. It also tracks password and device-token strings supplied on the current call, before authentication, so ordinary error messages can redact newly submitted credentials.

Independent probes against the real stdio server supplied previously unknown dummy values as arrays in each of `password`, `device_id`, and `otp_code`. All three calls returned `isError: true` with value-free validation messages. None of the dummy secrets appeared in responses, and a DEBUG-log probe likewise found no submitted secret. The rejected calls made no NAS request.

The documented masking policy excludes request-supplied strings shorter than four characters from blanket substring replacement, and excludes one-time codes from replacement by value. Argument-validation messages remain value-free regardless of these exclusions. These are explicit policy limits, separate from the escaped-password gap below.

Status: **resolved in the installed/local copy, including the additional escaped-password fix below.**

[Validation helper](https://github.com/Impjegat/mcp-server-synology/blob/63ec02bafc6e2e11fbc2c67f15fb83a8e362165b/src/mcp_server.py#L221)

### 2. Health summaries correctly report complete, partial, and failed checks

The aggregate result now distinguishes:

| Outcome | Tool behaviour |
|---|---|
| All available checks succeed | Successful result with `status: complete`. |
| Some checks succeed and others fail | Successful result with `status: partial`, a visible warning, successful `data`, and `failed_checks` naming the failures and their errors. |
| No check succeeds | Error result with details of the failed checks. |
| DSM reports the optional UPS API unavailable | Listed in `unavailable_checks`; successful available checks can still produce `status: complete`. Other UPS failures, such as network errors, remain failures. |

Independent probes verified each outcome through the MCP tool boundary. When all 11 underlying HTTP attempts, including fallbacks, failed, the result was an MCP error containing seven failed check entries. A single failed UPS network check produced a partial result and warning; an unavailable UPS API produced a complete result with its unavailability recorded.

A complete result means the requested available checks completed. A partial result does not establish that the NAS is healthy. The tool description and README explain that distinction.

Status: **resolved and consistent with the selected partial-success behaviour.**

[Health aggregation](https://github.com/Impjegat/mcp-server-synology/blob/63ec02bafc6e2e11fbc2c67f15fb83a8e362165b/src/health/synology_health.py#L171)

### 3. Task timeouts enforce the remaining budget and bound extra work

The deadline is established before starting the task. Polling uses the same deadline, each request receives only the remaining allowance, and waiting for a slow request is also bounded by elapsed time. Delete's initial metadata lookup is included in its budget and is separately capped at 15 seconds.

| Operation | Shared initial-work and polling budget | Separate allowances | Documented maximum waiting time |
|---|---|---|---|
| Search | 120 seconds | Results: 15 seconds; cleanup: 5 seconds | 140 seconds |
| Delete | 120 seconds, including metadata lookup | Cleanup: 5 seconds | 125 seconds |
| Move | 60 seconds | Cleanup: 5 seconds | 65 seconds |

Independent simulated-clock probes included 14 seconds for task startup. Search and delete exhausted their shared budget at 120 seconds, and move at 60 seconds. The last status requests received 4.5, 4.5, and 2.5 seconds respectively; cleanup received its own 5-second allowance. This replaces the previous search overrun to 130.5 seconds before cleanup.

A separate real elapsed-time probe blocked a status request and reduced its test allowance to 0.2 seconds. The caller stopped waiting after approximately 0.206 seconds. This exercises the elapsed-time guard independently of the HTTP library's socket timeout.

These limits bound how long the caller waits, subject to normal scheduling overhead. They do not guarantee cancellation of a background HTTP request or a NAS operation. Cleanup is best-effort. If a delete or move start request times out before returning a task ID, the error warns that the NAS may have started it anyway and advises checking before retrying. The README documents the same limitation.

Status: **resolved and consistent with the selected shared budget plus bounded extras.**

[Request wait guard](https://github.com/Impjegat/mcp-server-synology/blob/63ec02bafc6e2e11fbc2c67f15fb83a8e362165b/src/filestation/synology_filestation.py#L238), [search implementation](https://github.com/Impjegat/mcp-server-synology/blob/63ec02bafc6e2e11fbc2c67f15fb83a8e362165b/src/filestation/synology_filestation.py#L514)

## Additional credential finding — resolved locally

### P1 — JSON serialization bypassed credential masking

Locations: `src/mcp_server.py:866-868` and `src/utils/redact.py:67-68`.

`_dsm_result()` serializes a structured service result using `json.dumps()` before the response and logging redactors process it. The redactor replaces literal secret strings. JSON escapes quotes and backslashes, so the serialized text no longer contains the literal password even though decoding it reveals the entire password.

Reproduction against the reviewed revision:

1. Invoke `synology_create_user` through the real tool dispatcher with a dummy password containing a quote and a backslash. The value is longer than the four-character masking threshold and enters the current call's secret inventory.
2. Mock the user-management service to return an error whose diagnostic message includes that password. No NAS request is made.
3. Observe that the MCP result has `isError: true`, but its decoded JSON still contains the password.
4. Capture the accompanying warning through the normal redacting log filter. The JSON-escaped password remains in that filtered log message.
5. Repeat with a plain ASCII dummy password as a control: it is masked in both the response and the log.

This is conditional: the service response or diagnostic must contain the credential. The probe does not establish that ordinary DSM responses routinely echo passwords. It establishes that the promised masking does not protect this case when a credential does reach a structured response.

Remediation applied on 2026-10-06: the shared redactor now matches raw secrets and JSON-escaped spellings, with and without ASCII Unicode escaping. All spellings are replaced longest-first to preserve the existing overlapping-secret protection. Eight known-secret regression cases verify decoded JSON output and filtered log messages; eight additional dispatcher cases verify newly submitted passwords in successful and failed structured results. Value-free validation messages are retained.

The fix addresses the tested serialization gap in the README's masking claim. The documented short-request-credential and one-time-code policy exclusions remain unchanged; the fix does not promise masking of arbitrary encodings beyond raw and JSON-escaped representations.

Status: **resolved and regression-tested in the installed/local copy; not yet committed or pushed. The original reproduction applied to the remote `63ec02b` baseline.**

[Serialization before redaction](https://github.com/Impjegat/mcp-server-synology/blob/63ec02bafc6e2e11fbc2c67f15fb83a8e362165b/src/mcp_server.py#L866), [literal secret replacement](https://github.com/Impjegat/mcp-server-synology/blob/63ec02bafc6e2e11fbc2c67f15fb83a8e362165b/src/utils/redact.py#L67)

## Coverage of recommendations

| Recommendation | Current review result |
|---|---|
| MCP 2.x migration with a deliberate major-version bound | Implemented; tests use MCP 2.2.0 and the `<3` dependency bound remains. |
| Explicit errors for failed tools, including missing-file metadata and content requests | Implemented; the health aggregation gap is now resolved. |
| Safe validation messages and masking for newly submitted credentials | Original validation leak and JSON-escaped credential masking resolved in the installed/local copy. |
| Partial health results with visible failures; an error when every check fails | Implemented and independently verified. Optional unavailable UPS checks are identified separately. |
| Shared task deadlines, requests bounded by remaining time, and documented extras | Implemented and independently verified. Background/NAS cancellation remains best-effort. |
| Reject invalid and restricted calls before NAS requests | Implemented and covered by tests. |
| Protect settings permissions before writing secrets; abort if protection fails | Implemented with regression coverage. |
| Keep restricted mode enabled for unrecognised configuration values | Implemented with regression coverage. |
| Docker runtime credentials through optional `.env` and read-only settings | Implemented and documented. Local authenticated NAS startup is now verified. Docker authenticated startup remains unverified. |
| Docker image tests through the documented client launch command | Implemented; current container CI succeeds. |
| Keep future MCP major upgrades deliberate | Dependabot's major-version ignore rule remains. Whether dependency updates are enabled in repository settings was not checked. |
| Enforce the download size cap before JSON parsing and close responses | Implemented with regression coverage. |
| Windows test isolation | Implemented; the full isolated local Windows suite passes. |
| Documentation reflecting restricted mode, health outcomes, time limits, and settings-file naming | Updated in PR #17; the local serialization fix now closes the additional tested masking gap. |
| Optional approved-folder allowlist and credential-file exclusions | Still absent; the allowlist remains documented as deferred. |

## Verification and limits

Independent local Windows verification on 2026-10-01 used an isolated export of `63ec02b`, with production configuration excluded and automatic login disabled:

- Full automated suite excluding tests marked `real_nas`: **371 passed, 2 skipped, 40 deselected**, in 24.80 seconds.
- Additional real stdio probes verified value-free validation responses and DEBUG logs for newly submitted dummy credentials.
- Independent tool-level probes verified all-failed, partial, complete, and optional-UPS-unavailable health results.
- Simulated-clock probes verified shared search/delete/move deadlines and the request/cleanup allowances; a real elapsed-time probe verified bounded waiting for a blocked request.
- A separate mocked-service probe reproduced the remaining escaped-password leak in both the response and a filtered warning log.

The check statuses and logs for [CI run 36819597061](https://github.com/Impjegat/mcp-server-synology/actions/runs/36819597061), attached to this exact revision, were also verified:

| Check | Verified result |
|---|---|
| Windows tests | 371 passed, 2 skipped, 40 deselected. |
| Linux tests | 373 passed, 40 deselected. |
| Docker image | Image built successfully; 15 protocol tests passed, 1 skipped. |
| Lint and formatting | Successful. |

The container skips the separate DEBUG-log subprocess test because that test requires changing the server launch command. It therefore does not establish Docker coverage for that particular logging check; the local stdio probe covered it independently. Docker is unavailable on this review machine, so image-build and container results come from the GitHub job.

The 2026-10-01 review used no live NAS credentials. The 2026-10-06 installation check used the existing configured credentials without printing them, completed a verified-HTTPS login, and exercised real read-only tools over MCP stdio. No NAS files or administrative settings were modified. Loading the registered tools into the assistant application's next session remains the final user step. The optional approved-folder allowlist and credential-file exclusions remain deferred.

No new review document was created. The local implementation change is limited to `src/utils/redact.py`, with regression tests in `tests/test_redact.py` and `tests/test_tool_calls.py`. A separate installation guide records the installed configuration. The original `REVIEW_REPORT.md` was preserved.


## Installation validation — 2026-10-06

- Installed a dedicated local runtime: Python 3.13.14 and MCP 2.3.0, within the declared supported `<3` major-version bound. The installed dependency versions and source hashes are recorded locally.
- Full final automated suite with that runtime: **387 passed, 2 skipped, 40 deselected**, in 20.79 seconds. Live NAS tests were excluded from that automated suite; the connection checks below were performed separately.
- All three changed files pass formatting and lint checks.
- Credentials were copied from the existing configuration to a local settings file whose protected Windows ACL grants access only to the current Windows account. They are absent from the assistant application's MCP configuration.
- The installed launcher enforces restricted mode, certificate verification, disabled debug logging, disabled legacy dotenv loading, and a **1,000,000-byte** file-reading cap. It prevents inherited legacy NAS environment variables from overriding the installed connection.
- Registered the server as `synology`, with an explicit allowlist of **37 advertised read-only tools**, a 90-second startup allowance, and a 180-second client tool timeout. Client timeouts do not replace the server's task-specific budgets. Existing application settings and other MCP entries were preserved.
- Verified a real TLS-checked NAS login, successful listing of nine shares, successful system-information retrieval, and a complete health summary with no failed or unavailable checks through the installed server's MCP stdio interface. Modifying tools and account enumeration are hidden by restricted mode. The client allowlist also excludes direct login/logout calls; startup handles authentication.
- The current chat's tool inventory predates registration. Restart the assistant application and use a new chat to load the new tool definitions before treating integration as complete in the actual assistant session.
