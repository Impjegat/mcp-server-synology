# Manual authentication: implementation review

**Date:** 11 October 2026  
**Reviewed commit:** `b0374034b26d82fb57417edf3caf7eadd32a28b3`  
**Reviewed update:** [PR #25](https://github.com/Impjegat/mcp-server-synology/pull/25), including the preceding manual-authentication changes incorporated into that branch.  
**Requirements:** [Implementation roadmap](PLAN.md) and [original implementation plan](../2026-10-06-manual-authentication/PLAN.md).  
**Verdict:** The main software components are implemented, but the agreed security protections are not complete. The findings below need resolution before approving the new installation for use with a replacement NAS password.

This document records the review already performed. It does not implement fixes or authorize deployment, password rotation, OTP enrollment, or changes to the installed integration.

## Review scope and version

The updated branch was exported into an isolated temporary copy for source inspection, fake-only checks, and test execution. No production credential files were read, no real NAS requests were made, and the original repository was not modified during the code review.

At the time this document was written, the local checkout had advanced to `9a5e3ed42f41f680a84d1d47e97311375cbf2888`. Compared with the reviewed commit, it contains additional changes to `CHANGELOG.md`, `pytest.ini`, `tests/conftest.py`, and `tests/test_pytest_config.py`. The authentication, broker, adapter, and NAS service source files referenced below are unchanged. Test counts in this report belong to the earlier reviewed snapshot; the test suite was not rerun merely to write this document.

Code links deliberately point to the reviewed commit so that the evidence remains stable after subsequent fixes.

## Coverage of the agreed changes

| Agreed change | Review result |
|---|---|
| Protected broker and credential-free local adapter | Implemented. Actual host isolation and installed-client cutover still require deployment verification. |
| Private password/OTP input, owner passkey, and short-lived login worker | Implemented, with an enrollment authorization bug and an in-progress login cancellation bug. |
| No stored NAS password, password-based automatic renewal, or trusted-device persistence in manual mode | Implemented. Manual mode rejects stored password/OTP/device settings, skips dotenv loading, does not cache the password, does not request reusable device trust, and refuses transparent relogin. |
| Broker-owned in-memory sessions, idle/absolute deadlines, and scoped tool/NAS access | Implemented, with remaining authentication-state and client-token expiry concerns. |
| Folder allowlist, denied paths, and protection against alternate paths | Implemented in part. Denied-folder symlinks can bypass enforcement, and some discovery results are not filtered. |
| Consistent authentication-required errors | Implemented for common paths, including shared health/NFS/container/user requests. Some optional upload and DownloadStation fallbacks remain incorrect. |
| Verified NAS HTTPS and approved destinations | HTTPS URLs are used, but redirects can forward credentials elsewhere, certificate verification can be disabled, and private-CA settings are inconsistent. |
| Friendly command titles and generated catalog | Implemented; catalog consistency check passed. |
| Separate images, deployment templates, configuration examples, documentation, and CI | Implemented; repository checks and remote CI passed. These checks do not establish real-host isolation or resolve the findings below. |
| Safe migration, password rotation, old-session revocation, OTP enrollment/recovery, and live acceptance | Documented user-operated steps. Completion was not verified during this review. |

## Findings at a glance

**High** means a security control can be bypassed or authentication material can be exposed. **Medium** means a required restriction, configuration, or operation behavior is incomplete or incorrect.

| ID | Priority | Finding | Exposure |
|---|---|---|---|
| R01 | High | Passkey enrollment can bypass the enrollment-code check | Private interface during additional-device enrollment |
| R02 | High | A symbolic link can bypass a denied folder | Default file-reading capability |
| R03 | High | NAS redirects can forward credentials to another host | Authentication and authenticated NAS requests |
| R04 | High | Manual login permits disabled NAS certificate verification | Deployments configured with verification disabled |
| R05 | High | Cancelled or expired in-progress login can still install a session | Private login/session lifecycle |
| R06 | Medium | Directory listings disclose denied child metadata | Default directory browsing |
| R07 | Medium | NFS share discovery bypasses folder scope | Default NFS discovery |
| R08 | Medium | Private login ignores the documented server-level CA setting | NAS using a private CA |
| R09 | Medium | Download creation can repeat after an ambiguous failure | Optional modifying DownloadStation tools |
| R10 | Medium | Some expired-session paths do not return authentication required | Optional DownloadStation/upload tools |
| R11 | Medium | Legacy retries treat GET requests as proof of read-only behavior | Legacy mode |
| R12 | Medium | Client grants have no expiry validation | Requirement gap in broker client authorization |

No finding is marked fixed by this report.

## R01 — Bind passkey enrollment to authorized enrollment state

**Evidence:** [owner.py:354](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/private_auth/owner.py#L354), [private endpoint:553](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/private_auth/app.py#L553).

Sign-in and enrollment share a challenge table without recording the ceremony's purpose. Enrollment completion accepts a challenge created for ordinary sign-in. While an additional-device enrollment code is open, a caller who can reach the private interface can register a passkey without knowing that code.

A fake-only check using the real WebAuthn verifier and the existing simulated authenticator successfully registered the unauthorized passkey and then authenticated with it.

**Required fix:** Separate or explicitly tag sign-in and enrollment challenges. Bind an enrollment challenge to the successfully verified enrollment-code generation, and atomically check/consume that authorization when adding the credential.

**Acceptance:** A sign-in challenge cannot complete enrollment. Wrong, absent, expired, replaced, or consumed enrollment authorization cannot add a passkey. Concurrent completions cannot reuse one authorization. Legitimate first-device and additional-device enrollment still work.

**Roadmap owner:** Private login, PR 3.

## R02 — Apply denied paths in the resolved physical namespace

**Evidence:** [file_policy.py:214](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/broker/file_policy.py#L214).

Allowed roots are resolved to physical NAS paths, but denied paths remain share paths. A physical target can therefore pass the deny check even though its share-path equivalent is denied.

With allowed `/docs`, denied `/docs/private`, and a permitted-looking link resolving into the physical location of that denied directory, a fake-only content-read check reached the mocked download and returned the denied dummy content. Links outside an allowed root are not the only case that needs protection: links into denied subtrees inside an allowed root also matter.

**Required fix:** Enforce both lexical and resolved denials. Resolve denied locations into the same namespace as the target, including alternate share aliases, and refuse access when a required resolution cannot be established.

**Acceptance:** Direct access and links into denied subtrees both fail. Equivalent targets through another share or alias fail. Unknown resolution fails closed. Ordinary permitted files remain readable.

**Roadmap owner:** Broker sessions and policy, PR 2.

## R03 — Prevent authenticated NAS redirects from changing destination

**Evidence:** [password login:280](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/auth/synology_auth.py#L280), [shared NAS client:166](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/utils/synology_api.py#L166).

NAS requests use redirect-enabled Requests calls. An offline check using the real redirect engine and a fake HTTP adapter demonstrated that a redirect could forward a dummy login password/OTP to another HTTPS origin. An authenticated read also forwarded its session-token header.

This applies to NAS-side requests, independently of the adapter's broker transport protections.

**Required fix:** Disable redirects on all authenticated NAS requests, or implement explicitly approved same-origin redirect handling that cannot forward secrets to another destination. Audit login, logout, shared API, FileStation, DownloadStation, uploads, and content downloads.

**Acceptance:** Cross-origin redirects never cause a second authenticated request. Redirect responses produce safe errors. Passwords, OTPs, SIDs, cookies, and session-token headers never reach an unapproved origin.

**Roadmap owners:** Manual-authentication core, PR 1; private worker, PR 3.

## R04 — Require NAS certificate verification in manual mode

**Evidence:** [configuration:211](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/config.py#L211), [worker validation:60](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/private_auth/worker.py#L60), [deployment setting:48](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/deploy/broker/docker-compose.yml#L48).

Broker configuration accepts disabled NAS certificate verification. The worker accepts the boolean and forwards it into password authentication. A fake-only configuration/worker check produced a login request with verification disabled and no configuration validation error.

That does not meet the original plan's verified-HTTPS requirement.

**Required fix:** Manual mode must accept certificate verification enabled or an approved CA bundle, and reject disabled verification at startup and at the worker boundary. Align deployment examples and comments with that rule.

**Acceptance:** Disabled verification fails before any login request. Invalid or untrusted certificates fail safely. Approved public/private CA configurations succeed without weakening verification.

**Roadmap owners:** Core, PR 1; private login, PR 3; deployment, PR 6.

## R05 — Recheck authorization before adopting a completed login

**Evidence:** [login.py:192](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/private_auth/login.py#L192), [session installation:225](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/private_auth/login.py#L225).

The pending request is checked before awaiting the worker. A successful worker response installs a session afterward without atomically confirming that the pending request remains valid.

A controlled fake worker demonstrated that cancelling a request while it was running still resulted in a connected session after the worker completed.

**Required fix:** Atomically verify and consume the pending request when adopting the result. Cancellation, expiry, replacement, and disconnect must invalidate the outstanding login generation. Discard and perform bounded cleanup of any session returned after its authorization is withdrawn.

**Acceptance:** Cancellation, expiry, or disconnect during login cannot activate a session. Concurrent submissions cannot replace a newer session with an older result. Tests cover the period while the worker is running, not only cancellation before submission.

**Roadmap owners:** Broker sessions, PR 2; private login, PR 3.

## R06 — Filter directory children against the folder policy

**Evidence:** [list_directory:418](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/filestation/synology_filestation.py#L418).

Directory browsing verifies the requested parent, then returns every child. It does not apply the equivalent of search-result filtering to child paths and resolved targets.

A fake-only check returned a denied credential-file name, a denied directory, and a link resolving outside the allowed root, including metadata.

**Required fix:** Request the resolution information needed for each child, filter lexical and physical paths, and omit entries whose authorization cannot be demonstrated.

**Acceptance:** Denied children, outside links, and unresolved unsafe entries do not appear in directory results or expose metadata. Permitted children remain visible.

**Roadmap owner:** Broker folder policy, PR 2.

## R07 — Scope NFS discovery to permitted shares

**Evidence:** [NFS discovery:62](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/nfs/synology_nfs.py#L62), [unfiltered forwarding:1641](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/mcp_server.py#L1641).

The default NFS share-discovery tool returns all shares and their NFS permissions. Its response is forwarded without applying the caller's folder scope.

**Required fix:** Filter discovery to permitted shares and approved metadata, or remove this tool from the default broker scope if that filtering cannot be established safely.

**Acceptance:** A client scoped to one share cannot discover unrelated protected shares or their NFS client/permission information.

**Roadmap owner:** Broker policy, PR 2.

## R08 — Use one finalized NAS TLS configuration

**Evidence:** [per-NAS configuration:520](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/config.py#L520), [server override:547](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/config.py#L547), [worker payload:210](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/private_auth/login.py#L210).

Each NAS captures the current TLS setting before the server-level override is applied. Private login uses that stale per-NAS value, while other services use the final global value.

Fake settings with a server-level CA bundle produced the expected global path but left the NAS entry at ordinary system trust. This breaks the documented private-CA setup during login.

**Required fix:** Finalize per-NAS transport settings after applying overrides, or use a single authoritative transport configuration.

**Acceptance:** A configured CA bundle reaches the actual worker payload and subsequent NAS requests. Tests verify both configuration properties and request arguments.

**Roadmap owners:** Core, PR 1; private login, PR 3.

## R09 — Do not repeat download creation after uncertain outcomes

**Evidence:** [DownloadStation creation fallback:388](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/downloadstation/synology_downloadstation.py#L388).

After a generic error, including a timeout, creation falls back to another API version and sends another create request. The first request may already have created the download.

A fake-only check observed two create requests after the first timed out.

**Required fix:** Restrict version fallback to definite unsupported-version responses that establish no mutation occurred. Do not replay after timeout, connection loss, or other uncertain results.

**Acceptance:** Ambiguous failures cause one create request and a clear uncertain-outcome error. A definite unsupported-version response may use the documented safe fallback.

**Exposure:** Optional modifying DownloadStation tools, excluded from the default restricted broker scope.  
**Roadmap owner:** Core/service request handling, PR 1.

## R10 — Preserve authentication-required errors through every fallback

**Evidence:** [upload error:748](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/filestation/synology_filestation.py#L748), [task-list fallback:241](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/downloadstation/synology_downloadstation.py#L241), [statistics fallback:458](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/downloadstation/synology_downloadstation.py#L458).

Three fake-only checks demonstrated inconsistent expiry handling:

- File creation receives an expired-session upload response but raises a generic upload error.
- DownloadStation version fallback encounters session expiry but returns an apparently successful empty task list.
- Statistics fallback encounters session expiry but returns zero/default statistics.

**Required fix:** Apply typed session-loss handling to upload and explicitly rethrow authentication-required errors inside nested fallback handlers. The broker must invalidate the relevant session and request fresh private authentication.

**Acceptance:** Each affected path returns an error with `AUTHENTICATION_REQUIRED`; none reports fabricated empty or zero results as a substitute for authentication.

**Exposure:** Optional DownloadStation/upload tools.  
**Roadmap owner:** Core/service expiry handling, PR 1.

## R11 — Classify retry safety by operation, not HTTP verb

**Evidence:** [FileStation retry:236](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/filestation/synology_filestation.py#L236), [shared-client retry:126](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/utils/synology_api.py#L126).

Legacy recovery treats GET requests as read-only. Some NAS mutations use GET, including rename and task-start operations. A fake-only legacy check observed a repeated rename after session renewal. The shared client can also retry a POST mutation.

**Required fix:** Classify the actual operation explicitly. Never replay a modifying operation automatically during authentication recovery.

**Acceptance:** Rename, create, delete, and move starts are not replayed. Approved read recovery remains bounded. Manual mode continues to require human authentication rather than password renewal.

**Exposure:** Legacy mode; this is separate from the default manual broker workflow.  
**Roadmap owner:** Core/request recovery, PR 1.

## R12 — Implement the agreed client-grant expiry validation

**Evidence:** [policy.py:323](https://github.com/Impjegat/mcp-server-synology/blob/b0374034b26d82fb57417edf3caf7eadd32a28b3/src/broker/policy.py#L323).

The verifier returns an access token with `expires_at=None`. The agreed source plan requires client-grant expiry validation; the current client policy has no expiry field to enforce.

NAS session deadlines are implemented, but they are different from the lifetime of the client grant that can invoke broker operations.

**Required fix:** Add an administrator-controlled grant expiry policy and enforce it on authorization. Document how a client grant is renewed or revoked. If perpetual grants are intended instead, record that as an explicit change to the original requirement rather than claiming the expiry requirement is complete.

**Acceptance:** An expired or revoked grant cannot invoke broker tools; renewing a grant does not silently extend an existing DSM session's absolute lifetime.

**Roadmap owner:** Broker client authorization, PR 2.

## Verification performed

All automated authentication checks used dummy values and fake services. No real password, OTP, recovery material, or NAS session was supplied.

| Check | Result |
|---|---|
| Fake-only suite on the reviewed Windows snapshot | 1,353 passed, 49 skipped, 40 real-NAS tests deselected |
| Git-ignore checks initially skipped because the snapshot was an archive | 20 passed after adding Git metadata only to the temporary copy |
| Combined unique passing tests | 1,373 |
| Remaining skipped tests | 29: platform-specific checks and Docker tests not run locally |
| Lint | Passed |
| Formatting | Passed; 84 files would remain unchanged |
| Generated tool catalog | Up to date |
| Remote PR #25 checks | Linux tests, Windows tests, Docker images, and lint all succeeded |

The remote results are available in [PR #25 checks](https://github.com/Impjegat/mcp-server-synology/pull/25/checks). The local combined total includes the separately executed 20 Git-ignore tests; it is not a claim that a second full suite was run.

Fake-only checks confirmed the enrollment bypass, denied-folder content read, directory metadata disclosure, redirect forwarding, disabled certificate verification, cancellation race, CA-setting mismatch, download-creation replay, affected expiry fallbacks, and legacy mutation retry. The NFS discovery and client-grant expiry findings are established by source inspection.

A green existing suite is evidence of covered behavior, not evidence that these missing negative cases are safe.

## Remaining deployment acceptance

These items cannot be established from repository code or fake tests alone:

- [ ] Choose and prove an independently protected broker host.
- [ ] Confirm AI-side tools cannot read or modify its files, memory, code, dependencies, policy, private interface, logs, backups, or administration interfaces.
- [ ] Fix and verify the applicable findings in this report before entering a replacement NAS password.
- [ ] Deploy reviewed artifacts through a human-controlled administration path.
- [ ] Replace every installed direct-server registration and stop old authentication processes.
- [ ] Retire credential-bearing files, environment references, old sessions, and trusted-device grants.
- [ ] Rotate the NAS password privately only after isolation checks pass.
- [ ] Enroll the private passkey and NAS OTP, and verify the account's recovery path.
- [ ] Verify the actual browser/passkey ceremony, live read-only health check, folder scope, expiry, disconnect, and safe rollback.
- [ ] Update the existing outer installation guide and follow-up review in place with dated deployment evidence; preserve the original review report.

No box is marked complete merely because software for that step exists.

## Suggested remediation order

1. Close the private enrollment bypass and credential-transport weaknesses: R01, R03, R04.
2. Close the denied-folder content bypass and authentication cancellation race: R02, R05.
3. Correct discovery filtering and CA configuration: R06, R07, R08.
4. Complete client-grant expiry and applicable service/legacy behavior: R12, R09, R10, R11.
5. Add focused negative regression cases, rerun the relevant suite and CI, then perform the private user-operated deployment checks.

The main architecture follows the agreed design. Security approval remains pending until the applicable findings and real deployment acceptance are resolved.
