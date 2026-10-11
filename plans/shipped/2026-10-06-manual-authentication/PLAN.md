# Manual authentication and credential isolation implementation plan

**Written:** 6 October 2026  
**Status:** Implemented in the roadmap's PRs ([`../2026-10-10-manual-auth-roadmap/PLAN.md`](../2026-10-10-manual-auth-roadmap/PLAN.md)) and in the four fixes that followed the independent review. Deployment, the cutover and the live acceptance checks are the user's and are not done; the guide's "Moving from the old setup" lists them. (Originally: plan only, not started.)  
**Repository baseline:** `63ec02bafc6e2e11fbc2c67f15fb83a8e362165b`, together with the existing local redaction changes in `src/utils/redact.py`, `tests/test_redact.py`, and `tests/test_tool_calls.py`.

## 1. Outcome and agreed scope

The user will supply the NAS password privately when a new NAS login is needed. If two-factor authentication is enabled, the user will also supply the current verification code privately. An AI client will receive connection status and authorized NAS results without receiving the password, verification code, or NAS session credentials.

This plan covers every identified change needed for that workflow:

1. A protected service that performs NAS authentication and executes approved operations.
2. A credential-free connection from existing AI applications to that service.
3. Private, human-controlled password and OTP entry.
4. Removal of saved-password login, password-based reconnection, and trusted-device persistence from the recommended deployment.
5. OTP enrollment and recovery preparation performed privately by the user.
6. Clear command names, descriptions, and a readable command catalog.
7. Migration of the installed integration, security checks, regression checks, documentation, and safe rollback.

No new Windows account on the current computer is the preferred approach. This requires hosting the protected service somewhere with a real access boundary from AI applications. The exact host must be selected and validated before implementation can be declared secure.

1Password may be used by the user to fill the private login form. Automatic retrieval from a password manager is outside the selected manual workflow. This plan does not require a password-manager SDK, CLI, vault token, or vault access from an AI application.

Writing this plan authorizes documentation only. It does not change NAS accounts, enroll OTP, rotate passwords, change the installed integration, deploy a service, or alter repository code. Those are subsequent implementation and user-operated deployment steps.

## 2. What must change in the present design

The current manual-login setting is insufficient for the requested privacy goal:

- The server can accept a password, OTP, and device identifier through an MCP login tool.
- `SynologyAuth` caches the successful username/password in `_credentials` and can reuse them to renew an expired session.
- OTP login can request a trusted-device token, cache it, and save it to configuration.
- Shared API requests can silently reauthenticate on DSM session expiry. FileStation and DownloadStation also have HTTP paths that require separate review.
- NAS definitions currently depend on credentials being present; removing a password can make a configured NAS disappear.
- Both the configuration layer and the entry point have dotenv loading paths.
- The installed launcher still reads a password-bearing settings file and runs the authenticated service under the same Windows user accessible to AI applications.
- Existing restrictions protect individual tool calls but do not create an operating-system boundary around the password or authenticated process.
- Current NAS path protection blocks critical locations but does not implement an approved-folder allowlist.

A masked password box, file permissions for the existing Windows user, encrypted storage usable by that user, or a container controlled by that user cannot by themselves make the password inaccessible to an AI with the same access.

## 3. Required architecture and protection boundary

```text
AI application on the current computer
             |
             | local MCP over stdio; no NAS secrets
             v
Credential-free adapter
             |
             | authenticated HTTPS; approved MCP operations only
             v
Protected NAS broker on an independently administered host
             |
             | verified HTTPS; fixed NAS targets; private DSM sessions
             v
Synology DSM

User on a separate trusted device
             |
             | private human authentication channel
             v
Protected login interface -> short-lived authentication worker
                                      |
                                      | private internal session handoff
                                      v
                               Broker session manager
```

The adapter is a small local bridge. It forwards approved MCP requests to a remote broker using the SDK's supported transport rather than inventing a new wire protocol. The broker owns NAS authentication, NAS sessions, enforcement, and result sanitization. MCP supports a local stdio transport and a separately running Streamable HTTP server; the remote service must implement the associated authentication and origin protections. [MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

### 3.1 Hosting prerequisites

Before accepting a real password, demonstrate all of the following:

- AI applications cannot read the broker's files, memory, configuration, private logs, authentication requests, or runtime state.
- AI applications cannot edit the deployed broker's code, dependencies, startup command, policy, TLS configuration, or authentication interface.
- AI applications cannot administer the broker host through SSH, Docker, a mounted socket, a management API, remote execution, shared folders, backups, or another installed connector.
- AI applications cannot inspect or operate the user's private authentication device/browser, its password manager, its authenticator, or its recovery material.
- The protected deployment does not automatically execute changes from the AI-editable repository. A human-controlled release process approves and installs reviewed artifacts.
- Credentials and session-bearing artifacts are excluded from NAS browsing, searching, container inspection, logs, backups exposed through tools, and alternate share aliases.

A separate machine is the preferred straightforward boundary. A NAS-hosted broker is acceptable only after proving that the integration account and every AI-accessible NAS/host tool cannot expose or administer that broker. A container is a packaging choice, not sufficient evidence of isolation.

If a same-computer design is chosen later, it requires actual OS identity and administration separation. That changes the preferred deployment and must be documented before proceeding.

**Stop condition:** If these boundaries cannot be demonstrated, report the limitation. Do not describe the password as inaccessible to AI and do not ask the user to enter or rotate a real password into that design.

### 3.2 Two distinct forms of authorization

| Authorization | Purpose | May be accessible to the AI-side application? |
|---|---|---|
| MCP client grant | Invoke a limited set of broker operations for an approved NAS and folder scope | Yes, if necessary; it must not grant private-login access, DSM session export, or host administration |
| Private human authorization | Open and submit the protected login interface | No; keep it on the user's trusted device |
| NAS password and OTP | Establish a DSM session | No |
| DSM SID, SynoToken, cookies, device tokens | Authenticate NAS requests | No; sessions remain inside the broker; device-token persistence is disabled |

Use standard MCP authorization where applicable, with grants scoped to a particular broker, client, owner, and permitted operations. Validate audience, expiry, revocation, and permissions. A client-editable adapter or client grant must never enlarge the broker's policy.

Use an independently controlled human authorization method for the private interface, preferably a passkey on the user's trusted device. Initial enrollment is a human administration step outside AI-accessible channels. An AI-visible request identifier, URL, or notification must not function as a human-login bearer credential.

## 4. User experience and authentication state

### 4.1 Expected workflow

1. The AI application starts its adapter without a NAS password. It can list permitted NAS names and obtain safe connection status.
2. A NAS operation without a valid session returns `isError: true` with a stable `AUTHENTICATION_REQUIRED` code and a short instruction to authenticate privately. It returns promptly; it does not wait for a person to enter a password.
3. The user opens the previously enrolled private interface on the trusted device. The interface identifies the NAS, intended account, requesting client, and granted access before submission.
4. The user supplies the password and, when required, a fresh OTP. Password-manager autofill is optional and human-controlled.
5. The protected component logs in over verified HTTPS and supplies the resulting session only to the broker. The password and OTP are not saved for reuse.
6. The private interface confirms connection. The AI can see only a safe connected status. The user or client retries the original permitted read operation.
7. When a session expires, is disconnected, or is lost after a broker restart, a new private login is required.

The password and OTP must never be requested in chat, MCP arguments, an AI-operated terminal, a tool result, an AI-readable file, or an AI-operated browser. Do not add an MCP tool that collects them.

### 4.2 State model

| State | Broker behavior | AI-visible behavior |
|---|---|---|
| Disconnected | Holds no usable DSM session | Status is disconnected; NAS operations require private authentication |
| Authentication pending | Holds an expiring request reference; does not retain password while awaiting user input | Safe pending status; duplicate requests do not generate repeated prompts |
| Connected | Holds DSM session credentials in protected memory | Approved operations succeed subject to policy |
| Expired or revoked | Discards local session access; attempts bounded DSM logout where appropriate | `AUTHENTICATION_REQUIRED`; no automatic password login |
| Broker unavailable | Executes no NAS requests through a fallback | Safe connection error; no fallback to the old local server |

Implement real idle and absolute session deadlines. The existing configured session timeout must not be treated as an enforced lifetime until verified. Select concrete timeout values during deployment review, document them, and test enforcement. Define whether idle time advances on successful authorized operations, and ensure absolute expiry cannot be extended by activity.

A broker restart loses in-memory sessions and requires fresh authentication. An adapter/client restart may reuse a still-valid broker session only within its existing owner/client policy. Restarting an adapter must not extend the session's absolute lifetime.

### 4.3 Concurrency, failures, and operation handling

- Bind each session to the approved NAS, human owner, and MCP client grant. Do not share an administrator session indiscriminately between clients.
- Use session generations and locking. A delayed failure from an old request must not invalidate a newer successful login.
- Deduplicate pending authentication requests. AI requests must not trigger repeated DSM login attempts or account lockouts.
- Interpret authentication failures using the relevant API's documented error codes; do not treat every numeric error as session expiry.
- Disable password-based transparent relogin in manual mode. Never queue or automatically replay modifying operations after a new login. Default read retries remain explicit and bounded.
- Clear local session access on disconnect even if remote logout fails. Best-effort DSM logout has a fixed timeout and must not block cleanup indefinitely.
- Cancel or close in-flight requests where supported. Document that an already issued NAS request may finish after revocation; do not promise that a local timeout reverses a NAS action.
- Health summaries must distinguish missing authentication from poor NAS health. Preserve partial results for independent health failures; a globally expired session returns authentication required.
- Handle invalid password, wrong/expired OTP, cancelled entry, certificate failure, connection loss, and account lockout with safe, value-free messages. Never retain a password while waiting indefinitely for a second code.

## 5. Private login interface and secret lifetime

### 5.1 Human interface

Implement a private HTTPS interface separate from the MCP API's authorization surface. Restrict it to the user's trusted device/network or another demonstrable human-only access path. Apply independent owner authentication, expiring requests, target/client binding, rate limits, CSRF protection, strict origin checks, and secure cookies.

The interface must:

- Display the intended NAS and access scope clearly.
- Require deliberate human submission; an MCP call cannot approve a login or substitute the target/account.
- Keep passwords, OTPs, session tokens, and authorization codes out of URLs, page telemetry, analytics, crash reports, request-body logs, browser storage, and cached responses.
- Use restrictive browser security headers and framing rules; avoid third-party scripts or resources on secret-entry pages.
- Avoid public debug endpoints, request inspection, development error pages, and browser-console logging of form data.
- Return no password, OTP, DSM SID, SynoToken, cookie, or device identifier to the adapter.
- Support cancellation, clear expiry messages, and explicit disconnect.

The user must operate this interface outside the computer/browser session available to AI automation. A private route alone does not protect a secret if the AI can read the screen or browser DOM containing it.

### 5.2 Authentication worker

Introduce a short-lived protected process for secret-bearing login handling. Keep body parsing and login processing in that short-lived component where practical; otherwise explicitly audit and minimize copies created by the protected web front end. The long-lived broker receives session credentials through a protected internal channel, not passwords.

Changes include:

- HTTPS POST login with certificate and hostname verification; retain bounded authentication requests.
- Credentials received only through the private human channel and protected internal IPC, never process arguments, environment variables, temporary files, or terminal output.
- No `_credentials` assignment and no cached password for reconnection in manual mode.
- No trusted-device request, reuse, cache, or persistence. Omit/disable `enable_device_token`; do not use a returned `did` as a future authentication shortcut.
- Verify whether one DSM session can serve every enabled service, including DownloadStation, and implement correct service/session routing. If a separate service-specific login is necessary, request fresh private password/OTP input through a new human authentication step; do not reuse a previously submitted OTP or retain a password for a later login. Clean up partially established sessions if the overall login flow fails.
- End the secret-bearing worker after success, failure, cancellation, or a short bounded deadline. Pass only required DSM session state internally to the broker.
- Protect IPC, disable secret-bearing crash dumps where supported, and prevent logs/traces from capturing request bodies or exception locals.

Do not claim guaranteed in-process erasure of immutable Python strings. Process isolation, short lifetimes, reduced copies, and protected host access are the enforceable controls. A host administrator remains able to defeat that boundary.

### 5.3 Session manager

Add a broker-only session manager with per-owner/client/NAS records, creation/idle/absolute deadlines, session generation numbers, atomic replacement, revocation, and bounded cleanup. Keep SID, SynoToken, and related cookies in protected memory only. Do not serialize them to disk, manifests, health responses, diagnostics, MCP transport state, or client caches.

An MCP transport session identifier is separate from a DSM session identifier. Never use one to disclose or recover the other.


## 6. Configuration and enforcement changes

### 6.1 Secret-free manual configuration

Introduce an explicit manual-broker authentication mode as the recommended installation. Use separate schemas for the local adapter and protected broker.

| Local adapter configuration | Protected broker configuration |
|---|---|
| Broker HTTPS address and expected identity | Fixed approved NAS aliases and verified HTTPS endpoints |
| CA/trust configuration | NAS CA/trust configuration |
| Scoped MCP client authorization mechanism | Restricted tool policy and approved folder roots |
| Bounded connection/tool timeouts | Human interface authorization and enrollment policy |
| Safe logging settings | Session deadlines, quotas, audit settings, and secret-free account metadata |

No schema in manual mode may contain a NAS password, current OTP, OTP seed, recovery material, trusted-device token, SID, or SynoToken. The broker may contain a configured username if needed; it is not a password substitute.

Reject incompatible stored-password, OTP/device-token, or automatic-login settings with messages naming the prohibited fields, without echoing their values. Disable dotenv loading in both entry-point and configuration paths for manual mode. Do not silently fall back to `.env`, legacy settings, a password manager, or an inherited credential environment.

Load NAS names and endpoint metadata before authentication. Replace checks that conflate 'NAS configured' with 'password exists'. Status and permitted NAS discovery must work without secrets.

If legacy authentication is retained for other users, make it a separate explicit mode with clear security limitations and independent tests. It must not be available as a fallback in this deployment. Prefer separate entry points/build profiles so the adapter cannot accidentally start the legacy service.

### 6.2 Server-side tool and target policy

Enforce restrictions at the broker, even when the local adapter, application configuration, or a malicious direct caller is changed.

- Remove password-bearing login tools from discovery in manual mode and reject direct calls to them at dispatch and validation.
- For session-management tools, permit only credential-free connection status, permitted NAS discovery, and policy-scoped disconnect/authentication-request status operations. Approved health and file tools remain available within the broker policy.
- Do not expose generic HTTP forwarding, arbitrary Python/command execution, configuration reads, authentication exports, or secret diagnostics.
- Resolve tools against preconfigured NAS aliases. Reject arbitrary `base_url`, hostname, port, redirect, or target overrides; constrain trusted certificate paths to administrator-approved configuration.
- Maintain restricted mode and the existing explicit read-only scope. Account/group/permission enumeration remains excluded from the default scope.
- Apply schema validation, time bounds, quotas, permission checks, and redaction on the broker as well as safe adapter forwarding.
- Treat debug logs, container inspection, environment dumps, mounted-volume inspection, and log-reading tools as possible credential disclosure paths. Filter or disable them if safe redaction cannot be established.

### 6.3 Folder policy

Add an explicit administrator-controlled list of permitted NAS roots. Preserve current critical OS-path protection, with exact-root checks for raw volumes and `/homes` and appropriate prefix checks for genuine OS directories.

Apply the approved-root policy to directory lists, share discovery, metadata, search, content reads, and any enabled file operation. Filter disallowed search/list results and metadata; do not merely block subsequent content reads.

Deny access to broker deployment/state, legacy credential files, authentication/recovery material, protected logs, backups containing secrets, and equivalent locations through another share or mount. Canonicalize separators, Unicode, traversal, aliases, and link targets. Where DSM cannot establish that a link stays inside an approved root, refuse it rather than assume it is safe.

Preserve the current file-content size cap and bounded search/delete/move behavior. Server-side access control cannot replace operating-system restrictions on other independent AI tools; the hosting review must account for those too.

## 7. Exact repository and installation change inventory

Paths below are relative to the repository unless stated otherwise. New names are proposed implementation locations; equivalents are acceptable if the same responsibilities and tests remain explicit. This inventory records future work, not files changed while writing this plan.

### 7.1 Existing code

| File | Required implementation change |
|---|---|
| `main.py` | Split legacy and manual startup. Remove dotenv loading from manual startup. Select the adapter or protected broker entry point explicitly; never start password-based auto-login through the adapter. |
| `src/config.py` | Add strict adapter/broker schemas and explicit authentication mode; separate endpoint metadata from credentials; reject manual-mode secret settings; remove manual-mode dependence on credential presence; disable device-token saving and dotenv fallback; validate real session policy. |
| `src/auth/synology_auth.py` | Refactor private login for worker use; stop password caching, device trust, and password-based relogin in manual mode; cover required session types; restrict auth registry/secret iteration to the broker; make logout clear local state reliably. |
| `src/utils/synology_api.py` | Replace automatic password renewal with typed authentication-required handling; use broker-held session context; enforce target pinning, safe redirects, timeouts, generation-aware invalidation, and safe exceptions. |
| `src/mcp_server.py` | Separate NAS-executing broker handlers from adapter forwarding; remove/reject raw login schemas and direct dispatch; load NAS aliases before login; replace auto-login and relogin cache callbacks; make status/disconnect ownership-aware; preserve `isError` behavior and redaction; add human-readable tool metadata. |
| `src/filestation/synology_filestation.py` | Apply broker sessions and consistent expiry handling to direct HTTP calls, polling, and downloads; enforce canonical allowed roots and result filtering; preserve current limits and critical-path behavior; audit late-running requests after cancellation. |
| `src/downloadstation/synology_downloadstation.py` | Apply the same session ownership and domain-specific expiry handling to direct requests; avoid late password login for a service-specific session; prevent secret-bearing results and unauthorized operations. |
| `src/health/synology_health.py` | Short-circuit global authentication loss; preserve honest partial-health results and `failed_checks` for actual independent failures; distinguish unsupported optional checks. |
| `src/utils/redact.py` | Preserve existing raw/JSON-escaped redaction fixes. Cover broker/worker credentials, sessions, OTP, cookies, headers, and exceptions internally without transmitting a secret inventory to the adapter. Redaction remains a backstop, not permission to export authentication responses. |
| `src/nfs/synology_nfs.py`, `src/container/synology_container.py`, `src/usermanagement/synology_users.py` | Audit service session plumbing, exceptions, and outputs; adopt shared authentication-required semantics; exclude disallowed enumeration and secret-bearing container/log/config fields. Make direct code changes where the audit identifies a bypass. |

Verify actual existing function names during implementation; responsibilities include configuration loading/validation/device saving, login/session login/relogin/logout, tool discovery/validation/dispatch, `_auto_login_if_configured`, `_get_base_url`, session-cache synchronization, status/NAS discovery, and `_try_relogin`.

### 7.2 New components

| Proposed file or area | Responsibility |
|---|---|
| `adapter_main.py`, `src/adapter/` | Credential-free local stdio server and authenticated remote MCP forwarding, with safe failure mapping and clean protocol output. |
| `broker_main.py`, `src/broker/server.py` | Protected remote MCP entry point, transport authentication, lifecycle, readiness, and NAS tool execution. |
| `src/broker/policy.py` | Immutable administrator-controlled client/tool/NAS/folder policy, quotas, and rejection of unauthorized capabilities. |
| `src/broker/sessions.py` | In-memory DSM sessions, ownership, deadlines, generations, invalidation, and cleanup. |
| `src/broker/errors.py` | Stable safe authentication/authorization/transport errors and consistent translation across services. |
| `src/broker/file_policy.py` | Canonical folder authorization and filtering of discovery/search/metadata results. |
| `src/private_auth/` | Independently authorized human interface, expiring target-bound requests, protected secret-bearing handler, and short-lived worker/IPC. No public MCP password submission. |
| `src/tool_catalog.py` | One authoritative source for stable tool IDs, titles, descriptions, categories, permissions, and discovery/catalog generation. Integrate with the existing registry rather than maintaining a conflicting second allowlist. |
| `config/adapter.example.json`, `config/broker.example.json` | Secret-free examples and schema guidance; placeholders only, no passwords or session values. |

### 7.3 Packaging, deployment, and documents

| File or deployment area | Required implementation change |
|---|---|
| `.gitignore`, `.dockerignore` | Exclude authentication state, local private configuration, logs, recovery material, and temporary secret-bearing artifacts from version control and build contexts. Verify images and release packages contain only approved code and secret-free examples. |
| `requirements.txt`, `pyproject.toml` | Declare supported SDK/web/authorization dependencies as needed, compatibility bounds, separate entry points, and test extras. Avoid unnecessary password-manager dependencies. |
| `Dockerfile` | Provide clear broker/adapter targets or separate artifacts; run without root; make code/dependencies read-only; retain a minimal writable temporary area only where required; do not bake secrets into any image layer. |
| `docker-compose.yml` and proposed `deploy/` broker templates | Add the persistent protected broker deployment. Remove NAS password `env_file` and credential mounts from manual profiles; avoid privileged mode, host administration sockets, and shared secret/log mounts; restrict published interfaces and apply HTTPS. Add actual readiness/liveness checks. An unauthenticated but ready broker is not unhealthy. |
| Existing installed local `launch.py` and installed runtime copy | Replace direct authenticated server startup with the adapter. Remove password-config references and inherited NAS-secret environment. Preserve bounded requests, verified transport, restricted policy, and clean stdout. Source edits alone do not update this installed copy. |
| Existing application MCP registration | Point to the adapter; preserve the reviewed tool scope. Store no NAS secret in registration. Keep startup responsive while disconnected and use suitable operation deadlines. |
| `env.example` and configuration examples | Make manual mode the recommended secret-free example; remove manual-profile password/OTP/device-token instructions and document explicit legacy separation if retained. |
| `README.md`, `skills/synology-nas/SKILL.md`, `skills/synology-nas/references/auth.md`, other affected references | Replace instructions that solicit secrets through tools/chat or save trusted-device tokens. Document private login, session expiry, safe disconnect, hosting prerequisites, permitted targets, and folder policy. Do not direct an assistant to enable unrestricted mode automatically. |
| Proposed `docs/MANUAL_AUTHENTICATION.md` | User setup, deployment boundary, private enrollment, OTP preparation, login/relogin, migration, recovery, and troubleshooting; distinguish user-operated steps from software behavior. |
| Proposed `docs/TOOL_CATALOG.md` | Generate an understandable catalog from the registry and default policy, including disabled/restricted categories without exposing them as enabled tools. |
| `tests/README.md`, `CHANGELOG.md` | Explain hermetic/manual tests and document intentional authentication/deployment compatibility changes. |
| `.github/workflows/tests.yml` | Extend existing Windows/Linux tests, lint coverage, and Docker smoke checks to the adapter plus broker with fake authentication. Keep real NAS credentials out of CI. |
| Outer `INSTALLATION.md` | After implementation and verified cutover, update this existing document in place with the actual installed adapter and protected broker setup. |
| Outer `REVIEW_FOLLOWUP_2026-09-29.md` | After verification, update the same existing document to reflect evidence, remaining limitations, and the new authentication boundary. |
| Outer `REVIEW_REPORT.md` | Preserve the original report unchanged. |

This plan was held out of `plans/shipped/` until the work was implemented under the repository's planning convention, which is code complete, tested, committed and pushed; it now sits there with the PR folders that implemented it. It does not mean the requirements that need a live NAS (the host, the cutover, the password change) have been accepted.

## 8. OTP enrollment and recovery plan

OTP enrollment changes the NAS account and must be performed privately by the user after the protected login path is ready. The server can document the steps but must not see the authenticator seed or recovery material.

1. Identify the actual account used by the integration and the DSM version. Verify whether full monitoring requires administrator privileges. Preserve the selected monitoring scope unless the user agrees to a narrower account.
2. Prefer a dedicated integration account where required DSM permissions permit it. If administrator privileges are necessary, document that risk and enforce broker restrictions independently.
3. Confirm the recovery method supported for that account and DSM version, recovery contact details where applicable, and a separate working administration path before enabling OTP. Administrator recovery can differ from ordinary user recovery; do not assume email reset is available. [Synology sign-in protection specifications](https://www.synology.com/en-global/dsm/7.4/software_spec/signin_protection).
4. On a private trusted device, sign in to DSM and open the account's Security / two-factor authentication settings. Select verification-code OTP if that is the intended method, scan the setup QR code with the user's authenticator, and complete verification. Verify the exact menu for the installed DSM version. [Synology two-factor authentication help](https://kb.synology.com/index.php/en-in/DSM/help/DSM/SecureSignIn/2factor_authentication).
5. Keep the QR code, seed, authenticator access, and any available recovery material outside AI-readable screens, chat, files, shares, and logs. Store recovery information privately and test the documented recovery path without disabling protection.
6. Do not select trusted-device persistence for the integration. Configure the manual worker to request no reusable device trust and accept a fresh OTP for each new DSM login.
7. Confirm a valid private password/OTP establishes a session; an invalid or missing required OTP does not. Use a small controlled number of attempts to avoid lockout.
8. Confirm an expired/disconnected session requires a fresh private login. Normal tools may use the authenticated broker session until policy expires it; OTP is not required for every tool call.

DSM's login API distinguishes password, OTP, session, and device-token inputs/outputs; this plan deliberately keeps password/OTP entry private and avoids device-token reuse. [Synology DSM login API guide](https://global.download.synology.com/download/Document/Software/DeveloperGuide/Os/DSM/All/enu/DSM_Login_Web_API_Guide_enu.pdf).

If the user uses 1Password, use it only through the user's private interface/device in this workflow. Keep the authenticator independent if the user wants a separate factor. Do not install vault access in the adapter or make vault contents available through MCP.

## 9. More understandable commands

The supplied screenshot appears to show source files or skills in an application picker. Those entries are not necessarily the actual MCP command list. Validate each application's tool discovery before changing presentation; the server cannot dictate every application's picker design.

Implement the following server-owned improvements:

- Preserve stable machine-readable tool IDs so existing integrations continue to work.
- Add plain-language titles and concise descriptions, for example 'NAS health summary', 'Browse shared folders', and 'Search files'. Explain when private authentication is needed and when returned file contents may be sent to the AI provider.
- Group the catalog into Connection, Health, Files, and any other permitted monitoring categories. Clearly distinguish unavailable/restricted functions.
- Generate the catalog from the same registry and broker policy used by discovery. Include purpose, required inputs, read/write effect, authentication requirement, limits, and one safe example per enabled tool.
- Ensure titles and read-only annotations are supported metadata, not a replacement for server authorization. MCP tool definitions support a human-readable title in addition to a stable name and description. [MCP tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools).
- Show only safe connection state and authentication instructions in any optional control panel. A panel inside an AI application must not host password/OTP entry.
- Verify display in the applications the user actually uses. Where a client ignores titles/categories, the readable catalog remains the fallback.

A richer interactive tool dashboard can be a later enhancement. It is not required to establish private authentication and must not delay the security migration.


## 10. Verification plan

All automated checks use fake endpoints and dummy secrets. Live NAS authentication is a separate private user-operated acceptance step. No real password, OTP seed, recovery code, or session enters CI, test fixtures, screenshots, or reports.

### 10.1 Existing test files to extend

| Tests | Required coverage |
|---|---|
| `tests/test_config.py` | Secret-free endpoint loading; explicit adapter/broker modes; rejection of legacy secrets/auto-login; no dotenv fallback; invalid settings messages without values. |
| `tests/test_auth.py`, `tests/test_logout.py` | No manual-mode password cache, device trust, persistence, or relogin; worker failures; required session types; reliable cleanup and bounded logout. |
| `tests/test_tool_calls.py`, `tests/test_restricted_mode.py` | Hidden and directly invoked login rejection; no secret-bearing schemas; broker policy enforcement independent of the adapter; safe `isError` handling and status. |
| `tests/test_redact.py` | Existing raw/escaped masking plus fake OTP/session/cookie/header/exception cases; no regression of the current local changes. |
| `tests/test_file_station.py`, `tests/test_download_station.py` | Direct HTTP expiry; correct domain errors; folder policy; filtered listings/search; time bounds; no password renewal or unsafe replay. |
| `tests/test_health.py`, `tests/test_nfs.py`, `tests/test_container_manager.py` | Authentication-required propagation, honest partial health, denied secret-bearing container/log outputs, and existing read-only behavior. |
| `tests/test_stdio_protocol.py` | Actual stdio adapter to protected broker protocol, discovery, disconnected/authenticated states, error propagation, and clean stdout. |
| `tests/conftest.py`, `tests/socket_guard.py`, `tests/test_network_guard.py` | Fake broker/worker fixtures and scoped loopback test allowances; deny unintended network access; keep real NAS tests explicit and opt-in without stored production credentials. |

### 10.2 New automated and deployment checks

Add focused tests for broker sessions/policy, private authentication, forwarding, and folder authorization. Required scenarios are:

1. Startup and discovery with no password; legacy secret settings rejected; old dotenv/env/config cannot activate a fallback.
2. Direct calls to hidden login, raw session export, arbitrary URL/host, generic request, forbidden tool, and policy-changing operation rejected by the broker.
3. Missing/revoked/incorrect-audience client grant; a valid AI client grant cannot submit private login, enroll an owner, export a DSM session, or administer the host.
4. Private-interface owner authentication, CSRF/origin protections, expiring requests, correct NAS/client binding, cancellation, and rate limiting.
5. Invalid password, wrong/expired OTP, certificate failure, lockout, worker crash, and broker outage; responses and diagnostics contain no submitted values.
6. No password, OTP, device token, SID, SynoToken, or cookie in adapter traffic, tool results, public logs, environment, command lines, manifests, files, images, or tracebacks. Audit protected internal channels separately: those may carry DSM sessions and must never be public.
7. Authentication expiry across shared API, FileStation, DownloadStation, health aggregation, polling, and content reads; optional unsupported health checks remain distinct. Verify routing for every enabled service/session type, fresh private input for any additional login, and cleanup after partial session establishment.
8. Concurrent calls create one pending request; an old failure does not revoke a new session; no cross-client or cross-NAS session leakage.
9. Idle/absolute expiry, disconnect, restart, failed remote logout, and late requests; no automatic password login or replay of modifying operations.
10. Traversal, Unicode/separator variants, symbolic links, share aliases, filtered metadata/search, and legacy credential paths fail the folder policy correctly.
11. Restricted mode, account enumeration exclusion, file size cap, TLS verification, request deadlines, error signaling, and current redaction fixes remain effective.
12. Code/policy/dependency tampering attempts from the AI-side identity cannot change the deployed broker or reach its private runtime. Test with a distinct simulated client identity and dummy secrets on the actual proposed deployment.
13. Windows/Linux tests and Docker smoke tests cover the real adapter/broker path. Lint/format include new entry points and packages.
14. Installed-client discovery/status and a read-only live health check work after the user privately authenticates. Expiry/disconnect requires private login again.

Use deterministic fake secret markers and scan captured artifacts for them. Supplement marker tests with schema/authorization tests; a passing string scan alone is not proof of isolation.

## 11. Implementation order and migration

### Phase 1: Choose and prove the boundary

- Select the broker host and private authentication device.
- Inventory every AI-accessible file share, NAS command, shell, browser, host-management tool, backup, and container interface that could reach the protected deployment.
- Agree on account permissions, client ownership, approved NAS/folder scope, and session deadlines.
- Establish human-only enrollment and a human-controlled release process.
- Prove isolation with dummy data before using a real password.

**Exit criterion:** AI-side access cannot read or modify protected authentication/runtime assets. Any unresolved access path is documented and blocks the credential-secrecy claim.

### Phase 2: Implement the broker and manual authentication

- Implement strict configuration, policy, typed errors, private interface/worker, and in-memory sessions.
- Remove manual-mode raw MCP login, automatic password renewal, and device persistence.
- Refactor all NAS service paths to use broker session ownership and consistent expiry.
- Implement folder authorization and safe result filtering.
- Pass focused automated authentication/policy/session tests.

**Exit criterion:** A fake private login enables only permitted operations; credentials remain within protected components; expiry requires fresh human authentication.

### Phase 3: Implement the adapter and packaging

- Implement credential-free forwarding and safe disconnected startup.
- Package adapter and broker separately with reviewed dependencies and deployment settings.
- Extend stdio integration, Windows/Linux CI, and Docker smoke coverage.
- Document the precise installed-client registration and protected-host setup.

**Exit criterion:** The actual client-to-adapter-to-broker path works using fake authentication, with no fallback and no NAS secrets on the client.

### Phase 4: Prepare and perform user-operated cutover

1. Record a safe rollback configuration that remains disconnected; do not preserve usable passwords in a backup for convenience.
2. Stop all old direct-launch server instances, including containers and background processes. Their cached passwords/sessions must not survive the transition.
3. Replace the installed launcher/runtime and application registration with the reviewed adapter. Disable old scheduled/service startup and other direct-launch registrations.
4. Remove obsolete credentials and references from installed settings, source `.env`/settings copies, inherited environments, deployment mounts, and other identified copies. Do not print or copy their contents into a report. Review backups/history privately; password rotation invalidates residual historical copies but does not remove them.
5. Deploy the reviewed broker through the human administration path and run dummy-secret isolation checks on the real host.
6. Confirm the AI-side application can discover permitted tools and status while disconnected and cannot read/modify protected assets.
7. Only after those checks pass, tell the user the protected path is ready for private password rotation. The user rotates the password through DSM on the trusted device; the assistant must not receive the new password.
8. Revoke old DSM sessions and trusted-device grants as supported by the installed DSM version. A password change alone must not be assumed to revoke every session or reusable token.
9. Enroll OTP privately after checking recovery, and verify the private login path with the new credentials.
10. Complete the user's read-only NAS health check, folder-scope check, disconnect/expiry check, and client restart behavior check.

**Exit criterion:** The installed integration uses the broker only; old authentication processes and secrets are retired; the new password and OTP were never submitted through an AI-accessible channel.

### Phase 5: Presentation and final documentation

- Add titles/descriptions and generate the command catalog.
- Verify actual client display and provide the catalog where richer metadata is not shown.
- Update the existing installation guide and follow-up review in place with dated evidence and residual limitations; preserve the original report.
- Record the tested version, deployment identity, safe configuration, and actual acceptance results without secrets.

**Exit criterion:** The user has clear private-login instructions, understandable commands, recovery guidance, and a verified evidence record.

### Safe rollback

If the new deployment fails, disable broker access, discard/revoke sessions, and return the adapter to a disconnected state. A reviewed previous broker release may be restored without restoring credentials or widening permissions. Do not reinstate the old plaintext-password server, disable TLS/OTP, broaden folder scope, or enable unrestricted mode as an automatic rollback.

## 12. Completion checklist and evidence

These boxes are requirements, not claims of work already completed.

- [ ] Protected host and private user device selected; all AI access paths reviewed.
- [ ] AI cannot read or alter deployed authentication code, policy, dependencies, runtime, or private input.
- [ ] Client configuration and MCP registration contain no NAS password/OTP/session/device token.
- [ ] Manual mode starts disconnected and rejects stored credentials and legacy fallbacks.
- [ ] Password-bearing MCP login is absent from discovery and rejected by direct dispatch.
- [ ] Password caching, automatic password renewal, and device trust/persistence are disabled in manual mode.
- [ ] Protected worker/session lifecycle, ownership, deadlines, concurrency, logout, and restart behavior verified.
- [ ] Approved tool/NAS/folder policy enforced at the broker, including indirect disclosure paths.
- [ ] Secret-disclosure, authorization, boundary, and regression checks pass with fake data.
- [ ] Adapter/broker integration, Windows/Linux CI, and applicable Docker checks pass.
- [ ] Installed integration replaced; old processes/config references retired.
- [ ] User privately rotated password and revoked old authentication material after isolation passed.
- [ ] OTP and account recovery privately configured and tested.
- [ ] Real read-only NAS check and expiry/relogin behavior verified without exposing credentials.
- [ ] Friendly titles/catalog verified; existing installation and follow-up documents updated in place.
- [ ] Original `REVIEW_REPORT.md` and existing local redaction work preserved.

For each item, record the tested deployment/version, date, method, result, and any limitation. Record only safe evidence; never attach live authentication values or private screenshots.

## 13. Decisions required before deployment and limits of the promise

The plan deliberately does not invent a protected host that has not been verified. Before deployment, settle the host, private device, human enrollment method, client grant mechanism, NAS account permissions, folder scope, and session deadlines. Implementation may begin with fake services while these deployment decisions are resolved.

The assurance is that AI clients operating through the reviewed adapter/broker boundary cannot retrieve the new NAS password, OTP, or DSM session credentials. It does not make a host administrator, compromised trusted device, maliciously modified protected deployment, or another separately authorized tool harmless. AI clients still receive the NAS data the user explicitly authorizes, including permitted file contents.

All guarantees depend on the actual installed deployment and permissions. Repository tests, password masking, and this document alone do not establish that boundary. No implementation or new NAS-security verification was performed while writing this plan.

