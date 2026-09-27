# Synology MCP Server Remediation Plan

Status: Proposed (revised)

## Implementation roadmap

This plan is implemented as a sequence of PRs, each tracked in its own dated folder under `plans/` (see `plans/README.md` for the convention). A folder moves to `plans/shipped/` once that PR's changes are implemented.

1. [`plans/shipped/2026-09-27-credential-and-session-leak-hardening/`](plans/shipped/2026-09-27-credential-and-session-leak-hardening/PLAN.md) — §1 below, in full, plus the auth-specific timeout/retry-rule portion of §4. PR: [#2](https://github.com/Impjegat/mcp-server-synology/pull/2).
2. [`plans/shipped/2026-09-27-restricted-mode-tool-registry/`](plans/shipped/2026-09-27-restricted-mode-tool-registry/PLAN.md) — §3: unified deny-by-default tool registry, borderline-tool classification, restricted `synology_login`, path-check consolidation, dedicated-admin NAS hardening. PR: [#4](https://github.com/Impjegat/mcp-server-synology/pull/4).
3. [`plans/shipped/2026-09-27-connection-defaults-and-bounds/`](plans/shipped/2026-09-27-connection-defaults-and-bounds/PLAN.md) — remainder of §4: port default, CA-bundle support, `search_files`/`get_file_content` bounds, distinguished login errors. PR: [#5](https://github.com/Impjegat/mcp-server-synology/pull/5).
4. [`plans/shipped/2026-09-27-packaging-and-test-isolation/`](plans/shipped/2026-09-27-packaging-and-test-isolation/PLAN.md) — §2 and §5: Dockerfile/`.dockerignore`/compose fixes, conftest isolation ordering, the two pre-existing test failures root-caused and fixed, documentation. PR: TBD.

## Objective

Resolve the identified security and configuration issues, verify MCP compatibility, and prepare an initial installation limited to file browsing and NAS monitoring. The plan applies to any compatible MCP client and does not depend on a particular AI application or provider.

## Scope

- Remove credentials and authentication tokens from tool responses and logs.
- Prevent credentials from being embedded in container images.
- Enforce a restricted operating mode for browsing and monitoring, enforced through a single deny-by-default tool registry.
- Correct HTTPS connection defaults, bound authentication request times, and stop the password/OTP/device-token from traveling in a URL.
- Validate the changes and document installation and rollback.

The initial installation target is a local Python process communicating with an MCP client over STDIO and with the NAS over HTTPS. Container packaging remains supported and receives the same credential protections.

### NAS account for this installation

The NAS account used is a **dedicated administrator account created for this server**, not a personal account, so that all monitoring tools (which call `SYNO.Core.*` / `SYNO.Storage.CGI.*` APIs, normally admin-only) work. This means DSM's own permission model provides **no** protection against modifying operations for this account — restricted mode and the tool registry below are the only barrier. Sections 3 and 5 are written on that assumption.

## 1. Remove credentials and tokens from output

### Changes

- Replace raw authentication responses with an explicit set of safe status fields.
- Exclude passwords, one-time codes, session IDs, security tokens, and trusted-device tokens from tool responses and logs, including partial token values.
- Sanitize exception messages and request diagnostics that could contain credentials or authentication query parameters. This includes the shared API client (`src/utils/synology_api.py`) and each service module's own request code (FileStation, DownloadStation), not only the auth module — all of them can surface a live session ID or credential inside a network-error message.
- Send the password, OTP code, and device token in the login request body (POST) instead of the URL query string, so they never appear in `requests` exception text, DSM access logs, or an intermediate proxy's logs. This is the root-cause fix; redaction below is the backstop for what still passes through in memory.
- Apply a single redaction step at two points: where a tool response is built (`handle_call_tool`) and in the process's log configuration. It masks known live secrets (the current session ID, SynoToken, and device ID for each connected NAS, plus configured passwords) and pattern-masks `_sid=`, `passwd=`, `SynoToken=`, `device_id=`, and `otp_code=` wherever they appear in text.
- Move logging setup out of the unused `src/utils/logger.py` (nothing imports it) and into `main.py`, where `logging.basicConfig` already runs; attach the redaction filter there.
- Replace the current token-copying workflow with a local setup step that stores trusted-device tokens in protected user configuration without displaying them in logs or tool responses.
- Preserve two-factor authentication, trusted-device reuse, session renewal, and explicit logout behaviour.
- Protect stored credentials with user-specific Windows file permissions (via `icacls` or an ACL library) or restrictive POSIX permissions, as appropriate. Write the settings file atomically (temp file + replace) so a crash mid-write can't corrupt or truncate it, and keep unrelated configuration values intact.

Primary files: `src/mcp_server.py`, `src/auth/synology_auth.py`, `src/utils/synology_api.py`, `src/filestation/synology_filestation.py`, `src/downloadstation/synology_downloadstation.py`, `main.py`, authentication tests, and setup documentation. (`src/utils/logger.py` is removed, not modified.)

### Acceptance criteria

- Tests with recognizable dummy secrets confirm that successful responses, failures, and captured logs contain none of those values — including responses and logs produced by FileStation/DownloadStation/health/container/NFS/user-management calls, not only login/logout.
- The login request carries no credential material in its URL (verified by inspecting the outgoing request in a test, not just the response).
- Two-factor authentication, token reuse, session renewal, and logout regression tests pass.
- Failure to save a device token produces a sanitized error and does not fall back to printing it.

## 2. Keep credentials out of Docker images

### Changes

- Remove `COPY .env*` from the Dockerfile.
- Exclude local credential files, including `.env` variants and NAS settings files (e.g. `.env*`, `settings*.json`), from the Docker build context via `.dockerignore`.
- Supply credentials only at runtime through environment configuration or a read-only configuration mount.
- Keep token enrollment in the local setup workflow so the running container does not need write access to mounted credentials.
- Update container setup instructions to match the supported runtime configuration method.
- Fix `docker-compose.yml` so it matches a non-interactive stdio server: drop `tty: true` (a TTY is wrong for a process that speaks JSON-RPC over stdin/stdout) and reconsider `restart: unless-stopped`, which doesn't suit a `docker-compose run` client launch pattern.

Primary files: `Dockerfile`, `.dockerignore`, `docker-compose.yml`, and `README.md`.

### Acceptance criteria

- Build with dummy credentials present in the project and confirm that neither their files nor their values appear in the image or its layers.
- Confirm that a container can start and load runtime configuration without credentials embedded in the image.
- Use only dummy credentials for image inspection and build verification.

## 3. Enforce a restricted operating mode

### Changes

- Replace the two independent tool-dispatch paths with one tool registry: name → handler, plus a `read_only` / `modifying` classification, used by both `list_tools` and `call_tool`. Delete `call_tool_direct` and `get_tools_list` (`src/mcp_server.py`) — they were the entry points for the Xiaozhi WebSocket bridge, which was already removed from the codebase (commit `ca4de1a`), and have since drifted out of sync with the live dispatch table (missing `synology_list_nas` and `synology_create_share`). Keeping a second, unmaintained path to call any tool by name would undermine the restricted-mode work in this section regardless of how well the primary path is locked down.
- Add a read-only operating mode and enable it for the initial installation. Make it deny-by-default: a tool not explicitly classified as approved is unavailable, not merely "not yet reviewed".
- Audit the tool catalogue and explicitly allow browsing and monitoring operations, including the borderline cases below:
  - `get_file_content` — allowed (see acceptance criteria for its size cap).
  - `synology_system_log`, `synology_container_logs` — read-only; document that log output may contain sensitive data.
  - `synology_list_users`, `synology_get_user_permissions`, `synology_list_groups`, `synology_list_group_members` — read-only; included as monitoring/inventory, not modification.
  - `synology_login` — in restricted mode, accept only a `nas_name`/`base_url` that resolves to a NAS already present in `settings.json`; do not allow the model to point the configured admin credentials at an arbitrary host.
- Hide modifying tools from discovery and reject them at execution time, including direct calls by name, through the single registry from above.
- Preserve authentication and session management needed to use permitted tools.
- Add accurate MCP annotations for read-only and destructive operations (the installed `mcp` SDK version supports `ToolAnnotations`). Treat annotations as descriptive metadata, not access controls.
- Because the configured NAS account is an administrator, DSM-side permissions cannot make it read-only. Harden what's available on the NAS side instead:
  - use an account created specifically for this server, with 2FA and the device-token flow enabled;
  - deny it access to applications/privileges the server doesn't need where DSM's per-user application-access controls allow it (e.g. Download Station, Container Manager, file-sharing protocols not in use);
  - note DSM 7.2+ permission delegation as a possible future path to a non-admin account, to revisit once it's confirmed which delegated privileges cover the monitoring APIs this server calls.
- Add an optional allowlist of shares or path prefixes for the file-browsing tools (`list_directory`, `get_file_info`, `search_files`, `get_file_content`), built on the existing `_check_critical_path` check in `src/filestation/synology_filestation.py`, since an admin account can otherwise reach every share.
- Where supported, apply an additional tool allowlist in the MCP client.
- Document how to enable additional operations deliberately, including the NAS permissions they require.

Primary files: `src/mcp_server.py`, `src/config.py`, configuration examples, relevant tests, and `README.md`.

### Acceptance criteria

- Restricted mode advertises only the approved operations and necessary session tools.
- File deletion, user changes, permission changes, download modifications, and container control are rejected before a NAS request is sent — for every modifying tool name, and for any unrecognized tool name (deny-by-default, not an incomplete blocklist).
- `synology_login` in restricted mode refuses a `base_url`/`nas_name` that isn't already configured.
- `get_file_content` enforces its configured size limit (checked via file metadata before download, not only after reading the whole file) and refuses oversized files with a clear message.
- Enforcement tests cover both the sole remaining execution path (the unified registry) and direct requests for hidden tools by name; there is no second, unaudited entry point left in the codebase.
- Authenticated verification against the dedicated admin account confirms every intended monitoring tool actually returns data (rather than assuming a permission model that isn't in effect for this account).

## 4. Correct connection defaults and startup behaviour

### Changes

- Change the default NAS port from `5000` to `5001` when the port is omitted.
- Preserve explicitly configured custom ports.
- Retain HTTPS-only connections and certificate verification by default.
- Align configuration examples, documentation, and tests with the corrected default.
- Add bounded connection and response timeouts to login and logout requests (they currently have none, unlike every other API call in the codebase, which already uses `timeout=15`).
- Replace the current "retry on anything but 400/402/403/404" logic with an explicit rule keyed to DSM error codes: stop immediately on any authentication-outcome error (account disabled, 2FA required, IP auto-blocked, password expired, etc.), and fall back to an older API version only on a version/API-not-supported error or a transport-level failure. This avoids turning a version-fallback loop into repeated password submissions that can trip DSM's Auto Block.
- Add support for a CA-bundle path (`verify=<path>`) so a NAS using a private CA or self-signed certificate doesn't require disabling verification, and document that `REQUESTS_CA_BUNDLE` already works today; on Windows, note that `requests` uses its bundled CA store rather than the OS trust store, so a private CA must be supplied explicitly.
- Return clear, sanitized errors for unreachable servers, certificate failures, and authentication failures — distinguished from each other rather than collapsed into a generic "Authentication failed".
- Add a bounded polling deadline to `search_files` (`src/filestation/synology_filestation.py`), which currently polls with no timeout, since it's one of the tools enabled in restricted mode.

Primary files: `src/config.py`, `src/auth/synology_auth.py`, `src/filestation/synology_filestation.py`, `env.example`, configuration and authentication tests, and `README.md`.

### Acceptance criteria

- An omitted port resolves to HTTPS on port `5001`; explicit custom ports remain unchanged.
- Plain HTTP URLs remain rejected.
- Tests verify certificate-error handling, timeout handling, and the new error-code-based retry rule (including that an auth-outcome error does not trigger a version-fallback retry).
- `search_files` returns a clear timeout error rather than polling indefinitely against an unresponsive NAS.
- Startup failures do not expose secrets or wait indefinitely for an unreachable NAS.

## 5. Validate and prepare installation

### Validation sequence

1. Run relevant unit and regression tests with saved credential loading disabled and NAS network access blocked before test collection — this has to happen before `conftest.py` imports `config` (which reads `~/.config/synology-mcp/settings.json` and any `.env` at import time), for example by pointing `XDG_CONFIG_HOME` at an empty temp directory and blocking outbound sockets at test-session start. Do not rely solely on test markers to prevent live access.
2. Repeat the MCP initialization handshake, tool discovery, and status checks using isolated configuration.
3. Verify the restricted tool catalogue and rejection of disallowed operations, through the single tool registry.
4. Complete the container image checks using dummy credentials.
5. Prepare and document the local Python startup command, working directory, protected configuration location, and generic MCP client settings.
6. Perform authenticated, read-only verification of connectivity, permitted folder access, and available health information using the dedicated NAS admin account — confirming every intended monitoring tool returns data, and that every modifying tool is refused before it reaches the NAS.

### Documentation and rollback

- Update the Windows installation instructions (the README currently has none — a config-path mention only — so this section needs writing, not editing) and platform-neutral MCP configuration examples.
- Explain restricted mode, credential enrollment, certificate configuration (including the CA-bundle option), timeouts, and optional container execution.
- Correct the remaining "anything other than port 5001 uses HTTP" statement in `skills/synology-nas/references/auth.md`.
- Preserve the previous application configuration before installation.
- Document rollback by disabling the MCP server entry and restoring the previous application configuration. Keep the security fixes in the server source.

## Suggested implementation order

Sections 1 → 3 → 4 → 2 → 5. Because the configured account is an administrator, credential/session leakage (§1) and write-enforcement in the tool registry (§3) carry the most risk and should land first; connection correctness (§4) and packaging (§2) follow; validation (§5) closes the loop.

## Completion criteria

- Authentication secrets are absent from tool output and logs, across every service module, not only login/logout.
- The login request no longer carries credentials in its URL.
- Container images contain no embedded credentials.
- Restricted mode prevents modifying operations through the single supported execution path (the unmaintained direct-call path is removed, not merely left unaudited).
- HTTPS defaults, custom ports, certificate verification (including custom CA bundles), and bounded authentication requests behave as documented.
- The retry rule no longer resubmits credentials on an authentication-outcome error.
- Relevant automated checks and the isolated MCP handshake pass.
- Any unavailable live or container checks are recorded as unverified, with their outstanding prerequisites.
- Authenticated read-only checks against the dedicated admin account pass before the installation is considered operational.
