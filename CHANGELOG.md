# Changelog

## [Unreleased]

### Added
- **Continuous integration** (`.github/workflows/tests.yml`): the unit tests run on Linux and Windows, the Docker image is built and the stdio protocol tests are run against it through the same command the README gives MCP clients, and lint/format are checked. End-to-end tests (`tests/test_stdio_protocol.py`) start the real server and speak MCP to it over stdio. Dependabot is told to leave major `mcp` upgrades to a deliberate migration.

### Security
- **Restricted mode, on by default — a breaking change.** Set `RESTRICTED_MODE` (or `"restricted_mode"` under `"server"` in settings.json) to `false` to get the previous full tool set. While it is on, only browsing and monitoring tools are offered: every modifying tool is hidden from discovery and rejected before any request reaches the NAS, and the local user/group/permission tools are hidden too, although they only read, because enumerating accounts is a different trust level. If any NAS is configured, `synology_login` only accepts a `base_url` that is already configured. Only an explicit false value (`false`/`0`/`no`/`off`) turns it off; an unrecognised value keeps it on and logs a warning. Tools are dispatched and listed from one registry, so discovery and calls cannot disagree.
- **Secrets are redacted** from log output (including exception tracebacks), tool results and error messages: current session IDs, SynoTokens, device tokens and configured passwords, plus `key=value` patterns such as `_sid=` and `passwd=`. `synology_login` no longer returns the raw DSM response, and the trusted-device token is never logged or returned.
- Login requests are sent as POST bodies instead of URL query strings; login and logout have bounded timeouts; the login API-version fallback stops on any DSM authentication outcome instead of resubmitting the credentials, and a certificate, connection or timeout failure gets its own error (`certificate_error`, `connection_error`, `connection_timeout`).
- `settings.json` is written atomically and restricted to the current user before any secret is written (`chmod` on Linux and macOS, `icacls` on Windows); if the permissions cannot be restricted, nothing is written.
- **Docker no longer bakes credentials into the image.** `COPY .env*` was removed from the Dockerfile and `.env`, `.env.*` and `settings*.json` are excluded from the build context. `docker-compose.yml` hands `.env` to the container when it starts (an optional `env_file`, which needs Docker Compose v2.24 or later), and no longer sets `tty` or a restart policy, which do not suit a per-session stdio process.
- **HTTPS-only transport**: `SYNOLOGY_URL` and settings.json host configs that would resolve to plain `http://` are now rejected at startup with a clear error. Previously, settings.json silently downgraded to `http://` for any NAS port other than 5001.
- `VERIFY_SSL` (and every `verify_ssl` constructor default across the service classes) now defaults to `true` instead of `false`.
- The `synology_login` tool's URL validator now requires `https://`.
- Removed the false "RSA encrypted password transmission" claim from the README.
- **Credentials typed into a tool call are no longer echoed back.** A `password`, `device_id` or `otp_code` of the wrong type used to appear in the error message (`Invalid arguments for synology_login: ['…'] is not of type 'string'`) and in DEBUG logs, because the redactor only knew secrets from settings and established sessions. Validation messages are now built from the schema alone and never quote a submitted value, and every `password` and `device_id` in a call is treated as a secret for the duration of that call, before any login has taken place. Values shorter than 4 characters are not masked, because masking by substring would blank those characters out of everything the call prints; a validation message never quotes a value whatever its length, but other text, such as a NAS's own error message, could still quote a very short credential.

### Changed
- **The default NAS `port` is `5001`** (DSM's HTTPS port) instead of `5000`, which is HTTP-only and could never connect over the HTTPS-only transport.
- **`VERIFY_SSL` also accepts a CA bundle path** (env var, or `server.verify_ssl` in settings.json) to trust a private CA or self-signed certificate without disabling verification. `REQUESTS_CA_BUNDLE` still works as a process-wide override.
- **`get_file_content` refuses files larger than `MAX_FILE_CONTENT_SIZE`** (default 1,000,000 bytes; env var or `server.max_file_content_size`), checked from file metadata before anything is downloaded and again against the bytes actually read, because file contents are sent to the MCP client's AI provider.
- **`synology_health_summary` now says how complete it is.** The result carries `status: "complete"`, or `status: "partial"` with a `message` and `failed_checks` naming each check that could not be completed (the data gathered is still returned, but a partial result does not show the NAS is healthy). A UPS check that DSM reports as not available on the NAS (API error 102–104) is listed under `unavailable_checks` and does not make the result partial. If every check fails, the tool returns an error.
- **Invalid-argument messages are worded differently**: `path must be of type 'string'` instead of `123 is not of type 'string'`. The field is still named; the submitted value no longer is. A missing required property still reads `'path' is a required property`.
- **`search_files`, `delete` and `move_file` time limits are now enforced on every request.** Starting the task counts against the limit, each request is cut off at the time left, and a response that never completes is abandoned at the limit. Fetching search results and stopping a task keep small separate allowances, so the longest a call can take is 140 s (search), 125 s (delete) and 65 s (move) — see the README's "Time limits". Previously a 120 s search could take 130 s or more. If the request that starts a `delete` or `move_file` is abandoned at the limit, the error now says the NAS may have started it anyway and to check before retrying, and `delete`'s path lookup is capped at 15 s so it cannot starve that request.
- **The server now requires the `mcp` Python SDK 2.x** (`mcp>=2.2.0,<3`) and no longer runs on 1.x. It uses the 2.x low-level API: the tool handlers are passed to the `Server` constructor instead of registered with decorators, and tool arguments are validated against each tool's `inputSchema` by the server itself, because the SDK no longer does it. A fresh install of `requirements.txt` had been resolving to mcp 2.x, where the previous code failed on startup. Docker users: rebuild the image (`docker-compose build`). (#12)
- **Tool failures are now reported as errors — an intentional behavior change.** Previously nearly every failure came back as an ordinary, successful-looking text result; only an argument-schema violation was flagged. Now:
  - A tool that fails — an exception in a handler, a failed login or logout, a DSM call that reports `success: false`, no active session — returns a result with `isError: true`.
  - Invalid tool arguments and restricted-mode refusals return `isError: true`; both are still rejected before any request is made to the NAS.
  - An unknown tool name, or a malformed `tools/call` request (`arguments` that isn't an object, no tool name), returns a standard JSON-RPC `-32602` error instead of a tool result.
  - The flag is set explicitly by the code that detects each failure, never by matching text. Message text is otherwise unchanged, apart from invalid-argument messages, which now read `Invalid arguments for <tool>: <reason>`. Clients or scripts that looked for failures in the output text should read `isError` instead.
  - Every error path is redacted — the message, the log line, and the DEBUG traceback (which is now redacted by the server itself before it is logged).

### Fixed
- `search_files` had no time limit at all and could poll an unresponsive NAS forever; `delete` and `move_file` counted only the time they spent sleeping between polls, so a slow NAS could stretch their limits to about an hour. All three now use a wall-clock deadline (see the time-limits entry above).
- A JSON download bypassed the `get_file_content` size cap (the body was parsed before its size was checked), and a real `.json` file was mistaken for a DSM error and could not be read at all.
- Starting a container from the Docker quick start did not pass `.env` to it, although the README said to create one.
- Windows: loading `settings.json` crashed with an `AttributeError` (`os.getuid()` does not exist there); the permission check is now skipped with a warning on platforms without it.
- `synology_health_summary` no longer reports `success: true` with empty data when the NAS cannot be reached. It used to drop every failed check and always succeed, so an unavailable NAS looked like a healthy, empty summary.
- `get_file_info` no longer reports a nonexistent path as an empty file. DSM answers `getinfo` for a missing path with `success: true` and an error `code` (408) inside the file entry; that is now raised as "File not found" (any other per-entry code as an error), so the tool returns `isError: true`.

### Removed
- Dead code: the second tool-dispatch path (`call_tool_direct`, which had already drifted out of sync with the live one), `get_tools_list`, and the unused `src/utils/logger.py`.
- **WebSocket bridge integration** (`src/multiclient_bridge.py`, see the 1.1.0 entry below) and its associated configuration (the enable/disable toggle, token, and endpoint fields in both `.env` and `settings.json`) have been removed from this fork entirely. `main.py` now always launches the stdio MCP server directly. The `websockets` dependency was dropped from `requirements.txt` accordingly.
- `docker-compose.http.yml` and the HTTP/SSE remote-deployment path it supported (`requirements-http.txt`, the Dockerfile `INSTALL_HTTP` build arg, and the corresponding README section), since it contradicted HTTPS-only operation.

## [1.5.0] - 2026-06-27

### Added
- **Container Manager support** — ~30 new MCP tools for Synology DSM Container Manager (Docker), spanning containers (list/get/start/stop/restart/delete/logs/resource), compose projects (list/get/create/update/start/stop/restart/build/clean/delete), images (list/get/delete/pull), registries (list/search/tags/download), and networks (list/get/create/delete). They reuse the existing per-NAS session caching and multi-NAS targeting, and destructive operations require explicit names. The `synology-nas` Agent Skill gains a Container Manager domain (`references/containers.md`, GHCR + runtime-DNS gotchas, and an eval). Thanks @denisdasilvarocha. (#44)
- `synology_container_logs` exposes `offset`/`limit` pagination (defaults `0`/`1000`, bounded `offset >= 0` / `limit >= 1`) instead of a hardcoded 1000-line query. (#46, #49)

### Fixed
- `synology_logout` now evicts **all** per-domain service-instance caches (health, container, NFS, user management), not just FileStation/DownloadStation, so no stale instance lingers on a dead session — and the same applies to the graceful expired-session path. That branch now coerces the DSM error code with `str()` before matching, so DSM's **numeric** `105`/`106` (returned via JSON) hit the cleanup path instead of falling through to the failure branch. (#48, closes #47)
- `update_project` JSON-encodes the service-portal name/protocol consistently with `create_project`, so portal-config updates reach DSM correctly; `_project_id` tolerates non-dict project payloads instead of raising on lookup. (#44)

### Changed
- Container Manager API versions are typed as `int` to match `SynologyAPIClient.post()`, and `list_registry_tags` routes its v2 call through a named `registry_tags_version` field instead of a bare literal. (#45, #50, #49, #51)
- Extracted a single `_service_instance_dicts()` helper so session login, relogin, logout, and cleanup all evict the same canonical cache set. (#48)
- Dependency bumps: `mcp` `>=1.28.0`, `mcp-proxy` `>=0.12.0`, `pytest` `>=9.1.1`, and `actions/checkout` to v7. (#39–#43)

## [1.4.2] - 2026-06-12

### Added
- Optional HTTP/SSE transport for remote deployments via `docker-compose.http.yml` (mcp-proxy). The extra dependency is isolated in `requirements-http.txt` and only installed when the image is built with `INSTALL_HTTP=1`/`true`; the default stdio image is unchanged. (#25, #36)

### Fixed
- Transparent recovery from DSM error 119 ("SID not found"). When a server-side session expires — typically after ~1h of inactivity on `SYNO.Core.*` APIs — `SynologyAPIClient` now re-authenticates with the cached credentials and retries the call once instead of failing until the process restarts. The relogin is concurrency-safe (serialized per NAS, so simultaneous 119s collapse into a single new session rather than leaking orphaned SIDs) and resyncs `mcp_server`'s cached SID/token and lazily-built service instances, so a later logout targets the live session. A failed auth-module import on the recovery path is now logged instead of silently swallowed. (#27, #37)

### Changed
- Hardened the HTTP/SSE Docker build and isolated the mcp-proxy dependency from the core image. (#36)
- Bumped `mcp` to `>=1.27.2` and `pytest-asyncio` to `>=1.4.0`. (#26, #28)
- CI: gate `@claude` and PR-review workflows to trusted users, support fork PRs via `pull_request_target`, and skip Dependabot/fork runs where appropriate. (#29–#33)

## [1.4.1] - 2026-05-05

### Fixed
- `system_info`: use `SYNO.DSM.Info` version 2 as fallback on DSM 7.x — version 1 is below `minVersion` and returns error 104; `SYNO.DSM.Info/getinfo/v2` returns model, serial, DSM version string, RAM, temperature, and uptime successfully. Thanks @leto1210. (#17)

### Changed
- Hardened Claude Code workflows: skip runs on bot-triggered events, add `id-token: write` for claude-code-action OIDC, refresh Dependabot config with PR limits and labels, and add label-sync + issue-triage workflows. (#18, #19)

## [1.4.0] - 2026-05-01

### Added
- `synology-nas` Anthropic Agent Skill at `skills/synology-nas/` — teaches Claude how to use the MCP tools effectively (multi-NAS targeting, aggregate health checks, path conventions, per-domain workflows for files/downloads/health/NFS/users). Works in Claude Code, Claude Desktop, and claude.ai. (#14, closes #5)
- Claude Code `@claude`-mention reviewer workflow on PRs. (#15)

### Fixed
- CI now checks out the PR head SHA on `issue_comment` triggers so commit-aware reviews work. (#16)

## [1.3.0] - 2026-04-28

### Added
- DSM 7.3.2+ CSRF support: capture `SynoToken` at login (`enable_syno_token=yes`), thread `X-SYNO-TOKEN` through every service module, default session type changed to `webui`. Older DSM (6.x, 7.0–7.2) ignore the flag and continue to work header-less.

### Fixed
- `synology_create_share` on DSM 7.3.2 — `SYNO.Core.Share.create` now sends a JSON-encoded `shareinfo` envelope plus a top-level JSON-encoded `name`. Verified against DSM 7.3.2-86009 Update 3. (#8)
- Silent loss of `additional` field data on DSM 7.3.2 — now sent as JSON arrays in `FileStation.list_directory`, `FileStation.get_file_info`, and `DownloadStation.list_tasks`. Thanks @CynicalTyr. (#7)
- `FileStation.create_file` upload now threads `X-SYNO-TOKEN` on the direct `requests.Session().post(...)` path.

### Tests
- New regression test pinning the `create_share` wire format.
- Repaired 11 stale `test_config` tests broken by an earlier `SECRETS_FILE` → `SETTINGS_FILE` rename.

## [1.2.0] - 2026-02-27

### Added
- Unified `settings.json` configuration replacing `secrets.json` — single file for NAS credentials, the WebSocket bridge (see 1.1.0), and server settings. Uses XDG path `~/.config/synology-mcp/settings.json`. Supports multiple NAS devices.
- Centralized logging via Python's `logging` module with configurable levels (DEBUG/INFO/WARNING/ERROR), set in `settings.json`.
- Lint configuration in `pyproject.toml` (Ruff, Black, mypy). Codebase reformatted with Black.

### Security
- File permission enforcement: refuses to load settings with insecure permissions (e.g. 0644).
- README guidance on using dedicated accounts without 2FA.

## [1.1.0] - 2025-06-07

# 🚀 Synology MCP Server v1.1.0 - WebSocket Bridge & Enhanced Docker Support

**Release Date:** June 7, 2025

🌟 **Major feature update bringing WebSocket support and enhanced multi-client capabilities!**

## 🚀 What's New

### 🤖 **WebSocket Bridge Integration**
- **WebSocket-based MCP support** for a third-party ESP32 voice-assistant client
- **Dual client support** - Run both stdio (Claude/Cursor) and the WebSocket bridge simultaneously
- **Environment-based configuration** with an enable/disable toggle
- **Secure token authentication** for the WebSocket bridge
- **Auto-reconnection** and error recovery for WebSocket connections

### 🐳 **Enhanced Docker Support**
- **Multi-protocol Docker containers** supporting both stdio and WebSocket connections
- **Flexible deployment options** - Choose stdio-only or full WebSocket bridge mode
- **Improved environment variable handling** in containerized deployments
- **Better logging and debugging** for Docker-based setups

### 🔧 **Infrastructure Improvements**
- **Multi-client bridge architecture** for handling multiple connection types
- **Requirements validation** with helpful error messages
- **Enhanced startup diagnostics** and configuration display
- **Improved error handling** and graceful shutdown

## 📋 Configuration

### Environment Variables
- An enable/disable toggle for the WebSocket bridge (default: disabled)
- A bridge authentication token (required when the bridge is enabled)
- A configurable WebSocket endpoint for the bridge

### Usage Modes
- **Claude/Cursor Only** (default)
- **Dual Support** (stdio + WebSocket bridge simultaneously)

> **Note:** The WebSocket bridge and its third-party integration were removed
> in this fork — see the [Unreleased] section at the top of this file. This
> historical entry is kept for release-history accuracy.

---

## [1.0.0] - 2025-05-31

# 🎉 Synology MCP Server v1.0.0 - Initial Release

**Release Date:** May 31, 2025

🚀 **The first stable release of Synology MCP Server is here!**

## 🌟 What's New

This initial release brings full Model Context Protocol (MCP) integration for Synology NAS devices, enabling AI assistants to seamlessly manage your NAS through natural language commands.

## ✨ Key Features

### 🔐 **Secure Authentication & Session Management**
- **Persistent session management** across multiple NAS devices
- **Auto-login functionality** with environment configuration
- **Session cleanup** on server shutdown

### 📁 **Complete File System Operations**
- **📋 List & Browse**: List shares, directories with detailed metadata
- **🔍 Search**: Find files with pattern matching (wildcards supported)
- **📝 Create**: Create files with custom content and directories
- **🗑️ Delete**: Unified delete function (auto-detects files vs directories)
- **✏️ Rename**: Rename files and directories
- **📦 Move**: Move files/directories to new locations
- **ℹ️ Info**: Get detailed file/directory information with timestamps, permissions, ownership

### 📥 **Download Station Integration**
- **📊 Monitor**: View download tasks, statistics, and system info
- **➕ Create**: Add download tasks from URLs and magnet links
- **⏸️ Control**: Pause, resume, and delete download tasks
- **📈 Statistics**: Real-time download/upload statistics

### 🤖 **Multi-Client AI Support**
- **🤖 Claude Desktop** - Full integration with Anthropic's Claude
- **↗️ Cursor** - Seamless coding assistant integration
- **🔄 Continue** - VS Code extension support
- **💻 Codeium** - AI coding assistant compatibility

### 🐳 **Easy Deployment**
- **Docker Compose** setup with one command
- **Environment-based configuration** for security
- **Auto-SSL verification** options
- **Debug logging** for troubleshooting