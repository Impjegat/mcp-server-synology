# Changelog

## [Unreleased]

### Added
- **Manual authentication mode** (`SYNOLOGY_AUTH_MODE=broker`), the first step of `plans/2026-10-06-manual-authentication/`. The mode is read from the real process environment only, and the default (`legacy`) behaves exactly as before. In `broker` mode the process:
  - holds no NAS password, one-time code or trusted-device token. A stored credential (`password`, `otp_code`, `device_id` in settings.json; `SYNOLOGY_PASSWORD`, `SYNOLOGY_OTP_CODE`, `AUTO_LOGIN=true`, `server.auto_login`) is rejected at startup, and the message names the setting, never its value;
  - never reads a `.env` file, in `main.py` or in `config.py`;
  - starts disconnected, and knows its NAS endpoints without a password, so `synology_status` and `synology_list_nas` work before anyone has signed in;
  - never signs in on its own and never renews a lost session from a stored secret;
  - does not register or list `synology_login`, so no tool can take a password;
  - only accepts a configured NAS as `base_url`; any other target is `AUTHORIZATION_DENIED`.
- `AuthenticationRequired` (stable code `AUTHENTICATION_REQUIRED`) and `AuthorizationDenied`, in `src/broker/errors.py`. A lost DSM session (106, 107 or 119) now raises `AuthenticationRequired` from the shared API client, File Station and Download Station, and the tool result is an `isError: true` with a fixed message that tells the caller to have the user sign in privately. A health summary stops at the first lost session instead of reporting eleven failed checks as "partial".
- `SynologyMCPServer.install_session()`, the one place a session established elsewhere enters the server.
- **Packaging, deployment and documentation for manual authentication**, step 6 and the last piece of software in the manual-authentication roadmap.
  - **`docs/MANUAL_AUTHENTICATION.md`** is the guide: what changes, the three pieces, who does what (and what an AI assistant should not be asked to do), where the broker may run and why a container is not proof of that, setting it up (the broker host, the NAS account and `settings.json` without a password, the certificate, client tokens, the policy, starting the broker, enrolling your passkey, registering the adapter in each application), using it, turning on one-time codes, moving from the old setup with a rollback that is not "put the password back", an error table, and what it does not protect against. Tests check its commands against the real argument parser, its settings against the adapter's, its error codes against the adapter's, its numbers against the session defaults, and every link.
  - **Three images from one `Dockerfile`**: `--target adapter` (the credential-free adapter, with none of the NAS code or libraries), `--target broker`, and `legacy` (the original server, still the last stage, so `docker build .` and `docker-compose.yml` are unchanged in use). Each runs as a non-root account, with its code owned by root and not writable by that account, built from a finished virtual environment so no runtime image has a compiler, and with no secret baked in. The broker image has a real health check (`/readyz`; a broker nobody has signed in to is healthy) and prints its usage by default rather than starting without TLS or a policy.
  - **`deploy/broker/`**: a compose template for the broker with a read-only filesystem, all capabilities dropped, no privileged mode, no Docker socket, no host network and no environment file, running as the account that owns its directories. Nothing is published by default: the MCP address and the private-login address are both required, and the private login has its own. The only writable mount is the owner's public passkey.
  - **`config/adapter.example.json`, `config/broker.example.json` and `config/settings.broker.example.json`**: secret-free examples that the real parsers accept. **`env.example` now leads with manual authentication** and labels the password variables as legacy and commented out.
  - **`.gitignore` and `.dockerignore`** keep the policy, the owner store, tokens, keys and local configuration out of git and out of every build context, at any depth.
  - **The skill never solicits a password.** `skills/synology-nas/` now says that signing in is the user's job: on `AUTHENTICATION_REQUIRED` the assistant tells the user once to sign in on their private page and never asks for, accepts or repeats a NAS password or code. It also separates manual authentication from the legacy `synology_login` flow, and an eval covers a user who offers their password. The skill's `synology_logout` example now uses the `base_url` argument the tool actually takes.
  - **CI** lints every entry point, `scripts/` and `docker/`, checks the tool catalog, builds the adapter and broker images, validates the broker template as Compose reads it, and runs `tests/test_docker_images.py` against the built images. The real adapter and real broker tests already ran on both Linux and Windows. New `tests/test_tls_end_to_end.py` runs the real broker with a real (throwaway) certificate and the real adapter with the chain and the host name verified.
- **A tool catalog with plain-language titles**, step 5 of the manual-authentication roadmap. Every tool now has a readable title ("NAS health summary", "Browse shared folders", "Search files") served as `Tool.title` and `annotations.title`, so an application's tool picker shows it instead of `synology_disk_smart`. The tool IDs are unchanged, so existing integrations and broker policies keep working.
  - **`docs/TOOL_CATALOG.md`** lists every tool by category (Connection, Health and monitoring, Files, Downloads, Containers, Sharing and NFS, Users and groups) with what it does, whether it only reads or changes or deletes, whether a sign-in is needed, whether it is on by default (in a default installation and in a broker client's default grant), its required inputs, and a safe example for each tool that is on by default. It is generated by `python scripts/generate_tool_catalog.py` from the server's own registry, restricted-mode classification and the broker's default policy; `--check` says whether it is current, and a test fails when it is not. A catalog that has drifted from the registry makes the generator fail instead of printing a shorter document.
  - **It is presentation, not permission.** `src/tool_catalog.py` holds titles, categories, summaries and examples and no list of allowed tools; what a tool may do is still decided by restricted mode and the broker's policy. Tests show that scrambling every title and category changes nothing that is offered, and that a friendly title does not get a destructive tool through restricted mode. The document's claims are checked against the server: which tools answer `AUTHENTICATION_REQUIRED` with nobody signed in, which are offered by default, and which are granted to a broker client with no `tools` entry.
  - **Two sentences were added to tool descriptions, nothing else.** Tools that return free text or file content (`get_file_content`, `synology_system_log`, container `logs`, `get` and `project_get`) now say that what they return goes to the AI application and its provider. In manual-authentication mode `synology_status` tells a model that the user signs in on a private page and that a NAS password or one-time code must never be asked for or accepted in the chat.
  - The catalog states a limit plainly: the adapter refuses any call carrying a field named like a credential, so `synology_create_user` cannot be used through it, and `synology_set_user` and `ds_create_task` can be used only without their password field. None is on by default. It also states that the broker applies restricted mode too, so giving a client a tool that changes things takes `RESTRICTED_MODE=false` on the broker as well as the tool in the client's policy entry.
- **The credential-free adapter** (`adapter_main.py`, `src/adapter/`), step 4 of the manual-authentication roadmap: the local stdio MCP server an AI application launches in place of the old server. It forwards `tools/list` and `tools/call` to the broker over HTTPS with this client's broker token and returns what comes back unchanged, errors included. It holds no NAS password, one-time code, session or device token, never signs in by itself, and has no fallback to the old server.
  - **Configuration** (`~/.config/synology-mcp/adapter.json`, or `--config`, or `SYNOLOGY_ADAPTER_CONFIG`): the broker's URL, an optional CA file, timeouts, and a *reference* to the token, either `token_file` (read on every call, so a token can be replaced without restarting the application) or `token_env`. There is no place to put a credential: a setting named like a password, token, session or device id is refused by name, a user name in the URL is refused, plain `http` is accepted only to loopback with `allow_insecure_loopback`, and nothing is ever echoed.
  - **It refuses to start** if a NAS credential (`SYNOLOGY_PASSWORD`, `SYNOLOGY_OTP_CODE`, `SYNOLOGY_DEVICE_ID`) is in its environment, naming the variable, because an application registration that still carries a password is exactly what manual authentication removes.
  - **It starts without the broker and recovers when the broker returns.** Nothing is contacted at startup. With the broker down a call comes back as an error result and a tool list as a protocol error, each with a stable code; there is no fallback.
  - **Failures are a code and a fixed sentence, never an exception's text**: `BROKER_UNAVAILABLE`, `BROKER_TIMEOUT`, `BROKER_CERTIFICATE_ERROR`, `BROKER_UNAUTHORIZED`, `BROKER_TOKEN_MISSING`, `BROKER_TOKEN_INVALID`, `BROKER_REFUSED`, `BROKER_BUSY`, `BROKER_ERROR` (with the HTTP status) and `BROKER_PROTOCOL_ERROR`. The SDK client throws away the status of an error response, so a response hook records it (an integer, nothing else) to tell a refused token from a broker failure. A broker's own JSON-RPC error (an unknown tool) and its `AUTHENTICATION_REQUIRED` result pass through unchanged.
  - **A tool call carrying a field named like a credential is refused locally** and never leaves the computer, so it cannot reach any log between here and the broker. A name is split into words (`NASPassword`, `nas_password`, `userPassword` and `adminOTP` are all caught; `passwordless`, `hotpot` and `path` are not), and `device` followed by `id` counts as one. The reply names the field, never the value. This guard is a net for a model's mistake, not the boundary: it looks at names, not values, so a credential under an innocent name passes, and the broker's tools take none. A call whose arguments are nested more than eight levels deep is refused as well, because a branch that is too deep to inspect is not assumed to be safe.
  - **A broker token that is not a token** (too short, or with spaces or control characters in it) is reported as `BROKER_TOKEN_INVALID`, apart from `BROKER_TOKEN_MISSING`, and nothing is sent with it. Where file modes mean something (not Windows), a startup warning on standard error says when the token file can be read by other accounts; the file itself is never read for this.
  - **The time limits are overall limits.** `list_timeout` and `call_timeout` bound the whole operation, connection and all; `connect_timeout` only shortens how long a broker that is not answering can hold a call.
  - **Standard output is protocol only**: logging goes to standard error, the token is masked from every line, and chatty libraries are quieted.
  - **Importing the adapter pulls in none of the NAS code**, nor the project's `config`, `dotenv` or `requests`; a test enforces it.
- **The private login** (`src/private_auth/`), step 3 of the manual-authentication roadmap: how a person signs in to the NAS without the password ever passing through an AI client. Enabled with `broker_main.py serve --private-origin URL`, on its own address, port and TLS, never on the MCP listener.
  - **Owner proof** (`owner.py`): the owner signs in to the private page with a passkey (WebAuthn, new dependency `webauthn`), with user verification required, single-use challenges that expire after two minutes, and a counter that must move forward. The owner store holds public keys only. Enrolling needs a one-time code printed by `broker_main.py enroll new-code` on the broker host, so it cannot be done from an AI application elsewhere; a second device needs `--add-device`. `enroll list` and `enroll revoke` manage passkeys.
  - **The page** (`app.py`): the owner sees which clients are waiting, then, before typing anything, the NAS, the account, the requesting client, the tools it gets and the folders it can reach. State-changing requests need the owner session, a CSRF token and a matching Origin, checked in that order and before the body is read. Cookies are `__Host-` prefixed, Secure, HttpOnly and SameSite=Strict. Every response, errors included, carries `no-store`, a CSP with no inline script or style and nothing from another origin, and framing, referrer and sniffing limits. Failed passkey and enrollment-code attempts are rate limited. The account is the configured one and cannot be substituted; only when none is configured does the owner type it. The password field is a normal password field, so a password manager can fill it.
  - **The worker** (`worker.py`, `login.py`): each sign-in runs in a short-lived subprocess, started in Python's isolated mode with a minimal environment (no `SYNOLOGY_*`, no proxy settings), a neutral working directory and its standard error discarded. It receives the account, password and code on standard input only, signs in over verified HTTPS in manual mode (no device token is requested or returned), prints one line holding a session or a stable error code, and exits. A worker that outlives 25 seconds is killed. Core dumps and tracebacks are suppressed. Outcomes are fixed sentences that never contain a submitted value.
  - **Account protection**: three wrong answers in five minutes lock that client and NAS for ten, well inside what DSM's auto-block tolerates, and a locked sign-in never contacts the NAS. Asking for a code, an unreachable NAS and a certificate that did not verify are not counted.
  - **Requests the model cannot use**: a model's call that needs a session leaves one de-duplicated pending request on the private page. What the model is told is unchanged (`AUTHENTICATION_REQUIRED`) and carries no request id or address. No tool can start, approve or alter a sign-in, and the MCP listener serves none of the private pages.
- **The broker** (`broker_main.py`, `src/broker/`), step 2 of the manual-authentication roadmap: the protected process that holds DSM sessions and serves the tools to clients that hold no NAS credentials. `python broker_main.py serve --policy PATH` always runs in broker mode (whatever the environment says), never reads a `.env`, refuses to start without TLS unless it is bound to loopback with `--allow-plain-http-loopback`, and `python broker_main.py new-token` makes a client token and prints only the digest that goes in the policy file.
  - **Policy** (`src/broker/policy.py`): one file, read once, names each client and the NAS units, tools, folder roots and session limits it gets. It holds only a SHA-256 digest of each client's bearer token. Unknown settings, unknown NAS or tool names, a repeated token and anything that looks like a secret are rejected, naming the setting and never the value. The default tool set is a fixed list, so a tool added later never enters a client's scope silently; it leaves out container `get`/`project_get`/`image_get`/`logs`, `synology_system_log`, every `ds_*` tool and account enumeration. `synology_login` can never be granted.
  - **Sessions** (`src/broker/sessions.py`): in memory only, one per client and NAS, with an idle and an absolute deadline (activity moves the first and never the second), generation numbers that are never reused so a late failure from an old login cannot end a newer one, and de-duplicated pending sign-in requests. A session that expires, is replaced or is disconnected is also logged out on the NAS.
  - **Folders** (`src/broker/file_policy.py`): each client's folder roots, checked on the path as File Station will see it (`..`, `//`, Unicode, lookalike names, control characters) and again on where DSM says it really lives, so a symbolic link cannot lead out of a root. A path that exists but whose real location DSM does not report is refused, not judged by its parent. Secret-looking names (`.env`, `secrets.*`, `credentials.*`, keys, `.ssh`) are denied inside any root. Applied to listing, info, search, content reads and every write, and to Download Station destinations; shares and search hits outside the roots are filtered out.
  - **Per-client isolation** (`src/broker/runtime.py`): one tool executor per client, limited to that client's NAS units, tools and folders, with its sessions supplied by the session manager. The broker's session ids are registered with the redaction filter, so a raw session id in an error is masked.
  - **HTTP** (`src/broker/server.py`): authenticated Streamable HTTP on `/mcp` using the SDK's bearer-token and DNS-rebinding protections (stateless, JSON responses), plus unauthenticated `/healthz` and `/readyz` that say nothing about the NAS, clients or sessions. A broker nobody has signed in to is ready, not unhealthy.
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
- **Test dependencies moved out of `requirements.txt`.** It now lists only what the server and the broker need at run time; `pip install -r requirements-dev.txt` adds pytest, pytest-asyncio and PyYAML. The Docker images no longer contain the test tools. `requirements-adapter.txt` is the adapter's own, much smaller list.
- **The legacy Docker image's code is no longer writable by the account that runs it.** `/app` is owned by root; the only writable place is `/app/logs`, which `docker-compose.yml` mounts. Rebuild the image (`docker-compose build`). It now builds dependencies in a separate stage, so the image carries no compiler.
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
- Tool descriptions and messages no longer call the settings file `secrets.json`. The server only ever reads `settings.json`, but the `nas_name` description of nearly every tool, the description of `synology_list_nas`, and the validation error for missing credentials said `secrets.json`, and two `synology_list_nas` messages told users to create `~/.config/synology-mcp/secrets.json`, a file that is never read.
- `search_files` had no time limit at all and could poll an unresponsive NAS forever; `delete` and `move_file` counted only the time they spent sleeping between polls, so a slow NAS could stretch their limits to about an hour. All three now use a wall-clock deadline (see the time-limits entry above).
- A JSON download bypassed the `get_file_content` size cap (the body was parsed before its size was checked), and a real `.json` file was mistaken for a DSM error and could not be read at all.
- Starting a container from the Docker quick start did not pass `.env` to it, although the README said to create one.
- Windows: loading `settings.json` crashed with an `AttributeError` (`os.getuid()` does not exist there); the permission check is now skipped with a warning on platforms without it.
- `synology_health_summary` no longer reports `success: true` with empty data when the NAS cannot be reached. It used to drop every failed check and always succeed, so an unavailable NAS looked like a healthy, empty summary.
- File Station and Download Station now recover from an expired session (DSM 119) in legacy mode, as the shared API client always has: the session is renewed once from the cached login and a read is repeated. A write is never repeated.
- Download Station's `get_info`, `get_config` and `get_statistics` no longer answer a lost session with made-up default values in broker mode.
- In broker mode a session the NAS has dropped is now forgotten, so `synology_status` stops showing it as connected and the next call asks for a new sign-in instead of failing the same way again (review of #19).
- A configured NAS is now recognised however its URL is spelled (trailing slash, host case), and `AuthenticationRequired`/`AuthorizationDenied` messages are the fixed ones (review of #19).
- `SynologyAuth.logout()` in manual mode clears the local session even if the remote call raises, not only when it answers with an error (review of #19).
- Enrolling a passkey now checks the one-time code, adds the passkey and uses the code up as one step under one lock. They were three separate steps, so two enrollments begun with the same code could both finish; the new tests widen that window on purpose so the race is caught every time (review of #21).
- `/auth/begin` and `/enroll/begin`, which need no sign-in and each make a challenge, are rate limited per address (thirty a minute, every call counted), and the table of outstanding challenges is capped at 256, oldest first (review of #21).
- The sign-in worker keeps the certificate-trust settings a private CA needs (`REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR`) and still drops proxy settings and credentials; the docstring says why (review of #21).
- `BrokerRuntime.nas_config(name)` replaces the login service reaching into a private attribute, and refuses an unknown NAS by name (review of #21).
- The rate limiter no longer creates an entry for a key it is only asked about, drops entries whose events have aged out and sweeps itself under a flood of distinct addresses; expired owner sessions are removed whenever a new one is made (review of #21).
- A failed lookup of a folder root's real location is no longer remembered for five minutes, so one transient NAS error cannot block a root; and `BrokerRuntime.shutdown` now logs sessions out together and waits a bounded time in total, instead of up to ten seconds per session (review of #20).
- `config.py` no longer raises in a process started with a minimal environment: `Path.home()` was evaluated even when `XDG_CONFIG_HOME` was set.
- Disconnecting says whether the NAS confirmed the session closed, instead of implying it did (review of #19).
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