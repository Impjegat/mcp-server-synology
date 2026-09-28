# Synology MCP Server Independent Rereview

Date: 2026-09-28

Reviewed revision: `0ed41f6b198a4f5f2d66454571dc4d6b446eec58` (merged PR #7 on `main`).

Comparison baseline: `b76f8eb93e13d05d6dbf49fc94dafdbd3ae24987`, the version inspected in the original review.

## Assessment

The remediation substantially improves the server, and its restricted MCP connection works. Seven actionable issues remain. Resolve the three security findings below before treating the administrator-backed installation as ready. The remaining findings affect installation reliability, resource limits, and Windows validation.

The original local checkout is still on the baseline revision. The updated code was fetched and reviewed in a separate checkout at `remediation-review/`; the original checkout and production source were not edited.

## Findings

### 1. P1: Exception logs bypass secret redaction

Location: `src/utils/redact.py:74-98`.

The logging filter sanitizes string messages and string arguments, but does not sanitize exception objects, nested arguments, or the traceback appended by a logging formatter. Existing application paths log exception objects and use `exc_info=True`. Consequently, a known live session token can still appear in logs even when the filter is installed.

Evidence: A dummy token supplied to the filter's live-secret provider remained visible both in an exception traceback and in an exception object passed through a `%s` logging argument.

Required change: Redact the fully formatted log output, including chained exceptions and tracebacks, or otherwise comprehensively sanitize those fields before emission. Add regression coverage for these forms, and include configured credentials in the secret inventory before successful authentication.

[Source](https://github.com/Impjegat/mcp-server-synology/blob/0ed41f6b198a4f5f2d66454571dc4d6b446eec58/src/utils/redact.py#L74)

### 2. P1: Windows settings writes succeed after permission protection fails

Location: `src/config.py:177-238`.

`_restrict_file_permissions()` catches and suppresses permission-setting failures. `_atomic_write_settings()` then replaces the settings file and reports success anyway. On Windows, credentials are also written to the temporary file before its ACL is restricted. If the containing directory permits other users to read it, the operation can expose all configured passwords and the new device token.

Evidence: With the ACL command mocked to fail, `_atomic_write_settings()` returned `True` and created a settings file containing the dummy password.

Required change: Establish and verify restrictive permissions before writing secret material. Propagate permission failures, preserve the original settings file, and clean up temporary files safely. Prefer a unique temporary filename to avoid concurrent writers sharing `settings.json.tmp`.

[Source](https://github.com/Impjegat/mcp-server-synology/blob/0ed41f6b198a4f5f2d66454571dc4d6b446eec58/src/config.py#L227)

### 3. P1: Unexpected restricted-mode values enable modifying tools

Location: `src/config.py:113`.

Restricted mode is enabled only when the environment value, lowercased, equals the literal `true`. Every other value disables it. For example, a launcher setting `RESTRICTED_MODE=1` or passing a trailing space in `true ` unexpectedly enables the unrestricted tool catalogue. This contradicts the intended requirement that broader access must be deliberately enabled.

Evidence: Both inputs produced `restricted_mode=False` in isolated configuration probes.

Required change: Parse a documented set of true/false values and reject invalid values, or keep restricted mode enabled unless an explicit supported false value is supplied. Validate the settings-file value as well.

[Source](https://github.com/Impjegat/mcp-server-synology/blob/0ed41f6b198a4f5f2d66454571dc4d6b446eec58/src/config.py#L113)

### 4. P2: The documented Docker quick start no longer supplies credentials

Location: `docker-compose.yml:9-16`; `README.md` Docker quick start.

Removing `.env` from the image is correct. However, the quick start still tells users to configure `.env`, while the container configuration passes only `XDG_CONFIG_HOME` and mounts a separate settings directory. It neither forwards the NAS environment variables nor mounts `.env`. A fresh installation following that quick start has no NAS credentials inside the container and fails startup when auto-login uses its default value.

Required change: Make the quick start use a protected, runtime-mounted settings file, or explicitly support the documented environment-file workflow at runtime. Verify the complete fresh-install path with dummy credentials. Do not restore the build-time credential copy.

Evidence: Static inspection of the Dockerfile, Compose file, and instructions. Docker documents that container environment variables need explicit service configuration; a project `.env` file alone is not sufficient. A Docker build was not run because Docker was unavailable in this review environment.

[Source](https://github.com/Impjegat/mcp-server-synology/blob/0ed41f6b198a4f5f2d66454571dc4d6b446eec58/docker-compose.yml#L9) | [Docker documentation](https://docs.docker.com/compose/how-tos/environment-variables/set-environment-variables/)

### 5. P2: JSON responses bypass the file limit during buffering

Location: `src/filestation/synology_filestation.py:753-761`.

For an `application/json` download response, `response.json()` reads the complete body before the byte-counting streaming loop runs. If metadata is missing or stale, an oversized JSON response is fully downloaded into memory before the configured size limit rejects it. The subsequent rejection does not undo the resource-limit bypass.

Evidence: A mocked JSON response of 200,032 bytes was fully read before rejection with a configured limit of 1,024 bytes and unavailable metadata size.

Required change: Apply a bounded body read before parsing JSON or decoding text, including API-error responses. Ensure response resources close on every exit path.

[Source](https://github.com/Impjegat/mcp-server-synology/blob/0ed41f6b198a4f5f2d66454571dc4d6b446eec58/src/filestation/synology_filestation.py#L753)

### 6. P2: The search timeout measures sleep time, not elapsed time

Location: `src/filestation/synology_filestation.py:366-380`.

The new search timeout increments its counter only during the half-second sleep between status requests. Time spent waiting for each NAS response is excluded. Because each request can take many seconds, a search can occupy the server far longer than the documented two minutes.

Evidence: A simulated 14-second response for each unfinished status poll produced 240 polls and 3,480 seconds of elapsed time before the code reported a 120-second timeout. This simulation used mocked time and requests and did not take 58 real minutes.

Required change: Use a monotonic elapsed-time deadline and bound each request by the remaining budget. Retain task cleanup on timeout.

[Source](https://github.com/Impjegat/mcp-server-synology/blob/0ed41f6b198a4f5f2d66454571dc4d6b446eec58/src/filestation/synology_filestation.py#L366)

### 7. P2: The updated test isolation breaks Windows asynchronous tests

Location: `tests/conftest.py:36-56`; configuration tests that clear the entire environment.

The new socket-blocking fixture rejects every `connect()` call. On this Windows/Python version, creating an asynchronous event loop uses a loopback socket pair, so asynchronous tests fail during setup before reaching the code under test. Separately, configuration tests clear `USERPROFILE` and then reimport code that eagerly evaluates `Path.home()`, causing home-directory lookup failures on Windows. Permission tests also assume POSIX behaviour in places.

Evidence: The isolated full suite produced **149 passed, 26 failed, 40 skipped, and 10 setup errors** on Python 3.13.14. Repeating the run with loopback permitted in the independent review harness did not remove the errors: the repository's own fixture still blocked the event loop.

Required change: Keep external NAS access blocked while permitting the local IPC required by the runtime, or block requests at the HTTP boundary. Supply an isolated home directory in configuration tests and make filesystem-permission assertions platform-aware. Validate on both Windows and Linux.

[Source](https://github.com/Impjegat/mcp-server-synology/blob/0ed41f6b198a4f5f2d66454571dc4d6b446eec58/tests/conftest.py#L55)

## Confirmed improvements

- Passwords and authentication material are sent in the authentication POST body instead of URL query parameters.
- Normal successful login/status responses no longer print session tokens.
- Restricted mode is enforced during both discovery and dispatch through one tool registry.
- The five account/group/permission-enumeration tools remain correctly marked read-only but are excluded from restricted-mode access.
- Volume roots and `/homes` use exact matching; OS directories use path-component-aware subtree matching. Paths are normalized before these checks.
- The default HTTPS port is corrected to `5001`, and CA-bundle configuration is supported.
- File metadata size extraction and ordinary streaming size checks were improved.
- The Dockerfile no longer copies `.env`, and the Compose file no longer requests a TTY.

## Validation and limitations

- An isolated STDIO MCP handshake succeeded against the reviewed revision.
- Discovery returned **39 restricted tools**, all with tool annotations.
- The status tool succeeded. Direct calls to `delete` and `synology_list_users` were rejected as restricted before any NAS request.
- Tests and focused reproductions used dummy secrets, isolated configuration, and blocked live HTTP access. No real NAS login or NAS modification was performed.
- Docker was unavailable, so image-layer inspection and container startup remain unverified.
- The folder/share allowlist and credential-file exclusions discussed earlier are still absent. The shipped PR explicitly deferred the optional allowlist. With administrator credentials, the size cap and critical-path denylist do not restrict reading to approved data folders. This is an outstanding scope decision, not a verified implementation of the earlier recommendation.
- The optional identity/permission-inspection capability was not added; those tools currently require unrestricted mode.

## Recommended order

1. Close the redaction, permission-protection, and restricted-mode parsing gaps.
2. Correct the Docker setup and file/search resource limits.
3. Repair Windows test isolation and obtain a clean cross-platform test run.
4. Decide and document the allowed file scope, then perform the remaining container and authenticated read-only installation checks.
