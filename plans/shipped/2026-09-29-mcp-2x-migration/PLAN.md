# PR: Migrate the server to the mcp 2.x API

Status: Shipped — PR #13
Initiated: 2026-09-29
GitHub PR: [Impjegat/mcp-server-synology#13](https://github.com/Impjegat/mcp-server-synology/pull/13)
Closes: [Impjegat/mcp-server-synology#12](https://github.com/Impjegat/mcp-server-synology/issues/12)

## Why

`requirements.txt` capped `mcp>=1.28.1,<2` (added in [PR #11](../2026-09-28-windows-test-isolation/PLAN.md)) because the server was written against the mcp 1.x low-level API and does not run on 2.x: `SynologyMCPServer()` fails on construction with `'Server' object has no attribute 'list_tools'`. A fresh install and the Docker build would otherwise resolve to mcp 2.2.0. The cap was a stopgap; this PR removes the need for it by migrating, and links the issue from the new bound's comment.

## What changed in the SDK, and what it means here

Checked against mcp 2.2.0 in a scratch virtualenv before writing any code:

- **Only two places used API that 2.x removed:** the `@server.list_tools()` / `@server.call_tool()` decorators (in `_setup_handlers`) and the startup code in `run()`. `stdio_server`, `NotificationOptions` and `mcp.types` (now re-exported from the separate `mcp-types` package) all still exist, and all 39 tool definitions, annotations and dispatch worked unchanged once the decorators were bypassed.
- **2.x no longer validates tool arguments.** 1.x checked them against each tool's `inputSchema`; the server has to do it now.
- **An exception that escapes a 2.x handler reaches the client as its raw `str(e)`** and is logged with `logger.exception`, so the tool-call handler must catch everything itself.
- **Older clients still work:** 2.x accepts protocol versions `2024-11-05` through `2025-11-25`. Both SDK majors require Python 3.10+; the Docker image uses 3.13.

## Decisions

- **One PR** migrates the server and closes #12; the link to #12 lives in the new `requirements.txt` comment.
- **Corrected error reporting, as an intentional behavior change.** Under 1.x the only thing flagged `isError` was an argument-schema violation; every failure the server itself detected came back as an ordinary text result. Now:
  - tool execution failures, invalid arguments and restricted-mode refusals return `isError: true`;
  - an unknown tool name and malformed protocol requests return a standard JSON-RPC error (`-32602`);
  - the error status is set explicitly where each failure occurs, never by matching text;
  - every error path is redacted: result messages, validation messages, log lines and tracebacks.

## Changes

### `requirements.txt`
- `mcp>=2.2.0,<3`, with a comment linking #12 and explaining the upper bound (a major release broke this server once, so the next one should be a deliberate upgrade). The floor is the only version tested.
- `jsonschema>=4.20.0` added: an mcp dependency already, but now imported directly for argument validation.

### `src/mcp_server.py`: SDK wiring
- `Server(config.server_name, version=..., on_list_tools=self._on_list_tools, on_call_tool=self._on_call_tool)`; `_setup_handlers` and the decorators are gone.
- `_on_list_tools` returns a `ListToolsResult`; if listing fails it logs (redacted) and raises `MCPError(INTERNAL_ERROR, "Failed to list tools")`, so no exception text reaches the client. `_on_call_tool` hands `params.name` and `params.arguments or {}` to `_call_tool`.
- `run()` uses `server.create_initialization_options(NotificationOptions())`.
- The login/logout `types.Tool` definitions moved out of `_list_tools` into `_session_tool_definitions()`, so argument validation has their schemas even when auto-login keeps them out of the listing.
- `_compile_input_validators()` builds one `jsonschema` validator per tool from the same definitions discovery serves, at startup. It fails fast on an invalid schema and on a registered tool with no definition, rather than on the first call to it.

### `src/mcp_server.py`: error reporting
`_dispatch_tool_call` became `_call_tool(name, arguments) -> CallToolResult`. In order, and the first three all happen before any handler runs (so before any request to the NAS):

1. Unknown tool name: `MCPError(INVALID_PARAMS, "Unknown tool: <name>")`, redacted.
2. Restricted-mode refusal: `isError: true`, same text as before.
3. Invalid arguments: `isError: true`, `Invalid arguments for <tool>: <reason>`, redacted (jsonschema quotes the offending value, which could be a secret).
4. The handler runs. Success is `isError: false` with redacted content. A `ToolExecutionError` or any other exception is `isError: true`, logged at WARNING; its traceback is logged at DEBUG only, and redacted by the server itself before it is logged rather than left to a log filter. Building the result is inside the same `try`, so nothing but the unknown-tool `MCPError` can escape to the SDK.

Failures are marked where they happen:
- New `ToolExecutionError`. `_handle_login` raises it for an invalid `base_url`, a restricted-login refusal and a failed authentication; `_handle_logout` for "no active session" and a failed logout. An already-expired session stays a success, because it still cleans up locally and the caller's goal is met.
- New `_dsm_result(result, prefix="")` for the ~30 handlers that serialize a service result. The API client behind the health, NFS, user-management and container services reports failure as a *returned* `{"success": False, ...}` dict (the shape network errors are mapped to as well), which used to reach the client as ordinary output. `_dsm_result` raises `ToolExecutionError` when the top-level structured `success` field is `False`; the output text is unchanged. File Station and Download Station handlers already raise on failure and are untouched.

### Docs
- `CHANGELOG.md` `[Unreleased]` → Changed: the new requirement (Docker users rebuild) and the error-reporting behavior change, with the category list above.

## Tests

- `tests/test_restricted_mode.py`: the dispatch tests now assert on `CallToolResult.is_error`; an unknown tool now raises `MCPError` with `INVALID_PARAMS`.
- New `tests/test_tool_calls.py` (unit level): a success; output that merely talks about errors is not flagged; each error category (handler exception, `ToolExecutionError`, DSM `success: false`, failed/malformed/restricted login, logout without a session, failed vs. expired logout, missing and wrong-typed arguments, restricted refusal, unknown tool, listing failure); secret redaction in every message, the validation message, the unknown-tool name, WARNING log lines and the DEBUG traceback (with no filter attached, since the server redacts itself); for unknown, restricted and invalid calls, proof that no handler ran and no HTTP request was made; every registered tool has a compiled validator; a registered tool with no definition fails at startup.
- New `tests/test_stdio_protocol.py` (end to end): starts the real `python main.py` and speaks JSON-RPC to it over stdio, in a temporary config directory with no NAS configured. It covers the handshake at protocol versions `2024-11-05` and `2025-06-18`, the wire field names in `tools/list`, a success, each `isError` category, unknown tools and malformed requests as `-32602`, and that stdout carries only JSON-RPC. This is the check that was missing when 2.x broke the server: the unit tests never touch the SDK wiring.

## Verification

- A fresh virtualenv installed from `requirements.txt` resolves mcp 2.2.0 (and `jsonschema` 4.26); `pytest` (319 passed, 41 skipped, the new stdio tests included), `ruff check` and `black --check`, at the versions CI pins, all pass.
- **Regression proof:** against the previous `src/mcp_server.py` on mcp 2.x, all 48 new tests fail (35 failures and 13 errors, the server not starting), which is the state `main` was in.
- **Interop, run by hand against the migrated server** (a script driving `python main.py` through each SDK's own `stdio_client` and `ClientSession`): both an **mcp 2.2.0 client** and an **mcp 1.28.1 client** get the same behavior. 39 tools are listed, and `delete` is hidden in restricted mode. `synology_status` succeeds with `isError` false. Invalid arguments and a restricted tool both come back with `isError` true. An unknown tool comes back as a protocol error (`McpError` / `MCPError`, "Unknown tool: not_a_real_tool").
- One test-only fix while verifying: the "no session" assertions now match the handler's actual wording, `no active sessions`, and the restricted-mode one is now case-insensitive (the original comparison could never fail).
- Not verifiable from here: Claude Desktop or Cursor against a real NAS. After merging, rebuild the image (`docker-compose build`) and check one tool call from your client.
