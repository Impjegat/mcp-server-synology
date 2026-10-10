# The credential-free adapter

**Written:** 10 October 2026
**Roadmap:** [`../2026-10-10-manual-auth-roadmap/PLAN.md`](../2026-10-10-manual-auth-roadmap/PLAN.md), PR 4
**Source plan:** §3, §4.1 and §6.1 of [`../2026-10-06-manual-authentication/PLAN.md`](../2026-10-06-manual-authentication/PLAN.md)
**Builds on:** the broker (#20) and the private login (#21).

## What this adds

The local piece an AI application launches. After this PR the whole path exists end to end: the application starts the adapter, the adapter forwards to the broker, and the broker is signed in to through the private page.

| Piece | File | What it does |
|---|---|---|
| Configuration | `src/adapter/config.py` | Strict settings with no place for a credential; the broker token only referenced (a file read on every call, or an environment-variable name) |
| Broker client | `src/adapter/client.py` | One short-lived connection per operation with the token in the `Authorization` header; every failure becomes a stable code and a fixed sentence |
| Server | `src/adapter/server.py` | Forwards `tools/list` and `tools/call` and returns the broker's answer unchanged; refuses locally a call carrying a credential-looking field |
| Entry point | `adapter_main.py` | Refuses to start with a NAS credential in the environment; logs to stderr only, masking the token |

## Registering it

In the application's MCP registration, with no password and no token in it:

```json
{ "mcpServers": { "synology": { "command": "python", "args": ["adapter_main.py"] } } }
```

and `~/.config/synology-mcp/adapter.json`:

```json
{
  "broker_url": "https://broker.example:8443",
  "ca_file": "C:/certs/broker-ca.pem",
  "token_file": "C:/Users/you/.config/synology-mcp/broker.token"
}
```

(`ca_file` only if the broker's certificate is signed by a private CA. The token is the one `broker_main.py new-token` printed for this client.)

## Design choices worth knowing

- **No fallback, by construction.** The adapter imports none of the NAS modules and not the project's `config`, so there is no code in the process that could sign in. A test starts a clean interpreter and checks the import graph.
- **It refuses to start with a NAS credential in its environment**, rather than ignoring it. An existing registration that still carries `SYNOLOGY_PASSWORD` must be cleaned up, which is the point of the cutover.
- **The token is the client's own grant**, which the source plan allows an AI-side process to hold, but it is still referenced rather than written into the file, and a file is re-read each call so rotation needs no restart.
- **A call is refused locally if it carries a field named like a credential.** No tool the broker offers takes one, so such a field means a model is about to put a credential into a tool call. Names only are checked, never values.
- **What a model sees is never built from an exception.** A failure's text can carry a URL, a header or the token; the codes are fixed sentences. The only dynamic part is an HTTP status number.
- **One connection per operation.** The broker is stateless at the MCP layer, so there is no session worth keeping warm; the cost is a handshake per call on a LAN, in exchange for no stale-connection states and a token that can be replaced at any time.
- **`tools/list` with the broker down is a protocol error, not an empty list**, so a client does not cache "no tools".

## Acceptance criteria

- The adapter holds no NAS credential and its configuration has nowhere to put one; it refuses to start with one in its environment.
- It starts and initialises with the broker down, answers with stable errors meanwhile, and works once the broker is up, with no restart.
- Standard output carries only protocol; the token and any credential never appear on standard error, in a result or on the wire.
- A broker error, an `AUTHENTICATION_REQUIRED` result and an unknown-tool error reach the model unchanged.
- It cannot sign in by itself and has no fallback to the old server.

## Verification

`pytest -m "not real_nas"`: 1148 passed, 3 skipped (1017 before this PR, plus 131 new). New: `test_adapter_config`, `test_adapter_client` (against the real broker app in-process and against transports that fail in every way, plus real TLS with a self-signed certificate), `test_adapter_server` (through the real protocol, in memory) and `test_adapter_stdio` (the real adapter over real stdio in front of the real broker over loopback: startup and recovery, token masking, credentials refused end to end, stdout carrying only protocol, refusal to start, the old server's settings having no effect, the import graph).

Thirteen behaviours were broken on purpose to confirm the tests can fail; all were caught. Two gaps were found along the way and closed: a group made only of cancellations could have been reported to a model as a broker failure, and nothing forced the token into a log line, so the redaction filter could have been deleted unnoticed. One mutation turned out to be equivalent: the SDK ignores the client's `follow_redirects` setting and follows only same-origin redirects itself, so that line is a second layer, not the control, and the test that matters (only the configured URL ever receives a request) holds either way.

## Not yet verified

- A real AI application launching the adapter. The tests use the SDK's stdio client, which speaks the same protocol.
- Python 3.10. CI and the Docker image run 3.13 only. The code uses the `exceptiongroup` backport on 3.10 (declared in `requirements.txt`), but that branch is not exercised.
- TLS against the real broker with a real certificate; the tests use a self-signed one and loopback.
- Claude Desktop and Claude Code's own timeouts against `call_timeout` (180 s by default, for the slowest NAS searches).

## For PR 5

The tool catalog (titles, descriptions, categories) is generated from the broker's registry and policy; the adapter forwards whatever the broker lists and needs no change.
