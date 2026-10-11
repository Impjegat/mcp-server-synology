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
- **A call is refused locally if it carries a field named like a credential.** No tool the broker offers takes one, so such a field means a model is about to put a credential into a tool call. Names only are checked, never values. A name is split into words, so `NASPassword` and `nas_password` are caught and `passwordless` is not. This is a net for a model's mistake, not the boundary, and it says so in its header comment: a credential under an innocent name passes, as does one in a value. It fails closed on depth: arguments nested more than `MAX_DEPTH` (8) levels are refused, not passed on unchecked.
- **A malformed broker token is its own error.** A token that is present but cannot be one (too short, or with whitespace or control characters) is `BROKER_TOKEN_INVALID`, not `BROKER_TOKEN_MISSING`, so the person fixing the configuration is told the right thing, and nothing is sent. A token file that other accounts can read produces a warning at startup (POSIX only; Windows file modes are not permissions), without the file being read.
- **What a model sees is never built from an exception.** A failure's text can carry a URL, a header or the token; the codes are fixed sentences. The only dynamic part is an HTTP status number.
- **One connection per operation, measured rather than assumed.** The broker is stateless at the MCP layer, so there is no session worth keeping warm. A review asked for the client to be cached; a shared client was built and measured against a real broker, and it did not help: five operations used six connections, because the SDK discards its connection when an operation ends, so a pool would have added state and saved nothing. It was removed, and the measurement is recorded in the header of `src/adapter/client.py`. A call costs one connection and one TLS handshake, small beside the NAS call, and in exchange there are no stale-connection states and a token replaced on disk is used by the very next call.
- **The time limits are overall limits.** `list_timeout` and `call_timeout` bound the whole operation, including connecting. `connect_timeout` is only a shorter bound on the connection itself, so a broker that is not answering is reported quickly instead of after the full limit.
- **A broker's own error and a transport failure reach the model differently, on purpose.** A JSON-RPC error from the broker (an unknown tool) is passed through as a protocol error, as the broker sent it. A failure of the transport is turned into an error *result* with a stable code and a fixed sentence, because its text could hold a URL or a header. A list of tools that fails is a protocol error, so a client does not cache an empty list.
- **`tools/list` with the broker down is a protocol error, not an empty list**, so a client does not cache "no tools".

## Acceptance criteria

- The adapter holds no NAS credential and its configuration has nowhere to put one; it refuses to start with one in its environment.
- It starts and initialises with the broker down, answers with stable errors meanwhile, and works once the broker is up, with no restart.
- Standard output carries only protocol; the token and any credential never appear on standard error, in a result or on the wire.
- A broker error, an `AUTHENTICATION_REQUIRED` result and an unknown-tool error reach the model unchanged.
- It cannot sign in by itself and has no fallback to the old server.

## Verification

`pytest -m "not real_nas"`: 1148 passed, 3 skipped (1017 before this PR, plus 131 new). New: `test_adapter_config`, `test_adapter_client` (against the real broker app in-process and against transports that fail in every way, plus real TLS with a self-signed certificate), `test_adapter_server` (through the real protocol, in memory) and `test_adapter_stdio` (the real adapter over real stdio in front of the real broker over loopback: startup and recovery, token masking, credentials refused end to end, stdout carrying only protocol, refusal to start, the old server's settings having no effect, the import graph).

After the review fixes (the branch `manual-auth/adapter-review-fixes`): 1216 passed, 13 skipped. The skips are tests that need a POSIX filesystem (file modes), which a Windows run cannot do; CI runs them on Linux.

Thirteen behaviours were broken on purpose to confirm the tests can fail; all were caught. After the review of this PR ten more were broken on purpose (the depth limit and its refusal, word matching, the `device`/`id` pair, the acronym boundary, the malformed-token error and its mapping, the token-file warning and its group-access bit); the first run missed one outright (an acronym name that an older rule caught for the wrong reason) and could not report two others, because a test that patched `Path.stat` for the whole process crashed pytest while it reported the failure. Both were fixed. Two gaps were found along the way and closed: a group made only of cancellations could have been reported to a model as a broker failure, and nothing forced the token into a log line, so the redaction filter could have been deleted unnoticed. One mutation turned out to be equivalent: the SDK ignores the client's `follow_redirects` setting and follows only same-origin redirects itself, so that line is a second layer, not the control, and the test that matters (only the configured URL ever receives a request) holds either way.

## Not yet verified

- A real AI application launching the adapter. The tests use the SDK's stdio client, which speaks the same protocol.
- Python 3.10. CI and the Docker image run 3.13 only. The code uses the `exceptiongroup` backport on 3.10 (declared in `requirements.txt`), but that branch is not exercised.
- TLS against the real broker with a real certificate; the tests use a self-signed one and loopback.
- Claude Desktop and Claude Code's own timeouts against `call_timeout` (180 s by default, for the slowest NAS searches).

## For PR 5

The tool catalog (titles, descriptions, categories) is generated from the broker's registry and policy; the adapter forwards whatever the broker lists and needs no change.
