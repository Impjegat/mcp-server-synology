# The broker: sessions, policy, folders and the HTTP front

**Written:** 10 October 2026
**Roadmap:** [`../2026-10-10-manual-auth-roadmap/PLAN.md`](../2026-10-10-manual-auth-roadmap/PLAN.md), PR 2
**Source plan:** §4.2, §5.3, §6.2 and §6.3 of [`../2026-10-06-manual-authentication/PLAN.md`](../2026-10-06-manual-authentication/PLAN.md)
**Builds on:** `manual-auth-core` (merged as #19)

## What this adds

The protected process that holds DSM sessions and serves the tools to clients that hold no NAS credentials. Nothing in it can sign in yet: that is PR 3. Until then a broker serves only sessions that something installs through `BrokerRuntime.install_login`.

| Piece | File | What it does |
|---|---|---|
| Policy | `src/broker/policy.py` | One file naming each client and its NAS units, tools, folders and session limits. Only a SHA-256 digest of each bearer token. Strict: unknown or secret-looking settings, unknown NAS/tool names and repeated tokens are rejected by name, never value. Fixed default tool set |
| Sessions | `src/broker/sessions.py` | In-memory, per client and NAS. Idle and absolute deadlines; generations never reused; de-duplicated pending sign-ins; secret-free status |
| Folders | `src/broker/file_policy.py` | Roots per client, judged on the canonical path and on DSM's real path (symlinks); secret-looking names denied inside any root |
| Bridge | `src/broker/bridge.py` | The three questions an executor asks the broker: current session, session lost, close session |
| Runtime | `src/broker/runtime.py` | One executor per client, limited to its NAS units, tools and folders; remote logout in bounded background threads |
| HTTP | `src/broker/server.py` | Bearer-authenticated Streamable HTTP on `/mcp` (SDK middleware, stateless), `/healthz`, `/readyz` |
| Entry point | `broker_main.py` | `serve` and `new-token`; always broker mode, no `.env`, TLS required off loopback |

Changed to fit: `SynologyMCPServer` takes `allowed_nas`, `allowed_tools`, `folder_policy` and `session_bridge`; File Station and Download Station take a `folder_guard`; `iter_live_secrets` gains `register_secret_source`; and the four review fixes from #19 (dead session forgotten, URL spelling, `logout()` in a `finally`, honest disconnect message).

## Design choices worth knowing

- **One executor per client**, not one shared executor with a per-call identity. Isolation then holds by construction: a client's sessions, instances and folders live in its own object.
- **The session manager is the only authority.** The executor asks the bridge for its session at the moment it needs one and follows the answer; an expired or replaced session is never used.
- **Default tool set is a fixed list**, not "everything read-only", so a tool added later never enters scope silently.
- **Folder policy is checked twice**: lexically, before any request, and by DSM's reported real path. Where DSM cannot say where an existing path really is, it is refused.
- **Stateless HTTP**: each request is authenticated on its own. An MCP session id never identifies a caller and never leads to a DSM session.

## Acceptance criteria

- Legacy mode and PR 1's broker-mode behaviour are unchanged: the existing suite passes untouched.
- A client sees and can call only its own tools; a tool outside its list is `AUTHORIZATION_DENIED` before any request reaches the NAS.
- A client reaches only its own NAS units, by name or by address, and only inside its folder roots, including through a symbolic link.
- One client's session is never used for another; a late failure on an old login never ends a newer one; the absolute deadline cannot be extended.
- No session id, token or password appears in any reply, log or status.
- `broker_main.py` will not start without TLS (except on loopback with an explicit flag), ignores `.env` and an environment asking for legacy mode, and serves an MCP client over real HTTP.

## Verification

`pytest -m "not real_nas"`: 714 passed, 2 skipped. New files: `test_broker_policy.py`, `test_broker_sessions.py`, `test_file_policy.py`, `test_broker_runtime.py`, `test_broker_http.py` (the real MCP client against the real ASGI app, in-process), `test_broker_main.py` (a real subprocess on loopback), plus additions to `test_manual_auth.py`. Ten behaviours were broken on purpose to confirm the tests can fail (folder allowlist, real-path check, root boundary, generation check, absolute deadline, digest-as-token, tool allowlist, dead-session cleanup, session masking, and the real-path-omitted case); all ten were caught. `ruff` and `black` are clean.

## Not yet verified

- DSM's `real_path` for entries returned by `getinfo` and by search, against a real NAS. The code relies on File Station's documented `real_path` additional field; if a DSM version omits it the effect is refusal, not exposure. Check during live acceptance.
- Behaviour behind a real TLS terminator and a real client certificate chain; the tests use loopback HTTP.

## For PR 3

`BrokerRuntime.install_login(client, nas, session_id, syno_token)` is the one place a session enters, and `SessionManager.begin_pending` / `find_pending` / `cancel_pending` already hold the sign-in request the private login will bind to.
