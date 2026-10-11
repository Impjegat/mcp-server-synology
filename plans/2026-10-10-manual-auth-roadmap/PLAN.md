# Manual authentication: implementation roadmap

**Written:** 10 October 2026
**Source plan:** [`../2026-10-06-manual-authentication/PLAN.md`](../2026-10-06-manual-authentication/PLAN.md). Section numbers (§) below refer to it.
**Baseline:** `main` at `63ec02b` plus the redaction fix on `manual-auth/baseline`.

The source plan makes sure an AI client never receives the NAS password, OTP or DSM session credentials. A credential-free local **adapter** forwards to a protected **broker** that holds the DSM sessions. The user logs in through a **private interface** and a short-lived worker.

This roadmap splits that work into PRs. Each PR gets its own plan folder here, and the folder moves to `plans/shipped/` when the PR's code is pushed.

## Gaps in the source plan, covered here

1. **Three clients hold the password, not one.** Besides the Codex install, Claude Code (`~/.claude.json`) passes it as environment variables and Claude Desktop reads it from the repo `.env`. Cutover must replace all three.
2. **The password sits on the NAS share.** The repo and its `.env` are on `\\DS923Plus\Miscellaneous`, reachable by the File Station tools. The folder policy must deny that path, and cutover deletes the file.
3. **A NAS-hosted broker needs a proven boundary.** This PC has SMB access to the NAS and the MCP exposes container tools. A separate machine is the simpler boundary.
4. **Two instances on one NAS account invalidate each other's sessions** (DSM error 119). File Station and Download Station have no 119 handling at all. A single broker plus typed `AUTHENTICATION_REQUIRED` errors fixes this.
5. **No new transport dependency.** The pinned `mcp` 2.x ships the Streamable HTTP server and client, a bearer-token verifier and transport security. Only passkey support adds one (`webauthn`).
6. **The Codex install runs `mcp` 2.3.0, this repo's venv 2.2.0.** Keep the `>=2.2.0,<3` bound.

## Defaults assumed (§13)

| Decision | Default |
|---|---|
| Broker host | Not chosen. Build and test against fakes. Deployment is blocked until a host passes the §3.1 checks. Recommended: a separate machine. |
| Owner authentication | Passkey (WebAuthn). |
| Client grant | One bearer token per client, stored hashed, scoped to NAS aliases, tools and folder roots. |
| Legacy password mode | Kept as an explicit separate entry point; never a fallback; installed nowhere. |
| Clients cut over | Claude Code, Claude Desktop, Codex. |
| Session deadlines, folder roots, NAS account | Set at deployment review; no defaults that widen access. |

## PRs

| # | Folder | Scope | Source plan |
|---|---|---|---|
| 0 | `manual-auth/baseline` | Commit the redaction fix and this roadmap | baseline |
| 1 | `manual-auth-core` | `auth_mode`, no password/device-token caching, `AuthenticationRequired`, shared expiry handling in every service | §2, §4.3, §6.1, §7.1 |
| 2 | `broker-sessions-and-policy` | In-memory sessions, policy, folder allowlist, Streamable HTTP broker | §4.2, §5.3, §6.2, §6.3 |
| 3 | `private-login` | Passkey-protected login page, per-login worker, enrollment CLI | §5.1, §5.2 |
| 4 | `credential-free-adapter` | stdio adapter forwarding to the broker | §3, §4.1 |
| 5 | `tool-catalog-and-titles` | Tool catalog, titles, generated `docs/TOOL_CATALOG.md` | §9 |
| 6 | `packaging-deploy-docs` | Docker targets, deploy template, config examples, docs, CI | §7.3 |

## Remediation of the implementation review

[`IMPLEMENTATION_REVIEW_2026-10-11.md`](IMPLEMENTATION_REVIEW_2026-10-11.md) found twelve problems in PRs 1 to 6 once they had merged, and says the new setup is not to be approved for a replacement NAS password until the applicable ones are fixed. The review is kept exactly as written; this table is where progress is tracked. Each finding was checked against the code before work began, and each fix starts from a test that reproduces the reviewer's check and fails on the unfixed code.

| Fix PR | Folder | Findings | Status |
|---|---|---|---|
| 1 | [`2026-10-11-fix-nas-transport`](../2026-10-11-fix-nas-transport/PLAN.md) | R03 redirects forward credentials, R04 certificate verification can be disabled, R08 private login ignores the server-level CA | Fixed in this branch, awaiting review |
| 2 | `fix-private-login` | R01 enrollment bypass, R05 cancelled login still installs a session | Open |
| 3 | `fix-folder-policy` | R02 denied folder reachable through a link, R06 directory children unfiltered, R07 NFS discovery unscoped | Open |
| 4 | `fix-grants-and-service-errors` | R12 client grants have no expiry, R09 download creation replayed, R10 expiry hidden by fallbacks, R11 legacy replay by HTTP verb | Open |

R12 was decided with the owner: grant expiry is **required**, at most a year ahead.

## Done by the user (not by code)

Choose and prove the host (§11 phase 1), deploy the broker and enroll the passkey, cut over the three clients, rotate the password and revoke old sessions, and enroll OTP (§8). The assistant must not see the new password or OTP.

## Verification

Every PR keeps the hermetic suite green (`pytest -m "not real_nas"`, dummy secrets only) plus `ruff` and `black` as CI runs them. Marker scans for fake secrets (§10.2 scenario 6) supplement, and do not replace, the schema and authorization tests. Live acceptance happens after cutover, with the user entering the credentials privately.
