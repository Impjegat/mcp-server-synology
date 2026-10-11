# Plans

This folder tracks work-in-progress remediation/feature plans for this repository, one folder per PR.

## Convention

- Each PR gets a folder here named `<YYYY-MM-DD>-<slug>/`, where the date is when the plan was written and the slug is a short kebab-case name for the PR.
- The folder holds that PR's scoped plan document (e.g. `PLAN.md`) — what it changes, why, the acceptance criteria, and how it was verified.
- Once the PR's changes are implemented (code complete, tested, committed, and pushed), its folder is moved to `plans/shipped/<YYYY-MM-DD>-<slug>/` via `git mv`. "Implemented" here means the code is done and pushed to the working branch — it does not require the PR to be merged on GitHub, since a session doing this work may not control merging.
- A master roadmap that spans several PRs gets its own dated folder here too (e.g. `2026-09-27-remediation-roadmap/`), and moves to `shipped/` once every PR it links to has shipped.

## Shipped plans

Everything in `shipped/` is implemented and pushed. In date order:

**Remediation roadmap (2026-09-27)** — [`2026-09-27-remediation-roadmap/PLAN.md`](shipped/2026-09-27-remediation-roadmap/PLAN.md) is the roadmap and says which PR folder implements which section:

- [`credential-and-session-leak-hardening`](shipped/2026-09-27-credential-and-session-leak-hardening/PLAN.md) — secret redaction, POST logins, bounded auth timeouts
- [`restricted-mode-tool-registry`](shipped/2026-09-27-restricted-mode-tool-registry/PLAN.md) — one tool registry and deny-by-default restricted mode
- [`connection-defaults-and-bounds`](shipped/2026-09-27-connection-defaults-and-bounds/PLAN.md) — port default, CA-bundle support, `get_file_content` size cap, search deadline
- [`packaging-and-test-isolation`](shipped/2026-09-27-packaging-and-test-isolation/PLAN.md) — no credentials in the Docker image, hermetic test session

**Independent rereview (2026-09-28)** — [`rereview-followups`](shipped/2026-09-28-rereview-followups/PLAN.md) has the verdict table; its fixes shipped as:

- [`rereview-security-fixes`](shipped/2026-09-28-rereview-security-fixes/PLAN.md)
- [`rereview-reliability-fixes`](shipped/2026-09-28-rereview-reliability-fixes/PLAN.md)
- [`windows-test-isolation`](shipped/2026-09-28-windows-test-isolation/PLAN.md)

**MCP 2.x and Docker (2026-09-29)**

- [`mcp-2x-migration`](shipped/2026-09-29-mcp-2x-migration/PLAN.md) — the mcp 2.x API, and tool failures reported as errors
- [`docker-smoke-test`](shipped/2026-09-29-docker-smoke-test/PLAN.md) — the Docker image tested in CI; major `mcp` bumps held back
- [`test-config-hermetic-env`](shipped/2026-09-29-test-config-hermetic-env/PLAN.md) — a local `.env` can no longer leak into the config tests

**Follow-up review (2026-09-30)**

- [`followup-review-fixes`](shipped/2026-09-30-followup-review-fixes/PLAN.md) — validation errors no longer echo credentials, honest health summary, request-level time budgets

**Manual authentication (2026-10-06 to 2026-10-11)** — the NAS password and one-time code never pass through an AI client. [`2026-10-06-manual-authentication`](shipped/2026-10-06-manual-authentication/PLAN.md) is the design; [`2026-10-10-manual-auth-roadmap`](shipped/2026-10-10-manual-auth-roadmap/PLAN.md) splits it into six PRs, and tracks the fixes that followed an independent review of them ([`IMPLEMENTATION_REVIEW_2026-10-11.md`](shipped/2026-10-10-manual-auth-roadmap/IMPLEMENTATION_REVIEW_2026-10-11.md)):

- [`manual-auth-core`](shipped/2026-10-10-manual-auth-core/PLAN.md) — config modes, no stored secrets, typed session loss
- [`broker-sessions-and-policy`](shipped/2026-10-10-broker-sessions-and-policy/PLAN.md) — in-memory sessions, policy, folder allowlist, the HTTP front
- [`private-login`](shipped/2026-10-10-private-login/PLAN.md) — owner passkey, login page, short-lived worker
- [`credential-free-adapter`](shipped/2026-10-10-credential-free-adapter/PLAN.md) — the stdio adapter that forwards to the broker
- [`tool-catalog-and-titles`](shipped/2026-10-11-tool-catalog-and-titles/PLAN.md) — tool catalog and plain-language titles
- [`packaging-deploy-docs`](shipped/2026-10-11-packaging-deploy-docs/PLAN.md) — Docker targets, deploy template, config examples, documentation, CI
- the review fixes: [`fix-nas-transport`](shipped/2026-10-11-fix-nas-transport/PLAN.md) (redirects, verified certificate, final TLS setting), [`fix-private-login`](shipped/2026-10-11-fix-private-login/PLAN.md) (enrollment, cancelled logins), [`fix-folder-policy`](shipped/2026-10-11-fix-folder-policy/PLAN.md) (denied folders, listings, NFS discovery) and [`fix-grants-and-service-errors`](shipped/2026-10-11-fix-grants-and-service-errors/PLAN.md) (grant expiry, download creation, lost sessions, replay)

What is not done is the user's: choosing and proving the broker's host, the cutover and the live acceptance checks, listed in the guide's "Moving from the old setup". The plans are shipped because their code is, not because those are.
