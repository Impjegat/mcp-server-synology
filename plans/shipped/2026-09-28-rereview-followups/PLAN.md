# Independent rereview follow-ups

Status: Shipped — all three PRs merged into `main` ([#9](https://github.com/Impjegat/mcp-server-synology/pull/9), [#10](https://github.com/Impjegat/mcp-server-synology/pull/10), [#11](https://github.com/Impjegat/mcp-server-synology/pull/11))
Initiated: 2026-09-28
Source: [`REVIEW_REPORT.md`](REVIEW_REPORT.md) — an independent rereview of `main` at `0ed41f6` (the [remediation roadmap](../2026-09-27-remediation-roadmap/PLAN.md) merged via #7)

## Why

The independent rereview found seven remaining issues after the four-PR remediation roadmap shipped. Each was checked against the current code on `main` (`0766452`) before any fix was planned — see the verdict table below. All seven are real; several are narrower in practice than the report's P1/P2 labels suggest.

## Verdict

| # | Finding (report severity) | Verdict | Severity | Why |
|---|---|---|---|---|
| 3 | `RESTRICTED_MODE` parsing fails open (P1) | Fix — first | High | `src/config.py:114` treats only the exact string `true` as on. `1`, `yes`, and `true ` (trailing space) all disable restricted mode; in `settings.json`, `null` does too. Restricted mode is the only barrier against writes from the admin account. |
| 1 | Log redaction misses exceptions/tracebacks (P1) | Fix | Medium | `RedactingFilter` only redacts string messages/args. The three `exc_info=True` call sites log at DEBUG only; at that level the chained traceback can carry `_sid=`. Nothing currently passes an exception object through `%s`, so that part is latent rather than live. |
| 2 | Windows settings write continues after ACL failure (P1) | Fix | Low–Medium | Affects only the device-token auto-save path. Needs Windows plus an `icacls` failure or a world-readable config dir, neither the default. Fixed temp filename can also collide across concurrent writers. |
| 4 | Docker quick start has no credentials (P2) | Fix | Medium | Regression from PR #6: `.env` stopped being copied into the image, but nothing hands it to the container at runtime, and the README still tells users to create it. |
| 5 | JSON download bypasses the size cap (P2) | Fix | Low–Medium | `response.json()` reads the whole body before the byte limit is checked. Also found in the same code: a real `.json` file is misclassified as a DSM error response and fails to download at all. |
| 6 | Search timeout counts sleep only (P2) | Fix | Low | Worst case ~1 hour instead of 2 minutes. Same bug also found (not in the report) in `delete()` and `move_file()`. |
| 7 | Tests break on Windows (P2) | Fix | Medium (Windows dev) | Socket-blocking fixture blocks asyncio's own loopback socket pair on Windows; 23 `clear=True` env-clears strip `USERPROFILE`/`XDG_CONFIG_HOME`; one permission test assumes POSIX. |

Not included (scope decisions, not bugs):
- The share/path allowlist is still deferred — unchanged from the roadmap's own decision.
- Identity/permission-inspection tools still require unrestricted mode — your earlier explicit choice.

## PRs

1. [`plans/shipped/2026-09-28-rereview-security-fixes/`](../2026-09-28-rereview-security-fixes/PLAN.md) — findings 3, 1, 2. PR: [#9](https://github.com/Impjegat/mcp-server-synology/pull/9).
2. [`plans/shipped/2026-09-28-rereview-reliability-fixes/`](../2026-09-28-rereview-reliability-fixes/PLAN.md) — findings 4, 5, 6. PR: [#10](https://github.com/Impjegat/mcp-server-synology/pull/10).
3. [`plans/shipped/2026-09-28-windows-test-isolation/`](../2026-09-28-windows-test-isolation/PLAN.md) — finding 7. PR: [#11](https://github.com/Impjegat/mcp-server-synology/pull/11).

Each is its own PR against `main`, driven to green individually, same process as the original roadmap.
