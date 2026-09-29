# Plans

This folder tracks work-in-progress remediation/feature plans for this repository, one folder per PR.

## Convention

- Each PR gets a folder here named `<YYYY-MM-DD>-<slug>/`, where the date is when the plan was written and the slug is a short kebab-case name for the PR.
- The folder holds that PR's scoped plan document (e.g. `PLAN.md`) — what it changes, why, the acceptance criteria, and how it was verified.
- Once the PR's changes are implemented (code complete, tested, committed, and pushed), its folder is moved to `plans/shipped/<YYYY-MM-DD>-<slug>/` via `git mv`. "Implemented" here means the code is done and pushed to the working branch — it does not require the PR to be merged on GitHub, since a session doing this work may not control merging.
- A master roadmap that spans several PRs gets its own dated folder here too (e.g. `2026-09-27-remediation-roadmap/`), and moves to `shipped/` once every PR it links to has shipped.

## Current status

See [`shipped/2026-09-27-remediation-roadmap/PLAN.md`](shipped/2026-09-27-remediation-roadmap/PLAN.md) for the roadmap and which PR folder implements which section.

A later independent rereview produced a second, smaller set of fixes: see [`shipped/2026-09-28-rereview-followups/PLAN.md`](shipped/2026-09-28-rereview-followups/PLAN.md).
