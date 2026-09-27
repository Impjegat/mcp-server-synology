# Plans

This folder tracks work-in-progress remediation/feature plans for this repository, one folder per PR.

## Convention

- Each PR gets a folder here named `<YYYY-MM-DD>-<slug>/`, where the date is when the plan was written and the slug is a short kebab-case name for the PR.
- The folder holds that PR's scoped plan document (e.g. `PLAN.md`) — what it changes, why, the acceptance criteria, and how it was verified.
- Once the PR's changes are implemented (code complete, tested, committed, and pushed), its folder is moved to `plans/shipped/<YYYY-MM-DD>-<slug>/` via `git mv`. "Implemented" here means the code is done and pushed to the working branch — it does not require the PR to be merged on GitHub, since a session doing this work may not control merging.
- The top-level `REMEDIATION_PLAN.md` (when present) is the standing master roadmap across multiple PRs; it links to each PR's folder here rather than living inside one itself.

## Current status

See `../REMEDIATION_PLAN.md` for the roadmap and which PR folder implements which section.
