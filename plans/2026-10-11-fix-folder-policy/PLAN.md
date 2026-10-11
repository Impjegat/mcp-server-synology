# Fix: the folder policy (review findings R02, R06 and R07)

**Written:** 11 October 2026
**Roadmap:** [`../2026-10-10-manual-auth-roadmap/PLAN.md`](../2026-10-10-manual-auth-roadmap/PLAN.md), Remediation, fix PR 3
**Review:** [`IMPLEMENTATION_REVIEW_2026-10-11.md`](../2026-10-10-manual-auth-roadmap/IMPLEMENTATION_REVIEW_2026-10-11.md)
**Builds on:** the broker's folder policy (#20) and the two fix PRs before this one (#27, #28).

## What the review found, and what was checked

R02 is High and R06 and R07 are Medium. All three were reproduced against `main` (`7e6df8d`) before any change, with tests that fail on that code.

| ID | Finding | Reproduced as |
|---|---|---|
| R02 | An allowed root is resolved to where DSM says it really is (`/volume1/docs`), but `deny_paths` stay share paths (`/docs/private`). A target whose real location is `/volume1/docs/private/x` is not recognised as inside the denied folder, so a link in an allowed folder that leads into a denied one passes | Allowed `/docs`, denied `/docs/private`, a link `/docs/shortcut` resolving to `/volume1/docs/private`: the download request for content behind the link **was made**, and a search returned `secret.txt` from the denied folder |
| R06 | `list_directory` checks the folder asked for and then returns every child, whatever it is or points at | A listing returned seven children it should not have: `.env`, `secrets`, `id.pem`, a link leading out of the root and three with no real location, with their metadata |
| R07 | `synology_nfs_list_shares` is in a broker client's default tools and returns every share with its NFS client and permission rules, unfiltered | A client scoped to `/docs` was handed all six shares and every NFS rule |

## What changes

| Piece | Files | What it does |
|---|---|---|
| Denials in the physical namespace | `src/broker/file_policy.py` | Each denied folder is placed where DSM says it really is, and a target inside that place is refused. `FolderGuard.verify_real` takes the lookup |
| File Station | `src/filestation/synology_filestation.py` | Passes its `getinfo` lookup to every location check; `list_directory` asks for each child's real path and filters children like search hits |
| NFS discovery | `src/mcp_server.py`, `src/broker/file_policy.py` | `_scope_nfs_shares` and the stricter `share_in_scope`: shares inside the client's folders in full, a share that only holds one by name only, everything else absent, `total` corrected |
| Documents | `docs/MANUAL_AUTHENTICATION.md`, `skills/synology-nas/references/`, `CHANGELOG.md` | Say how links, listings and NFS discovery are judged |

## Design choices worth knowing

- **A denied folder is judged where the target is judged.** The target's real location comes from DSM, so the denied folder's does too. That one idea covers a link into it, a second share onto the same place, and a denied folder that is itself a link, with no list of cases.
- **A denied folder that does not exist is placed by its nearest existing parent** (the share's real path plus the rest of the name). Nothing is in it today, but a link made to where it would be must not become a way in once the folder exists. One whose whole path is missing, not even its share, protects nothing.
- **What cannot be located fails closed.** A denied folder that exists but whose location DSM will not name refuses every request until it does, because nothing can then be shown to be outside it. With denials and no way to look them up, `verify_real` refuses. A denied folder deeper than sixteen levels with no existing parent is refused rather than assumed safe. A failed lookup raises and is never remembered, so one transient NAS error blocks nothing for long.
- **Answers are remembered like roots, but only the certain ones.** DSM's answer for an existing denied folder is kept for the same five minutes as an allowed root; a derived location (the folder was missing) is not, because the folder may be created, or replaced by a link, a moment later. So a folder moved or replaced by a link takes up to five minutes to be seen, which the guide now says.
- **A listing or a search works the denied folders out once.** A missing denied folder is placed by walking up to its nearest existing parent, one request a level, and that is not remembered, so doing it for every child (the first version did) made a listing cost one probe of the denied folder per entry: 5 children cost 33 requests to DSM and 60 cost 308. The review caught it. `list_directory` and `search_files` now call `_denied_locations()` once, after the lexical checks and before the first request about the entry, and pass the answer to `_verify_location` and to the per-entry `_entry_allowed`; `verify_real` takes it as `denied` (even empty, which means nothing is denied, not "ask again"). The alternative the review offered, caching the derived answer for a few minutes, would also have worked; it was not chosen because it keeps a stale answer for the very case (a folder about to appear, or become a link) where the answer is most likely to change, whereas working it out once per request is always current. Every other request still works it out afresh.
- **Listings are judged like search hits.** `_entry_allowed` already existed for search; listing reuses it, so one rule decides what a result may show. A child with no real location is omitted, never shown on trust, and the real path itself is not passed on. A listing without a policy (legacy mode) is unchanged and does not ask for the extra field.
- **NFS rules say who may mount the whole share**, so a share that merely holds one of the client's folders is named and nothing more. The existing `share_visible` (name only, wider) stays for the share list; `share_in_scope` (inside a root) decides who sees the details. A share name containing `/` is dropped rather than read as a path, so `x/../docs` cannot pose as the allowed `docs`.
- **An unexpected answer is refused, not forwarded.** An NFS answer that is not an object, or has no list of shares, raises `AUTHORIZATION_DENIED` instead of being passed on unfiltered. A failure from the NAS (`success: false`) carries no share data and is returned as it is.

## Acceptance criteria

- Direct access, and a link into a denied subtree, both fail; so does an equivalent path through another share. A denied folder that is missing is still protected by a link made to where it would be. Unknown resolution fails closed. Ordinary permitted files and folders remain reachable.
- Denied children, links out of the root and children whose location is not given do not appear in a listing and expose no metadata; permitted children keep theirs.
- A client scoped to one folder cannot discover unrelated shares or their NFS rules.

## Verification

`pytest -m "not real_nas"`, ruff and black over `src/`, the entry points, `scripts/`, `docker/` and `tests/`, and `python scripts/generate_tool_catalog.py --check`.

New or changed: `tests/test_file_policy.py` (the denied folders in the physical namespace, the reviewer's link at File Station level, and the listing filter), the new `tests/test_nfs_scope.py` (through the real broker runtime), and `tests/test_broker_runtime.py` and one listing test in `tests/test_file_policy.py` changed so that the children they list carry the real location DSM now has to give.

Result: 1578 passed, 29 skipped (the 13 that need a POSIX filesystem and the 16 image tests that need Docker, as before); 1517 passed before this PR. Ruff, Black and the catalog check are clean.

**Review follow-up.** The bot's review of this PR found that the first version re-placed a missing denied folder for every child (see the design choices above). Tests were written first and failed on that version (6 and 61 probes of the denied folder for 5 and 60 children; 33 and 308 requests in all), then passed once the answer was worked out once. The same review suggested logging how many children a listing left out, which is now a debug line holding a count and nothing else. Ten further faults were put into this change (a listing or a search working it out per entry, either check ignoring the answer it was handed, an empty answer read as "ask again", the answer never used, nothing worked out at all, a wrong count, names in the log, a log line when nothing was left out) and all ten were caught.

The new tests were run against the unfixed code first, and they fail for the findings themselves: a download request was made for content behind the link, a search returned the denied file, a listing returned every extra child, and a scoped client was handed all six shares. The tests that exercise the new `lookup` argument failed because it did not exist yet.

Twenty-eight faults were then put into the code one at a time to confirm the tests can fail: denied folders never compared, a case-sensitive comparison, a missing denied folder protecting nothing, an unlocatable one ignored, denials without a lookup ignored, a derived location remembered, a location never remembered or remembered forever, a folder too deep to resolve taken as safe, the parent search one level short, a failed lookup swallowed, the lookup not passed on either path, a listing not filtered or not asking for real paths (or asking without a policy), share discovery not scoped, a partial share shown in full or not named, `total` not corrected, an unknown answer passed on, a failure no longer passed on, a share name with a slash read as a path, and a denied or merely containing share counted as in scope. Twenty-three were caught the first time. Five were not, and none was an equivalent change in the code: one pattern no longer matched after Black reformatted the line, one of my mutations was itself equivalent to the original (so it proved nothing and was replaced by a real removal of the check), and three were gaps in my tests: the case-insensitive comparison was never what decided the test (the root check refused first), no test passed an NFS answer that is not an object, and no test had a denied-name share inside a root. The tests were tightened and all twenty-eight are now caught.

## Observed, not changed

- **Download Station judges a destination by its name only.** `_check_destination` and `_check_destination_exists` use the lexical check; they do not ask where the destination really is, so a destination that is a link into a denied folder, or out of the root, is not caught. `list_downloaded_files` also lists a destination's children unfiltered. None of the `ds_*` tools is in a broker client's default grant (they appear in the policy's own list of tools to leave off by default), and the review does not name them, so this PR leaves them as they are. It is worth a fix before anyone grants them.
- **A partial share is named, not described.** `synology_nfs_list_shares` shows a share that only holds the client's folder by name. That is deliberate (see above), and it does mean a share's existence is disclosed to a client whose folder is inside it.

## Not yet verified

- **A real DSM.** The tests use a fake DSM. How a real File Station reports `real_path` for a share root, for a link, and for a path the account cannot see has not been observed here; the code relies on the same `getinfo` answer the allowed roots already use.
- **The other four findings.** R09 to R12 (grant expiry and service errors) are fix PR 4.
