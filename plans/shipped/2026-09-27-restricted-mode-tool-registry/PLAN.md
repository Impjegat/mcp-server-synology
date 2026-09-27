# PR 2: Restricted-mode tool registry

Status: In progress
Initiated: 2026-09-27
Implements: `REMEDIATION_PLAN.md` §3 (Enforce a restricted operating mode)

## Why

The remediation plan's objective is "an initial installation limited to file browsing and NAS monitoring." Today, every tool — including file deletion, user/group management, and container control — is reachable through two separate dispatch paths in `mcp_server.py`: the live `handle_call_tool` if/elif chain, and a second, already-drifted `call_tool_direct` dict (dead code left over from the removed Xiaozhi bridge, confirmed to have no callers and to already be missing two tool names). There is no deny-by-default gate at all. This PR replaces both paths with one tool registry, adds a restricted operating mode that's on by default, and closes the one credential-adjacent gap restricted mode doesn't otherwise cover: `synology_login` accepting an arbitrary `base_url` from the model.

## Changes

1. **Delete `call_tool_direct` and `get_tools_list`** (`src/mcp_server.py`) — confirmed dead code (only the removed Xiaozhi bridge called them).
2. **Single tool registry**: `_build_tool_registry()` returns one `Dict[str, Callable]` covering every tool name (including all 30 `synology_container_*` suffixes). Both `handle_list_tools` and `handle_call_tool` read from it — one place a tool name maps to behavior, not two.
3. **Deny-by-default restricted mode**: new `config.restricted_mode` (default `True`). A tool not explicitly classified `_READ_ONLY_TOOLS` (or a session tool) is unavailable — hidden from `list_tools` and rejected in `call_tool` before any handler runs, so a rejected call never reaches the network. Classification covers every tool, including container tools (list/get/logs/resource/project_list/project_get/image_list/image_get/registry_list/registry_search/registry_tags/network_list/network_get are read-only monitoring; everything else in Container Manager is modifying). One carve-out, added after review: `synology_list_users`/`synology_get_user`/`synology_list_groups`/`synology_list_group_members`/`synology_get_user_permissions` perform no writes (they keep `readOnlyHint=True`), but full account/group/permission enumeration is a different trust tier than file browsing or NAS monitoring, so `_ACCOUNT_ENUMERATION_TOOLS` excludes them from restricted mode's default set too — `_is_tool_allowed` checks this before falling back to the read-only set.
4. **Restricted `synology_login`**: when restricted mode is on and at least one NAS is already configured in `settings.json`, `base_url` must match one of them — the model can't point admin credentials at an arbitrary host. No configured NAS yet (fresh install) leaves it unrestricted, since there's nothing to check against.
5. **Path-check consolidation** (`src/filestation/synology_filestation.py`): `_check_critical_path` and `delete()`'s separate inline denylist are unified into one prefix-matching helper (the stricter of the two previous behaviors), applied consistently across every path-taking method (list_directory, get_file_info, search_files, get_file_content, rename_file, move_file, create_file, create_directory, delete) instead of just three of them.
6. **MCP tool annotations**: `readOnlyHint`/`destructiveHint` added to every `types.Tool` definition per its classification (metadata only, not itself an access control — enforcement is the registry above).
7. **Documentation**: README security section covers restricted mode, the dedicated-admin-account recommendation (2FA, deny unneeded application privileges), and how to disable restricted mode deliberately.

## Explicitly out of scope (later PRs)

- `get_file_content` size cap and `search_files` timeout — PR 3 (§4 remainder).
- Port default, CA-bundle support — PR 3.
- Docker/packaging, test-isolation ordering — PR 4.
- An optional share/path allowlist beyond the critical-path denylist was considered but is deferred — the denylist consolidation above is the correctness fix the review-worthy gap actually needs; an allowlist is a separate feature, not a bug fix, and would benefit from its own design pass rather than being folded in here.

## Verification

- `pytest -m "not real_nas"` — new tests for: tool classification correctness (spot-checked read-only vs. modifying names), `handle_call_tool` rejecting a modifying tool in restricted mode before any network call, `handle_list_tools` excluding modifying tools when restricted, the restricted-login base_url check, and the path-check consolidation (prefix-nested paths now blocked, and now checked from methods that had no check before).
- Confirm `call_tool_direct`/`get_tools_list` no longer exist anywhere in the module.
- `ruff check` / `black --check` clean.
