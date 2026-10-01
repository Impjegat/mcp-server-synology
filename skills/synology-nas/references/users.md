# User & group management

## Tools

| Tool | Purpose |
|------|---------|
| `synology_list_users` | List all DSM users |
| `synology_get_user` | Get one user's details |
| `synology_create_user` | Create a new user |
| `synology_set_user` | Update an existing user |
| `synology_delete_user` | Delete a user |
| `synology_list_groups` | List all groups |
| `synology_list_group_members` | Members of a specific group |
| `synology_add_user_to_group` | Add a user to a group |
| `synology_remove_user_from_group` | Remove a user from a group |
| `synology_get_user_permissions` | Get a user's share-level permissions |
| `synology_set_user_permissions` | Set a user's share-level permissions |

All accept `nas_name` / `base_url`.

**Restricted mode** (the default) hides **all** of these tools — the read-only listings too, because enumerating every account, its groups and its permissions is treated as a different trust level from browsing files. If the user wants any of this, tell them to set `RESTRICTED_MODE=false` (see [../SKILL.md](../SKILL.md)).

## When to use this domain

User management is **admin-level**. The MCP must be authenticated as a user with admin rights for these calls to succeed. If the user is connecting with a non-admin account (recommended for safety), most of these tools will fail with permission errors — surface that clearly rather than retrying.

The README warns against running the MCP as a primary admin account. If user-management actions are needed, the user should temporarily authenticate with an admin account, do the work, and switch back. Don't try to elevate from inside Claude.

## Read before write

- Before `synology_set_user`: call `synology_get_user` to see the current settings, so updates merge cleanly instead of overwriting fields unintentionally.
- Before `synology_add_user_to_group` / `synology_remove_user_from_group`: `synology_list_group_members` to confirm the current state.
- Before `synology_set_user_permissions`: `synology_get_user_permissions` to see what's already granted.

DSM's user model is additive (group membership grants permissions, plus per-user overrides). Reading first prevents accidental privilege escalation/demotion.

## Workflow patterns

### Creating a new user

`synology_create_user` requires at minimum a `name` and `password`. Optional fields:

- `email` — for password recovery and notifications.
- `description` — surface this when listing users.
- `cannot_chg_passwd` — boolean (default false): stop the user changing their own password.
- `passwd_never_expire` — boolean (default true).

There is no group option at creation: add the user to groups afterwards with `synology_add_user_to_group(username=..., groups=[...])`. Common groups: `users`, `administrators`, `http`. Putting someone in `administrators` is a meaningful trust decision — confirm before doing it. To disable an account later, use `synology_set_user(name=..., expired="now")` (`"normal"` re-enables it).

### Setting share permissions

`synology_set_user_permissions(name=..., permissions=[...])` sets per-share access for a user. Each entry in `permissions` looks like:

```json
{
  "name": "Photos",
  "is_writable": false,
  "is_deny": false
}
```

`name` is the shared folder, `is_writable` grants write access, and `is_deny` denies access entirely. Don't assume what happens to shares you leave out: read the result back with `synology_get_user_permissions(name=...)` to confirm the final state, and set `"is_deny": true` explicitly to revoke a share.

### Deleting users

`synology_delete_user` is permanent. The user's home directory may or may not be removed depending on DSM's "preserve home" setting. Ask the user whether they want home-folder cleanup as a separate step (using `delete` against `/homes/<user>`).

## Gotchas

- **Built-in users**: `admin`, `guest`, and any DSM-built-in accounts behave specially. Don't try to delete `admin` (DSM may refuse). Don't change `guest`'s group memberships unless the user knows what they're doing.
- **Password requirements**: DSM enforces minimum length and complexity. If `synology_create_user` fails with a password error, surface DSM's specific requirements rather than retrying with a slightly different password.
- **Group changes don't always take effect immediately for active sessions** — a user logged in when added to a group may need to log out and back in to see new permissions on shares.
- **Deleting a user doesn't revoke active sessions automatically.** If you're removing access urgently, also tell the user to invalidate sessions in DSM Control Panel → Security → Account → Online Users.
- **Quota** is a separate feature managed via shared-folder quota or volume quota — not directly exposed in user-management tools here.

## Examples

### "Create a user 'photographer' with read-only access to Photos"

```
synology_create_user(
  name="photographer",
  password="<strong-pass>",
  description="Read-only photo access",
)
synology_add_user_to_group(username="photographer", groups=["users"])
synology_set_user_permissions(
  name="photographer",
  permissions=[{"name": "Photos", "is_writable": false, "is_deny": false}]
)
```

### "Who's in the administrators group?"

```
synology_list_group_members(group="administrators")
```

### "Remove user 'temp-contractor'"

```
synology_get_user(name="temp-contractor")           # confirm it's the right one
synology_delete_user(name="temp-contractor")        # permanent
# optionally:
delete(path="/homes/temp-contractor")                # cleanup home dir
```

Confirm both steps with the user before running.
