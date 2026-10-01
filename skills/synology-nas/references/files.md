# File Station: files & directories

## Tools

| Tool | Purpose | Required |
|------|---------|----------|
| `list_shares` | List top-level shares (Photos, video, homes, …) | — |
| `list_directory` | List contents of a path | `path` |
| `get_file_info` | Detailed metadata for one file/dir | `path` |
| `get_file_content` | Read the bytes of a file | `path` |
| `search_files` | Pattern search under a path (wildcards: `*.pdf`) | `path`, `pattern` |
| `create_file` | Create a new file with content | `path` |
| `create_directory` | Make a new folder | `folder_path`, `name` |
| `rename_file` | Rename in-place | `path`, `new_name` |
| `move_file` | Move (or rename across paths) | `source_path`, `destination_path` |
| `delete` | Delete file or directory (auto-detects type) | `path` |

All accept the optional `nas_name` / `base_url` target.

**Restricted mode** (the default) offers only `list_shares`, `list_directory`, `get_file_info`, `get_file_content` and `search_files`. `create_file`, `create_directory`, `rename_file`, `move_file` and `delete` are hidden until the user sets `RESTRICTED_MODE=false`.

## Path conventions

- Every path **must start with `/`**. Relative paths are rejected.
- The root `/` is empty for file operations — it's the share index. Use `list_shares` to enumerate.
- Real data lives under `/volume1/...` (or `/volume2/...`, etc., on multi-volume systems). The shares like `Photos`, `homes`, `video` are accessible at `/Photos`, `/homes`, `/video` — they're symlinks/mounts for the underlying `/volume1/Photos` etc.
- When in doubt, `list_directory` the parent before constructing a child path. NAS layouts vary by user.

## Workflow patterns

### Search before you operate

If the user says "delete all the .DS_Store files in Photos", don't try to walk the tree manually. Use `search_files`:

```
search_files(path="/Photos", pattern=".DS_Store")
```

Then summarize what you found and confirm before bulk-deleting.

### Create a directory tree

`create_directory` accepts `force_parent: true` to create intermediate parents. Use it when the user gives you a deep path that doesn't exist yet — saves multiple round-trips:

```
create_directory(folder_path="/volume1/projects", name="2026/q2/budgets", force_parent=true)
```

### Reading file content

`get_file_content` returns the file as text. It refuses files larger than the server's `MAX_FILE_CONTENT_SIZE` (1,000,000 bytes unless the user changed it) with an error, because file contents are sent on to the AI provider — don't retry, tell the user. Use `get_file_info` first if the user only wants metadata (size, mtime). Don't dump file content to chat unless the user asked to see it.

### Move vs. rename

- `rename_file` keeps the file in the same directory. Use for "rename foo.txt to bar.txt".
- `move_file` changes the path. It also handles renaming across directories — so for "move foo.txt to /archive/foo-old.txt", use `move_file`, not `rename_file` followed by `move_file`.

## Gotchas

- **`delete` is recursive on directories.** It auto-detects file vs. directory. Confirm with the user before deleting anything that looks like a folder, especially if it's not empty.
- **Missing paths are errors.** `get_file_info` and `get_file_content` on a path that doesn't exist fail with "File not found" rather than returning an empty file.
- **Some paths are refused outright**: a volume root such as `/volume1` itself, `/homes` itself, and anything under `/var`, `/etc`, `/usr`, `/bin` or `/sbin`. Shares and folders underneath a volume are fine.
- **Time limits.** `search_files` and `delete` stop waiting after 2 minutes, `move_file` after 1 minute, and the call returns an error saying it "timed out". A timeout doesn't prove nothing happened: DSM may still finish a `delete` or `move_file`, and if the error says the NAS "may have started it anyway", the request that starts the operation was given up on without an answer. Check with `get_file_info` / `list_directory` before retrying.
- **Overwrite is opt-in.** `create_file` and `move_file` default `overwrite: false`. If the user says "replace the existing one", set `overwrite: true` explicitly — don't silently fail and retry.
- **Trash isn't automatic.** `delete` is permanent unless DSM Recycle Bin is enabled on the share. Mention this if the user is deleting something irreplaceable.
- **Case sensitivity** depends on the underlying filesystem (Btrfs/ext4 are case-sensitive, eCryptfs may differ). Don't assume.
- **Path encoding**: paths with spaces, accents, or non-ASCII characters work fine; just pass them as-is in the JSON. Don't URL-encode.

## Examples

### "What's in my Photos folder?"

```
list_directory(path="/Photos")
```

### "Find all PDFs in /volume1/documents"

```
search_files(path="/volume1/documents", pattern="*.pdf")
```

### "Save these notes to my homes folder"

```
create_file(
  path="/homes/<user>/notes/2026-04-29.md",
  content="...",
  overwrite=false
)
```

If the parent dir doesn't exist, you'll get an error — fall back to `create_directory(force_parent=true)` first, then retry.

### "Move last month's photos into the archive"

```
search_files(path="/Photos", pattern="*.jpg") # to find them
# then per-file:
move_file(source_path="/Photos/2026-03-01.jpg", destination_path="/Photos/archive/2026-03/2026-03-01.jpg", overwrite=false)
```

For batch moves, surface a summary first and confirm before iterating.
