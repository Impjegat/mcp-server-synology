# Synology MCP Server Tests

Two kinds of tests live here:

- **Offline tests** need no NAS. They mock the network, and a guard in `conftest.py` refuses any real outbound connection from them, so they cannot reach a NAS by accident. This is what CI runs, and almost everything is in this group.
- **`real_nas` tests** talk to a real Synology NAS with real credentials. They are skipped when no credentials are configured.

## Quick start (offline)

```bash
pip install -r requirements.txt     # Python 3.10 or later; also installs pytest

python -m pytest -m "not real_nas"
```

The suite does not read your `~/.config/synology-mcp/settings.json` or a local `.env`: `conftest.py` points `XDG_CONFIG_HOME` at a fresh temporary directory, and the config tests run from an empty one.

## Running against a real NAS

1. Copy the template and fill in your NAS details:
   ```bash
   cp env.example .env
   ```
   ```env
   SYNOLOGY_URL=https://your-nas-ip:5001
   SYNOLOGY_USERNAME=your-username
   SYNOLOGY_PASSWORD=your-password
   ```
2. Run the `real_nas` tests:
   ```bash
   python -m pytest -m real_nas
   ```

Use a throwaway or dedicated account if you can. Tests marked `destructive` change state on the NAS (they create and remove Download Station tasks and change NFS settings), and tests marked `slow` run searches that can take a while:

```bash
python -m pytest -m "real_nas and not destructive"   # read-only against the NAS
python -m pytest -m "real_nas and not slow"          # skip the searches
```

## Test files

| File | What it covers |
|---|---|
| `test_tool_calls.py` | How a tool call is reported: success versus `isError`, protocol errors, restricted-mode and invalid-argument refusals before any NAS request, and that no message, log line or result echoes a submitted credential |
| `test_restricted_mode.py` | The tool registry, restricted-mode classification (and that discovery and dispatch agree), and the restricted `synology_login` check |
| `test_stdio_protocol.py` | End to end: starts the real server over stdio and speaks MCP to it, as Claude Desktop or Cursor would |
| `test_redact.py` | Secret redaction, used on tool responses and the log filter |
| `test_config.py` | `.env` and `settings.json` loading, HTTPS-only validation, `VERIFY_SSL`, restricted-mode parsing, file permissions |
| `test_auth.py` | Login, logout, 2FA and API-version fallback (partly `real_nas`) |
| `test_logout.py` | Logout evicts every cached service instance |
| `test_file_station.py` | File Station: paths and critical-path denylist, size cap, time limits and deadlines (offline), plus `real_nas` operations |
| `test_download_station.py` | Download Station (mostly `real_nas`; creating tasks is `destructive`) |
| `test_health.py` | Health monitoring, including how the summary reports partial and failed checks (partly `real_nas`) |
| `test_container_manager.py` | Container Manager module |
| `test_nfs.py` | NFS and shared-folder management (partly `real_nas`; changing settings is `destructive`) |
| `test_network_guard.py` | The socket guard in `conftest.py` that keeps offline tests off the network |

`conftest.py` holds the shared fixtures and the guard; `socket_guard.py` is the guard's address classification, kept separate so the guard itself can be tested.

## The stdio end-to-end test

`test_stdio_protocol.py` starts the server as `python main.py` with no NAS configured and restricted mode on, in a temporary config directory. Setting `MCP_STDIO_SERVER_COMMAND` (a JSON array of strings) replaces that command, which is how CI runs the same test against the Docker image through the `docker compose run --rm` command the README gives MCP clients:

```bash
docker compose build
MCP_STDIO_SERVER_COMMAND='["docker","compose","run","--rm","-e","AUTO_LOGIN","-e","RESTRICTED_MODE","-e","LOG_LEVEL","synology-mcp"]' \
  python -m pytest tests/test_stdio_protocol.py
```

One test in it needs DEBUG logging and is skipped when the command is overridden.

## Markers

| Marker | Meaning |
|---|---|
| `real_nas` | Needs a real NAS and credentials (excluded by `-m "not real_nas"`) |
| `destructive` | Modifies state on the NAS |
| `slow` | May take several seconds, for example searches |

## Handy commands

```bash
python -m pytest -m "not real_nas" -q        # the offline suite, as CI runs it
python -m pytest tests/test_tool_calls.py    # one module
python -m pytest -k "restricted"             # by name
python -m pytest -s -v                       # live output
```

CI also runs `ruff check src/ main.py tests/` and `black --check src main.py tests`.
