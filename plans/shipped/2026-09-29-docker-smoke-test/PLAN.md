# PR: Test the Docker image in CI, and hold back mcp major bumps

Status: Shipped — PR #15
Initiated: 2026-09-29
GitHub PR: [Impjegat/mcp-server-synology#15](https://github.com/Impjegat/mcp-server-synology/pull/15)
Follows: [the mcp 2.x migration](../2026-09-29-mcp-2x-migration/PLAN.md) (#13, closes #12)

## Why

Three loose ends were left after the mcp 2.x migration:

1. **The Docker image was never tested the way clients use it.** The migrated server was verified with `python main.py`, but Claude Desktop and Cursor launch it as `docker-compose run --rm synology-mcp` (README, Client Setup). That path has its own moving parts — the image build, the bind-mounted settings directory, environment passing, no TTY on a piped stdin — and the image is also exactly where the mcp 2.x breakage would have landed for a user (`pip install -r requirements.txt` at build time). Nothing in CI built it.
2. **Nothing kept the next mcp major release from being merged automatically.** `requirements.txt` bounds mcp at `<3`, but that only stops pip; a Dependabot PR proposing to widen it would just be another PR.
3. **A Copilot review comment on `tests/test_config.py`.** That one needs no change here: the comment is on upstream `atom2ueki/mcp-server-synology#13` (line 157 is in upstream commit `f5abdc5`), not on this fork, and this fork's #14 already records the finding and the fix.

Dependabot has never opened a PR on this fork (its last activity in the history is upstream's, in July), although mcp 1.29 through 2.2 were released since. Version updates aren't running here, so the config change below only takes effect once Dependabot is enabled for the fork in the repository settings.

## Changes

### `tests/test_stdio_protocol.py`
- The server command is taken from a new env var, `MCP_STDIO_SERVER_COMMAND` (a JSON array of strings) when it is set, and is `python main.py` otherwise, so local runs and the Ubuntu and Windows jobs are unchanged. The same 15 tests then hold the container to exactly the bar the local server meets: handshake at protocol versions 2024-11-05 and 2025-06-18, wire field names, each `isError` category, `-32602` protocol errors, and stdout carrying only JSON-RPC.
- The test creates the (empty) `<tmp>/xdg/synology-mcp/` directory that the compose file bind-mounts read-only, so "no settings.json" means the same thing in both modes.

### `.github/workflows/tests.yml`: new `docker` job
Builds the image (`docker compose build`) and runs `tests/test_stdio_protocol.py` with `MCP_STDIO_SERVER_COMMAND` set to the README's client command plus three `-e` flags (`AUTO_LOGIN`, `RESTRICTED_MODE`, `LOG_LEVEL`) that hand the test's server settings through to the container — without them, auto-login defaults on and the server, with no credentials, refuses to start. Linux only (Windows runners can't run the Linux image); no secrets; read-only token; 15-minute timeout. It uses `docker compose`, the plugin form, which is present on current runners; it is the same Compose v2 that Docker Desktop's `docker-compose` alias runs.

### `.github/dependabot.yml`
An `ignore` rule for `mcp`'s `version-update:semver-major` under the pip ecosystem, with a comment pointing at #12. Minor and patch releases still come through and CI checks them.

## Verification

Run in this container, which has a Docker daemon but a restricted network:

- **The container test:** with the command CI uses, all 15 stdio tests pass against the container (`docker compose run --rm`).
- **Negative controls:** a nonexistent compose service fails; the same command without the `-e` flags fails (all 15, "server exited before answering 'initialize'"), which shows the env passing is needed and the test really exercises the container.
- **Regression proof:** an image built from the pre-migration server code (`b866dbb`) with mcp 2.x installed fails all 15 (2 failed, 13 errors); started by hand it logs `Server error: 'Server' object has no attribute 'list_tools'`, the failure #13 fixed.
- **Interop:** the container, driven through an mcp 2.2 client and an mcp 1.28.1 client, gives identical results: 39 tools listed with `delete` hidden in restricted mode, success is not an error, invalid arguments and a restricted tool are `isError: true`, an unknown tool is a protocol error. `docker compose run` prints its `Container … Creating/Created` progress on stderr, so stdout stays clean JSON-RPC.
- `pytest` (319 passed, 41 skipped), `black` and `ruff` at the CI-pinned versions; both YAML files parse and the workflow's command comes out as the intended JSON array.

**Not exercised here, on purpose:** the Dockerfile's `apt-get install gcc` step. This sandbox blocks Debian's mirrors (403), so the image used for the checks above was built from a copy of the Dockerfile without that step, in a scratch directory that isn't committed. Everything else in the Dockerfile, and the `docker compose` launch path, was tested as shipped. The new CI job builds the real Dockerfile on every PR, so that step is checked there.

**Not verifiable from here:** Claude Desktop or Cursor against a real NAS. After merging, on the machine that runs the client: `git pull`, `docker-compose build`, restart the client, then ask it to run `synology_status` and a read-only tool such as `list_shares`.
