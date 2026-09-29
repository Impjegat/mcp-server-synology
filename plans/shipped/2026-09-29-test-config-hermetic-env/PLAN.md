# PR: Keep a local `.env` from leaking into the config tests

Status: Shipped — PR #14
Initiated: 2026-09-29
GitHub PR: [Impjegat/mcp-server-synology#14](https://github.com/Impjegat/mcp-server-synology/pull/14)
Origin: a Copilot review comment on `tests/test_config.py` about `test_validate_config_no_credentials`

## Why

`config` loads a legacy `./.env`, in two places: at import (its module-level `config = SynologyConfig()`) and whenever a `SynologyConfig()` is constructed. The config tests re-import it constantly (`reload_config()`), so every test in `tests/test_config.py` reads whatever `.env` sits in the working directory. That is the repo root when pytest is run from it, which is exactly where a developer keeps their real credentials.

`test_validate_config_no_credentials` tried to prevent this by patching `config.os.path.exists` — but only *after* the import that had already read the file (`patch("config.SETTINGS_FILE", ...)` imports `config` first). The reviewer was right about the ordering, and the problem is wider than that one test: run from a directory containing a `.env`, **five** tests fail — `test_validate_config_no_credentials`, `test_default_values`, and three `TestIterConfiguredSecrets` tests. They pass on CI and in a clean checkout, and fail only on a machine with a real `.env`.

## Changes

- `tests/test_config.py`: an autouse fixture, `_run_from_an_empty_directory`, runs every test in the module from `tmp_path`. With no `.env` in the working directory there is nothing to load, at import time or at construction, whatever order things are imported in. This is preferred to the reviewer's alternatives (patching `dotenv.load_dotenv` or `os.path.exists` before importing) because it needs no stdlib patching and covers every test in the module, including ones added later.
- `test_validate_config_no_credentials`: drops the `patch("config.os.path.exists", ...)` that never worked, and its comment.

Not applied to other test files: `tests/conftest.py` and the `real_nas` tests deliberately read the developer's `.env` for live-NAS credentials.

## Verification

- Run from a directory that contains a `.env` (fake `SYNOLOGY_*`, `AUTO_LOGIN=false`, `VERIFY_SSL=false`): 54 passed with the fix; 5 failed without it (checked by stashing the change).
- Full suite from the repo root: 319 passed, 41 skipped; `black` and `ruff` clean at the CI-pinned versions.
- No regression test for the fixture itself: it would need a nested pytest run from a directory with a `.env`, which is slower and more fragile than the fixture it would guard, and any new test in the module inherits the fixture automatically.
