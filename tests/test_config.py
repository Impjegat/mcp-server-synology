"""Configuration module tests."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Environment variables a test must not lose when it clears os.environ:
# reloading `config` re-runs its module-level code, which resolves the home
# directory via Path.home() — and on Windows that reads USERPROFILE (or
# HOMEDRIVE + HOMEPATH), raising RuntimeError once they're gone (POSIX falls
# back to the password database, so it never noticed). XDG_CONFIG_HOME is
# kept so the settings.json lookup stays pointed at the throwaway directory
# tests/conftest.py set up, instead of the real ~/.config. The last two are
# Windows-only needs of code running inside these blocks: USERNAME names the
# account the settings file is locked down to (config._restrict_file_permissions),
# and SYSTEMROOT must stay set for the socket module (and child processes such as
# icacls) to work at all.
_KEPT_ENV_VARS = (
    "XDG_CONFIG_HOME",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "USERNAME",
    "SYSTEMROOT",
)


def clean_env(overrides=None):
    """Like `patch.dict(os.environ, overrides, clear=True)`, but keeps the
    variables in _KEPT_ENV_VARS so the home directory stays resolvable.
    Everything else — every SYNOLOGY_*/setting variable — is cleared, and
    `overrides` is applied on top."""
    env = {name: os.environ[name] for name in _KEPT_ENV_VARS if name in os.environ}
    env.update(overrides or {})
    return patch.dict(os.environ, env, clear=True)


# Force reimport of config module to avoid cached global instance
def reload_config():
    """Reload the config module to get fresh state."""
    modules_to_remove = [k for k in sys.modules.keys() if k.startswith("config")]
    for mod in modules_to_remove:
        del sys.modules[mod]


@pytest.fixture(autouse=True)
def _run_from_an_empty_directory(tmp_path, monkeypatch):
    """Run every test in this module from an empty directory.

    `config` loads `./.env` (a legacy fallback) both at import — its
    module-level `config = SynologyConfig()` — and whenever a
    SynologyConfig() is built, and these tests re-import it constantly
    (`reload_config()`). Patching `os.path.exists` only after the import, as
    one test used to, is too late: the import itself has already read the
    file. So a developer's own `.env` in the working directory (the repo
    root, when pytest is run from it) leaked real credentials and settings
    into tests that expect none, and they failed on that machine only.
    With no `.env` anywhere in the working directory, there is nothing to
    leak, whatever the order things are imported in.
    """
    monkeypatch.chdir(tmp_path)


class TestSynologyConfig:
    """Test Synology configuration loading and validation."""

    def test_env_fallback(self):
        """Test that .env values are used as fallback."""
        # Clear any cached config
        reload_config()

        with patch.dict(
            os.environ,
            {
                "SYNOLOGY_URL": "https://test.local:5001",
                "SYNOLOGY_USERNAME": "testuser",
                "SYNOLOGY_PASSWORD": "testpass",
            },
        ):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    config = SynologyConfig()

                    assert config.synology_url == "https://test.local:5001"
                    assert config.synology_username == "testuser"
                    assert config.synology_password == "testpass"

    def test_env_rejects_http_url(self):
        """SYNOLOGY_URL using plain http:// must fail fast at startup."""
        reload_config()

        with patch.dict(
            os.environ,
            {
                "SYNOLOGY_URL": "http://test.local:5000",
                "SYNOLOGY_USERNAME": "testuser",
                "SYNOLOGY_PASSWORD": "testpass",
            },
        ):
            # config.py constructs a module-level `config = SynologyConfig()`
            # singleton at import time, and _load_env_settings() (which
            # validates SYNOLOGY_URL) runs before _load_settings() (which
            # touches SETTINGS_FILE) — so the fresh import below (sys.modules
            # was cleared by reload_config() above) raises here, under this
            # patched env, before SETTINGS_FILE is ever read. No need to mock
            # it: patch("config.SETTINGS_FILE", ...) would itself trigger
            # this same fresh import via its own string-based target
            # resolution, outside of any pytest.raises context.
            #
            # Match on ValueError (InsecureURLError's stable base class)
            # rather than InsecureURLError itself: a fresh reimport defines a
            # brand-new class object each time, so any reference obtained
            # only after a *successful* import wouldn't be the same class
            # this raise actually uses.
            with pytest.raises(ValueError, match="https://") as exc_info:
                import config  # noqa: F401

            assert exc_info.value.__class__.__name__ == "InsecureURLError"

    def test_default_values(self):
        """Test default configuration values."""
        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    config = SynologyConfig()

                    assert config.server_name == "synology-mcp-server"
                    assert config.server_version == "1.0.0"
                    assert config.default_session_timeout == 3600
                    assert config.auto_login is True
                    assert config.verify_ssl is True
                    # Restricted mode is on by default — the whole
                    # remediation objective is an installation limited to
                    # browsing and monitoring unless deliberately widened.
                    assert config.restricted_mode is True
                    assert config.max_file_content_size == 1_000_000

    def test_max_file_content_size_env_var_override(self):
        reload_config()

        with clean_env({"MAX_FILE_CONTENT_SIZE": "5000"}):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    assert SynologyConfig().max_file_content_size == 5000

    def test_max_file_content_size_settings_json_overrides_env(self, tmp_path):
        secrets_data = {
            "synology": {
                "nas1": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "pass123",
                }
            },
            "server": {"max_file_content_size": 42},
        }
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)

        reload_config()

        with clean_env({"MAX_FILE_CONTENT_SIZE": "5000"}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                assert SynologyConfig().max_file_content_size == 42

    def test_max_file_content_size_settings_json_coerces_quoted_number(self, tmp_path):
        """Unlike the MAX_FILE_CONTENT_SIZE env var (always a string, always
        int()-cast), a settings.json author could quote the number. Coerce
        it the same way, so a quoted value fails fast here with a clear
        error if it's ever non-numeric, rather than raising deep inside
        get_file_content's size comparison."""
        secrets_data = {
            "synology": {
                "nas1": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "pass123",
                }
            },
            "server": {"max_file_content_size": "42"},
        }
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                assert SynologyConfig().max_file_content_size == 42

    def test_restricted_mode_env_var_disables_it(self):
        reload_config()

        with clean_env({"RESTRICTED_MODE": "false"}):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    assert SynologyConfig().restricted_mode is False

    def test_restricted_mode_settings_json_overrides_env(self, tmp_path):
        secrets_data = {
            "synology": {
                "nas1": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "pass123",
                }
            },
            "server": {"restricted_mode": False},
        }
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)

        reload_config()

        with clean_env({"RESTRICTED_MODE": "true"}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                assert SynologyConfig().restricted_mode is False

    @pytest.mark.parametrize("value", ["1", "yes", "true ", "TRUE", "garbage"])
    def test_restricted_mode_env_var_unrecognized_or_truthy_values_stay_restricted(self, value):
        """RESTRICTED_MODE must fail closed: before this fix, only the exact
        string "true" was treated as "on" (a bare `.lower() == "true"`
        comparison), so `1`, `yes`, or a value with incidental whitespace
        all silently disabled restricted mode — the only barrier against
        write actions from the (necessarily administrator) account this
        server runs as. A value this parser doesn't recognize at all must
        also stay restricted, not fail open."""
        reload_config()

        with clean_env({"RESTRICTED_MODE": value}):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    assert SynologyConfig().restricted_mode is True

    @pytest.mark.parametrize("value", ["false", "0", "no", " Off "])
    def test_restricted_mode_env_var_recognizes_falsy_aliases(self, value):
        reload_config()

        with clean_env({"RESTRICTED_MODE": value}):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    assert SynologyConfig().restricted_mode is False

    @pytest.mark.parametrize(
        "restricted_mode_value,expected",
        [
            (None, True),  # JSON null — not a recognized false value
            ("false", False),  # string form, parsed the same as the env var
            (False, False),  # JSON boolean, used as-is
            ("nonsense", True),  # unrecognized string — fails closed
        ],
    )
    def test_restricted_mode_settings_json_value_types(
        self, tmp_path, restricted_mode_value, expected
    ):
        secrets_data = {
            "synology": {
                "nas1": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "pass123",
                }
            },
            "server": {"restricted_mode": restricted_mode_value},
        }
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                assert SynologyConfig().restricted_mode is expected

    def test_verify_ssl_env_var_accepts_ca_bundle_path(self):
        """VERIFY_SSL isn't just true/false — a value that isn't either
        literal string is a CA-bundle path, passed straight through to
        requests' own `verify=` parameter (which already accepts a path)."""
        reload_config()

        with clean_env({"VERIFY_SSL": "/etc/ssl/certs/my-ca.pem"}):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    assert SynologyConfig().verify_ssl == "/etc/ssl/certs/my-ca.pem"

    def test_verify_ssl_ca_bundle_path_strips_incidental_whitespace(self):
        """Env vars sourced from files/Docker/K8s secrets commonly carry
        incidental leading/trailing whitespace — left in, the path would
        silently fail to resolve, producing a confusing error deep inside
        `requests` rather than a clear config error."""
        reload_config()

        with clean_env({"VERIFY_SSL": "  /etc/ssl/certs/my-ca.pem  "}):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    assert SynologyConfig().verify_ssl == "/etc/ssl/certs/my-ca.pem"

    @pytest.mark.parametrize("value,expected", [("1", True), ("yes", True), ("On", True)])
    def test_verify_ssl_recognizes_truthy_aliases(self, value, expected):
        reload_config()

        with clean_env({"VERIFY_SSL": value}):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    assert SynologyConfig().verify_ssl is expected

    @pytest.mark.parametrize("value", ["0", "no", "Off"])
    def test_verify_ssl_recognizes_falsy_aliases(self, value):
        """Before CA-bundle-path support, any non-"true" value silently
        meant "disabled" (`.lower() == "true"`) — these common boolean
        aliases must keep working rather than being treated as a CA-bundle
        path and failing hard the first time DSM is contacted."""
        reload_config()

        with clean_env({"VERIFY_SSL": value}):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    assert SynologyConfig().verify_ssl is False

    def test_verify_ssl_settings_json_accepts_ca_bundle_path(self, tmp_path):
        secrets_data = {
            "synology": {
                "nas1": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "pass123",
                }
            },
            "server": {"verify_ssl": "/etc/ssl/certs/my-ca.pem"},
        }
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                assert SynologyConfig().verify_ssl == "/etc/ssl/certs/my-ca.pem"

    def test_has_credentials_with_secrets(self, tmp_path):
        """Test credential detection with secrets.json."""
        secrets_data = {
            "synology": {
                "test_nas": {
                    "host": "192.168.1.100",
                    "port": 5000,
                    "username": "admin",
                    "password": "pass123",
                }
            }
        }

        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)  # config refuses insecure-perm files

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()

                assert cfg.has_synology_credentials() is True
                assert "test_nas" in cfg.nas_configs
                # HTTPS is forced regardless of port — no silent http fallback.
                assert cfg.nas_configs["test_nas"]["base_url"] == "https://192.168.1.100:5000"

    def test_omitted_port_defaults_to_5001(self, tmp_path):
        """5001 is DSM's default HTTPS port; the old default (5000, HTTP-only)
        would fail outright since base_url is always forced to https://."""
        secrets_data = {
            "synology": {
                "test_nas": {
                    "host": "192.168.1.100",
                    "username": "admin",
                    "password": "pass123",
                }
            }
        }

        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)  # config refuses insecure-perm files

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()

                assert cfg.nas_configs["test_nas"]["base_url"] == "https://192.168.1.100:5001"

    def test_get_nas_names(self, tmp_path):
        """Test getting NAS names from secrets.json."""
        secrets_data = {
            "synology": {
                "nas1": {"host": "192.168.1.1", "port": 5000, "username": "a", "password": "b"},
                "nas2": {"host": "192.168.1.2", "port": 5001, "username": "c", "password": "d"},
            }
        }

        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)  # config refuses insecure-perm files

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()

                names = cfg.get_nas_names()
                assert len(names) == 2
                assert "nas1" in names
                assert "nas2" in names

    def test_get_synology_config_with_nas_name(self, tmp_path):
        """Test getting config for specific NAS."""
        secrets_data = {
            "synology": {
                "primary": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "secret",
                }
            }
        }

        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)  # config refuses insecure-perm files

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()

                specific = cfg.get_synology_config("primary")
                assert specific["base_url"] == "https://192.168.1.100:5001"
                assert specific["username"] == "admin"

    def test_validate_config_no_credentials(self):
        """Test validation fails with no credentials."""
        reload_config()

        # clean_env() wipes os.environ, but `config` would re-inject whatever
        # is in a `.env` in the working directory — the autouse fixture
        # above runs this from an empty directory, so there is none to find,
        # at import time or when SynologyConfig() is constructed below.
        with clean_env({}):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    cfg = SynologyConfig()

                    errors = cfg.validate_config()
                    assert len(errors) > 0
                    assert "No Synology credentials" in errors[0]

    def test_validate_config_timeout_too_low(self):
        """Test validation fails with low timeout."""
        reload_config()

        with patch.dict(
            os.environ,
            {
                "SYNOLOGY_URL": "https://test.local:5001",
                "SYNOLOGY_USERNAME": "user",
                "SYNOLOGY_PASSWORD": "pass",
                "SESSION_TIMEOUT": "30",
            },
            clear=False,
        ):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    cfg = SynologyConfig()
                    errors = cfg.validate_config()

                    assert any("SESSION_TIMEOUT" in e for e in errors)

    def test_missing_required_fields_in_secrets(self, tmp_path, capsys):
        """Test handling of missing required fields in secrets."""
        secrets_data = {
            "synology": {
                "incomplete_nas": {
                    "host": "192.168.1.100"
                    # missing username, password
                }
            }
        }

        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)  # config refuses insecure-perm files

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()

                # Should not add incomplete NAS to configs
                assert (
                    "incomplete_nas" not in cfg.nas_configs
                    or cfg.nas_configs.get("incomplete_nas") is None
                )

    def test_invalid_json_in_secrets(self, tmp_path, capsys):
        """Test handling of invalid JSON in secrets file."""
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text("{ invalid json }")

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()

                # Should handle gracefully and not crash
                assert cfg.nas_configs == {}

    def test_resolve_base_url(self, tmp_path):
        """Test resolving base URL from NAS name."""
        secrets_data = {
            "synology": {
                "office_nas": {
                    "host": "office.example.com",
                    "port": 5000,
                    "username": "admin",
                    "password": "pass",
                }
            }
        }

        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)  # config refuses insecure-perm files

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()

                url = cfg.resolve_base_url("office_nas")
                assert url == "https://office.example.com:5000"

                # Test non-existent NAS
                url = cfg.resolve_base_url("nonexistent")
                assert url is None


class TestFilePermissions:
    """Test file permission checking."""

    @pytest.mark.skipif(
        not hasattr(os, "getuid"),
        reason="POSIX permission bits: Windows has no os.getuid(), and the check is skipped there",
    )
    def test_permission_warning_for_open_permissions(self, tmp_path, caplog):
        """Test that warning is logged for overly open permissions."""
        import logging

        # Create a file with open permissions
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text("{}")

        # Make it world-readable
        os.chmod(str(secrets_file), 0o644)

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                with caplog.at_level(logging.WARNING, logger="synology-mcp"):
                    _cfg = SynologyConfig()

                # Permission warning is emitted via logger.warning, not stderr
                assert any("permission" in rec.message.lower() for rec in caplog.records)

    def test_permission_check_skips_without_getuid(self, tmp_path, caplog, monkeypatch):
        """Platforms without os.getuid() (Windows) must not crash on load.

        os.getuid() and the group/other mode bits it gates don't exist on
        Windows (NTFS uses ACLs, not POSIX mode bits). The check should
        degrade to "skip with a warning" rather than raising AttributeError.
        """
        import json
        import logging

        secrets_data = {
            "synology": {
                "test_nas": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "pass123",
                }
            }
        }
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))

        # Simulate a platform without os.getuid() regardless of what's
        # actually running this test (raising=False: a no-op on platforms
        # where it's already absent, e.g. Windows).
        monkeypatch.delattr(os, "getuid", raising=False)
        # On real Windows, Path.home() never touches os.getuid() at all —
        # ntpath.expanduser() resolves "~" from USERPROFILE/HOME instead.
        # Deleting os.getuid() to simulate that here would otherwise also
        # break config.py's own unrelated module-level Path.home() call
        # (used to default XDG_CONFIG_HOME), which does depend on getuid()
        # via posixpath.expanduser() on this POSIX test runner.
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                with caplog.at_level(logging.WARNING, logger="synology-mcp"):
                    cfg = SynologyConfig()

                assert any(
                    "skipping file-permission check" in rec.message.lower()
                    for rec in caplog.records
                )
                # The file must still actually load (not be refused) once
                # the permission check is skipped.
                assert "test_nas" in cfg.nas_configs


class TestSaveDeviceId:
    """Test SynologyConfig.save_device_id()'s atomic, permission-safe write."""

    def test_save_device_id_writes_restricted_file_and_preserves_other_fields(self, tmp_path):
        """The settings file must never sit at default-umask permissions,
        not even momentarily via an intermediate temp file — and fields
        this class doesn't know about (here, `note`) must survive the
        read-modify-write untouched."""
        secrets_data = {
            "synology": {
                "nas1": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "pass123",
                    "note": "primary",
                }
            }
        }
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()
                assert cfg.save_device_id("nas1", "DID_test123") is True

        if hasattr(os, "getuid"):
            import stat

            mode = stat.S_IMODE(secrets_file.stat().st_mode)
            assert mode == 0o600

        on_disk = json.loads(secrets_file.read_text())
        nas1 = on_disk["synology"]["nas1"]
        assert nas1["device_id"] == "DID_test123"
        assert nas1["password"] == "pass123"
        assert nas1["note"] == "primary"

        # In-memory config reflects the write immediately, no restart needed.
        assert cfg.nas_configs["nas1"]["device_id"] == "DID_test123"

    def test_save_device_id_returns_false_for_unknown_nas(self, tmp_path):
        secrets_data = {
            "synology": {
                "nas1": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "pass123",
                }
            }
        }
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()
                assert cfg.save_device_id("does_not_exist", "DID_x") is False

    def test_atomic_write_settings_refuses_when_permission_restriction_fails(self, tmp_path):
        """If restricting the temp file's permissions fails (e.g. `icacls`
        erroring on Windows), the write must not proceed — writing the
        secret-bearing content first and restricting afterward, regardless
        of whether that restriction succeeded, is exactly the gap that let
        every configured NAS's password sit in a world/group-readable file.
        The original settings file must survive untouched, and no
        half-written or insecurely-permissioned temp file may be left
        behind."""
        original_data = {
            "synology": {
                "nas1": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "pass123",
                    "note": "primary",
                }
            }
        }
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(original_data))
        os.chmod(str(secrets_file), 0o600)
        original_bytes = secrets_file.read_bytes()

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()
                with patch.object(cfg, "_restrict_file_permissions", return_value=False):
                    assert cfg.save_device_id("nas1", "DID_should_not_be_saved") is False

        # Original file untouched — not even the new device_id present.
        assert secrets_file.read_bytes() == original_bytes
        assert "device_id" not in json.loads(secrets_file.read_text())["synology"]["nas1"]
        # No stray temp file left in the directory.
        leftover = [p for p in tmp_path.iterdir() if p.name != "secrets.json"]
        assert leftover == []

    def test_atomic_write_settings_uses_unique_temp_filenames(self, tmp_path):
        """A fixed temp filename (the previous `settings.json.tmp`) lets two
        concurrent writers collide; each write must use its own unique
        name."""
        secrets_data = {
            "synology": {
                "nas1": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "pass123",
                }
            }
        }
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)

        reload_config()

        seen_tmp_names = []
        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()
                real_replace = os.replace

                def _capture_replace(src, dst):
                    seen_tmp_names.append(Path(src).name)
                    return real_replace(src, dst)

                with patch("config.os.replace", side_effect=_capture_replace):
                    assert cfg.save_device_id("nas1", "DID_1") is True
                    assert cfg.save_device_id("nas1", "DID_2") is True

        assert len(seen_tmp_names) == 2
        assert seen_tmp_names[0] != seen_tmp_names[1]


class TestIterConfiguredSecrets:
    """Test SynologyConfig.iter_configured_secrets() — the configured
    (not-yet-necessarily-live) counterpart to auth.iter_live_secrets(),
    used to redact a configured password/device token from logs and tool
    output even before any login using it has happened. Deliberately
    excludes otp_code — see the method's own docstring for why blanket
    substring-masking a value that's always short and purely numeric does
    more harm (corrupting unrelated legitimate output) than good (its
    actual leak vector is already covered by redact()'s key=value pattern,
    independent of this list)."""

    def test_yields_settings_json_secrets_across_multiple_nas(self, tmp_path):
        secrets_data = {
            "synology": {
                "nas1": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "pass123",
                    "otp_code": "111111",
                    "device_id": "DID_nas1",
                },
                "nas2": {
                    "host": "192.168.1.200",
                    "port": 5001,
                    "username": "admin2",
                    "password": "pass456",
                },
            }
        }
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()
                secrets = set(cfg.iter_configured_secrets())

        # otp_code's "111111" is deliberately absent.
        assert secrets == {"pass123", "DID_nas1", "pass456"}

    def test_excludes_otp_code_even_when_it_is_the_only_secret_configured(self, tmp_path):
        secrets_data = {
            "synology": {
                "nas1": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "pass123",
                    "otp_code": "111111",
                }
            }
        }
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()
                secrets = set(cfg.iter_configured_secrets())

        assert "111111" not in secrets
        assert secrets == {"pass123"}

    def test_yields_legacy_env_password_but_not_otp_code(self):
        reload_config()

        with clean_env(
            {
                "SYNOLOGY_URL": "https://nas.example.com:5001",
                "SYNOLOGY_USERNAME": "admin",
                "SYNOLOGY_PASSWORD": "legacy_pass",
                "SYNOLOGY_OTP_CODE": "222222",
            }
        ):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    cfg = SynologyConfig()
                    secrets = set(cfg.iter_configured_secrets())

        assert secrets == {"legacy_pass"}

    def test_yields_nothing_when_unconfigured(self):
        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
                with patch.object(Path, "exists", return_value=False):
                    from config import SynologyConfig

                    assert list(SynologyConfig().iter_configured_secrets()) == []

    def test_coerces_a_bare_json_number_to_a_string(self, tmp_path):
        """settings.json is user-edited JSON, and nothing stops password or
        device_id from being written as a bare number rather than a quoted
        string — valid JSON, but redact()'s str.replace() call would raise
        on a non-string value, which would surface as an unhandled
        exception from inside an error handler wherever this feeds
        redact() (see mcp_server.py's _call_tool)."""
        secrets_data = {
            "synology": {
                "nas1": {
                    "host": "192.168.1.100",
                    "port": 5001,
                    "username": "admin",
                    "password": "pass123",
                    "device_id": 87654321,  # bare JSON number, not a string
                }
            }
        }
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps(secrets_data))
        os.chmod(str(secrets_file), 0o600)

        reload_config()

        with clean_env({}):
            with patch("config.SETTINGS_FILE", secrets_file):
                from config import SynologyConfig

                cfg = SynologyConfig()
                secrets = list(cfg.iter_configured_secrets())

        assert all(isinstance(s, str) for s in secrets)
        assert "87654321" in secrets


def test_config_str_representation():
    """Test string representation of config."""
    reload_config()

    with patch.dict(
        os.environ,
        {
            "SYNOLOGY_URL": "https://test.local:5001",
            "SYNOLOGY_USERNAME": "user",
            "SYNOLOGY_PASSWORD": "pass",
        },
    ):
        with patch("config.SETTINGS_FILE", Path("/nonexistent/secrets.json")):
            with patch.object(Path, "exists", return_value=False):
                from config import SynologyConfig

                cfg = SynologyConfig()
                cfg_str = str(cfg)

                assert "SynologyConfig" in cfg_str
                assert "auto_login" in cfg_str


class TestCleanEnv:
    """`clean_env()` is what keeps the config tests' cleared environments
    usable on Windows: reloading `config` needs a resolvable home directory
    even when XDG_CONFIG_HOME is set (its default is computed eagerly)."""

    def test_clears_everything_except_the_home_variables(self):
        ambient = {
            "USERPROFILE": r"C:\Users\someone",
            "HOMEDRIVE": "C:",
            "HOMEPATH": r"\Users\someone",
            "USERNAME": "someone",
            "SYSTEMROOT": r"C:\Windows",
            "HOME": "/home/someone",
            "XDG_CONFIG_HOME": "/some/config",
            "SYNOLOGY_URL": "https://ambient.example:5001",
            "SOMETHING_ELSE": "x",
        }
        with patch.dict(os.environ, ambient):
            with clean_env({"MAX_FILE_CONTENT_SIZE": "5"}):
                for name in (
                    "XDG_CONFIG_HOME",
                    "HOME",
                    "USERPROFILE",
                    "HOMEDRIVE",
                    "HOMEPATH",
                    "USERNAME",
                    "SYSTEMROOT",
                ):
                    assert os.environ[name] == ambient[name]
                assert "SYNOLOGY_URL" not in os.environ
                assert "SOMETHING_ELSE" not in os.environ
                assert os.environ["MAX_FILE_CONTENT_SIZE"] == "5"

            # The ambient environment comes back afterwards.
            assert os.environ["SYNOLOGY_URL"] == ambient["SYNOLOGY_URL"]
            assert "MAX_FILE_CONTENT_SIZE" not in os.environ

    def test_an_override_wins_over_a_kept_variable(self):
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": "/ambient"}):
            with clean_env({"XDG_CONFIG_HOME": "/override"}):
                assert os.environ["XDG_CONFIG_HOME"] == "/override"

    def test_config_still_imports_when_home_comes_only_from_userprofile(
        self, tmp_path, monkeypatch
    ):
        """Windows-shaped home lookup: Path.home() reads USERPROFILE and
        raises without it. A plain `patch.dict(os.environ, {}, clear=True)`
        made the (re)import of `config` fail; clean_env() must not."""

        def windows_like_home():
            try:
                return Path(os.environ["USERPROFILE"])
            except KeyError:
                raise RuntimeError("Could not determine home directory.") from None

        monkeypatch.setattr(Path, "home", windows_like_home)
        monkeypatch.setenv("USERPROFILE", str(tmp_path))

        reload_config()
        with clean_env():
            with patch("config.SETTINGS_FILE", tmp_path / "does-not-exist.json"):
                import config  # noqa: F401

        # The failure this guards against, for contrast.
        reload_config()
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="home directory"):
                import config  # noqa: F401,F811
