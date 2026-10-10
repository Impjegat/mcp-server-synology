"""Manual (broker) authentication mode.

In this mode the process holds no NAS password, one-time code or trusted-device
token, never signs in by itself, never renews a lost session from a stored
secret, and offers no tool that takes a password. A lost session is reported
as the typed `AuthenticationRequired` error. Legacy mode is unchanged and is
covered by the rest of the suite.

All checks use fake endpoints and dummy values; nothing here talks to a NAS.
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import mcp.types as types
import pytest
from mcp.shared.exceptions import MCPError

BASE_URL = "https://nas.example.test:5001"
# Deterministic dummy values, scanned for in every message below.
DUMMY_PASSWORD = "Dummy-Password-5e1c"
DUMMY_OTP = "Dummy-Otp-9b2d"
DUMMY_DEVICE = "Dummy-Device-3a7f"

# Environment variables a test must keep when it clears os.environ (the home
# directory has to stay resolvable on Windows; see tests/test_config.py).
_KEPT_ENV_VARS = (
    "XDG_CONFIG_HOME",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "USERNAME",
    "SYSTEMROOT",
)


def _clean_env(overrides=None):
    env = {name: os.environ[name] for name in _KEPT_ENV_VARS if name in os.environ}
    env.update(overrides or {})
    return patch.dict(os.environ, env, clear=True)


@pytest.fixture(autouse=True)
def _run_from_an_empty_directory(tmp_path, monkeypatch):
    """No `.env` in the working directory, so only what a test writes exists."""
    monkeypatch.chdir(tmp_path)


# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------


@pytest.fixture
def config_module():
    """A freshly imported `config` module, imported under a clean environment
    so its module-level instance is built in legacy mode."""
    for name in [k for k in sys.modules if k == "config" or k.startswith("config.")]:
        del sys.modules[name]
    with _clean_env():
        import config as module
    return module


def _write_settings(tmp_path, data):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(data))
    os.chmod(str(path), 0o600)
    return path


def _build(config_module, tmp_path, env=None, settings=None):
    """`SynologyConfig()` built from `env` and an optional settings file."""
    path = _write_settings(tmp_path, settings) if settings is not None else Path("/nonexistent")
    with _clean_env(env or {}):
        with patch.object(config_module, "SETTINGS_FILE", path):
            return config_module.SynologyConfig()


_NAS = {"nas1": {"host": "nas.example.test", "port": 5001, "username": "reader"}}


class TestBrokerConfig:
    def test_default_mode_is_legacy(self, config_module, tmp_path):
        assert _build(config_module, tmp_path).auth_mode == "legacy"

    def test_the_mode_is_case_insensitive(self, config_module, tmp_path):
        env = {"SYNOLOGY_AUTH_MODE": "BROKER"}
        assert _build(config_module, tmp_path, env, {"synology": _NAS}).auth_mode == "broker"

    def test_an_unknown_mode_fails_rather_than_falling_back(self, config_module, tmp_path):
        with pytest.raises(ValueError, match="SYNOLOGY_AUTH_MODE") as error:
            _build(config_module, tmp_path, {"SYNOLOGY_AUTH_MODE": "brokr"})
        assert "brokr" not in str(error.value)

    def test_endpoints_load_without_a_password(self, config_module, tmp_path):
        cfg = _build(config_module, tmp_path, {"SYNOLOGY_AUTH_MODE": "broker"}, {"synology": _NAS})
        assert cfg.get_nas_names() == ["nas1"]
        assert cfg.nas_configs["nas1"]["base_url"] == BASE_URL
        assert cfg.has_nas_endpoints() is True
        assert cfg.has_synology_credentials() is False
        assert cfg.auto_login is False
        assert not {"password", "otp_code", "device_id"} & set(cfg.nas_configs["nas1"])
        assert cfg.validate_config() == []

    def test_a_bare_url_becomes_the_default_endpoint(self, config_module, tmp_path):
        env = {"SYNOLOGY_AUTH_MODE": "broker", "SYNOLOGY_URL": BASE_URL}
        cfg = _build(config_module, tmp_path, env)
        assert cfg.get_nas_names() == ["default"]
        assert cfg.resolve_base_url("default") == BASE_URL

    def test_no_endpoint_is_a_validation_error(self, config_module, tmp_path):
        cfg = _build(config_module, tmp_path, {"SYNOLOGY_AUTH_MODE": "broker"})
        assert any("NAS endpoint" in error for error in cfg.validate_config())

    @pytest.mark.parametrize("field", ["password", "otp_code", "device_id"])
    def test_a_stored_credential_in_settings_is_rejected_by_name_only(
        self, config_module, tmp_path, field
    ):
        nas = {"nas1": {**_NAS["nas1"], field: DUMMY_PASSWORD}}
        with pytest.raises(ValueError, match=f"synology.nas1.{field}") as error:
            _build(config_module, tmp_path, {"SYNOLOGY_AUTH_MODE": "broker"}, {"synology": nas})
        assert DUMMY_PASSWORD not in str(error.value)

    @pytest.mark.parametrize(
        "env_name,value",
        [
            ("SYNOLOGY_PASSWORD", DUMMY_PASSWORD),
            ("SYNOLOGY_OTP_CODE", DUMMY_OTP),
            ("AUTO_LOGIN", "true"),
        ],
    )
    def test_a_credential_or_auto_login_in_the_environment_is_rejected(
        self, config_module, tmp_path, env_name, value
    ):
        env = {"SYNOLOGY_AUTH_MODE": "broker", "SYNOLOGY_URL": BASE_URL, env_name: value}
        with pytest.raises(ValueError, match=env_name) as error:
            _build(config_module, tmp_path, env)
        assert value not in str(error.value)

    def test_auto_login_switched_off_is_compatible(self, config_module, tmp_path):
        env = {"SYNOLOGY_AUTH_MODE": "broker", "SYNOLOGY_URL": BASE_URL, "AUTO_LOGIN": "false"}
        assert _build(config_module, tmp_path, env).auto_login is False

    def test_auto_login_in_settings_is_rejected(self, config_module, tmp_path):
        settings = {"synology": _NAS, "server": {"auto_login": True}}
        with pytest.raises(ValueError, match="server.auto_login"):
            _build(config_module, tmp_path, {"SYNOLOGY_AUTH_MODE": "broker"}, settings)

    def test_every_violation_is_reported_together(self, config_module, tmp_path):
        env = {
            "SYNOLOGY_AUTH_MODE": "broker",
            "SYNOLOGY_PASSWORD": DUMMY_PASSWORD,
            "SYNOLOGY_OTP_CODE": DUMMY_OTP,
        }
        with pytest.raises(ValueError) as error:
            _build(config_module, tmp_path, env, {"synology": _NAS})
        assert "SYNOLOGY_PASSWORD" in str(error.value)
        assert "SYNOLOGY_OTP_CODE" in str(error.value)

    def test_a_dotenv_file_is_never_read(self, config_module, tmp_path):
        (tmp_path / ".env").write_text(
            f"SYNOLOGY_URL=https://leak.example:5001\nSYNOLOGY_PASSWORD={DUMMY_PASSWORD}\n"
        )
        cfg = _build(config_module, tmp_path, {"SYNOLOGY_AUTH_MODE": "broker"}, {"synology": _NAS})
        assert cfg.synology_url is None
        assert cfg.synology_password is None
        assert list(cfg.iter_configured_secrets()) == []

    def test_legacy_mode_still_reads_dotenv(self, config_module, tmp_path):
        (tmp_path / ".env").write_text("SYNOLOGY_URL=https://from-dotenv.example:5001\n")
        assert _build(config_module, tmp_path).synology_url == "https://from-dotenv.example:5001"

    def test_a_device_token_is_never_saved(self, config_module, tmp_path):
        settings = {"synology": _NAS}
        path = _write_settings(tmp_path, settings)
        before = path.read_text()
        with _clean_env({"SYNOLOGY_AUTH_MODE": "broker"}):
            with patch.object(config_module, "SETTINGS_FILE", path):
                cfg = config_module.SynologyConfig()
                assert cfg.save_device_id("nas1", DUMMY_DEVICE) is False
        assert path.read_text() == before


# ----------------------------------------------------------------------------
# Test helpers for the modules below
# ----------------------------------------------------------------------------


@pytest.fixture
def broker_mode(monkeypatch):
    """Put every consumer's `config` into broker mode, with one NAS configured.
    Each module is patched through its own attribute: a test that reloads
    `config` can leave the modules holding different instances."""
    import auth.synology_auth  # noqa: F401
    import mcp_server  # noqa: F401
    import utils.synology_api  # noqa: F401

    for target in ("mcp_server", "utils.synology_api", "auth.synology_auth"):
        module = sys.modules[target]
        monkeypatch.setattr(module.config, "auth_mode", "broker")
    server_config = sys.modules["mcp_server"].config
    monkeypatch.setattr(server_config, "auto_login", False)
    monkeypatch.setattr(server_config, "restricted_mode", True)
    monkeypatch.setattr(
        server_config,
        "nas_configs",
        {"nas1": {"base_url": BASE_URL, "username": "reader", "verify_ssl": True, "note": ""}},
    )
    return server_config


def _json_response(payload):
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = payload
    return response


def _lost(code=119):
    return _json_response({"success": False, "error": {"code": code}})


# ----------------------------------------------------------------------------
# SynologyAuth
# ----------------------------------------------------------------------------


def _manual_auth(url="https://auth-manual.example.test:5001"):
    from auth.synology_auth import SynologyAuth

    return SynologyAuth(url, manual_mode=True)


class TestManualSynologyAuth:
    def test_manual_mode_follows_the_process_wide_mode(self, broker_mode):
        from auth.synology_auth import SynologyAuth

        assert SynologyAuth("https://auth-default.example.test:5001").manual_mode is True

    def test_login_keeps_no_credential_and_no_device_token(self):
        auth = _manual_auth()
        reply = _json_response(
            {"success": True, "data": {"sid": "SID1", "synotoken": "TOK1", "did": DUMMY_DEVICE}}
        )
        with patch("auth.synology_auth.requests.post", return_value=reply):
            result = auth.login("reader", DUMMY_PASSWORD, otp_code="123456")

        assert result["success"] is True
        assert "did" not in result["data"]
        assert auth._credentials is None
        assert auth.current_device_id is None
        assert auth._cached_device_id is None
        assert auth.current_session_id == "SID1"

    def test_login_never_asks_dsm_for_a_device_token(self):
        auth = _manual_auth()
        reply = _json_response({"success": True, "data": {"sid": "SID1"}})
        with patch("auth.synology_auth.requests.post", return_value=reply) as post:
            auth.login("reader", DUMMY_PASSWORD, otp_code="123456")

        payload = post.call_args.kwargs["data"]
        assert payload["otp_code"] == "123456"
        assert "enable_device_token" not in payload
        assert "device_id" not in payload

    def test_a_trusted_device_token_is_refused_without_a_request(self):
        auth = _manual_auth()
        with patch("auth.synology_auth.requests.post") as post:
            result = auth.login("reader", DUMMY_PASSWORD, device_id=DUMMY_DEVICE)

        assert result["success"] is False
        assert result["error"]["code"] == "device_token_not_allowed"
        assert DUMMY_DEVICE not in json.dumps(result)
        post.assert_not_called()

    def test_relogin_never_signs_in_again(self):
        auth = _manual_auth()
        auth.current_session_id = "SID1"
        auth._credentials = ("reader", DUMMY_PASSWORD)  # even if one somehow existed
        with patch("auth.synology_auth.requests.post") as post:
            assert auth.relogin("SID1") is False
        post.assert_not_called()

    def test_logout_clears_the_local_session_when_the_nas_is_unreachable(self):
        import requests

        auth = _manual_auth()
        auth.current_session_id = "SID1"
        auth.current_syno_token = "TOK1"
        with patch("auth.synology_auth.requests.post", side_effect=requests.ConnectionError("x")):
            result = auth.logout()

        assert result["success"] is False
        assert auth.current_session_id is None
        assert auth.current_syno_token is None

    def test_logout_of_a_different_session_leaves_the_current_one(self):
        import requests

        auth = _manual_auth()
        auth.current_session_id = "SID1"
        with patch("auth.synology_auth.requests.post", side_effect=requests.ConnectionError("x")):
            auth.logout("SOME-OTHER-SID")

        assert auth.current_session_id == "SID1"

    def test_legacy_logout_keeps_the_session_when_the_nas_is_unreachable(self):
        import requests

        from auth.synology_auth import SynologyAuth

        auth = SynologyAuth("https://auth-legacy.example.test:5001", manual_mode=False)
        auth.current_session_id = "SID1"
        with patch("auth.synology_auth.requests.post", side_effect=requests.ConnectionError("x")):
            auth.logout()

        assert auth.current_session_id == "SID1"


# ----------------------------------------------------------------------------
# Lost sessions: the shared client and the services that make their own calls
# ----------------------------------------------------------------------------


class TestLostSessionBecomesAuthenticationRequired:
    @pytest.mark.parametrize("code", [106, 107, 119])
    def test_the_shared_client_raises_and_does_not_renew(self, broker_mode, code):
        from broker.errors import AuthenticationRequired
        from utils.synology_api import SynologyAPIClient

        client = SynologyAPIClient(BASE_URL, "SID1")
        with patch("utils.synology_api.requests.get", return_value=_lost(code)):
            with patch("utils.synology_api._try_relogin") as relogin:
                with pytest.raises(AuthenticationRequired):
                    client.get("SYNO.Core.System", "info")
        relogin.assert_not_called()

    def test_a_permission_error_is_not_a_lost_session(self, broker_mode):
        from utils.synology_api import SynologyAPIClient

        client = SynologyAPIClient(BASE_URL, "SID1")
        with patch("utils.synology_api.requests.get", return_value=_lost(105)):
            result = client.get("SYNO.Core.System", "info")
        assert result["success"] is False
        assert result["error"]["code"] == 105

    def test_legacy_mode_still_renews_on_119(self, monkeypatch):
        import utils.synology_api as api

        monkeypatch.setattr(api.config, "auth_mode", "legacy")
        client = api.SynologyAPIClient(BASE_URL, "SID1")
        replies = [_lost(119), _json_response({"success": True, "data": {"ok": 1}})]
        with patch("utils.synology_api.requests.get", side_effect=replies):
            with patch("utils.synology_api._try_relogin", return_value=("SID2", "T2")) as relogin:
                result = client.get("SYNO.Core.System", "info")

        relogin.assert_called_once_with(BASE_URL, "SID1")
        assert result["success"] is True
        assert client.session_id == "SID2"

    def test_a_health_summary_stops_at_the_first_lost_session(self, broker_mode):
        from broker.errors import AuthenticationRequired
        from health import SynologyHealth

        health = SynologyHealth(BASE_URL, "SID1")
        with patch("utils.synology_api.requests.get", return_value=_lost(119)) as get:
            with pytest.raises(AuthenticationRequired):
                health.health_summary()
        # Not eleven failed checks reported as a "partial" summary.
        assert get.call_count == 1

    def test_file_station_raises(self, broker_mode):
        from broker.errors import AuthenticationRequired
        from filestation import SynologyFileStation

        fs = SynologyFileStation(BASE_URL, "SID1")
        with patch("filestation.synology_filestation.requests.get", return_value=_lost(119)):
            with pytest.raises(AuthenticationRequired):
                fs.list_shares()

    def test_file_station_raises_for_a_lost_session_during_a_download(self, broker_mode):
        from broker.errors import AuthenticationRequired
        from filestation import SynologyFileStation

        fs = SynologyFileStation(BASE_URL, "SID1")
        fs.get_file_info = lambda path: {"name": "a", "path": path, "type": "file", "size": 1}
        body = json.dumps({"success": False, "error": {"code": 119}}).encode()
        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.headers = {"Content-Type": "application/json"}
        response.encoding = None
        response.iter_content = lambda chunk_size=None: iter([body])
        with patch("filestation.synology_filestation.requests.get", return_value=response):
            with pytest.raises(AuthenticationRequired):
                fs.get_file_content("/share/a.txt")

    def test_file_station_does_not_mistake_another_error_for_a_lost_session(self, broker_mode):
        from filestation import SynologyFileStation

        fs = SynologyFileStation(BASE_URL, "SID1")
        with patch("filestation.synology_filestation.requests.get", return_value=_lost(408)):
            with pytest.raises(Exception, match="API error: 408"):
                fs.list_shares()

    def test_legacy_file_station_renews_once_and_repeats_a_read(self, monkeypatch):
        import utils.synology_api as api
        from filestation import SynologyFileStation

        monkeypatch.setattr(api.config, "auth_mode", "legacy")
        fs = SynologyFileStation(BASE_URL, "SID1")
        replies = [_lost(119), _json_response({"success": True, "data": {"shares": []}})]
        with patch("filestation.synology_filestation.requests.get", side_effect=replies) as get:
            with patch("utils.synology_api._try_relogin", return_value=("SID2", "T2")):
                assert fs.list_shares() == []

        assert get.call_count == 2
        assert fs.session_id == "SID2"
        assert get.call_args.kwargs["params"]["_sid"] == "SID2"

    def test_legacy_file_station_never_repeats_a_write(self, monkeypatch):
        import utils.synology_api as api
        from filestation import SynologyFileStation

        monkeypatch.setattr(api.config, "auth_mode", "legacy")
        fs = SynologyFileStation(BASE_URL, "SID1")
        with patch(
            "filestation.synology_filestation.requests.post", return_value=_lost(119)
        ) as post:
            with patch("utils.synology_api._try_relogin", return_value=("SID2", "T2")) as relogin:
                with pytest.raises(Exception, match="API error: 119"):
                    fs._make_request("SYNO.FileStation.Delete", "2", "start", use_post=True)

        assert post.call_count == 1
        relogin.assert_not_called()

    def test_legacy_file_station_gives_up_after_one_renewal(self, monkeypatch):
        import utils.synology_api as api
        from filestation import SynologyFileStation

        monkeypatch.setattr(api.config, "auth_mode", "legacy")
        fs = SynologyFileStation(BASE_URL, "SID1")
        with patch("filestation.synology_filestation.requests.get", return_value=_lost(119)) as get:
            with patch("utils.synology_api._try_relogin", return_value=("SID2", "T2")):
                with pytest.raises(Exception, match="API error: 119"):
                    fs.list_shares()
        assert get.call_count == 2

    def test_download_station_raises(self, broker_mode):
        from broker.errors import AuthenticationRequired
        from downloadstation import SynologyDownloadStation

        ds = SynologyDownloadStation(BASE_URL, "SID1")
        with patch("downloadstation.synology_downloadstation.requests.get", return_value=_lost()):
            with pytest.raises(AuthenticationRequired):
                ds.list_tasks()

    @pytest.mark.parametrize("method", ["get_info", "get_config", "get_statistics"])
    def test_download_station_does_not_hide_it_behind_a_fallback(self, broker_mode, method):
        """These used to answer a lost session with made-up default values."""
        from broker.errors import AuthenticationRequired
        from downloadstation import SynologyDownloadStation

        ds = SynologyDownloadStation(BASE_URL, "SID1")
        with patch("downloadstation.synology_downloadstation.requests.get", return_value=_lost()):
            with pytest.raises(AuthenticationRequired):
                getattr(ds, method)()

    def test_download_station_list_downloaded_files_raises(self, broker_mode):
        from broker.errors import AuthenticationRequired
        from downloadstation import SynologyDownloadStation

        ds = SynologyDownloadStation(BASE_URL, "SID1")
        with patch("downloadstation.synology_downloadstation.requests.get", return_value=_lost()):
            with pytest.raises(AuthenticationRequired):
                ds.list_downloaded_files("downloads")

    def test_legacy_download_station_renews_once_and_repeats_a_read(self, monkeypatch):
        import utils.synology_api as api
        from downloadstation import SynologyDownloadStation

        monkeypatch.setattr(api.config, "auth_mode", "legacy")
        ds = SynologyDownloadStation(BASE_URL, "SID1")
        ok = _json_response({"success": True, "data": {"tasks": [], "total": 0}})
        with patch(
            "downloadstation.synology_downloadstation.requests.get", side_effect=[_lost(), ok]
        ) as get:
            with patch("utils.synology_api._try_relogin", return_value=("SID2", "T2")):
                assert ds.list_tasks()["tasks"] == []

        assert get.call_count == 2
        assert ds.session_id == "SID2"


# ----------------------------------------------------------------------------
# The MCP server
# ----------------------------------------------------------------------------


def _server():
    from mcp_server import SynologyMCPServer

    return SynologyMCPServer()


def _text(result):
    assert len(result.content) == 1
    return result.content[0].text


class TestBrokerModeServer:
    @pytest.mark.asyncio
    async def test_the_password_login_tool_is_neither_listed_nor_callable(self, broker_mode):
        server = _server()
        names = {tool.name for tool in await server._list_tools()}

        assert "synology_login" not in names
        assert {"synology_logout", "synology_status", "synology_list_nas"} <= names
        assert "synology_login" not in server._tool_registry
        assert "synology_login" not in server._input_validators

        with patch("mcp_server.SynologyAuth") as auth_class:
            with pytest.raises(MCPError) as error:
                await server._call_tool(
                    "synology_login",
                    {"base_url": BASE_URL, "username": "reader", "password": DUMMY_PASSWORD},
                )
        assert error.value.error.code == types.INVALID_PARAMS
        assert DUMMY_PASSWORD not in error.value.error.message
        auth_class.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_tool_schema_has_a_credential_property(self, broker_mode):
        server = _server()
        for tool in await server._list_tools():
            properties = set(tool.input_schema.get("properties", {}))
            assert not {"password", "otp_code", "device_id"} & properties, tool.name

    @pytest.mark.asyncio
    async def test_it_starts_disconnected_and_never_signs_in(self, broker_mode):
        server = _server()
        with patch("mcp_server.SynologyAuth") as auth_class:
            await server._auto_login_if_configured()

        auth_class.assert_not_called()
        assert server.sessions == {}

    @pytest.mark.asyncio
    async def test_status_and_nas_discovery_work_without_a_session(self, broker_mode):
        server = _server()

        status = _text(await server._call_tool("synology_status", {}))
        assert "manual" in status
        assert "AUTHENTICATION_REQUIRED" in status

        listing = json.loads(_text(await server._call_tool("synology_list_nas", {})))
        assert listing == [
            {"nas_name": "nas1", "base_url": BASE_URL, "username": "reader", "connected": False}
        ]

    @pytest.mark.asyncio
    async def test_a_nas_call_without_a_session_asks_for_private_authentication(self, broker_mode):
        server = _server()
        with patch("requests.get") as get, patch("requests.post") as post:
            result = await server._call_tool("list_shares", {"nas_name": "nas1"})

        assert result.is_error is True
        assert _text(result).startswith("AUTHENTICATION_REQUIRED")
        assert "private" in _text(result)
        get.assert_not_called()
        post.assert_not_called()

    @pytest.mark.asyncio
    async def test_an_installed_session_serves_requests(self, broker_mode):
        from filestation import SynologyFileStation

        server = _server()
        server.install_session(BASE_URL, "SID1", "TOK1")
        with patch.object(SynologyFileStation, "list_shares", return_value=[{"name": "docs"}]):
            result = await server._call_tool("list_shares", {"nas_name": "nas1"})

        assert result.is_error is False
        assert json.loads(_text(result)) == [{"name": "docs"}]
        status = _text(await server._call_tool("synology_status", {}))
        assert "nas1" in status and "connected" in status

    @pytest.mark.asyncio
    async def test_a_session_lost_mid_call_is_a_flagged_authentication_error(self, broker_mode):
        from filestation import SynologyFileStation

        server = _server()
        server.install_session(BASE_URL, "SID1")
        with patch("filestation.synology_filestation.requests.get", return_value=_lost(107)):
            result = await server._call_tool("list_shares", {"nas_name": "nas1"})

        assert result.is_error is True
        assert _text(result).startswith("AUTHENTICATION_REQUIRED")
        assert "SID1" not in _text(result)
        assert SynologyFileStation  # imported for the patch target above

    @pytest.mark.asyncio
    async def test_only_a_configured_nas_can_be_targeted(self, broker_mode):
        server = _server()
        server.install_session("https://elsewhere.example.test:5001", "SID9")

        with patch("requests.get") as get:
            denied = await server._call_tool(
                "list_shares", {"base_url": "https://elsewhere.example.test:5001"}
            )

        assert denied.is_error is True
        assert _text(denied).startswith("AUTHORIZATION_DENIED")
        get.assert_not_called()

    @pytest.mark.asyncio
    async def test_a_configured_base_url_is_accepted(self, broker_mode):
        from filestation import SynologyFileStation

        server = _server()
        server.install_session(BASE_URL, "SID1")
        with patch.object(SynologyFileStation, "list_shares", return_value=[]):
            result = await server._call_tool("list_shares", {"base_url": BASE_URL})
        assert result.is_error is False

    @pytest.mark.asyncio
    async def test_logout_disconnects_an_installed_session(self, broker_mode):
        server = _server()
        server.install_session(BASE_URL, "SID1", "TOK1")

        result = await server._call_tool("synology_logout", {"base_url": BASE_URL})

        assert result.is_error is False
        assert server.sessions == {}
        assert server.syno_tokens == {}
        assert "SID1" not in _text(result)

    def test_installing_a_session_replaces_cached_services(self, broker_mode):
        server = _server()
        server.install_session(BASE_URL, "SID1", "TOK1")
        first = server._get_filestation(BASE_URL)

        server.install_session(BASE_URL, "SID2", "TOK2")
        second = server._get_filestation(BASE_URL)

        assert second is not first
        assert second.session_id == "SID2"
        assert second.syno_token == "TOK2"

    @pytest.mark.asyncio
    async def test_authentication_errors_never_carry_a_secret(self, broker_mode):
        """Every message on the no-session path is the fixed, value-free one."""
        server = _server()
        server.install_session(BASE_URL, "SID-LIVE-1", "TOK-LIVE-1")
        server.sessions.clear()  # the session ended
        result = await server._call_tool("synology_health_summary", {"nas_name": "nas1"})

        assert result.is_error is True
        for marker in ("SID-LIVE-1", "TOK-LIVE-1"):
            assert marker not in _text(result)


# ----------------------------------------------------------------------------
# Follow-ups from the review of the first pull request
# ----------------------------------------------------------------------------


class TestReviewFollowUps:
    @pytest.mark.asyncio
    async def test_a_session_the_nas_dropped_is_forgotten_not_reported_as_connected(
        self, broker_mode
    ):
        """After AuthenticationRequired the dead session must not linger: status
        said "connected", the fallback target was the dead session, and every
        later call went to the NAS and failed the same way."""
        from filestation import SynologyFileStation

        server = _server()
        server.install_session(BASE_URL, "SID1", "TOK1")
        with patch("filestation.synology_filestation.requests.get", return_value=_lost(107)):
            first = await server._call_tool("list_shares", {"nas_name": "nas1"})

        assert first.is_error is True
        assert server.sessions == {} and server.syno_tokens == {}
        assert server.filestation_instances == {}
        status = _text(await server._call_tool("synology_status", {}))
        assert "AUTHENTICATION_REQUIRED" in status and "connected" not in status

        # The next call asks for a sign-in without touching the NAS again.
        with patch("filestation.synology_filestation.requests.get") as get:
            second = await server._call_tool("list_shares", {"nas_name": "nas1"})
        assert _text(second).startswith("AUTHENTICATION_REQUIRED")
        get.assert_not_called()
        assert SynologyFileStation  # imported so the patch target above is loaded

    @pytest.mark.asyncio
    async def test_losing_one_nas_session_leaves_another_alone(self, broker_mode, monkeypatch):
        import mcp_server

        other = "https://nas2.example.test:5001"
        monkeypatch.setattr(
            mcp_server.config,
            "nas_configs",
            {
                "nas1": {
                    "base_url": BASE_URL,
                    "username": "reader",
                    "verify_ssl": True,
                    "note": "",
                },
                "nas2": {"base_url": other, "username": "reader", "verify_ssl": True, "note": ""},
            },
        )
        server = _server()
        server.install_session(BASE_URL, "SID1")
        server.install_session(other, "SID2")
        with patch("filestation.synology_filestation.requests.get", return_value=_lost(119)):
            await server._call_tool("list_shares", {"nas_name": "nas1"})

        assert list(server.sessions) == [other]

    @pytest.mark.parametrize(
        "spelling",
        [
            BASE_URL,
            BASE_URL + "/",
            BASE_URL.upper(),
            "HTTPS://NAS.EXAMPLE.TEST:5001/",
            BASE_URL + "///",
        ],
    )
    def test_a_configured_nas_is_recognised_however_its_url_is_spelled(self, broker_mode, spelling):
        server = _server()
        # The configured spelling comes back, because sessions are keyed by it.
        assert server._get_base_url({"base_url": spelling}) == BASE_URL

    @pytest.mark.parametrize(
        "spelling",
        [
            "https://nas.example.test:5002",  # another port
            "http://nas.example.test:5001",  # another scheme
            "https://nas.example.test.evil.test:5001",
            "https://evil.test:5001@nas.example.test:5001",
            BASE_URL + "/other-path",
        ],
    )
    def test_a_different_address_is_still_refused(self, broker_mode, spelling):
        from broker.errors import AuthorizationDenied

        with pytest.raises(AuthorizationDenied):
            _server()._get_base_url({"base_url": spelling})

    @pytest.mark.asyncio
    async def test_disconnect_says_the_nas_session_was_not_closed_when_nothing_closed_it(
        self, broker_mode
    ):
        server = _server()
        server.install_session(BASE_URL, "SID1")

        result = await server._call_tool("synology_logout", {"base_url": BASE_URL})

        assert result.is_error is False
        assert "did not close the session on the NAS" in _text(result)

    def test_logout_clears_the_local_session_even_if_the_remote_call_raises(self):
        auth = _manual_auth("https://auth-raises.example.test:5001")
        auth.current_session_id = "SID1"
        auth.current_syno_token = "TOK1"

        with patch.object(auth, "_logout_remote", side_effect=RuntimeError("boom")):
            with pytest.raises(RuntimeError):
                auth.logout()

        assert auth.current_session_id is None
        assert auth.current_syno_token is None
