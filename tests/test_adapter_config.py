"""The adapter's configuration: strict, with nowhere to put a NAS credential, and
the broker token only ever referenced, never written into the file."""

import json
import os

import pytest

from adapter.config import (
    PROHIBITED_ENVIRONMENT,
    AdapterConfigError,
    MalformedTokenError,
    _mode_warning,
    default_config_path,
    load_settings,
    make_token_provider,
    parse_settings,
    prohibited_environment,
    token_file_warning,
)

URL = "https://broker.example:8443/mcp"
TOKEN = "broker-token-value-0123456789"


def _config(**overrides):
    config = {"broker_url": URL, "token_env": "BROKER_TOKEN"}
    config.update(overrides)
    return config


class TestParsing:
    def test_a_minimal_configuration_gets_sensible_defaults(self):
        settings = parse_settings(_config())
        assert settings.broker_url == URL
        assert (settings.connect_timeout, settings.list_timeout, settings.call_timeout) == (
            5.0,
            30.0,
            180.0,
        )
        assert settings.ca_file is None and settings.allow_insecure_loopback is False
        assert settings.server_name == "synology"

    @pytest.mark.parametrize(
        "given,expected",
        [
            ("https://broker.example:8443", "https://broker.example:8443/mcp"),
            ("https://broker.example:8443/", "https://broker.example:8443/mcp"),
            ("https://broker.example:8443/mcp/", "https://broker.example:8443/mcp"),
            ("https://broker.example/custom/path", "https://broker.example/custom/path"),
        ],
    )
    def test_the_url_is_normalised(self, given, expected):
        assert parse_settings(_config(broker_url=given)).broker_url == expected

    def test_a_token_file_or_a_token_variable_but_not_both_or_neither(self):
        assert parse_settings({"broker_url": URL, "token_file": "t.txt"}).token_file == "t.txt"
        for config in (
            {"broker_url": URL},
            {"broker_url": URL, "token_file": "t.txt", "token_env": "X"},
        ):
            with pytest.raises(AdapterConfigError, match="exactly one of token_file and token_env"):
                parse_settings(config)

    def test_a_ca_file_must_exist(self, tmp_path):
        with pytest.raises(AdapterConfigError, match="ca_file: no such file"):
            parse_settings(_config(ca_file=str(tmp_path / "absent.pem")))
        ca = tmp_path / "ca.pem"
        ca.write_text("x")
        assert parse_settings(_config(ca_file=str(ca))).ca_file == str(ca)

    @pytest.mark.parametrize(
        "config,message",
        [
            ([], "JSON object"),
            ({"token_env": "X"}, "broker_url: required"),
            (_config(broker_url=""), "broker_url: required"),
            (_config(broker_url="ftp://broker.example"), "must be an https URL"),
            (_config(broker_url="https://"), "must be an https URL"),
            (_config(broker_url="https://user:pass@broker.example"), "user name or password"),
            (_config(broker_url="https://user@broker.example"), "user name or password"),
            (_config(broker_url="https://broker.example/mcp?token=abc"), "query or fragment"),
            (_config(broker_url="https://broker.example/mcp#frag"), "query or fragment"),
            (_config(broker_url="http://broker.example/mcp"), "plain http is allowed only"),
            (_config(broker_url="http://127.0.0.1:8443/mcp"), "plain http is allowed only"),
            (
                _config(broker_url="http://broker.example/mcp", allow_insecure_loopback=True),
                "plain http is allowed only",
            ),
            (_config(allow_insecure_loopback="yes"), "true or false"),
            (_config(token_env="1BAD"), "name of an environment variable"),
            (_config(token_env="has space"), "name of an environment variable"),
            (_config(token_env="SYNOLOGY_PASSWORD"), "must not be a NAS credential setting"),
            (_config(connect_timeout=0), "between 1 and 60"),
            (_config(connect_timeout=61), "between 1 and 60"),
            (_config(list_timeout=True), "between 1 and 600"),
            (_config(call_timeout="soon"), "between 1 and 900"),
            (_config(call_timeout=901), "between 1 and 900"),
            (_config(server_name="bad name"), "server_name: invalid"),
        ],
    )
    def test_a_bad_configuration_is_refused(self, config, message):
        with pytest.raises(AdapterConfigError, match=message):
            parse_settings(config)

    def test_plain_http_is_allowed_to_loopback_only_when_asked(self):
        settings = parse_settings(
            _config(broker_url="http://127.0.0.1:8443", allow_insecure_loopback=True)
        )
        assert settings.broker_url == "http://127.0.0.1:8443/mcp"
        assert parse_settings(
            _config(broker_url="http://localhost:8443", allow_insecure_loopback=True)
        )


class TestNoPlaceForACredential:
    @pytest.mark.parametrize(
        "key",
        [
            "password",
            "passwd",
            "otp_code",
            "otp",
            "device_id",
            "token",
            "bearer",
            "api_token",
            "session_id",
            "sid",
            "synotoken",
            "cookie",
            "secret",
            "username_password",
        ],
    )
    def test_a_credential_setting_is_refused_by_name_without_its_value(self, key):
        value = "Dummy-Secret-Value-5e1c"
        with pytest.raises(
            AdapterConfigError, match="holds no NAS credential and no token"
        ) as error:
            parse_settings(_config(**{key: value}))
        assert key in str(error.value) and value not in str(error.value)

    def test_an_unknown_but_harmless_setting_is_refused_plainly(self):
        with pytest.raises(AdapterConfigError, match="unknown setting 'colour'") as error:
            parse_settings(_config(colour="blue"))
        assert "no NAS credential" not in str(error.value)

    def test_the_settings_print_without_the_url_or_token_source(self):
        text = repr(parse_settings({"broker_url": URL, "token_file": "/secret/place/token.txt"}))
        assert "broker.example" not in text and "secret" not in text


class TestLoading:
    def test_a_file_is_read(self, tmp_path):
        path = tmp_path / "adapter.json"
        path.write_text(json.dumps(_config()))
        assert load_settings(path).broker_url == URL

    def test_a_missing_file_is_named(self, tmp_path):
        with pytest.raises(AdapterConfigError, match="does not exist"):
            load_settings(tmp_path / "absent.json")

    def test_broken_json_does_not_echo_the_file(self, tmp_path):
        path = tmp_path / "adapter.json"
        path.write_text('{"broker_url": SECRET-LOOKING-CONTENT')
        with pytest.raises(AdapterConfigError, match="cannot be read as JSON") as error:
            load_settings(path)
        assert "SECRET-LOOKING-CONTENT" not in str(error.value)

    def test_the_default_location_follows_the_environment(self, tmp_path):
        assert (
            default_config_path({"SYNOLOGY_ADAPTER_CONFIG": str(tmp_path / "x.json")})
            == tmp_path / "x.json"
        )
        assert (
            default_config_path({"XDG_CONFIG_HOME": str(tmp_path)})
            == tmp_path / "synology-mcp" / "adapter.json"
        )


class TestProhibitedEnvironment:
    def test_nas_credentials_in_the_environment_are_reported_by_name_only(self):
        environ = {
            "SYNOLOGY_PASSWORD": "Dummy-Password-1",
            "SYNOLOGY_OTP_CODE": "123456",
            "PATH": "/bin",
        }
        assert prohibited_environment(environ) == ["SYNOLOGY_PASSWORD", "SYNOLOGY_OTP_CODE"]

    def test_empty_values_and_other_settings_are_not_a_problem(self):
        assert (
            prohibited_environment(
                {"SYNOLOGY_PASSWORD": "", "SYNOLOGY_URL": "https://nas", "AUTO_LOGIN": "true"}
            )
            == []
        )

    def test_every_listed_name_is_a_nas_credential(self):
        assert set(PROHIBITED_ENVIRONMENT) == {
            "SYNOLOGY_PASSWORD",
            "SYNOLOGY_OTP_CODE",
            "SYNOLOGY_DEVICE_ID",
        }


class TestTokenProvider:
    def test_a_token_is_read_from_the_named_variable(self):
        provider = make_token_provider(parse_settings(_config()), {"BROKER_TOKEN": f"  {TOKEN}\n"})
        assert provider() == TOKEN

    def test_a_token_file_is_read_every_time_so_it_can_be_replaced(self, tmp_path):
        path = tmp_path / "token"
        path.write_text(TOKEN + "\n")
        provider = make_token_provider(parse_settings({"broker_url": URL, "token_file": str(path)}))
        assert provider() == TOKEN
        path.write_text(TOKEN + "-rotated\n")
        assert provider() == TOKEN + "-rotated"

    @pytest.mark.parametrize("raw", ["", "   ", "\n", None])
    def test_an_empty_or_absent_token_is_no_token(self, raw):
        environ = {} if raw is None else {"BROKER_TOKEN": raw}
        assert make_token_provider(parse_settings(_config()), environ)() is None

    @pytest.mark.parametrize(
        "raw",
        ["short", "has a space-inside-it-0123456789", "line\nbreak-0123456789", "x" * 5000],
        ids=["too-short", "inner-space", "inner-newline", "too-long"],
    )
    def test_a_token_that_is_there_but_not_shaped_like_one_is_reported_as_malformed(self, raw):
        """Told apart from a missing one, so the message can say which."""
        provider = make_token_provider(parse_settings(_config()), {"BROKER_TOKEN": raw})
        with pytest.raises(MalformedTokenError) as error:
            provider()
        assert raw not in str(error.value)

    def test_a_malformed_token_file_is_reported_the_same_way(self, tmp_path):
        path = tmp_path / "token"
        path.write_text("too short")
        provider = make_token_provider(parse_settings({"broker_url": URL, "token_file": str(path)}))
        with pytest.raises(MalformedTokenError):
            provider()

    def test_a_missing_token_file_is_no_token(self, tmp_path):
        provider = make_token_provider(
            parse_settings({"broker_url": URL, "token_file": str(tmp_path / "absent")})
        )
        assert provider() is None


class TestTokenFileWarning:
    @staticmethod
    def _settings(path):
        return parse_settings({"broker_url": URL, "token_file": str(path)})

    @pytest.mark.skipif(os.name == "nt", reason="file modes mean something only off Windows")
    @pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666, 0o755])
    def test_a_token_other_accounts_can_read_is_warned_about(self, tmp_path, mode):
        path = tmp_path / "token"
        path.write_text(TOKEN)
        os.chmod(path, mode)
        warning = token_file_warning(self._settings(path))
        assert warning is not None and str(path) in warning and f"{mode:04o}" in warning
        assert TOKEN not in warning

    @pytest.mark.skipif(os.name == "nt", reason="file modes mean something only off Windows")
    @pytest.mark.parametrize("mode", [0o600, 0o400, 0o700])
    def test_a_private_token_file_is_not(self, tmp_path, mode):
        path = tmp_path / "token"
        path.write_text(TOKEN)
        os.chmod(path, mode)
        assert token_file_warning(self._settings(path)) is None

    def test_a_missing_file_and_a_token_from_the_environment_are_not_warned_about(self, tmp_path):
        assert token_file_warning(self._settings(tmp_path / "absent")) is None
        assert token_file_warning(parse_settings(_config())) is None

    def test_the_warning_never_reads_the_file(self, tmp_path, monkeypatch):
        from pathlib import Path

        path = tmp_path / "token"
        path.write_text(TOKEN)

        def refuse(*args, **kwargs):
            raise AssertionError("the token file was read")

        monkeypatch.setattr(Path, "read_text", refuse)
        monkeypatch.setattr(Path, "read_bytes", refuse)
        token_file_warning(self._settings(path))

    @pytest.mark.parametrize(
        "mode,text",
        [
            (0o644, "0644"),
            (0o640, "0640"),
            (0o604, "0604"),
            (0o660, "0660"),
            (0o666, "0666"),
            (0o755, "0755"),
        ],
    )
    def test_any_group_or_other_access_is_warned_about(self, mode, text):
        """The mode logic itself, run on every platform (no filesystem involved)."""
        warning = _mode_warning("/etc/broker.token", mode)
        assert warning is not None and text in warning and "/etc/broker.token" in warning

    @pytest.mark.parametrize("mode", [0o600, 0o400, 0o700, 0o500, 0o000])
    def test_a_mode_private_to_the_owner_is_not(self, mode):
        assert _mode_warning("/etc/broker.token", mode) is None

    def test_the_file_is_looked_at_and_the_result_reported(self, tmp_path, monkeypatch):
        """The wiring, on every platform: the platform check is told this is not
        Windows (in this module only), and a freshly written file is never private
        by default (0666 on Windows, 0644 under the usual umask)."""
        from types import SimpleNamespace

        path = tmp_path / "token"
        path.write_text(TOKEN)
        monkeypatch.setattr("adapter.config.os", SimpleNamespace(name="posix"))
        warning = token_file_warning(self._settings(path))
        assert (
            warning is not None and str(path) in warning and "readable by other accounts" in warning
        )
        assert TOKEN not in warning

    def test_on_windows_there_is_nothing_to_say_because_modes_are_not_permissions(
        self, tmp_path, monkeypatch
    ):
        from types import SimpleNamespace

        path = tmp_path / "token"
        path.write_text(TOKEN)
        monkeypatch.setattr("adapter.config.os", SimpleNamespace(name="nt"))
        assert token_file_warning(self._settings(path)) is None
