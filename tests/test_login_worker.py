"""The sign-in worker and the code that runs it.

The password goes in on standard input and nowhere else; what comes out is a
session or an error code, never anything that could echo what went in. Several
of these tests run the real worker as a subprocess, one of them against a fake
DSM over real TLS with certificate verification on.
"""

import asyncio
import copy
import json
import os
import socket
import subprocess
import sys

import pytest

from private_auth import login as login_module
from private_auth.login import WORKER_PATH, parse_worker_output, run_worker
from private_auth.worker import MAX_INPUT_BYTES, run, validate
from tests.fake_dsm import FakeDsmServer

PASSWORD = "PRIVATE-PASSWORD-MARKER-4d2e"
OTP = "482913"


def _payload(**overrides):
    payload = {
        "base_url": "https://127.0.0.1:9",
        "verify_ssl": True,
        "username": "reader",
        "password": PASSWORD,
        "otp": None,
    }
    payload.update(overrides)
    return payload


class FakeAuth:
    """Stands in for SynologyAuth, returning what DSM would."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, base_url, verify_ssl=True, manual_mode=False):
        self.created = (base_url, verify_ssl, manual_mode)
        return self

    def login(self, username, password, otp_code=None):
        self.calls.append((username, password, otp_code))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class TestValidate:
    def test_a_good_request_passes(self):
        assert validate(_payload(otp="123456"))["otp"] == "123456"

    @pytest.mark.parametrize(
        "change",
        [
            {"base_url": "http://nas.example:5000"},
            {"base_url": "ftp://nas.example"},
            {"base_url": None},
            {"username": ""},
            {"username": 5},
            {"password": ""},
            {"password": "x" * 1025},
            {"otp": "12ab56"},
            {"otp": "123"},
            {"otp": 123456},
            {"verify_ssl": 5},
            {"verify_ssl": None},
        ],
    )
    def test_a_bad_request_is_refused(self, change):
        assert validate(_payload(**change)) is None

    @pytest.mark.parametrize("payload", [None, [], "text", 5])
    def test_a_request_that_is_not_an_object_is_refused(self, payload):
        assert validate(payload) is None

    def test_a_ca_bundle_path_is_accepted_as_the_verify_setting(self):
        assert validate(_payload(verify_ssl="/etc/ssl/ca.pem"))["verify_ssl"] == "/etc/ssl/ca.pem"


class TestRun:
    def test_a_success_yields_only_a_session_and_its_token(self):
        auth = FakeAuth(
            {"success": True, "data": {"sid": "SID-1", "synotoken": "TOK-1", "did": "DEVICE"}}
        )
        result = run(_payload(otp="123456"), auth_factory=auth)

        assert result == {"ok": True, "sid": "SID-1", "synotoken": "TOK-1"}
        assert auth.created == ("https://127.0.0.1:9", True, True)  # manual mode
        assert auth.calls == [("reader", PASSWORD, "123456")]

    def test_a_session_without_a_token_is_fine(self):
        result = run(_payload(), auth_factory=FakeAuth({"success": True, "data": {"sid": "SID-1"}}))
        assert result == {"ok": True, "sid": "SID-1", "synotoken": None}

    @pytest.mark.parametrize("sid", [None, "", 5, "has space", "line\nbreak", "x" * 3000])
    def test_a_session_id_that_is_not_plain_is_a_failure(self, sid):
        result = run(_payload(), auth_factory=FakeAuth({"success": True, "data": {"sid": sid}}))
        assert result == {"ok": False, "code": "worker_error"}

    def test_a_failure_yields_only_its_code(self):
        failure = {"success": False, "error": {"code": 400, "message": f"bad {PASSWORD}"}}
        result = run(_payload(), auth_factory=FakeAuth(failure))
        assert result == {"ok": False, "code": "400"}
        assert PASSWORD not in json.dumps(result)

    @pytest.mark.parametrize(
        "code", ["certificate_error", "connection_timeout", "connection_error", 403]
    )
    def test_other_codes_pass_through(self, code):
        failure = {"success": False, "error": {"code": code}}
        assert run(_payload(), auth_factory=FakeAuth(failure))["code"] == str(code)

    @pytest.mark.parametrize("code", ["has space", "x" * 100, "<script>", "a/b"])
    def test_a_code_that_is_not_plain_becomes_unknown(self, code):
        failure = {"success": False, "error": {"code": code}}
        assert run(_payload(), auth_factory=FakeAuth(failure)) == {"ok": False, "code": "unknown"}

    def test_an_exception_is_a_failure_that_says_nothing(self):
        result = run(_payload(), auth_factory=FakeAuth(RuntimeError(f"boom {PASSWORD}")))
        assert result == {"ok": False, "code": "worker_error"}

    def test_a_bad_request_never_reaches_dsm(self):
        auth = FakeAuth({"success": True, "data": {"sid": "S"}})
        assert run(_payload(password=""), auth_factory=auth) == {
            "ok": False,
            "code": "invalid_request",
        }
        assert auth.calls == []


class TestParseWorkerOutput:
    def test_a_session_is_accepted(self):
        out = b'{"ok": true, "sid": "SID-1", "synotoken": "TOK-1"}\n'
        assert parse_worker_output(out) == {"ok": True, "sid": "SID-1", "synotoken": "TOK-1"}

    def test_extra_fields_are_dropped(self):
        out = json.dumps(
            {"ok": True, "sid": "S", "synotoken": None, "did": "DEVICE", "password": PASSWORD}
        )
        assert parse_worker_output(out.encode()) == {"ok": True, "sid": "S", "synotoken": None}

    def test_the_last_line_counts(self):
        out = b'noise\n{"ok": false, "code": "400"}\n'
        assert parse_worker_output(out) == {"ok": False, "code": "400"}

    @pytest.mark.parametrize(
        "out",
        [
            b"",
            b"\n",
            b"not json",
            b"[1,2]",
            b'"text"',
            b'{"ok": true}',
            b'{"ok": true, "sid": "has space"}',
            b'{"ok": true, "sid": "S", "synotoken": "has space"}',
            b'{"ok": "yes"}',
        ],
    )
    def test_anything_else_is_a_failure(self, out):
        assert parse_worker_output(out)["ok"] is False

    @pytest.mark.parametrize("code", [5, None, "has space", "a" * 80, "<b>"])
    def test_an_unsafe_code_becomes_unknown(self, code):
        out = json.dumps({"ok": False, "code": code}).encode()
        assert parse_worker_output(out) == {"ok": False, "code": "unknown"}


def _run_worker_process(payload_bytes: bytes):
    return subprocess.run(
        [sys.executable, "-I", str(WORKER_PATH)],
        input=payload_bytes,
        capture_output=True,
        timeout=60,
        env={k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "TEMP", "TMP") if k in os.environ},
    )


class TestWorkerProcess:
    def test_it_prints_one_line_and_nothing_to_stderr(self):
        done = _run_worker_process(json.dumps(_payload()).encode())

        lines = done.stdout.decode().strip().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["ok"] is False
        assert done.stderr == b""
        assert PASSWORD.encode() not in done.stdout + done.stderr

    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param(b"", id="empty"),
            pytest.param(b"not json", id="not-json"),
            pytest.param(b"[]", id="not-an-object"),
            pytest.param(b'{"base_url": 1}', id="wrong-types"),
            pytest.param(b"x" * (MAX_INPUT_BYTES + 10), id="oversized"),
        ],
    )
    def test_it_refuses_bad_input_quietly(self, raw):
        done = _run_worker_process(raw)
        assert json.loads(done.stdout.decode().strip()) == {"ok": False, "code": "invalid_request"}
        assert done.stderr == b""

    def test_it_ignores_a_dotenv_and_the_callers_credentials(self, tmp_path):
        """Started from a directory with a .env, and an environment that carries
        credentials, it still runs in manual mode and reads neither."""
        (tmp_path / ".env").write_text("SYNOLOGY_PASSWORD=from-dotenv\nAUTO_LOGIN=true\n")
        env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "TEMP", "TMP") if k in os.environ}
        env.update(
            {"SYNOLOGY_PASSWORD": "from-env", "AUTO_LOGIN": "true", "SYNOLOGY_AUTH_MODE": "legacy"}
        )
        done = subprocess.run(
            [sys.executable, "-I", str(WORKER_PATH)],
            input=json.dumps(_payload()).encode(),
            capture_output=True,
            timeout=60,
            cwd=tmp_path,
            env=env,
        )
        assert json.loads(done.stdout.decode().strip())["ok"] is False
        assert done.stderr == b""


class TestAgainstARealTlsEndpoint:
    """The real worker, the real SynologyAuth, a fake DSM over TLS that the
    worker verifies against the test certificate."""

    @pytest.fixture
    def dsm(self, tmp_path):
        with FakeDsmServer(tmp_path, accounts={"reader": PASSWORD}, otp_accounts={}) as server:
            yield server

    def _payload(self, dsm, **overrides):
        return _payload(base_url=dsm.base_url, verify_ssl=str(dsm.cert_path), **overrides)

    @pytest.mark.asyncio
    async def test_a_valid_sign_in_returns_a_session(self, dsm):
        result = await run_worker(self._payload(dsm))
        assert result == {
            "ok": True,
            "sid": "FAKE-SID-from-dsm",
            "synotoken": "FAKE-TOKEN-from-dsm",
        }

    @pytest.mark.asyncio
    async def test_the_password_travels_in_the_post_body_never_in_a_url(self, dsm):
        await run_worker(self._payload(dsm))

        method, path, form = dsm.requests[-1]
        assert method == "POST"
        assert PASSWORD not in path
        assert form["passwd"] == PASSWORD
        assert all(PASSWORD not in p for _, p, _ in dsm.requests)

    @pytest.mark.asyncio
    async def test_no_device_token_is_requested_or_returned(self, dsm):
        result = await run_worker(self._payload(dsm, otp=OTP))
        assert "enable_device_token" not in dsm.requests[-1][2]
        assert "device_id" not in dsm.requests[-1][2]
        assert set(result) == {"ok", "sid", "synotoken"}

    @pytest.mark.asyncio
    async def test_a_wrong_password_is_reported_as_a_code_and_not_retried_with_other_versions(
        self, dsm
    ):
        result = await run_worker(self._payload(dsm, password="WRONG-" + PASSWORD))
        assert result == {"ok": False, "code": "400"}
        assert len(dsm.requests) == 1  # DSM's answer is final: no further versions tried

    @pytest.mark.asyncio
    async def test_a_code_is_asked_for_and_then_checked(self, tmp_path):
        with FakeDsmServer(
            tmp_path, accounts={"reader": PASSWORD}, otp_accounts={"reader": OTP}
        ) as dsm:
            payload = dict(base_url=dsm.base_url, verify_ssl=str(dsm.cert_path))
            asked = await run_worker(_payload(**payload))
            wrong = await run_worker(_payload(otp="000000", **payload))
            right = await run_worker(_payload(otp=OTP, **payload))

        assert asked == {"ok": False, "code": "403"}
        assert wrong == {"ok": False, "code": "404"}
        assert right["ok"] is True

    @pytest.mark.asyncio
    async def test_a_certificate_that_does_not_verify_stops_before_anything_is_sent(self, dsm):
        result = await run_worker(_payload(base_url=dsm.base_url, verify_ssl=True))
        assert result == {"ok": False, "code": "certificate_error"}
        assert dsm.requests == []  # nothing, so no password, reached the server


class TestRunWorkerDiscipline:
    @pytest.mark.asyncio
    async def test_an_unreachable_nas_is_a_code_not_a_traceback(self):
        result = await run_worker(_payload())
        assert result["ok"] is False and result["code"] in {
            "connection_error",
            "connection_timeout",
        }

    @pytest.mark.asyncio
    async def test_a_worker_that_outlives_its_deadline_is_killed(self):
        """A server that accepts and never answers: the worker would wait for its
        own long timeout, but it is stopped at the deadline."""
        silent = socket.socket()
        silent.bind(("127.0.0.1", 0))
        silent.listen(5)
        try:
            started = asyncio.get_running_loop().time()
            result = await run_worker(
                _payload(base_url=f"https://127.0.0.1:{silent.getsockname()[1]}"), deadline=1.5
            )
            took = asyncio.get_running_loop().time() - started
        finally:
            silent.close()

        assert result == {"ok": False, "code": "timeout"}
        assert took < 8

    @pytest.mark.asyncio
    async def test_the_password_reaches_the_worker_on_stdin_only(self, monkeypatch):
        """Spy on how the process is started: the marker must not appear in its
        arguments, its environment or its working directory, and must be in what
        is written to its standard input. Credentials in this process's own
        environment must not be inherited."""
        monkeypatch.setenv("SYNOLOGY_PASSWORD", "inherited-must-not-leak")
        monkeypatch.setenv("SYNOLOGY_USERNAME", "inherited-user")
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
        seen = {}
        real_exec = asyncio.create_subprocess_exec

        async def spy(*args, **kwargs):
            process = await real_exec(*args, **kwargs)
            seen.update(args=args, kwargs=kwargs)
            real_communicate = process.communicate

            async def communicate(input=None):
                seen["stdin"] = input
                return await real_communicate(input)

            process.communicate = communicate
            return process

        monkeypatch.setattr(login_module.asyncio, "create_subprocess_exec", spy)
        await run_worker(_payload(otp=OTP))

        everything_else = (
            " ".join(map(str, seen["args"])) + " " + json.dumps(seen["kwargs"], default=str)
        )
        assert PASSWORD not in everything_else and OTP not in everything_else
        assert PASSWORD.encode() in seen["stdin"] and OTP.encode() in seen["stdin"]
        env = seen["kwargs"]["env"]
        assert env["SYNOLOGY_AUTH_MODE"] == "broker"
        assert not [k for k in env if k.startswith("SYNOLOGY_") and k != "SYNOLOGY_AUTH_MODE"]
        assert "HTTPS_PROXY" not in env and "AUTO_LOGIN" not in env
        assert seen["kwargs"]["stderr"] == asyncio.subprocess.DEVNULL
        assert "-I" in seen["args"]  # isolated mode: no user site, no PYTHON* variables

    @pytest.mark.asyncio
    async def test_the_payload_given_to_the_service_is_not_changed_by_running(self):
        payload = _payload()
        before = copy.deepcopy(payload)
        await run_worker(payload)
        assert payload == before


class TestWorkerEnvironment:
    def test_certificate_trust_settings_are_kept_for_a_private_ca(self, monkeypatch):
        from private_auth.login import _minimal_environment

        for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"):
            monkeypatch.setenv(name, f"/etc/ssl/{name.lower()}.pem")

        env = _minimal_environment()

        for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"):
            assert env[name] == f"/etc/ssl/{name.lower()}.pem"

    @pytest.mark.parametrize(
        "name",
        [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "NO_PROXY",
            "SYNOLOGY_PASSWORD",
            "SYNOLOGY_URL",
            "AUTO_LOGIN",
            "PYTHONPATH",
            "PYTHONSTARTUP",
        ],
    )
    def test_proxies_credentials_and_python_settings_are_not_inherited(self, monkeypatch, name):
        from private_auth.login import _minimal_environment

        monkeypatch.setenv(name, "leak-me")
        assert name not in _minimal_environment()
        assert _minimal_environment()["SYNOLOGY_AUTH_MODE"] == "broker"

    def test_the_choice_to_drop_proxies_is_written_down(self):
        from private_auth.login import _minimal_environment

        assert "proxy" in _minimal_environment.__doc__.lower()
