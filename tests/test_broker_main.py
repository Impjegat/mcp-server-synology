"""The broker's entry point: what it refuses to start with, and a real start.

The smoke tests run `broker_main.py` as a subprocess, on a loopback port, with
a `.env` file holding a dummy password in its working directory and an
environment that asks for legacy mode. It must come up in broker mode anyway,
read neither, and answer an MCP client over real HTTP.
"""

import datetime
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx2
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

import broker_main
from broker.policy import hash_token
from tests.broker_support import future_expiry

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "smoke-token-value"
DUMMY_PASSWORD = "Dummy-Password-5e1c"
PASSWORD = "PRIVATE-PASSWORD-MARKER-4d2e"


@pytest.fixture(autouse=True)
def _restore_auth_mode(monkeypatch):
    """`main()` sets SYNOLOGY_AUTH_MODE for the process it runs in. Here that is
    the test process, so put it back afterwards: monkeypatch undoes this."""
    monkeypatch.setenv("SYNOLOGY_AUTH_MODE", "")


def test_importing_the_entry_point_changes_nothing():
    """Collection imports every test module; an import that set the mode would
    put the whole test session into broker mode."""
    code = (
        "import os, sys; sys.path.insert(0, sys.argv[1]); import broker_main; "
        "print(os.environ.get('SYNOLOGY_AUTH_MODE'), 'src' in ' '.join(sys.path[:1]))"
    )
    env = {k: v for k, v in os.environ.items() if k != "SYNOLOGY_AUTH_MODE"}
    out = subprocess.run(
        [sys.executable, "-c", code, str(ROOT)], capture_output=True, text=True, env=env, check=True
    ).stdout
    assert out.split() == ["None", "False"]


class TestNewToken:
    def test_it_prints_a_token_and_the_digest_to_put_in_the_policy(self, capsys):
        assert broker_main.main(["new-token"]) == 0
        lines = [
            line.strip() for line in capsys.readouterr().out.splitlines() if line.startswith("  ")
        ]
        token, digest, expires = lines
        assert digest == hash_token(token)
        assert len(token) >= 40
        # A grant also needs an end date, so the command suggests a real one: a date
        # the policy parser would accept, about a year ahead and not past the limit.
        suggested = datetime.date.fromisoformat(json.loads("{" + expires + "}")["expires"])
        assert 360 <= (suggested - datetime.date.today()).days <= 366

    def test_each_token_is_different(self, capsys):
        broker_main.main(["new-token"])
        first = capsys.readouterr().out
        broker_main.main(["new-token"])
        assert capsys.readouterr().out != first


class TestRefusals:
    @pytest.mark.parametrize(
        "argv,message",
        [
            (["serve", "--policy", "p.json"], "without TLS"),
            (
                ["serve", "--policy", "p.json", "--host", "0.0.0.0", "--allow-plain-http-loopback"],
                "without TLS",
            ),
            (
                ["serve", "--policy", "p.json", "--tls-cert", "c.pem"],
                "both --tls-cert and --tls-key",
            ),
            (
                ["serve", "--policy", "p.json", "--tls-key", "k.pem"],
                "both --tls-cert and --tls-key",
            ),
            (
                [
                    "serve",
                    "--policy",
                    "p.json",
                    "--host",
                    "0.0.0.0",
                    "--tls-cert",
                    "c",
                    "--tls-key",
                    "k",
                ],
                "--allowed-host",
            ),
        ],
    )
    def test_it_will_not_start_unsafely(self, argv, message, capsys):
        assert broker_main.main(argv) == 2
        assert message in capsys.readouterr().err

    def test_plain_http_is_for_loopback_testing_only(self, capsys):
        # Loopback plus the explicit flag gets past the transport rules; it then
        # stops on the missing policy file rather than serving.
        code = broker_main.main(
            ["serve", "--policy", "does-not-exist.json", "--allow-plain-http-loopback"]
        )
        assert code == 2
        error = capsys.readouterr().err
        assert "without TLS" not in error
        assert "Policy error" in error or "Configuration errors" in error


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _environment(tmp_path, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SYNOLOGY_", "AUTO_LOGIN"))}
    env["XDG_CONFIG_HOME"] = str(tmp_path / "config")
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra)
    return env


def _write_policy(tmp_path, document):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document))
    return path


def _start(tmp_path, policy, port, extra_args=(), **env):
    # A hostile working directory: a .env with a password, which broker mode must not read.
    workdir = tmp_path / "work"
    workdir.mkdir(exist_ok=True)
    (workdir / ".env").write_text(f"SYNOLOGY_PASSWORD={DUMMY_PASSWORD}\nAUTO_LOGIN=true\n")
    return subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "broker_main.py"),
            "serve",
            "--policy",
            str(policy),
            "--port",
            str(port),
            "--allow-plain-http-loopback",
            *extra_args,
        ],
        cwd=workdir,
        env=_environment(tmp_path, **env),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _wait_until_up(process, port, seconds=40):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"the broker exited early:\n{process.stdout.read()}")
        try:
            if httpx2.get(f"http://127.0.0.1:{port}/healthz", timeout=2).status_code == 200:
                return
        except httpx2.HTTPError:
            time.sleep(0.2)
    process.kill()
    raise AssertionError(f"the broker did not come up:\n{process.stdout.read()}")


def _stop(process):
    process.terminate()
    try:
        return process.communicate(timeout=20)[0]
    except subprocess.TimeoutExpired:
        process.kill()
        return process.communicate()[0]


def _policy_document(nas="default"):
    return {
        "clients": {
            "smoke": {"token_sha256": hash_token(TOKEN), "nas": [nas], "expires": future_expiry()},
        }
    }


@pytest.mark.slow
class TestRealStart:
    @pytest.mark.asyncio
    async def test_it_serves_mcp_in_broker_mode_whatever_the_environment_says(self, tmp_path):
        policy = _write_policy(tmp_path, _policy_document())
        port = _free_port()
        process = _start(
            tmp_path,
            policy,
            port,
            SYNOLOGY_URL="https://nas.example.test:5001",
            SYNOLOGY_AUTH_MODE="legacy",  # asked for legacy; the entry point must ignore that
        )
        try:
            _wait_until_up(process, port)

            async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}) as http:
                async with streamable_http_client(
                    f"http://127.0.0.1:{port}/mcp", http_client=http
                ) as streams:
                    async with ClientSession(streams[0], streams[1]) as session:
                        await session.initialize()
                        names = {t.name for t in (await session.list_tools()).tools}
                        status = await session.call_tool("synology_status", {})
                        shares = await session.call_tool("list_shares", {"nas_name": "default"})

            refused = httpx2.post(f"http://127.0.0.1:{port}/mcp", json={}, timeout=5)
            wrong = httpx2.post(
                f"http://127.0.0.1:{port}/mcp",
                json={},
                headers={"Authorization": "Bearer nope"},
                timeout=5,
            )
        finally:
            output = _stop(process)

        assert "synology_login" not in names and "list_shares" in names
        assert "manual" in status.content[0].text
        assert shares.is_error is True and shares.content[0].text.startswith(
            "AUTHENTICATION_REQUIRED"
        )
        assert (refused.status_code, wrong.status_code) == (401, 401)
        # Neither the .env password nor a client token reached the log.
        assert DUMMY_PASSWORD not in output and TOKEN not in output

    @pytest.mark.asyncio
    async def test_a_grant_that_has_ended_is_named_at_start_up_and_refused_while_others_work(
        self, tmp_path
    ):
        """Implementation review R12, against a real broker process."""
        ended_token = "ended-client-token-0123456789abcdefghij0123456789"
        yesterday = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        soon = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=5)
        document = _policy_document()
        document["clients"]["ended"] = {
            "token_sha256": hash_token(ended_token),
            "nas": ["default"],
            "expires": yesterday.isoformat(),
        }
        document["clients"]["soon"] = {
            "token_sha256": hash_token("soon-client-token-0123456789abcdefghij012345"),
            "nas": ["default"],
            "expires": soon.isoformat(),
        }
        policy = _write_policy(tmp_path, document)
        port = _free_port()
        process = _start(tmp_path, policy, port, SYNOLOGY_URL="https://nas.example.test:5001")
        try:
            _wait_until_up(process, port)
            url = f"http://127.0.0.1:{port}/mcp"
            ended = httpx2.post(
                url, json={}, headers={"Authorization": f"Bearer {ended_token}"}, timeout=5
            )
            live = httpx2.post(
                url, json={}, headers={"Authorization": f"Bearer {TOKEN}"}, timeout=5
            )
        finally:
            output = _stop(process)

        assert ended.status_code == 401
        assert live.status_code != 401  # the token is good; the empty body is what it objects to
        assert "client 'ended' ended on" in output
        assert "client 'soon' ends in 5 day(s)" in output
        assert "client 'smoke'" not in output  # nothing to say about a grant with time left
        for secret in (ended_token, hash_token(ended_token), TOKEN):
            assert secret not in output

    def test_it_stops_on_a_policy_that_names_an_unknown_nas(self, tmp_path):
        policy = _write_policy(tmp_path, _policy_document(nas="elsewhere"))
        process = _start(
            tmp_path, policy, _free_port(), SYNOLOGY_URL="https://nas.example.test:5001"
        )
        output = _stop_after_exit(process)

        assert process.returncode == 2
        assert "not a configured NAS" in output

    def test_it_stops_when_no_nas_is_configured(self, tmp_path):
        policy = _write_policy(tmp_path, _policy_document())
        process = _start(tmp_path, policy, _free_port())
        output = _stop_after_exit(process)

        assert process.returncode == 2
        assert "No NAS endpoint" in output


def _stop_after_exit(process, seconds=40):
    try:
        return process.communicate(timeout=seconds)[0]
    except subprocess.TimeoutExpired:
        process.kill()
        raise AssertionError("the broker should have exited")


class TestPrivateLoginRefusals:
    BASE = ["serve", "--policy", "p.json", "--allow-plain-http-loopback"]

    @pytest.mark.parametrize(
        "extra,message",
        [
            (
                ["--private-origin", "https://b.example:8444", "--private-host", "0.0.0.0"],
                "without TLS",
            ),
            (
                ["--private-origin", "https://b.example:8444", "--private-tls-cert", "c"],
                "both --private-tls-cert",
            ),
            (["--private-origin", "ftp://b.example"], "must be a URL"),
            (["--private-origin", "not a url"], "must be a URL"),
        ],
    )
    def test_it_will_not_start_the_private_login_unsafely(self, extra, message, capsys):
        assert broker_main.main(self.BASE + extra) == 2
        assert message in capsys.readouterr().err

    def test_a_private_login_off_loopback_needs_its_own_allowed_host(self, capsys):
        argv = [
            "serve",
            "--policy",
            "p.json",
            "--host",
            "0.0.0.0",
            "--tls-cert",
            "c",
            "--tls-key",
            "k",
        ]
        argv += ["--allowed-host", "b.example", "--private-origin", "https://b.example:8444"]
        assert broker_main.main(argv) == 2
        assert "--private-allowed-host" in capsys.readouterr().err

    def test_a_plain_http_origin_needs_the_loopback_flag_and_a_loopback_address(self, capsys):
        argv = [
            "serve",
            "--policy",
            "p.json",
            "--tls-cert",
            "c",
            "--tls-key",
            "k",
            "--allowed-host",
            "b.example",
        ]
        argv += ["--private-origin", "http://b.example:8444", "--private-allowed-host", "b.example"]
        assert broker_main.main(argv) == 2
        assert "must be https" in capsys.readouterr().err


class TestEnrollCommand:
    def _run(self, store, *args, capsys):
        code = broker_main.main(["enroll", "--owner-store", str(store), *args])
        out = capsys.readouterr()
        return code, out.out, out.err

    def test_it_prints_a_one_time_code(self, tmp_path, capsys):
        code, out, _ = self._run(tmp_path / "owner.json", "new-code", capsys=capsys)
        assert code == 0 and "One-time enrollment code" in out and "/enroll" in out
        printed = [line.strip() for line in out.splitlines() if line.startswith("  ")]
        assert len(printed) == 1 and len(printed[0]) >= 10

    def test_it_lists_and_removes_passkeys(self, tmp_path, capsys):
        from private_auth.owner import OwnerStore

        store = OwnerStore(tmp_path / "owner.json")
        store.add_credential(b"\x01\x02\x03", b"public", 0, "my phone")
        _, listing, _ = self._run(tmp_path / "owner.json", "list", capsys=capsys)
        ident = listing.split()[0]
        assert "my phone" in listing

        code, out, _ = self._run(tmp_path / "owner.json", "revoke", ident, capsys=capsys)
        assert code == 0 and "Removed" in out
        assert (
            "No passkey is enrolled" in self._run(tmp_path / "owner.json", "list", capsys=capsys)[1]
        )
        assert self._run(tmp_path / "owner.json", "revoke", ident, capsys=capsys)[0] == 1

    def test_a_second_passkey_needs_add_device(self, tmp_path, capsys):
        from private_auth.owner import OwnerStore

        OwnerStore(tmp_path / "owner.json").add_credential(b"id", b"key", 0, "first")
        code, _, err = self._run(tmp_path / "owner.json", "new-code", capsys=capsys)
        assert code == 2 and "already enrolled" in err
        assert self._run(tmp_path / "owner.json", "new-code", "--add-device", capsys=capsys)[0] == 0


@pytest.mark.slow
class TestPrivateLoginEndToEnd:
    @pytest.mark.asyncio
    async def test_enrol_sign_in_and_try_a_login_beside_the_mcp_listener(self, tmp_path, capsys):
        pytest.importorskip("webauthn")
        from tests.software_authenticator import SoftwareAuthenticator

        policy = _write_policy(tmp_path, _policy_document())
        port, private_port = _free_port(), _free_port()
        store = tmp_path / "owner.json"
        origin = f"http://127.0.0.1:{private_port}"
        process = _start(
            tmp_path,
            policy,
            port,
            extra_args=[
                "--private-origin",
                origin,
                "--private-port",
                str(private_port),
                "--owner-store",
                str(store),
            ],
            SYNOLOGY_URL="https://127.0.0.1:9",  # refused at once: no DNS,
        )
        try:
            _wait_until_up(process, port)
            for _ in range(100):
                try:
                    if httpx2.get(f"{origin}/healthz", timeout=2).status_code == 200:
                        break
                except httpx2.HTTPError:
                    pass
                time.sleep(0.2)
            else:
                raise AssertionError("the private login did not come up")

            headers = {"Origin": origin}
            async with httpx2.AsyncClient(base_url=origin, timeout=60) as http:
                front = await http.get("/")
                assert "No owner enrolled" in front.text and "smoke" not in front.text
                assert front.headers["cache-control"] == "no-store"
                assert "default-src 'none'" in front.headers["content-security-policy"]

                # Enrol with a code made on the host, as the owner would.
                assert broker_main.main(["enroll", "--owner-store", str(store), "new-code"]) == 0
                lines = capsys.readouterr().out.splitlines()
                code = [line.strip() for line in lines if line.startswith("  ")][0]
                device = SoftwareAuthenticator("127.0.0.1", origin)
                begun = (
                    await http.post("/enroll/begin", headers=headers, json={"code": code})
                ).json()
                done = await http.post(
                    "/enroll/finish",
                    headers=headers,
                    json={
                        "state": begun["state"],
                        "label": "phone",
                        "credential": device.create(begun["options"]),
                    },
                )
                assert done.status_code == 200

                # Sign in with the passkey.
                begun = (await http.post("/auth/begin", headers=headers, json={})).json()
                done = await http.post(
                    "/auth/finish",
                    headers=headers,
                    json={"state": begun["state"], "credential": device.get(begun["options"])},
                )
                assert done.status_code == 200

                # A model's call, on the MCP listener, leaves a request waiting here.
                async with httpx2.AsyncClient(
                    headers={"Authorization": f"Bearer {TOKEN}"}
                ) as mcp_http:
                    mcp_url = f"http://127.0.0.1:{port}/mcp"
                    async with streamable_http_client(mcp_url, http_client=mcp_http) as streams:
                        async with ClientSession(streams[0], streams[1]) as session:
                            await session.initialize()
                            reply = await session.call_tool("list_shares", {"nas_name": "default"})
                reply_text = reply.content[0].text
                assert reply_text.startswith("AUTHENTICATION_REQUIRED")
                assert "/login" not in reply_text and origin not in reply_text

                dashboard = (await http.get("/")).text
                assert "smoke" in dashboard and "waiting for you to sign in" in dashboard
                location = re.search(r'href="(/login/[^"]+)"', dashboard).group(1)
                csrf = re.search(r'name="csrf" value="([^"]+)"', dashboard).group(1)

                page = await http.get(location)
                assert "Sign in to the NAS" in page.text

                # Try a login. The NAS here is unreachable; that must come back as a plain sentence.
                attempt = await http.post(
                    location,
                    headers=headers,
                    data={"csrf": csrf, "password": PASSWORD, "username": "reader"},
                )
                assert attempt.status_code == 200 and "could not be reached" in attempt.text
                assert PASSWORD not in attempt.text and PASSWORD not in str(dict(attempt.headers))

            # The MCP listener serves none of the private pages.
            assert httpx2.get(f"http://127.0.0.1:{port}/login/x", timeout=5).status_code in (
                401,
                404,
            )
            posted = httpx2.post(f"http://127.0.0.1:{port}/auth/begin", json={}, timeout=5)
            assert posted.status_code in (401, 404, 405)
        finally:
            output = _stop(process)

        assert PASSWORD not in output and TOKEN not in output and code not in output
