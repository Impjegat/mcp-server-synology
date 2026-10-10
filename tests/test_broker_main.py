"""The broker's entry point: what it refuses to start with, and a real start.

The smoke tests run `broker_main.py` as a subprocess, on a loopback port, with
a `.env` file holding a dummy password in its working directory and an
environment that asks for legacy mode. It must come up in broker mode anyway,
read neither, and answer an MCP client over real HTTP.
"""

import json
import os
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

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "smoke-token-value"
DUMMY_PASSWORD = "Dummy-Password-5e1c"


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
        token, digest = lines
        assert digest == hash_token(token)
        assert len(token) >= 40

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


def _start(tmp_path, policy, port, **env):
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
            "smoke": {"token_sha256": hash_token(TOKEN), "nas": [nas]},
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
