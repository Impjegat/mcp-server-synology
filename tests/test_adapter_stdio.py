"""The real adapter, over real stdio, in front of the real broker over loopback.

These start two processes, so they are slow and few. They show what the unit tests
cannot: that the adapter starts and answers with the broker down, that standard
output carries nothing but protocol, that a credential in the environment or in a
tool call never gets past it, that no setting of the old server can reach it, and
that it cannot sign in by itself.
"""

import contextlib
import json
import os
import subprocess
import sys
import time

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError

from tests.test_broker_main import (
    ROOT,
    TOKEN,
    _free_port,
    _policy_document,
    _start,
    _stop,
    _wait_until_up,
    _write_policy,
)

ADAPTER = str(ROOT / "adapter_main.py")
PASSWORD = "PRIVATE-PASSWORD-MARKER-4d2e"
WRONG_TOKEN = "wrong-token-value-0123456789"


def _config(port, **overrides):
    config = {
        "broker_url": f"http://127.0.0.1:{port}/mcp",
        "allow_insecure_loopback": True,
        "token_env": "ADAPTER_TEST_TOKEN",
        "connect_timeout": 3,
        "list_timeout": 20,
        "call_timeout": 30,
    }
    config.update(overrides)
    return config


def _write_config(tmp_path, config):
    path = tmp_path / "adapter.json"
    path.write_text(json.dumps(config))
    return path


@contextlib.asynccontextmanager
async def adapter(tmp_path, port, *, token=TOKEN, env=None, **config):
    """A client session on a real adapter process. Its standard error goes to
    `tmp_path/adapter.err` so a test can read exactly what it logged."""
    path = _write_config(tmp_path, _config(port, **config))
    params = StdioServerParameters(
        command=sys.executable,
        args=[ADAPTER, "--config", str(path)],
        env={"ADAPTER_TEST_TOKEN": token, **(env or {})},
        cwd=str(tmp_path),
    )
    with open(tmp_path / "adapter.err", "w", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


def adapter_log(tmp_path) -> str:
    return (tmp_path / "adapter.err").read_text(encoding="utf-8", errors="replace")


@pytest.fixture
def broker(tmp_path):
    """A real broker process on a loopback port, stopped afterwards. Its output
    is kept in `broker.output` once it has stopped."""

    class Running:
        port = _free_port()
        process = None
        output = ""

        def start(self):
            self.process = _start(
                tmp_path,
                _write_policy(tmp_path, _policy_document()),
                self.port,
                SYNOLOGY_URL="https://127.0.0.1:9",
            )
            _wait_until_up(self.process, self.port)

        def stop(self):
            if self.process is not None and self.process.poll() is None:
                self.output = _stop(self.process)
            return self.output

    running = Running()
    yield running
    running.stop()


@pytest.mark.slow
class TestThroughTheAdapter:
    @pytest.mark.asyncio
    async def test_a_client_reaches_the_broker_through_the_adapter(self, tmp_path, broker):
        broker.start()
        async with adapter(tmp_path, broker.port) as session:
            tools = {t.name for t in (await session.list_tools()).tools}
            shares = await session.call_tool("list_shares", {"nas_name": "default"})
            status = await session.call_tool("synology_status", {})

        assert "list_shares" in tools and "synology_login" not in tools
        assert shares.is_error is True and shares.content[0].text.startswith(
            "AUTHENTICATION_REQUIRED"
        )
        assert status.is_error is False and "manual" in status.content[0].text
        assert TOKEN not in adapter_log(tmp_path)

    @pytest.mark.asyncio
    async def test_it_starts_and_answers_with_the_broker_down_and_recovers_when_it_returns(
        self, tmp_path, broker
    ):
        started = time.monotonic()
        async with adapter(tmp_path, broker.port) as session:
            assert time.monotonic() - started < 30  # initialising needed no broker

            with pytest.raises(MCPError) as error:
                await session.list_tools()
            down = await session.call_tool("list_shares", {"nas_name": "default"})

            broker.start()  # the broker comes up after the adapter
            tools = {t.name for t in (await session.list_tools()).tools}

        assert error.value.error.message.startswith("BROKER_UNAVAILABLE: ")
        assert down.is_error is True and down.content[0].text.startswith("BROKER_UNAVAILABLE: ")
        assert "list_shares" in tools
        log = adapter_log(tmp_path)
        assert "127.0.0.1" not in log and TOKEN not in log

    @pytest.mark.asyncio
    async def test_a_token_the_broker_does_not_accept_is_reported_without_being_shown(
        self, tmp_path, broker
    ):
        broker.start()
        async with adapter(tmp_path, broker.port, token=WRONG_TOKEN) as session:
            result = await session.call_tool("synology_status", {})

        assert result.is_error is True and result.content[0].text.startswith(
            "BROKER_UNAUTHORIZED: "
        )
        assert WRONG_TOKEN not in result.content[0].text and WRONG_TOKEN not in adapter_log(
            tmp_path
        )

    @pytest.mark.asyncio
    async def test_a_credential_in_a_tool_call_never_reaches_the_broker(self, tmp_path, broker):
        broker.start()
        async with adapter(tmp_path, broker.port) as session:
            refused = await session.call_tool(
                "list_shares", {"nas_name": "default", "password": PASSWORD, "otp_code": "123456"}
            )
        output = broker.stop()

        assert refused.is_error is True and refused.content[0].text.startswith(
            "CREDENTIALS_REFUSED: "
        )
        assert PASSWORD not in refused.content[0].text
        assert (
            PASSWORD not in output
            and "123456" not in output
            and PASSWORD not in adapter_log(tmp_path)
        )

    @pytest.mark.asyncio
    async def test_the_old_servers_settings_cannot_reach_it(self, tmp_path, broker):
        """A .env in its working directory, and the old server's URL and username in
        its environment, change nothing: it reads none of them."""
        (tmp_path / "work").mkdir()
        (tmp_path / "work" / ".env").write_text(f"SYNOLOGY_PASSWORD={PASSWORD}\nAUTO_LOGIN=true\n")
        broker.start()
        env = {
            "SYNOLOGY_URL": "https://nas.example.test:5001",
            "SYNOLOGY_USERNAME": "admin",
            "AUTO_LOGIN": "true",
        }
        path = _write_config(tmp_path, _config(broker.port))
        params = StdioServerParameters(
            command=sys.executable,
            args=[ADAPTER, "--config", str(path)],
            env={"ADAPTER_TEST_TOKEN": TOKEN, **env},
            cwd=str(tmp_path / "work"),
        )
        with open(tmp_path / "adapter.err", "w", encoding="utf-8") as errlog:
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    status = await session.call_tool("synology_status", {})
        output = broker.stop()

        assert tools.tools and status.is_error is False
        assert PASSWORD not in adapter_log(tmp_path) + output + status.content[0].text
        assert "nas.example.test" not in adapter_log(tmp_path)


def _run_adapter(tmp_path, config=None, env=None, args=None, write=True):
    path = tmp_path / "adapter.json"
    if config is not None and write:
        path.write_text(json.dumps(config))
    argv = [sys.executable, ADAPTER] + (args if args is not None else ["--config", str(path)])
    full_env = {"PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
    full_env.update(env or {})
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=60, env=full_env, cwd=tmp_path
    )


@pytest.mark.slow
class TestRefusesToStart:
    def test_with_a_nas_credential_in_its_environment(self, tmp_path):
        done = _run_adapter(
            tmp_path,
            _config(1234),
            {
                "SYNOLOGY_PASSWORD": PASSWORD,
                "SYNOLOGY_OTP_CODE": "123456",
                "ADAPTER_TEST_TOKEN": TOKEN,
            },
        )

        assert done.returncode == 2
        assert "SYNOLOGY_PASSWORD" in done.stderr and "SYNOLOGY_OTP_CODE" in done.stderr
        assert PASSWORD not in done.stderr and "123456" not in done.stderr
        assert done.stdout == ""

    def test_with_no_configuration(self, tmp_path):
        done = _run_adapter(tmp_path, args=["--config", str(tmp_path / "absent.json")])
        assert done.returncode == 2 and "does not exist" in done.stderr and done.stdout == ""

    def test_with_a_credential_setting_in_the_configuration(self, tmp_path):
        done = _run_adapter(
            tmp_path, _config(1234, password=PASSWORD), {"ADAPTER_TEST_TOKEN": TOKEN}
        )
        assert done.returncode == 2
        assert "password" in done.stderr and "holds no NAS credential" in done.stderr
        assert PASSWORD not in done.stderr and done.stdout == ""

    def test_with_a_token_written_into_the_configuration(self, tmp_path):
        done = _run_adapter(tmp_path, _config(1234, token=TOKEN))
        assert done.returncode == 2 and TOKEN not in done.stderr


@pytest.mark.slow
@pytest.mark.skipif(os.name == "nt", reason="file modes mean something only off Windows")
class TestTokenFileWarningAtStartup:
    @pytest.mark.parametrize("mode,warned", [(0o644, True), (0o600, False)])
    def test_a_token_file_other_accounts_can_read_is_warned_about_on_stderr(
        self, tmp_path, mode, warned
    ):
        token = tmp_path / "broker.token"
        token.write_text(TOKEN)
        os.chmod(token, mode)
        config = _config(1)
        del config["token_env"]
        config["token_file"] = str(token)
        path = _write_config(tmp_path, config)
        process = subprocess.run(
            [sys.executable, ADAPTER, "--config", str(path)],
            input="",  # closing standard input ends it at once
            capture_output=True,
            text=True,
            timeout=60,
            cwd=tmp_path,
            env={"PATH": os.environ.get("PATH", "")},
        )
        assert process.returncode == 0
        assert ("readable by other accounts" in process.stderr) is warned
        assert TOKEN not in process.stderr and process.stdout == ""


@pytest.mark.slow
class TestStandardOutputIsProtocolOnly:
    def test_every_line_the_adapter_writes_is_a_json_rpc_message(self, tmp_path, broker):
        broker.start()
        path = _write_config(tmp_path, _config(broker.port))
        process = subprocess.Popen(
            [sys.executable, ADAPTER, "--config", str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env={
                "PATH": os.environ.get("PATH", ""),
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
                "ADAPTER_TEST_TOKEN": TOKEN,
            },
            cwd=tmp_path,
        )
        requests = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "1"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "synology_status", "arguments": {}},
            },
        ]
        try:
            stdout, stderr = process.communicate(
                "".join(json.dumps(r) + "\n" for r in requests), timeout=90
            )
        finally:
            if process.poll() is None:
                process.kill()

        lines = [line for line in stdout.splitlines() if line.strip()]
        messages = [json.loads(line) for line in lines]  # every line must parse
        assert all(m.get("jsonrpc") == "2.0" for m in messages)
        assert {m.get("id") for m in messages} >= {1, 2, 3}
        assert TOKEN not in stdout + stderr
        assert process.returncode == 0  # closing stdin ends it cleanly


class TestItCannotSignInByItself:
    def test_importing_it_pulls_in_none_of_the_nas_code_or_the_old_servers_configuration(self):
        code = (
            "import sys; sys.path.insert(0, sys.argv[1] + '/src'); sys.path.insert(0, sys.argv[1]);"
            "import adapter_main, adapter.config, adapter.client, adapter.server;"
            "adapter_main._prepare();"
            "banned = {'config', 'mcp_server', 'auth', 'filestation', 'downloadstation', 'health', 'nfs',"
            " 'container', 'usermanagement', 'broker', 'private_auth', 'dotenv', 'requests', 'Crypto'};"
            "print(sorted(m for m in sys.modules if m.split('.')[0] in banned))"
        )
        done = subprocess.run(
            [sys.executable, "-c", code, str(ROOT)],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        assert done.stdout.strip() == "[]", done.stdout

    def test_it_has_no_tool_of_its_own(self):
        import inspect

        import adapter.server as server

        source = inspect.getsource(server)
        # It registers a list handler and a call handler that forward, and nothing else.
        assert source.count("on_list_tools=") == 1 and source.count("on_call_tool=") == 1
        assert "types.Tool(" not in source
