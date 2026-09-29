"""End to end: start the real server (`python main.py`) and speak MCP to it
over stdio, the way Claude Desktop or Cursor does.

The unit tests call the server's own methods directly, so none of them
exercise the MCP SDK wiring — which is how a new SDK major version could
break the server (it could not even start) without a single test noticing.
This is the check that does.

The server runs with no NAS configured, auto-login off and restricted mode
on, in a temporary config directory, so nothing here can reach a NAS.
"""

import contextlib
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RESPONSE_TIMEOUT = 30  # seconds to wait for any one response
INVALID_PARAMS = -32602


class _StdioClient:
    """A minimal newline-delimited JSON-RPC client over a process's pipes.

    A reader thread feeds a queue so waiting for a response can time out —
    a blocking readline() on a pipe can't, on Windows or anywhere else.
    """

    def __init__(self, process):
        self.process = process
        self.stdout_noise = []  # anything on stdout that wasn't JSON-RPC
        self._lines = queue.Queue()
        self._next_id = 1
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.process.stdout:
            self._lines.put(line)
        self._lines.put(None)  # EOF: the server exited

    def _send(self, message):
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def notify(self, method, params=None):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def request(self, method, params=None):
        """Send a request; return the matching response message (a dict with
        either "result" or "error")."""
        request_id = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
        while True:
            try:
                line = self._lines.get(timeout=RESPONSE_TIMEOUT)
            except queue.Empty:
                raise AssertionError(f"no response to {method!r} within {RESPONSE_TIMEOUT}s")
            if line is None:
                raise AssertionError(f"server exited before answering {method!r}")
            try:
                message = json.loads(line)
            except ValueError:
                # stdout is the protocol channel: anything else on it is a bug.
                self.stdout_noise.append(line)
                continue
            if message.get("id") == request_id:
                return message

    def initialize(self, protocol_version):
        response = self.request(
            "initialize",
            {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "stdio-protocol-test", "version": "0"},
            },
        )
        assert "result" in response, response
        self.notify("notifications/initialized")
        return response["result"]

    def call_tool(self, name, arguments=None):
        params = {"name": name}
        if arguments is not None:
            params["arguments"] = arguments
        return self.request("tools/call", params)


@contextlib.contextmanager
def _running_server(directory):
    """Start `python main.py` and yield a client connected to it."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("SYNOLOGY_")}
    env.update(
        {
            # Nothing configured, nothing to log in to, restricted as shipped.
            "XDG_CONFIG_HOME": str(directory / "xdg"),
            "AUTO_LOGIN": "false",
            "RESTRICTED_MODE": "true",
            "LOG_LEVEL": "WARNING",
            "PYTHONUNBUFFERED": "1",
            "PYTHONUTF8": "1",
        }
    )
    stderr_path = directory / "server-stderr.log"
    with open(stderr_path, "w", encoding="utf-8") as stderr:
        process = subprocess.Popen(
            [sys.executable, str(ROOT / "main.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            cwd=directory,  # empty: no stray .env for the server to pick up
            env=env,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        client = _StdioClient(process)
        try:
            yield client
        except BaseException:
            stderr.flush()
            print(f"--- server stderr ---\n{stderr_path.read_text(encoding='utf-8')}")
            raise
        finally:
            with contextlib.suppress(OSError):
                process.stdin.close()  # EOF is the shutdown signal
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    with _running_server(tmp_path_factory.mktemp("stdio-server")) as client:
        client.initialize("2025-06-18")
        yield client
        assert client.stdout_noise == [], "server wrote non-JSON-RPC output to stdout"


def _result_text(response):
    assert "error" not in response, response
    content = response["result"]["content"]
    assert len(content) == 1 and content[0]["type"] == "text"
    return content[0]["text"]


def _is_error(response):
    assert "result" in response, response
    return response["result"].get("isError", False)


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("protocol_version", ["2024-11-05", "2025-06-18"])
def test_the_server_starts_and_completes_the_handshake(tmp_path, protocol_version):
    """The server starts, and clients speaking an older MCP protocol version
    (every released Claude Desktop / Cursor is one) can connect to it."""
    with _running_server(tmp_path) as client:
        result = client.initialize(protocol_version)

        assert result["serverInfo"]["name"]
        assert "tools" in result["capabilities"]
        assert result["protocolVersion"]

        # ...and it then serves requests.
        assert client.request("tools/list")["result"]["tools"]


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_discovery_lists_only_the_restricted_tool_set_with_the_wire_field_names(server):
    tools = {tool["name"]: tool for tool in server.request("tools/list")["result"]["tools"]}

    assert {"list_directory", "get_file_content", "synology_system_info"} <= set(tools)
    # Restricted mode (the shipped default) hides everything that modifies.
    assert not {"delete", "move_file", "synology_create_user", "ds_create_task"} & set(tools)

    listing = tools["list_directory"]
    assert listing["inputSchema"]["required"] == ["path"]
    assert listing["annotations"]["readOnlyHint"] is True
    assert listing["annotations"]["destructiveHint"] is False


def test_the_login_tools_are_listed_when_auto_login_is_off(server):
    names = {tool["name"] for tool in server.request("tools/list")["result"]["tools"]}

    assert {"synology_login", "synology_logout"} <= names


# ---------------------------------------------------------------------------
# Tool calls
# ---------------------------------------------------------------------------


def test_a_successful_call_is_not_flagged_as_an_error(server):
    response = server.call_tool("synology_status", {})

    assert _is_error(response) is False
    assert "Auto-login: disabled" in _result_text(response)


def test_a_call_with_no_arguments_member_works(server):
    """`arguments` is optional in the protocol."""
    assert _is_error(server.call_tool("synology_status")) is False


def test_a_restricted_tool_is_refused_as_an_error_result(server):
    response = server.call_tool("delete", {"path": "/share/x"})

    assert _is_error(response) is True
    assert "restricted mode" in _result_text(response)


def test_invalid_arguments_are_refused_as_an_error_result(server):
    missing = server.call_tool("list_directory", {})
    wrong_type = server.call_tool("list_directory", {"path": 123})

    assert _is_error(missing) is True
    assert "'path' is a required property" in _result_text(missing)
    assert _is_error(wrong_type) is True
    assert "123 is not of type 'string'" in _result_text(wrong_type)


def test_a_tool_that_fails_is_reported_as_an_error_result(server):
    """No NAS is configured, so the handler itself fails for want of a session."""
    response = server.call_tool("list_directory", {"path": "/share"})

    assert _is_error(response) is True
    assert "no active sessions" in _result_text(response)


def test_a_failed_login_step_is_reported_as_an_error_result(server):
    response = server.call_tool(
        "synology_login",
        {"base_url": "http://nas.example.test:5000", "username": "u", "password": "p"},
    )

    assert _is_error(response) is True
    assert "Invalid base_url format" in _result_text(response)


# ---------------------------------------------------------------------------
# Protocol errors
# ---------------------------------------------------------------------------


def test_an_unknown_tool_is_a_protocol_error(server):
    response = server.call_tool("not_a_real_tool", {})

    assert "result" not in response
    assert response["error"]["code"] == INVALID_PARAMS
    assert "Unknown tool" in response["error"]["message"]


@pytest.mark.parametrize(
    "params",
    [
        {"name": "list_directory", "arguments": "not-an-object"},
        {"arguments": {"path": "/share"}},  # no tool name
        {"name": None},
    ],
)
def test_a_malformed_tool_call_is_a_protocol_error(server, params):
    response = server.request("tools/call", params)

    assert "result" not in response
    assert response["error"]["code"] == INVALID_PARAMS


def test_the_server_keeps_working_after_errors(server):
    server.call_tool("not_a_real_tool", {})
    server.request("tools/call", {"name": None})

    assert _is_error(server.call_tool("synology_status", {})) is False
