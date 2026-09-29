"""How `SynologyMCPServer._call_tool` reports a tool call's outcome.

Success is a normal result. Every kind of failure is reported with the error
flag set explicitly by the code that detected it (never by looking at what a
message says), except an unknown tool name, which is a protocol error. Every
message and log line on every error path is redacted, and an unknown,
restricted or invalid call is rejected before any handler runs — so before
any request reaches the NAS.
"""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import mcp.types as types
import pytest
from mcp.shared.exceptions import MCPError

SECRET = "TopSecretSessionId123"
BASE_URL = "https://nas.example.test:5001"


def _server():
    from mcp_server import SynologyMCPServer

    return SynologyMCPServer()


def _text(result):
    assert len(result.content) == 1
    return result.content[0].text


def _stub(server, name, result=None, error=None):
    """Replace tool `name`'s handler with an AsyncMock and return it."""
    handler = AsyncMock(
        return_value=result if result is not None else [types.TextContent(type="text", text="ok")],
        side_effect=error,
    )
    server._tool_registry[name] = handler
    return handler


@pytest.fixture
def unrestricted():
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = False
        yield fake_config


@pytest.fixture
def restricted():
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        yield fake_config


@pytest.fixture
def live_secret():
    """One live secret the redactor knows about."""
    with patch("mcp_server.iter_all_secrets", return_value=[SECRET]):
        yield SECRET


@pytest.fixture
def no_network():
    """Fails the test if anything gets as far as sending an HTTP request."""
    with patch("requests.sessions.Session.request") as request:
        yield request
        request.assert_not_called()


# ---------------------------------------------------------------------------
# Success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_successful_call_is_not_an_error(unrestricted):
    server = _server()
    _stub(server, "list_shares", [types.TextContent(type="text", text="the shares")])

    result = await server._call_tool("list_shares", {})

    assert result.is_error is False
    assert _text(result) == "the shares"


@pytest.mark.asyncio
async def test_a_successful_result_is_redacted(unrestricted, live_secret):
    server = _server()
    _stub(server, "list_shares", [types.TextContent(type="text", text=f"sid={SECRET} ok")])

    result = await server._call_tool("list_shares", {})

    assert result.is_error is False
    assert SECRET not in _text(result)


@pytest.mark.asyncio
async def test_output_that_talks_about_an_error_is_not_flagged_as_one(unrestricted):
    """The flag comes from the code path that detected a failure, never from
    what the text says: a successful result whose data happens to contain
    "Error" or "failed" is still a success."""
    server = _server()
    _stub(
        server,
        "list_shares",
        [types.TextContent(type="text", text="❌ Error: 3 tasks failed (this is just data)")],
    )

    result = await server._call_tool("list_shares", {})

    assert result.is_error is False


@pytest.mark.asyncio
async def test_the_sdk_handler_passes_the_tool_name_and_arguments_through(unrestricted):
    server = _server()
    handler = _stub(server, "list_shares")

    params = types.CallToolRequestParams(name="list_shares", arguments={"nas_name": "nas1"})
    result = await server._on_call_tool(None, params)

    assert result.is_error is False
    handler.assert_awaited_once_with({"nas_name": "nas1"})

    # No arguments at all is an empty dict, not None.
    handler.reset_mock()
    await server._on_call_tool(None, types.CallToolRequestParams(name="list_shares"))
    handler.assert_awaited_once_with({})


# ---------------------------------------------------------------------------
# Tool execution failures -> isError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_exception_from_a_handler_is_an_error_result(unrestricted):
    server = _server()
    _stub(server, "list_shares", error=RuntimeError("DSM went away"))

    result = await server._call_tool("list_shares", {})

    assert result.is_error is True
    assert _text(result) == "Error executing list_shares: DSM went away"


@pytest.mark.asyncio
async def test_a_tool_execution_error_is_an_error_result_with_its_own_message(unrestricted):
    from mcp_server import ToolExecutionError

    server = _server()
    _stub(server, "list_shares", error=ToolExecutionError("that did not work"))

    result = await server._call_tool("list_shares", {})

    assert result.is_error is True
    assert _text(result) == "that did not work"


@pytest.mark.asyncio
async def test_an_exception_message_is_redacted(unrestricted, live_secret):
    server = _server()
    _stub(server, "list_shares", error=RuntimeError(f"GET https://nas/x?_sid={SECRET} failed"))

    result = await server._call_tool("list_shares", {})

    assert result.is_error is True
    assert SECRET not in _text(result)


@pytest.mark.asyncio
async def test_a_tool_execution_error_message_is_redacted(unrestricted, live_secret):
    from mcp_server import ToolExecutionError

    server = _server()
    _stub(server, "list_shares", error=ToolExecutionError(f"login used {SECRET}"))

    result = await server._call_tool("list_shares", {})

    assert result.is_error is True
    assert SECRET not in _text(result)


def _health_server(system_info_result):
    server = _server()
    health = MagicMock()
    health.system_info.return_value = system_info_result
    server._get_health = MagicMock(return_value=health)
    server._get_base_url = MagicMock(return_value=BASE_URL)
    return server


@pytest.mark.asyncio
async def test_a_dsm_result_reporting_failure_is_an_error_result(unrestricted):
    """The API client behind the health/NFS/user/container tools *returns*
    `{"success": False, ...}` rather than raising."""
    failure = {"success": False, "error": {"code": 119, "message": "SID not found"}}
    server = _health_server(failure)

    result = await server._call_tool("synology_system_info", {})

    assert result.is_error is True
    # The client still sees exactly what DSM said.
    assert '"code": 119' in _text(result)


@pytest.mark.asyncio
async def test_a_dsm_result_reporting_success_is_not_an_error(unrestricted):
    server = _health_server({"success": True, "data": {"model": "DS920+"}})

    result = await server._call_tool("synology_system_info", {})

    assert result.is_error is False
    assert "DS920+" in _text(result)


def test_dsm_result_decides_from_the_structured_success_field():
    from mcp_server import SynologyMCPServer, ToolExecutionError

    dsm_result = SynologyMCPServer._dsm_result

    with pytest.raises(ToolExecutionError) as excinfo:
        dsm_result({"success": False, "error": {"code": 1}}, prefix="Create task result: ")
    assert str(excinfo.value).startswith("Create task result: {")

    # Anything that isn't a top-level `success: false` is output as before.
    assert dsm_result({"success": True})[0].text == '{\n  "success": true\n}'
    assert dsm_result({"total": 0, "tasks": []})[0].text.startswith("{")
    assert dsm_result([{"success": False}])[0].text.startswith("[")
    assert dsm_result({"data": {"success": False}})[0].text.startswith("{")
    assert dsm_result({"success": None})[0].text.startswith("{")
    assert dsm_result({}, prefix="Result: ")[0].text == "Result: {}"


@pytest.mark.asyncio
async def test_a_failed_login_is_an_error_result(unrestricted):
    auth = MagicMock()
    auth.login.return_value = {"success": False, "error": {"code": 400, "message": "bad login"}}
    server = _server()

    with patch("mcp_server.SynologyAuth", return_value=auth):
        result = await server._call_tool(
            "synology_login", {"base_url": BASE_URL, "username": "u", "password": "p"}
        )

    assert result.is_error is True
    assert _text(result) == "Authentication failed: 400 - bad login"


@pytest.mark.asyncio
async def test_a_successful_login_is_not_an_error(unrestricted):
    auth = MagicMock()
    auth.login.return_value = {"success": True, "data": {"sid": "sid_xyz"}}
    server = _server()

    with patch("mcp_server.SynologyAuth", return_value=auth):
        result = await server._call_tool(
            "synology_login", {"base_url": BASE_URL, "username": "u", "password": "p"}
        )

    assert result.is_error is False
    assert "Successfully authenticated" in _text(result)


@pytest.mark.asyncio
async def test_a_login_with_a_malformed_url_is_an_error_result(unrestricted):
    server = _server()

    result = await server._call_tool(
        "synology_login",
        {"base_url": "http://nas.example.test:5000", "username": "u", "password": "p"},
    )

    assert result.is_error is True
    assert "Invalid base_url format" in _text(result)


@pytest.mark.asyncio
async def test_a_restricted_login_to_an_unconfigured_nas_is_an_error_result(restricted):
    restricted.nas_configs = {"nas1": {"base_url": BASE_URL}}
    restricted.synology_url = None
    server = _server()

    with patch("mcp_server.SynologyAuth") as auth_class:
        result = await server._call_tool(
            "synology_login",
            {"base_url": "https://attacker.example:5001", "username": "u", "password": "p"},
        )

    assert result.is_error is True
    assert "attacker.example" in _text(result)
    auth_class.assert_not_called()


@pytest.mark.asyncio
async def test_logout_without_a_session_is_an_error_result(unrestricted):
    result = await _server()._call_tool("synology_logout", {"base_url": BASE_URL})

    assert result.is_error is True
    assert "No active session" in _text(result)


@pytest.mark.asyncio
async def test_a_failed_logout_is_an_error_result_but_an_expired_session_is_not(unrestricted):
    def logged_in_server(logout_result):
        server = _server()
        server.sessions[BASE_URL] = "sid_xyz"
        auth = MagicMock()
        auth.logout.return_value = logout_result
        server.auth_instances[BASE_URL] = auth
        return server

    failed = logged_in_server({"success": False, "error": {"code": 500, "message": "nope"}})
    result = await failed._call_tool("synology_logout", {"base_url": BASE_URL})
    assert result.is_error is True
    assert "Logout failed" in _text(result)

    # The session had already expired: local state is cleaned up, and the
    # caller's goal (no session left) is met, so this stays a success.
    expired = logged_in_server({"success": False, "error": {"code": 106, "message": "timeout"}})
    result = await expired._call_tool("synology_logout", {"base_url": BASE_URL})
    assert result.is_error is False
    assert "already expired" in _text(result)


# ---------------------------------------------------------------------------
# Invalid arguments -> isError, before the handler
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "arguments,expected",
    [
        ({}, "'path' is a required property"),
        ({"path": 123}, "123 is not of type 'string'"),
        ({"path": "/share", "nas_name": ["nas1"]}, "is not of type 'string'"),
    ],
)
@pytest.mark.asyncio
async def test_invalid_arguments_are_an_error_result_and_the_handler_never_runs(
    unrestricted, no_network, arguments, expected
):
    server = _server()
    handler = _stub(server, "list_directory")

    result = await server._call_tool("list_directory", arguments)

    assert result.is_error is True
    assert _text(result).startswith("Invalid arguments for list_directory: ")
    assert expected in _text(result)
    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_validation_message_is_redacted(unrestricted, live_secret):
    """jsonschema quotes the offending value in its message; if a secret was
    submitted as that value, it must not be echoed back."""
    server = _server()
    handler = _stub(server, "list_directory")

    result = await server._call_tool("list_directory", {"path": [SECRET]})

    assert result.is_error is True
    assert "Invalid arguments" in _text(result)
    assert SECRET not in _text(result)
    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_login_arguments_are_validated_even_when_login_is_not_listed(unrestricted):
    """With auto-login the login tool is not in discovery, but it is still
    callable — and still validated."""
    unrestricted.auto_login = True
    unrestricted.has_synology_credentials.return_value = True
    server = _server()
    assert "synology_login" not in {t.name for t in await server._list_tools()}

    result = await server._call_tool("synology_login", {"base_url": BASE_URL})

    assert result.is_error is True
    assert "'username' is a required property" in _text(result)


# ---------------------------------------------------------------------------
# Restricted mode -> isError, before the handler
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_restricted_call_is_an_error_result_and_the_handler_never_runs(
    restricted, no_network
):
    server = _server()
    handler = _stub(server, "delete")

    result = await server._call_tool("delete", {"path": "/share/x"})

    assert result.is_error is True
    assert "restricted mode" in _text(result)
    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_the_restriction_is_reported_before_the_arguments_are_looked_at(restricted):
    server = _server()
    handler = _stub(server, "delete")

    result = await server._call_tool("delete", {})  # also missing its required path

    assert result.is_error is True
    assert "restricted mode" in _text(result)
    assert "Invalid arguments" not in _text(result)
    handler.assert_not_awaited()


# ---------------------------------------------------------------------------
# Unknown tool -> protocol error
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("restricted_mode", [True, False])
@pytest.mark.asyncio
async def test_an_unknown_tool_is_a_protocol_error(no_network, restricted_mode):
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = restricted_mode
        with pytest.raises(MCPError) as excinfo:
            await _server()._call_tool("not_a_real_tool", {})

    assert excinfo.value.code == types.INVALID_PARAMS
    assert excinfo.value.message == "Unknown tool: not_a_real_tool"


@pytest.mark.asyncio
async def test_an_unknown_tool_message_is_redacted(unrestricted, live_secret):
    with pytest.raises(MCPError) as excinfo:
        await _server()._call_tool(f"tool_{SECRET}", {})

    assert SECRET not in excinfo.value.message


# ---------------------------------------------------------------------------
# Listing failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_listing_failure_becomes_a_generic_protocol_error(live_secret, caplog):
    server = _server()
    server._list_tools = AsyncMock(side_effect=RuntimeError(f"registry exploded {SECRET}"))

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(MCPError) as excinfo:
            await server._on_list_tools(None, None)

    assert excinfo.value.code == types.INTERNAL_ERROR
    assert excinfo.value.message == "Failed to list tools"
    assert SECRET not in caplog.text
    assert "registry exploded" in caplog.text  # still diagnosable from the log


@pytest.mark.asyncio
async def test_the_sdk_list_handler_returns_the_listing(restricted):
    restricted.auto_login = True
    restricted.has_synology_credentials.return_value = True
    server = _server()

    result = await server._on_list_tools(None, None)

    assert isinstance(result, types.ListToolsResult)
    names = {t.name for t in result.tools}
    assert "list_directory" in names
    assert "delete" not in names


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_failure_logs_and_tracebacks_are_redacted_without_relying_on_a_filter(
    unrestricted, live_secret, caplog
):
    """The server redacts what it logs itself, so a log destination with no
    redaction filter attached still never sees a secret — including in the
    DEBUG traceback, where a `requests` error would carry the full URL."""
    from mcp_server import ToolExecutionError

    server = _server()
    _stub(server, "list_shares", error=RuntimeError(f"GET /x?_sid={SECRET} refused"))
    _stub(server, "list_directory", error=ToolExecutionError(f"denied for {SECRET}"))

    with caplog.at_level(logging.DEBUG):
        await server._call_tool("list_shares", {})
        await server._call_tool("list_directory", {"path": "/share"})
        await server._call_tool("list_directory", {"path": [SECRET]})

    assert SECRET not in caplog.text
    assert "refused" in caplog.text  # the failure itself was logged...
    assert "Traceback" in caplog.text  # ...with its traceback at DEBUG


@pytest.mark.asyncio
async def test_a_failure_logs_a_warning_and_only_debug_gets_the_traceback(unrestricted, caplog):
    server = _server()
    _stub(server, "list_shares", error=RuntimeError("kaput"))

    with caplog.at_level(logging.INFO):
        await server._call_tool("list_shares", {})

    assert any(r.levelno == logging.WARNING and "kaput" in r.getMessage() for r in caplog.records)
    assert "Traceback" not in caplog.text


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


def test_every_registered_tool_has_a_compiled_input_validator():
    server = _server()

    assert set(server._tool_registry) <= set(server._input_validators)
    assert {"synology_login", "synology_logout"} <= set(server._input_validators)


def test_a_registered_tool_without_a_definition_fails_at_startup():
    from mcp_server import SynologyMCPServer

    with patch.object(SynologyMCPServer, "_get_tool_definitions", return_value=[]):
        with pytest.raises(RuntimeError, match="without an input schema"):
            SynologyMCPServer()
