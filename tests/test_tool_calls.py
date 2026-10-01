"""How `SynologyMCPServer._call_tool` reports a tool call's outcome.

Success is a normal result. Every kind of failure is reported with the error
flag set explicitly by the code that detected it (never by looking at what a
message says), except an unknown tool name, which is a protocol error. Every
message and log line on every error path is redacted, and an unknown,
restricted or invalid call is rejected before any handler runs — so before
any request reaches the NAS.
"""

import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import mcp.types as types
import pytest
from mcp.shared.exceptions import MCPError

SECRET = "TopSecretSessionId123"
# A secret typed into a call: unlike SECRET, no fixture registers it anywhere.
NEW_SECRET = "NeverSeenBefore-7f3a9c"
SWEEP_SENTINEL = "SWEEP-SENTINEL-d41d8c"
BASE_URL = "https://nas.example.test:5001"
_MASK = "***REDACTED***"


def _valid_value(schema):
    """Some value that satisfies `schema` (enough to get past `required`)."""
    if "enum" in schema:
        return schema["enum"][0]
    return {
        "string": "ok",
        "integer": 1,
        "number": 1,
        "boolean": True,
        "array": [_valid_value(schema["items"])] if "items" in schema else [],
        "object": {},
    }[schema["type"]]


def _poison(schema):
    """A value of the wrong type for `schema`, carrying SWEEP_SENTINEL at the
    deepest level the schema describes."""
    kind = schema["type"]
    if kind == "string":
        return [SWEEP_SENTINEL]
    if kind == "array":
        return [_poison(schema["items"])] if "items" in schema else SWEEP_SENTINEL
    if kind == "object" and schema.get("properties"):
        name, sub = next(iter(schema["properties"].items()))
        return {name: _poison(sub)}
    return SWEEP_SENTINEL


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


def _server_with_session():
    """A real server, logged in to BASE_URL, whose health calls go through the
    real SynologyHealth/SynologyAPIClient — only the HTTP layer is replaced."""
    server = _server()
    server.sessions[BASE_URL] = "a-session-id"
    return server


def _dsm_response(payload):
    response = MagicMock()
    response.json.return_value = payload
    return response


@pytest.mark.asyncio
async def test_a_health_summary_of_an_unreachable_nas_is_an_error_result(unrestricted):
    """The P2 finding, at the tool boundary: with the NAS unreachable every
    underlying request fails, and the tool used to answer `isError: false`
    with `{"success": true, "data": {}}`."""
    import requests

    server = _server_with_session()

    with patch(
        "utils.synology_api.requests.get", side_effect=requests.ConnectionError("unreachable")
    ) as get:
        result = await server._call_tool("synology_health_summary", {"base_url": BASE_URL})

    assert get.call_count == 11
    assert result.is_error is True
    assert '"health_checks_failed"' in _text(result)
    assert '"success": true' not in _text(result)


@pytest.mark.asyncio
async def test_a_partial_health_summary_is_a_success_that_says_it_is_partial(unrestricted):
    def fake_get(url, params=None, **kwargs):
        if params["api"] == "SYNO.Core.ExternalDevice.UPS":
            return _dsm_response({"success": False, "error": {"code": 117}})
        return _dsm_response({"success": True, "data": {"api": params["api"]}})

    server = _server_with_session()

    with patch("utils.synology_api.requests.get", side_effect=fake_get):
        result = await server._call_tool("synology_health_summary", {"base_url": BASE_URL})

    assert result.is_error is False
    body = json.loads(_text(result))
    assert body["status"] == "partial"
    assert body["message"] == "Some health checks could not be completed."
    assert body["failed_checks"] == [{"check": "ups", "error": {"code": 117}}]
    assert "ups" not in body["data"] and "system" in body["data"]


@pytest.mark.asyncio
async def test_a_nas_without_a_ups_still_gets_a_complete_health_summary(unrestricted):
    def fake_get(url, params=None, **kwargs):
        if params["api"] == "SYNO.Core.ExternalDevice.UPS":
            return _dsm_response({"success": False, "error": {"code": 102}})
        return _dsm_response({"success": True, "data": {"api": params["api"]}})

    server = _server_with_session()

    with patch("utils.synology_api.requests.get", side_effect=fake_get):
        result = await server._call_tool("synology_health_summary", {"base_url": BASE_URL})

    assert result.is_error is False
    body = json.loads(_text(result))
    assert body["status"] == "complete"
    assert body["unavailable_checks"] == [{"check": "ups", "error": {"code": 102}}]
    assert "failed_checks" not in body


@pytest.mark.asyncio
async def test_a_complete_health_summary_says_so(unrestricted):
    server = _server_with_session()

    with patch(
        "utils.synology_api.requests.get",
        side_effect=lambda url, params=None, **kw: _dsm_response({"success": True, "data": {}}),
    ):
        result = await server._call_tool("synology_health_summary", {"base_url": BASE_URL})

    assert result.is_error is False
    assert json.loads(_text(result))["status"] == "complete"


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
            {
                "base_url": "https://attacker.example:5001",
                "username": "u",
                "password": "a-realistic-passphrase",
            },
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
        ({"path": 123}, "path must be of type 'string'"),
        ({"path": "/share", "nas_name": ["nas1"]}, "nas_name must be of type 'string'"),
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
async def test_a_validation_message_does_not_quote_the_submitted_value(unrestricted, caplog):
    """jsonschema's own message quotes the rejected value. The message built
    from the schema must not, and — unlike the redactor, which only knows
    secrets it has been told about — it must not need to: `path` is not a
    credential, so nothing registers this value anywhere."""
    caplog.set_level(logging.DEBUG)
    server = _server()
    handler = _stub(server, "list_directory")

    result = await server._call_tool("list_directory", {"path": [NEW_SECRET]})

    assert result.is_error is True
    assert _text(result) == "Invalid arguments for list_directory: path must be of type 'string'"
    assert NEW_SECRET not in caplog.text
    handler.assert_not_awaited()


@pytest.mark.parametrize("field", ["password", "device_id", "otp_code"])
@pytest.mark.asyncio
async def test_a_mistyped_login_credential_is_never_echoed(unrestricted, no_network, caplog, field):
    """The P1 finding: a credential submitted with the wrong type fails
    validation before any login, so it is in no inventory of known secrets.
    Neither the client's result nor the DEBUG log may carry it."""
    caplog.set_level(logging.DEBUG)
    arguments = {"base_url": BASE_URL, "username": "admin", "password": "pw"}
    arguments[field] = [NEW_SECRET]
    server = _server()

    result = await server._call_tool("synology_login", arguments)

    assert result.is_error is True
    assert (
        _text(result) == f"Invalid arguments for synology_login: {field} must be of type 'string'"
    )
    assert NEW_SECRET not in _text(result)
    assert NEW_SECRET not in caplog.text


@pytest.mark.asyncio
async def test_no_tool_quotes_a_rejected_value_for_any_property(unrestricted, no_network, caplog):
    """Sweep: for every property of every tool, submit a wrong-typed value
    carrying a unique sentinel (nothing is registered with the redactor) and
    check the refusal names the field but never the sentinel."""
    caplog.set_level(logging.DEBUG)
    server = _server()
    definitions = [*server._get_tool_definitions(), *server._session_tool_definitions()]
    handlers = {tool.name: _stub(server, tool.name) for tool in definitions}
    checked = 0

    for tool in definitions:
        schema = tool.input_schema
        for prop, prop_schema in schema.get("properties", {}).items():
            arguments = {
                name: _valid_value(schema["properties"][name])
                for name in schema.get("required", [])
            }
            arguments[prop] = _poison(prop_schema)

            result = await server._call_tool(tool.name, arguments)

            where = f"{tool.name}.{prop}"
            assert result.is_error is True, where
            assert _text(result).startswith(f"Invalid arguments for {tool.name}: "), where
            assert prop in _text(result), where
            assert SWEEP_SENTINEL not in _text(result), where
            checked += 1

    assert checked > 100  # the sweep actually covered the tool set
    assert SWEEP_SENTINEL not in caplog.text
    for handler in handlers.values():
        handler.assert_not_awaited()


@pytest.mark.parametrize(
    "tool,arguments,expected",
    [
        (
            "synology_set_user_permissions",
            {"name": "u", "permissions": [{"name": [SWEEP_SENTINEL]}]},
            "permissions[].name must be of type 'string'",
        ),
        (
            "synology_set_user_permissions",
            {"name": "u", "permissions": [{}]},
            "permissions[]: 'name' is a required property",
        ),
        (
            "ds_pause_tasks",
            {"task_ids": ["ok", [SWEEP_SENTINEL]]},
            "task_ids[] must be of type 'string'",
        ),
        ("ds_pause_tasks", {"task_ids": SWEEP_SENTINEL}, "task_ids must be of type 'array'"),
        ("synology_container_logs", {"name": "c", "offset": -1}, "offset must be >= 0"),
    ],
)
@pytest.mark.asyncio
async def test_a_validation_message_names_the_field_and_the_constraint(
    unrestricted, no_network, tool, arguments, expected
):
    server = _server()
    _stub(server, tool)

    result = await server._call_tool(tool, arguments)

    assert _text(result) == f"Invalid arguments for {tool}: {expected}"
    assert SWEEP_SENTINEL not in _text(result)


@pytest.mark.asyncio
async def test_a_rejected_enum_value_is_not_quoted(unrestricted, no_network):
    server = _server()
    _stub(server, "synology_nfs_set_permission")

    result = await server._call_tool(
        "synology_nfs_set_permission",
        {"share_name": "s", "client_ip": "1.2.3.4", "privilege": SWEEP_SENTINEL},
    )

    assert result.is_error is True
    assert SWEEP_SENTINEL not in _text(result)
    assert "privilege must be one of: 'readonly', 'readwrite'" in _text(result)


@pytest.mark.asyncio
async def test_a_credential_in_this_call_is_redacted_from_a_later_failure(unrestricted, caplog):
    """A well-typed login reaches the handler, and whatever it raises may
    quote the password. The redactor has never seen this password — it is
    not configured and no session exists — only this call's registration."""
    caplog.set_level(logging.DEBUG)
    server = _server()
    with patch("mcp_server.SynologyAuth") as auth_class:
        auth_class.return_value.login.side_effect = RuntimeError(f"boom, sent {NEW_SECRET}")

        result = await server._call_tool(
            "synology_login", {"base_url": BASE_URL, "username": "admin", "password": NEW_SECRET}
        )

    assert result.is_error is True
    assert "boom" in _text(result)
    assert NEW_SECRET not in _text(result)
    assert NEW_SECRET not in caplog.text


@pytest.mark.asyncio
async def test_a_credential_in_this_call_is_redacted_from_a_successful_result(unrestricted):
    server = _server()
    _stub(server, "synology_login", [types.TextContent(type="text", text=f"otp {NEW_SECRET} ok")])

    result = await server._call_tool(
        "synology_login",
        {
            "base_url": BASE_URL,
            "username": "u",
            "password": "pw-1234-abcd",
            "device_id": NEW_SECRET,
        },
    )

    assert result.is_error is False
    assert NEW_SECRET not in _text(result)


@pytest.mark.asyncio
async def test_request_secrets_are_forgotten_when_the_call_ends(unrestricted):
    from auth import iter_all_secrets

    server = _server()
    _stub(server, "synology_login")

    await server._call_tool(
        "synology_login", {"base_url": BASE_URL, "username": "u", "password": NEW_SECRET}
    )

    assert NEW_SECRET not in list(iter_all_secrets())


@pytest.mark.asyncio
async def test_concurrent_calls_do_not_share_request_secrets(unrestricted):
    """Two overlapping calls: each masks its own credential, and only its own."""
    import asyncio

    server = _server()
    both_running = asyncio.Event()
    started = []

    async def handler_for(mine, theirs):
        async def handler(arguments):
            started.append(mine)
            if len(started) == 2:
                both_running.set()
            await both_running.wait()  # force the two calls to overlap
            return [types.TextContent(type="text", text=f"mine={mine} theirs={theirs}")]

        return handler

    server._tool_registry["synology_login"] = await handler_for("PASSWORD-A", "PASSWORD-B")
    server._tool_registry["synology_logout"] = await handler_for("PASSWORD-B", "PASSWORD-A")
    # synology_logout takes no password; carry B's in a credential-named field
    first, second = await asyncio.gather(
        server._call_tool(
            "synology_login", {"base_url": BASE_URL, "username": "u", "password": "PASSWORD-A"}
        ),
        server._call_tool("synology_logout", {"base_url": BASE_URL, "password": "PASSWORD-B"}),
    )

    assert _text(first) == f"mine={_MASK} theirs=PASSWORD-B"
    assert _text(second) == f"mine={_MASK} theirs=PASSWORD-A"


def test_a_very_short_credential_is_not_registered():
    """Substring-masking a one- or two-character value would blank those
    characters out of everything the call prints."""
    from mcp_server import _MIN_CREDENTIAL_LENGTH, _credential_strings

    assert _credential_strings({"password": "p", "device_id": "ab"}) == []
    assert _credential_strings({"password": "x" * (_MIN_CREDENTIAL_LENGTH - 1)}) == []
    assert _credential_strings({"password": "x" * _MIN_CREDENTIAL_LENGTH}) == [
        "x" * _MIN_CREDENTIAL_LENGTH
    ]


@pytest.mark.asyncio
async def test_a_short_password_does_not_corrupt_the_output_of_the_call(restricted):
    """The restricted-login refusal quotes the URL; a one-character password
    must not turn every "p" in it into a mask."""
    restricted.nas_configs = {"nas1": {"base_url": "https://configured.example:5001"}}
    restricted.synology_url = None
    server = _server()

    with patch("mcp_server.SynologyAuth"):
        result = await server._call_tool(
            "synology_login",
            {"base_url": "https://attacker.example:5001", "username": "u", "password": "p"},
        )

    assert result.is_error is True
    assert "https://attacker.example:5001" in _text(result)


def test_credential_strings_are_found_at_any_depth():
    from mcp_server import _credential_strings

    found = _credential_strings(
        {
            "password": ["pw-aaaa", ["pw-bbbb"], {"x": "pw-cccc"}],
            "device_id": "did-dddd",
            "otp_code": "one-shot-codes-are-left-out",
            "nested": {"password": "pw-eeee", "note": "not-a-credential"},
            "path": "/share",
            "items": [{"device_id": "did-ffff"}],
        }
    )

    assert sorted(found) == [
        "did-dddd",
        "did-ffff",
        "pw-aaaa",
        "pw-bbbb",
        "pw-cccc",
        "pw-eeee",
    ]


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
