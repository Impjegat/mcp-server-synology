"""What the adapter's MCP server does with a request: forward it, return what comes
back unchanged, and refuse locally anything that looks like a credential. Driven
through the real protocol in-memory, with a fake broker client behind it."""

import logging

import mcp.types as types
import pytest
from mcp.client import Client
from mcp.shared.exceptions import MCPError

from adapter.client import BrokerError
from adapter.server import (
    CREDENTIAL_WORDS,
    MAX_DEPTH,
    TOO_DEEP_MESSAGE,
    build_adapter_server,
    credential_fields,
    inspect_arguments,
    looks_like_credential,
)

PASSWORD = "PRIVATE-PASSWORD-MARKER-4d2e"
TOOLS = [
    types.Tool(
        name="list_shares",
        title="Shares",
        description="List shared folders.",
        input_schema={"type": "object", "properties": {"nas_name": {"type": "string"}}},
        annotations=types.ToolAnnotations(read_only_hint=True),
    ),
    types.Tool(name="synology_status", description="Status.", input_schema={"type": "object"}),
]


class FakeBroker:
    def __init__(self, tools=None, result=None, error=None):
        self.tools = TOOLS if tools is None else tools
        self.result = result or types.CallToolResult(
            content=[types.TextContent(type="text", text="from the broker")], is_error=False
        )
        self.error = error
        self.calls = []
        self.listed = 0

    async def list_tools(self):
        self.listed += 1
        if self.error is not None:
            raise self.error
        return self.tools

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if self.error is not None:
            raise self.error
        return self.result

    def known_secrets(self):
        return []


async def _client(broker):
    return Client(build_adapter_server(broker, name="synology"))


class TestForwarding:
    @pytest.mark.asyncio
    async def test_the_tool_list_is_the_brokers_unchanged(self):
        broker = FakeBroker()
        async with await _client(broker) as client:
            listed = (await client.list_tools()).tools

        assert [t.name for t in listed] == ["list_shares", "synology_status"]
        assert listed[0].description == "List shared folders."
        assert listed[0].title == "Shares"
        assert listed[0].input_schema == TOOLS[0].input_schema
        assert listed[0].annotations.read_only_hint is True

    @pytest.mark.asyncio
    async def test_a_call_goes_to_the_broker_exactly_as_made_and_its_result_comes_back_as_it_is(
        self,
    ):
        broker = FakeBroker()
        async with await _client(broker) as client:
            result = await client.call_tool(
                "list_shares", {"nas_name": "nas1", "extra": [1, {"a": 2}]}
            )

        assert broker.calls == [("list_shares", {"nas_name": "nas1", "extra": [1, {"a": 2}]})]
        assert result.is_error is False and result.content[0].text == "from the broker"

    @pytest.mark.asyncio
    async def test_a_call_with_no_arguments_sends_an_empty_object(self):
        broker = FakeBroker()
        async with await _client(broker) as client:
            await client.call_tool("synology_status")
        assert broker.calls == [("synology_status", {})]

    @pytest.mark.asyncio
    async def test_the_brokers_error_result_is_passed_on_with_its_flag_and_text(self):
        broker = FakeBroker(
            result=types.CallToolResult(
                content=[types.TextContent(type="text", text="AUTHENTICATION_REQUIRED: sign in")],
                is_error=True,
            )
        )
        async with await _client(broker) as client:
            result = await client.call_tool("list_shares", {"nas_name": "nas1"})

        assert result.is_error is True
        assert result.content[0].text == "AUTHENTICATION_REQUIRED: sign in"

    @pytest.mark.asyncio
    async def test_the_brokers_json_rpc_error_is_passed_on_with_its_code(self):
        broker = FakeBroker(error=MCPError(types.INVALID_PARAMS, "Unknown tool: nope"))
        async with await _client(broker) as client:
            with pytest.raises(MCPError) as error:
                await client.call_tool("nope", {})
        assert error.value.error.code == types.INVALID_PARAMS
        assert "Unknown tool: nope" in error.value.error.message


class TestWhenTheBrokerCannotBeReached:
    @pytest.mark.asyncio
    async def test_a_failed_call_is_a_flagged_result_with_the_fixed_text(self):
        broker = FakeBroker(error=BrokerError("BROKER_UNAVAILABLE"))
        async with await _client(broker) as client:
            result = await client.call_tool("list_shares", {"nas_name": "nas1"})

        assert result.is_error is True
        assert result.content[0].text.startswith("BROKER_UNAVAILABLE: ")

    @pytest.mark.asyncio
    async def test_a_failed_list_is_a_protocol_error_naming_the_code(self):
        broker = FakeBroker(error=BrokerError("BROKER_TIMEOUT"))
        async with await _client(broker) as client:
            with pytest.raises(MCPError) as error:
                await client.list_tools()
        assert error.value.error.code == types.INTERNAL_ERROR
        assert error.value.error.message.startswith("BROKER_TIMEOUT: ")

    @pytest.mark.asyncio
    async def test_starting_and_initialising_never_touch_the_broker(self):
        broker = FakeBroker(error=BrokerError("BROKER_UNAVAILABLE"))
        async with await _client(broker):
            pass  # connecting and initialising is all this does
        assert broker.listed == 0 and broker.calls == []

    @pytest.mark.asyncio
    async def test_the_log_records_the_code_and_nothing_else(self, caplog):
        caplog.set_level(logging.DEBUG)
        broker = FakeBroker(error=BrokerError("BROKER_CERTIFICATE_ERROR"))
        async with await _client(broker) as client:
            await client.call_tool("list_shares", {"nas_name": "nas1", "path": "/private/folder"})
        assert "BROKER_CERTIFICATE_ERROR" in caplog.text
        assert "/private/folder" not in caplog.text and "nas1" not in caplog.text


class TestCredentialsNeverLeaveTheComputer:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "arguments,fields",
        [
            ({"password": PASSWORD}, ["password"]),
            ({"nas_name": "nas1", "otp_code": "123456"}, ["otp_code"]),
            ({"device_id": "x"}, ["device_id"]),
            ({"options": {"Password": PASSWORD}}, ["Password"]),
            ({"items": [{"ok": 1}, {"passwd": PASSWORD}]}, ["passwd"]),
            ({"password": PASSWORD, "otp": "123456"}, ["password", "otp"]),
        ],
    )
    async def test_a_call_with_a_credential_field_is_refused_without_contacting_the_broker(
        self, arguments, fields, caplog
    ):
        caplog.set_level(logging.DEBUG)
        broker = FakeBroker()
        async with await _client(broker) as client:
            result = await client.call_tool("list_shares", arguments)

        assert broker.calls == []
        assert result.is_error is True
        text = result.content[0].text
        assert text.startswith("CREDENTIALS_REFUSED: ")
        assert all(field in text for field in fields)
        assert PASSWORD not in text and "123456" not in text
        assert PASSWORD not in caplog.text and "123456" not in caplog.text

    @pytest.mark.asyncio
    async def test_a_value_that_merely_mentions_the_word_is_not_a_credential_field(self):
        broker = FakeBroker()
        async with await _client(broker) as client:
            result = await client.call_tool(
                "list_shares", {"path": "/docs/password.txt", "query": "otp"}
            )
        assert result.is_error is False
        assert broker.calls[0][1] == {"path": "/docs/password.txt", "query": "otp"}

    def test_the_words_are_a_small_fixed_set(self):
        assert {"password", "otp", "passwd"} <= CREDENTIAL_WORDS

    @pytest.mark.parametrize(
        "arguments,expected",
        [
            (None, []),
            ({}, []),
            ("password", []),
            ([{"PASSWORD": 1}], ["PASSWORD"]),
            ({"a": {"b": {"c": {"password": 1}}}}, ["password"]),
            ({5: {"password": 1}}, ["password"]),
            ({"password": 1, "Password": 2}, ["password", "Password"]),
        ],
    )
    def test_credential_fields_are_found_by_name_anywhere(self, arguments, expected):
        assert credential_fields(arguments) == expected


class TestTheGuardReadsWordsAndFailsClosed:
    """The guard is a safety net for a model's mistake, not the boundary; but it
    should catch the obvious variations, and it must not let an unchecked branch
    through just because it is nested deeply."""

    @pytest.mark.parametrize(
        "name",
        [
            "password",
            "PASSWORD",
            "nas_password",
            "userPassword",
            "admin_PASSWORD",
            "Passphrase",
            "otp",
            "otp_code",
            "OTPCode",
            "adminOTP",
            "otpcode",
            "pwd",
            "device_id",
            "deviceId",
            "nas_device_id",
            "DeviceID",
            "deviceid",
            "NASPassword",
            "SMBPwd",
            "SMBDeviceId",
            "HTTPPassphrase",
        ],
    )
    def test_a_name_with_a_credential_word_in_it_is_caught(self, name):
        assert looks_like_credential(name) is True

    @pytest.mark.parametrize(
        "name",
        [
            "passwordless",
            "hotpot",
            "footprint",
            "compass",
            "passed",
            "sword",
            "path",
            "nas_name",
            "query",
            "pattern",
            "identity",
            "provider",
            "device",
            "id",
            "options",
            "topic",
            "NASName",
            "SMBPath",
        ],
    )
    def test_a_name_that_only_looks_similar_is_not(self, name):
        assert looks_like_credential(name) is False

    @staticmethod
    def _nested(levels, leaf):
        value = leaf
        for _ in range(levels):
            value = {"x": value}
        return value

    def test_nesting_up_to_the_limit_is_looked_through(self):
        check = inspect_arguments(self._nested(MAX_DEPTH, {"password": 1}))
        assert check.fields == ["password"] and check.too_deep is False

    def test_nesting_beyond_the_limit_is_flagged_not_silently_passed(self):
        check = inspect_arguments(self._nested(MAX_DEPTH + 1, {"password": 1}))
        assert check.too_deep is True

    def test_a_deep_structure_with_no_credential_is_still_flagged(self):
        assert inspect_arguments(self._nested(MAX_DEPTH + 1, {"ok": 1})).too_deep is True

    def test_a_long_flat_list_is_not_deep(self):
        check = inspect_arguments({"items": [{"a": i} for i in range(1000)]})
        assert check.too_deep is False and check.fields == []

    def test_a_deeply_nested_scalar_is_not_a_container_and_is_fine(self):
        assert inspect_arguments(self._nested(MAX_DEPTH, "just text")).too_deep is False

    @pytest.mark.asyncio
    async def test_arguments_too_deep_to_check_are_refused_without_contacting_the_broker(
        self, caplog
    ):
        caplog.set_level(logging.DEBUG)
        broker = FakeBroker()
        deep = self._nested(MAX_DEPTH + 1, {"password": PASSWORD})
        async with await _client(broker) as client:
            result = await client.call_tool("list_shares", deep)

        assert broker.calls == []
        assert result.is_error is True and result.content[0].text == TOO_DEEP_MESSAGE
        assert PASSWORD not in result.content[0].text and PASSWORD not in caplog.text

    @pytest.mark.asyncio
    @pytest.mark.parametrize("name", ["nas_password", "userPassword", "adminOTP", "nas_device_id"])
    async def test_a_name_containing_a_credential_word_is_refused_end_to_end(self, name):
        broker = FakeBroker()
        async with await _client(broker) as client:
            result = await client.call_tool("list_shares", {name: PASSWORD})
        assert broker.calls == []
        assert (
            result.content[0].text.startswith("CREDENTIALS_REFUSED: ")
            and name in result.content[0].text
        )
        assert PASSWORD not in result.content[0].text

    @pytest.mark.asyncio
    async def test_ordinary_arguments_with_look_alike_names_go_through(self):
        broker = FakeBroker()
        args = {
            "passwordless": True,
            "hotpot": "x",
            "path": "/docs/password.txt",
            "options": {"footprint": 1},
        }
        async with await _client(broker) as client:
            result = await client.call_tool("list_shares", args)
        assert result.is_error is False and broker.calls[0][1] == args
