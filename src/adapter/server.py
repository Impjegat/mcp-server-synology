# src/adapter/server.py - The adapter's MCP server: it forwards, and nothing more.
#
# `tools/list` and `tools/call` go to the broker as they are and what comes back
# is returned as it is, errors included, so a model sees exactly what the broker
# decided. The adapter adds nothing, decides nothing about the NAS, and has no
# other way to reach one: it holds no NAS credential and imports no NAS module.
#
# One thing it does refuse, locally and before anything leaves this computer: a
# tool call whose arguments carry a field named like a password or a one-time
# code. No tool the broker offers takes one, so such a field means a model is
# about to put a credential into a tool call; stopping it here keeps it out of
# every log between here and the broker.
#
# That guard is a safety net for a model's mistake, not the security boundary (the
# boundary is that the broker offers no tool that takes a credential, and the
# adapter holds none). Its limits: it reads field *names*, split into words, so
# `nas_password` and `userPassword` are caught but a password typed into a *value*
# (a path, a search pattern) is not; and it fails closed on arguments nested deeper
# than any tool needs, refusing them rather than letting an unchecked branch through.
#
# What a model is shown when the broker answers badly depends on what kind of
# failure it was. A JSON-RPC error the broker sent on purpose (an unknown tool) is
# passed on as the protocol error it is, exactly as a direct connection would have
# shown it. A failure to *reach* the broker becomes a tool-error result, because it
# is a condition a model can report to the user.

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import mcp.types as types
from mcp.server import Server, ServerRequestContext
from mcp.shared.exceptions import MCPError

from adapter.client import BrokerClient, BrokerError

logger = logging.getLogger("synology-adapter")

# Words that, anywhere in an argument's name, mean a credential. A name is split at
# punctuation and at case changes (`userPassword`, `OTPCode`), so `otp_code`, `nas_password` and
# `userPassword` all contain a word below, and `passwordless`, `hotpot` and
# `footprint` contain none. Names only, never values.
CREDENTIAL_WORDS = frozenset(
    {"password", "passwd", "passphrase", "pwd", "otp", "otpcode", "deviceid"}
)
# Pairs of adjacent words that mean one: `device_id`, `deviceId`, `nas_device_id`.
CREDENTIAL_PAIRS = frozenset({("device", "id")})
# Arguments nested deeper than this are refused unchecked. No tool needs more.
MAX_DEPTH = 8

_WORD_BREAK = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

TOO_DEEP_MESSAGE = (
    "ARGUMENTS_REFUSED: the arguments are nested too deeply to be checked for credentials. "
    "No tool needs arguments nested this deeply."
)

REFUSED_MESSAGE = (
    "CREDENTIALS_REFUSED: this tool call has a field that looks like a password or a one-time "
    "code ({fields}). Credentials must never be sent through tools. Ask the user to sign in on "
    "the private login page instead."
)


def looks_like_credential(name: str) -> bool:
    """Whether an argument's name is, or contains as a word, a credential."""
    words = [word.lower() for word in _WORD_BREAK.split(name) if word]
    if any(word in CREDENTIAL_WORDS for word in words):
        return True
    return any(pair in CREDENTIAL_PAIRS for pair in zip(words, words[1:]))


@dataclass
class ArgumentCheck:
    """What looking through a call's arguments found."""

    fields: List[str] = field(default_factory=list)
    too_deep: bool = False


def inspect_arguments(arguments: Any) -> ArgumentCheck:
    """The credential-like field names anywhere in `arguments`, and whether some
    part was nested too deeply to look through."""
    result = ArgumentCheck()

    def walk(value: Any, depth: int = 0) -> None:
        if isinstance(value, (dict, list)) and depth > MAX_DEPTH:
            result.too_deep = True
            return
        if isinstance(value, dict):
            for key, inner in value.items():
                if isinstance(key, str) and looks_like_credential(key) and key not in result.fields:
                    result.fields.append(key)
                walk(inner, depth + 1)
        elif isinstance(value, list):
            for item in value:
                walk(item, depth + 1)

    walk(arguments)
    return result


def credential_fields(arguments: Any) -> List[str]:
    """The names, found anywhere in `arguments`, that look like credentials."""
    return inspect_arguments(arguments).fields


def _error_result(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)


def build_adapter_server(
    client: BrokerClient, *, name: str = "synology", version: str = "1.0.0"
) -> Server:
    async def on_list_tools(
        ctx: ServerRequestContext, params: Optional[types.PaginatedRequestParams]
    ) -> types.ListToolsResult:
        try:
            return types.ListToolsResult(tools=await client.list_tools())
        except BrokerError as error:
            logger.warning("Listing tools failed (%s)", error.code)
            # A protocol error, not a tool result: there is no tool to attach it to.
            raise _protocol_error(error) from None

    async def on_call_tool(
        ctx: ServerRequestContext, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        arguments: Dict[str, Any] = params.arguments or {}
        check = inspect_arguments(arguments)
        if check.fields:
            logger.warning("A tool call was refused locally: it carried a credential-like field")
            return _error_result(REFUSED_MESSAGE.format(fields=", ".join(check.fields)))
        if check.too_deep:
            logger.warning("A tool call was refused locally: its arguments were nested too deeply")
            return _error_result(TOO_DEEP_MESSAGE)
        try:
            return await client.call_tool(params.name, arguments)
        except BrokerError as error:
            logger.warning("A tool call failed (%s)", error.code)
            return _error_result(error.text)

    return Server(name, version=version, on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def _protocol_error(error: BrokerError) -> MCPError:
    return MCPError(types.INTERNAL_ERROR, error.text)
