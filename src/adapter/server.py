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

import logging
from typing import Any, Dict, List, Optional

import mcp.types as types
from mcp.server import Server, ServerRequestContext

from adapter.client import BrokerClient, BrokerError

logger = logging.getLogger("synology-adapter")

# Argument names that mean a credential. Names only, never values.
CREDENTIAL_FIELDS = frozenset({"password", "passwd", "passphrase", "otp", "otp_code", "device_id"})

REFUSED_MESSAGE = (
    "CREDENTIALS_REFUSED: this tool call has a field that looks like a password or a one-time "
    "code ({fields}). Credentials must never be sent through tools. Ask the user to sign in on "
    "the private login page instead."
)


def credential_fields(arguments: Any) -> List[str]:
    """The names, found anywhere in `arguments`, that look like credentials."""
    found: List[str] = []

    def walk(value: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(value, dict):
            for key, inner in value.items():
                if isinstance(key, str) and key.lower() in CREDENTIAL_FIELDS and key not in found:
                    found.append(key)
                walk(inner, depth + 1)
        elif isinstance(value, list):
            for item in value:
                walk(item, depth + 1)

    walk(arguments)
    return found


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
        offending = credential_fields(arguments)
        if offending:
            logger.warning("A tool call was refused locally: it carried a credential-like field")
            return _error_result(REFUSED_MESSAGE.format(fields=", ".join(offending)))
        try:
            return await client.call_tool(params.name, arguments)
        except BrokerError as error:
            logger.warning("A tool call failed (%s)", error.code)
            return _error_result(error.text)

    return Server(name, version=version, on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def _protocol_error(error: BrokerError):
    from mcp.shared.exceptions import MCPError

    return MCPError(types.INTERNAL_ERROR, error.text)
