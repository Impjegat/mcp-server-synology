# src/adapter/client.py - Talking to the broker for the adapter.
#
# Each operation gets its own HTTP client and its own MCP session: the broker is
# stateless at the MCP layer, so there is no session to keep warm, and a token
# replaced on disk is used by the very next call. An operation is three requests
# (initialize, the call, the initialized notification) and they share one
# connection. Sharing a client between operations was tried and measured against
# a real broker: it did not reduce the number of connections (five operations
# used six), because the SDK discards its connection when an operation ends, so a
# pool would have added state and no saving. What a call costs is one connection
# and its TLS handshake, a few milliseconds to a broker on a LAN and negligible
# beside the NAS call itself. If that ever matters, the place to look is the SDK's
# handling of the connection at the end of a session, not a cache here.
#
# The time limits are overall: `list_timeout` and `call_timeout` bound an
# operation from the first byte of connecting to the last of the reply, handshake
# included. `connect_timeout` bounds only establishing the TCP and TLS connection,
# so a host that is down is reported in seconds instead of after the whole limit.
#
# The token must not travel anywhere the configuration did not name: the SDK
# follows only same-origin redirects and ignores the client's own setting, so a
# redirect to another origin is not followed (a test asserts that only the
# configured URL ever receives a request). `follow_redirects=False` below is a
# second layer for any request the SDK does not make itself.
#
# Every way this can fail becomes a stable code and a fixed sentence. Nothing a
# model sees is built from an exception's text, which can carry a URL, a header or
# a token. The SDK client throws the HTTP status away for any error response, so
# the status is noted here by a response hook (an integer, nothing else) and used
# to say whether the token was refused or the broker failed.

import asyncio
import contextlib
import ssl
import sys
from typing import Any, Callable, Dict, List, Optional

import anyio
import httpx2
import mcp.types as types
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError

from adapter.config import AdapterSettings, MalformedTokenError

if sys.version_info < (3, 11):  # the builtin arrived in 3.11; anyio installs this backport
    from exceptiongroup import BaseExceptionGroup

_MESSAGES: Dict[str, str] = {
    "BROKER_UNAVAILABLE": "The Synology broker could not be reached. Ask the user to check that it is running and reachable.",
    "BROKER_TIMEOUT": "The Synology broker did not answer in time.",
    "BROKER_CERTIFICATE_ERROR": "The broker's certificate could not be verified, so nothing was sent.",
    "BROKER_UNAUTHORIZED": "The broker did not accept this client's token. Ask the user to check the client's token.",
    "BROKER_TOKEN_MISSING": "This client has no broker token. Ask the user to check the adapter configuration.",
    "BROKER_TOKEN_INVALID": "This client's broker token is not a valid token (too short, too long, or containing spaces or line breaks). Ask the user to check it.",
    "BROKER_REFUSED": "The broker refused the request. Ask the user to check the broker address and its allowed hosts.",
    "BROKER_BUSY": "The broker is receiving too many requests. Try again shortly.",
    "BROKER_ERROR": "The broker reported an error.",
    "BROKER_PROTOCOL_ERROR": "The broker's reply could not be understood.",
}


class BrokerError(Exception):
    """A failure to get an answer from the broker. `text` is safe to show a model:
    a code and a fixed sentence, never anything taken from the failure itself."""

    def __init__(self, code: str, detail: Optional[str] = None):
        self.code = code
        message = _MESSAGES.get(code, _MESSAGES["BROKER_ERROR"])
        self.text = f"{code}: {message}" + (f" ({detail})" if detail else "")
        super().__init__(self.text)


def _leaves(exc: BaseException):
    """The exceptions inside a (possibly nested) exception group, or `exc` itself."""
    if isinstance(exc, BaseExceptionGroup):
        for inner in exc.exceptions:
            yield from _leaves(inner)
    else:
        yield exc


def _chain(exc: BaseException):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


def _status_error(statuses: List[int]) -> BrokerError:
    status = statuses[0]
    if status == 401:
        return BrokerError("BROKER_UNAUTHORIZED")
    if status in (403, 421):
        return BrokerError("BROKER_REFUSED", f"HTTP {status}")
    if status == 429:
        return BrokerError("BROKER_BUSY")
    return BrokerError("BROKER_ERROR", f"HTTP {status}")


def translate(exc: BaseException, statuses: List[int]) -> BaseException:
    """What to raise for a failed operation. A broker error response gets a precise
    code from its HTTP status; a JSON-RPC error the broker sent on purpose (an unknown
    tool, say) is passed through unchanged; everything else is a transport failure
    with a fixed description."""
    leaves = list(_leaves(exc))
    if statuses:
        return _status_error(statuses)
    for leaf in leaves:
        if isinstance(leaf, MCPError):
            return leaf
    for leaf in leaves:
        if isinstance(leaf, (TimeoutError, httpx2.TimeoutException)):
            return BrokerError("BROKER_TIMEOUT")
    for leaf in leaves:
        if any(isinstance(link, ssl.SSLError) for link in _chain(leaf)):
            return BrokerError("BROKER_CERTIFICATE_ERROR")
    for leaf in leaves:
        if isinstance(leaf, (httpx2.TransportError, OSError)):
            return BrokerError("BROKER_UNAVAILABLE")
    return BrokerError("BROKER_PROTOCOL_ERROR")


class BrokerClient:
    def __init__(
        self,
        settings: AdapterSettings,
        token_provider: Callable[[], Optional[str]],
        *,
        transport: Optional[httpx2.AsyncBaseTransport] = None,
    ):
        self._settings = settings
        self._token_provider = token_provider
        self._transport = transport
        self._last_token: Optional[str] = None
        self._ssl: Any = (
            ssl.create_default_context(cafile=settings.ca_file)
            if settings.broker_url.startswith("https://")
            else True
        )

    def known_secrets(self) -> List[str]:
        """The token in use, for the log redaction filter."""
        return [self._last_token] if self._last_token else []

    @contextlib.asynccontextmanager
    async def _session(self, timeout: float):
        try:
            token = self._token_provider()
        except MalformedTokenError:
            raise BrokerError("BROKER_TOKEN_INVALID") from None
        if not token:
            raise BrokerError("BROKER_TOKEN_MISSING")
        self._last_token = token
        statuses: List[int] = []

        async def note_status(response: httpx2.Response) -> None:
            if response.status_code >= 400:
                statuses.append(response.status_code)

        settings = self._settings
        client = httpx2.AsyncClient(
            transport=self._transport,
            verify=self._ssl,
            headers={"Authorization": f"Bearer {token}"},
            timeout=httpx2.Timeout(
                connect=settings.connect_timeout, read=timeout, write=timeout, pool=timeout
            ),
            follow_redirects=False,
            event_hooks={"response": [note_status]},
        )
        try:
            with anyio.fail_after(timeout):
                async with client:
                    async with streamable_http_client(
                        settings.broker_url, http_client=client, terminate_on_close=False
                    ) as streams:
                        async with ClientSession(streams[0], streams[1]) as session:
                            await session.initialize()
                            yield session
        except (Exception, BaseExceptionGroup) as exc:
            if isinstance(exc, BrokerError) or all(
                isinstance(leaf, asyncio.CancelledError) for leaf in _leaves(exc)
            ):
                raise
            raise translate(exc, statuses) from None

    async def list_tools(self) -> List[types.Tool]:
        tools: List[types.Tool] = []
        async with self._session(self._settings.list_timeout) as session:
            cursor: Optional[str] = None
            for _ in range(20):  # a bound, in case a broker never stops paging
                params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
                page = await session.list_tools(params=params)
                tools.extend(page.tools)
                cursor = page.next_cursor
                if not cursor:
                    break
        return tools

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> types.CallToolResult:
        async with self._session(self._settings.call_timeout) as session:
            result = await session.call_tool(name, arguments)
        if not isinstance(result, types.CallToolResult):
            raise BrokerError("BROKER_PROTOCOL_ERROR")
        return result
