# src/broker/server.py - The broker's HTTP front: authenticated MCP, nothing else.
#
# One endpoint, `/mcp`, speaks Streamable HTTP and requires a bearer token that
# matches a client in the policy. Behind it every tool call is run for the
# client the token identifies, by `BrokerRuntime`. Two small unauthenticated
# endpoints report liveness and readiness without saying anything about the
# NAS, the clients or the sessions.
#
# The server is stateless at the MCP layer: each request is authenticated on
# its own, and nothing about who a caller is lives in an MCP session id. (An
# MCP transport session id is not a DSM session id and never leads to one.)

from typing import Any, Optional, Sequence

import mcp.types as types
from mcp.server import Server, ServerRequestContext
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import (
    AuthenticatedUser,
    BearerAuthBackend,
    RequireAuthMiddleware,
)
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from broker.policy import Policy, PolicyTokenVerifier
from broker.runtime import BrokerRuntime

SERVER_NAME = "synology-broker"


def _client_id(ctx: ServerRequestContext) -> str:
    """The client the request's bearer token identified. The authentication
    middleware has already refused anything without a valid token, so a request
    that reaches a handler without one is a wiring error, and is refused."""
    request = ctx.request
    scope = getattr(request, "scope", None)
    user = scope.get("user") if isinstance(scope, dict) else None
    if not isinstance(user, AuthenticatedUser):
        raise MCPError(types.INVALID_REQUEST, "Authentication required")
    return user.access_token.client_id


def build_mcp_server(runtime: BrokerRuntime, *, version: str = "1.0.0") -> Server:
    """The low-level MCP server whose handlers run each call as its client."""

    async def on_list_tools(
        ctx: ServerRequestContext, params: Optional[types.PaginatedRequestParams]
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=await runtime.list_tools(_client_id(ctx)))

    async def on_call_tool(
        ctx: ServerRequestContext, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        return await runtime.call_tool(_client_id(ctx), params.name, params.arguments or {})

    return Server(
        SERVER_NAME, version=version, on_list_tools=on_list_tools, on_call_tool=on_call_tool
    )


def create_broker_app(
    runtime: BrokerRuntime,
    policy: Policy,
    *,
    allowed_hosts: Sequence[str],
    allowed_origins: Sequence[str] = (),
    ready: Any = lambda: True,
) -> Starlette:
    """The ASGI app. `allowed_hosts` and `allowed_origins` are required, not
    defaulted: DNS-rebinding protection is on, and only the names listed here
    may be used to reach the broker."""
    if not allowed_hosts:
        raise ValueError("allowed_hosts must name how clients reach the broker")

    session_manager = StreamableHTTPSessionManager(
        app=build_mcp_server(runtime),
        json_response=True,
        stateless=True,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(allowed_hosts),
            allowed_origins=list(allowed_origins),
        ),
    )
    mcp_endpoint = RequireAuthMiddleware(StreamableHTTPASGIApp(session_manager), required_scopes=[])

    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    async def readyz(request: Request) -> JSONResponse:
        # Ready means able to serve, not signed in: a broker nobody has signed
        # in to yet is healthy, and says nothing more than that.
        is_ready = bool(ready())
        return JSONResponse({"ready": is_ready}, status_code=200 if is_ready else 503)

    return Starlette(
        routes=[
            Route("/mcp", endpoint=mcp_endpoint),
            Route("/healthz", endpoint=healthz, methods=["GET"]),
            Route("/readyz", endpoint=readyz, methods=["GET"]),
        ],
        middleware=[
            Middleware(
                AuthenticationMiddleware, backend=BearerAuthBackend(PolicyTokenVerifier(policy))
            ),
            Middleware(AuthContextMiddleware),
        ],
        lifespan=lambda app: session_manager.run(),
    )
