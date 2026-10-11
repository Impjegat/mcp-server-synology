"""The broker over HTTP, end to end: the real MCP client talks to the real ASGI
app in-process (no sockets). Covers who may connect, what each client sees, and
that nothing from a DSM session reaches the wire."""

import contextlib
from unittest.mock import patch

import httpx2
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from broker.errors import AuthenticationRequired
from broker.server import create_broker_app
from tests.broker_support import BASE_URLS, Broker

ORIGIN = "http://testserver"
CLIENTS = {
    "alice": {"token": "alice-token-value", "nas": ["nas1"], "folders": {"nas1": ["/docs"]}},
    "bob": {
        "token": "bob-token-value",
        "nas": ["nas1"],
        "tools": ["list_shares", "synology_status"],
        "disconnect": False,
    },
}


@pytest.fixture
def broker(monkeypatch):
    return Broker(monkeypatch, CLIENTS, session={"idle_seconds": 100, "absolute_seconds": 1000})


def _app(broker, **kwargs):
    kwargs.setdefault("allowed_hosts", ["testserver"])
    return create_broker_app(broker.runtime, broker.policy, **kwargs)


@contextlib.asynccontextmanager
async def _running(app):
    async with app.router.lifespan_context(app):
        yield httpx2.ASGITransport(app=app)


@contextlib.asynccontextmanager
async def _client(transport, token):
    """An MCP session over `transport` (an app that is already running), signed
    in with bearer `token`."""
    async with httpx2.AsyncClient(
        transport=transport, base_url=ORIGIN, headers={"Authorization": f"Bearer {token}"}
    ) as http:
        async with streamable_http_client(f"{ORIGIN}/mcp", http_client=http) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                yield session


@contextlib.asynccontextmanager
async def _single(app, token):
    """Start `app`, open one MCP session on it, and stop it afterwards."""
    async with _running(app) as transport:
        async with _client(transport, token) as session:
            yield session


def _text(result):
    return result.content[0].text


class TestWhoMayConnect:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"Authorization": "Bearer wrong-token"},
            {"Authorization": "Basic YWxpY2U6cGFzcw=="},
            {"Authorization": "Bearer "},
            {"Authorization": "bearer"},
        ],
    )
    async def test_a_request_without_a_valid_token_is_refused(self, broker, headers):
        async with _running(_app(broker)) as transport:
            async with httpx2.AsyncClient(transport=transport, base_url=ORIGIN) as http:
                response = await http.post("/mcp", headers=headers, json={})

        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith("Bearer")
        assert "wrong-token" not in response.text

    @pytest.mark.asyncio
    async def test_a_token_in_the_url_does_not_count(self, broker):
        async with _running(_app(broker)) as transport:
            async with httpx2.AsyncClient(transport=transport, base_url=ORIGIN) as http:
                response = await http.post("/mcp?token=alice-token-value", json={})
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_the_policy_digest_is_not_a_token(self, broker):
        digest = broker.policy.clients["alice"].token_sha256
        async with _running(_app(broker)) as transport:
            async with httpx2.AsyncClient(
                transport=transport, base_url=ORIGIN, headers={"Authorization": f"Bearer {digest}"}
            ) as http:
                response = await http.post("/mcp", json={})
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_a_host_that_is_not_listed_is_refused(self, broker):
        async with _running(_app(broker)) as transport:
            async with httpx2.AsyncClient(
                transport=transport,
                base_url="http://rebound.example",
                headers={"Authorization": "Bearer alice-token-value"},
            ) as http:
                response = await http.post("/mcp", json={})
        assert response.status_code in (400, 403, 421)

    def test_the_app_needs_to_be_told_how_clients_reach_it(self, broker):
        with pytest.raises(ValueError, match="allowed_hosts"):
            create_broker_app(broker.runtime, broker.policy, allowed_hosts=[])


class TestAGrantThatEnds:
    """A client token is honoured only until its grant ends, checked on every
    request, so a grant that ends while a session is open is refused from then on
    (implementation review R12)."""

    @staticmethod
    def _clock():
        import time

        now = [time.time()]
        return now, lambda: now[0]

    @pytest.mark.asyncio
    async def test_r12_the_token_stops_working_the_moment_its_grant_ends(self, broker):
        now, clock = self._clock()
        ends = broker.policy.clients["alice"].expires_at
        headers = {"Authorization": "Bearer alice-token-value"}
        async with _running(_app(broker, clock=clock)) as transport:
            async with httpx2.AsyncClient(
                transport=transport, base_url=ORIGIN, headers=headers
            ) as http:
                before = await http.post("/mcp", json={})
                now[0] = ends - 1
                just_before = await http.post("/mcp", json={})
                now[0] = ends
                at_the_end = await http.post("/mcp", json={})
                now[0] = ends + 86400
                after = await http.post("/mcp", json={})

        # Before it ends the token is accepted (the empty body is what is refused).
        assert before.status_code != 401 and just_before.status_code != 401
        assert at_the_end.status_code == 401 and after.status_code == 401
        assert at_the_end.headers["www-authenticate"].startswith("Bearer")
        assert "alice-token-value" not in at_the_end.text

    @pytest.mark.asyncio
    async def test_r12_a_session_that_is_open_when_the_grant_ends_is_refused_next(self, broker):
        now, clock = self._clock()
        async with _single(_app(broker, clock=clock), "alice-token-value") as session:
            assert "list_shares" in {t.name for t in (await session.list_tools()).tools}
            now[0] = broker.policy.clients["alice"].expires_at  # ends while it is open
            with pytest.raises(Exception):
                await session.list_tools()

    @pytest.mark.asyncio
    async def test_one_clients_grant_ending_does_not_end_anothers(self, broker):
        now, clock = self._clock()
        policy = broker.policy
        now[0] = policy.clients["alice"].expires_at  # alice's has ended; bob's is the same date
        async with _running(_app(broker, clock=clock)) as transport:
            async with httpx2.AsyncClient(transport=transport, base_url=ORIGIN) as http:
                alice = await http.post(
                    "/mcp", json={}, headers={"Authorization": "Bearer alice-token-value"}
                )
        assert alice.status_code == 401

    @pytest.mark.asyncio
    async def test_the_default_clock_is_the_real_one(self, broker):
        """With no clock given, a grant that really has ended is refused."""
        import dataclasses
        import time

        from broker.policy import Policy

        ended = dataclasses.replace(broker.policy.clients["alice"], expires_at=time.time() - 5)
        policy = Policy(clients={"alice": ended}, session=broker.policy.session)
        async with _running(
            create_broker_app(broker.runtime, policy, allowed_hosts=["testserver"])
        ) as transport:
            async with httpx2.AsyncClient(transport=transport, base_url=ORIGIN) as http:
                response = await http.post(
                    "/mcp", json={}, headers={"Authorization": "Bearer alice-token-value"}
                )
        assert response.status_code == 401


class TestHealthEndpoints:
    @pytest.mark.asyncio
    async def test_they_need_no_token_and_say_nothing_about_the_nas_or_sessions(self, broker):
        broker.sign_in("alice")
        async with _running(_app(broker)) as transport:
            async with httpx2.AsyncClient(transport=transport, base_url=ORIGIN) as http:
                live = await http.get("/healthz")
                ready = await http.get("/readyz")

        assert (live.status_code, live.json()) == (200, {"status": "ok"})
        assert (ready.status_code, ready.json()) == (200, {"ready": True})

    @pytest.mark.asyncio
    async def test_a_broker_nobody_has_signed_in_to_is_ready(self, broker):
        async with _running(_app(broker)) as transport:
            async with httpx2.AsyncClient(transport=transport, base_url=ORIGIN) as http:
                assert (await http.get("/readyz")).status_code == 200

    @pytest.mark.asyncio
    async def test_a_broker_that_cannot_serve_says_so(self, broker):
        async with _running(_app(broker, ready=lambda: False)) as transport:
            async with httpx2.AsyncClient(transport=transport, base_url=ORIGIN) as http:
                response = await http.get("/readyz")
        assert (response.status_code, response.json()) == (503, {"ready": False})


class TestWhatEachClientSees:
    @pytest.mark.asyncio
    async def test_each_token_gets_its_own_tools(self, broker):
        async with _running(_app(broker)) as transport:
            async with _client(transport, "alice-token-value") as session:
                alice = {t.name for t in (await session.list_tools()).tools}
            async with _client(transport, "bob-token-value") as session:
                bob = {t.name for t in (await session.list_tools()).tools}

        assert "list_directory" in alice and "synology_logout" in alice
        assert "synology_login" not in alice | bob
        assert bob == {"list_shares", "synology_status"}

    @pytest.mark.asyncio
    async def test_a_call_without_a_sign_in_asks_for_one(self, broker):
        async with _single(_app(broker), "alice-token-value") as session:
            result = await session.call_tool("list_shares", {"nas_name": "nas1"})

        assert result.is_error is True
        assert _text(result).startswith("AUTHENTICATION_REQUIRED")

    @pytest.mark.asyncio
    async def test_a_tool_outside_the_clients_list_is_denied(self, broker):
        broker.sign_in("bob")
        async with _single(_app(broker), "bob-token-value") as session:
            result = await session.call_tool("synology_health_summary", {"nas_name": "nas1"})

        assert result.is_error is True
        assert _text(result).startswith("AUTHORIZATION_DENIED")

    @pytest.mark.asyncio
    async def test_a_signed_in_client_is_served_and_another_is_not(self, broker):
        from filestation import SynologyFileStation

        broker.sign_in("alice")
        with patch.object(SynologyFileStation, "list_shares", return_value=[{"name": "docs"}]):
            async with _running(_app(broker)) as transport:
                async with _client(transport, "alice-token-value") as session:
                    mine = await session.call_tool("list_shares", {"nas_name": "nas1"})
                async with _client(transport, "bob-token-value") as session:
                    theirs = await session.call_tool("list_shares", {"nas_name": "nas1"})

        assert mine.is_error is False
        assert theirs.is_error is True
        assert _text(theirs).startswith("AUTHENTICATION_REQUIRED")

    @pytest.mark.asyncio
    async def test_a_session_ending_at_the_nas_shows_up_over_http_too(self, broker):
        from filestation import SynologyFileStation

        broker.sign_in("alice")
        with patch.object(SynologyFileStation, "list_shares", side_effect=AuthenticationRequired()):
            async with _single(_app(broker), "alice-token-value") as session:
                result = await session.call_tool("list_shares", {"nas_name": "nas1"})
                status = await session.call_tool("synology_status", {})

        assert _text(result).startswith("AUTHENTICATION_REQUIRED")
        assert "AUTHENTICATION_REQUIRED" in _text(status)

    @pytest.mark.asyncio
    async def test_the_same_token_can_open_a_new_session_after_the_first_closes(self, broker):
        async with _running(_app(broker)) as transport:
            for _ in range(2):
                async with _client(transport, "alice-token-value") as session:
                    assert (await session.call_tool("synology_status", {})).is_error is False


class TestNothingSecretOnTheWire:
    @pytest.mark.asyncio
    async def test_no_reply_carries_a_session_value_or_a_token(self, broker):
        from filestation import SynologyFileStation

        broker.sign_in("alice", session_id="RAW-SID-VALUE-7d3f9", token="RAW-TOKEN-VALUE-1b8e")
        replies = []
        with patch.object(
            SynologyFileStation, "list_shares", side_effect=Exception("RAW-SID-VALUE-7d3f9")
        ):
            async with _single(_app(broker), "alice-token-value") as session:
                replies.append(await session.list_tools())
                replies.append(await session.call_tool("synology_status", {}))
                replies.append(await session.call_tool("synology_list_nas", {}))
                replies.append(await session.call_tool("list_shares", {"nas_name": "nas1"}))
                replies.append(
                    await session.call_tool("synology_logout", {"base_url": BASE_URLS["nas1"]})
                )

        wire = " ".join(reply.model_dump_json() for reply in replies)
        for secret in ("RAW-SID-VALUE", "RAW-TOKEN-VALUE", "alice-token-value"):
            assert secret not in wire
        assert broker.logouts == [(BASE_URLS["nas1"], "RAW-SID-VALUE-7d3f9")]
