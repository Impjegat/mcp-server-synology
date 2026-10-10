"""The adapter's connection to the broker, against the real broker app in-process
and against transports that fail in each way a network can. Whatever happens, what
a model is shown is a stable code and a fixed sentence, never text taken from the
failure, which can carry a URL, a header or the token."""

import asyncio
import sys
from unittest.mock import patch

import anyio
import httpx2
import mcp.types as types
import pytest
from mcp.shared.exceptions import MCPError

from adapter.client import BrokerClient, BrokerError
from adapter.config import AdapterSettings
from broker.server import create_broker_app
from tests.broker_support import Broker
from tests.fake_dsm import FakeDsmServer

if sys.version_info < (3, 11):  # the builtin arrived in 3.11; anyio installs this backport
    from exceptiongroup import BaseExceptionGroup

TOKEN = "alice-token-value-0123456789"
CLIENTS = {"alice": {"token": TOKEN, "nas": ["nas1"], "folders": {"nas1": ["/docs"]}}}
URL = "http://testserver/mcp"


def _settings(**overrides):
    values = dict(
        broker_url=URL, token_env="X", connect_timeout=2.0, list_timeout=5.0, call_timeout=5.0
    )
    values.update(overrides)
    return AdapterSettings(**values)


class Recorder(httpx2.AsyncBaseTransport):
    """Passes requests to another transport and remembers them."""

    def __init__(self, inner):
        self.inner = inner
        self.requests = []

    async def handle_async_request(self, request):
        self.requests.append(request)
        return await self.inner.handle_async_request(request)


class Fails(httpx2.AsyncBaseTransport):
    def __init__(self, error=None, status=None, headers=None):
        self.error, self.status, self.headers, self.requests = error, status, headers or {}, []

    async def handle_async_request(self, request):
        self.requests.append(request)
        if self.error is not None:
            raise self.error(
                f"boom {request.url} {request.headers.get('authorization')}", request=request
            )
        return httpx2.Response(self.status, headers=self.headers, text="nope", request=request)


class Hangs(httpx2.AsyncBaseTransport):
    async def handle_async_request(self, request):
        await anyio.sleep(60)


@pytest.fixture
def broker(monkeypatch):
    return Broker(monkeypatch, CLIENTS, session={"idle_seconds": 100, "absolute_seconds": 1000})


class Live:
    """The real broker app, running, with a recording transport onto it."""

    def __init__(self, broker, allowed_hosts):
        self.broker = broker
        self.app = create_broker_app(broker.runtime, broker.policy, allowed_hosts=allowed_hosts)

    async def __aenter__(self):
        self._lifespan = self.app.router.lifespan_context(self.app)
        await self._lifespan.__aenter__()
        self.transport = Recorder(httpx2.ASGITransport(app=self.app))
        return self

    async def __aexit__(self, *exc):
        await self._lifespan.__aexit__(*exc)

    def client(self, token=TOKEN, **settings):
        return BrokerClient(_settings(**settings), lambda: token, transport=self.transport)


class TestAgainstTheRealBroker:
    @pytest.mark.asyncio
    async def test_it_lists_the_clients_tools(self, broker):
        async with Live(broker, ["testserver"]) as live:
            tools = await live.client().list_tools()

        names = {tool.name for tool in tools}
        assert "list_shares" in names and "synology_logout" in names
        assert "synology_login" not in names

    @pytest.mark.asyncio
    async def test_a_call_without_a_session_comes_back_as_the_brokers_own_error_result(
        self, broker
    ):
        async with Live(broker, ["testserver"]) as live:
            result = await live.client().call_tool("list_shares", {"nas_name": "nas1"})

        assert result.is_error is True
        assert result.content[0].text.startswith("AUTHENTICATION_REQUIRED")

    @pytest.mark.asyncio
    async def test_a_call_with_a_session_succeeds(self, broker):
        from filestation import SynologyFileStation

        broker.sign_in("alice")
        async with Live(broker, ["testserver"]) as live:
            with patch.object(SynologyFileStation, "list_shares", return_value=[{"name": "docs"}]):
                result = await live.client().call_tool("list_shares", {"nas_name": "nas1"})

        assert result.is_error is False and "docs" in result.content[0].text

    @pytest.mark.asyncio
    async def test_an_unknown_tool_is_the_brokers_json_rpc_error_passed_through(self, broker):
        async with Live(broker, ["testserver"]) as live:
            with pytest.raises(MCPError) as error:
                await live.client().call_tool("no_such_tool", {})
        assert error.value.error.code == types.INVALID_PARAMS

    @pytest.mark.asyncio
    async def test_the_token_goes_in_the_authorization_header_and_nowhere_else(self, broker):
        async with Live(broker, ["testserver"]) as live:
            await live.client().call_tool("synology_status", {})

        assert live.transport.requests
        for request in live.transport.requests:
            assert request.headers["authorization"] == f"Bearer {TOKEN}"
            assert TOKEN not in str(request.url) and TOKEN not in request.content.decode()

    @pytest.mark.asyncio
    async def test_a_replaced_token_is_used_by_the_next_call(self, broker):
        tokens = iter([TOKEN, "wrong-token-value-0123456789"])
        async with Live(broker, ["testserver"]) as live:
            client = BrokerClient(_settings(), lambda: next(tokens), transport=live.transport)
            ok = await client.call_tool("synology_status", {})
            with pytest.raises(BrokerError) as error:
                await client.call_tool("synology_status", {})

        assert ok.is_error is False
        assert error.value.code == "BROKER_UNAUTHORIZED"

    @pytest.mark.asyncio
    async def test_concurrent_calls_do_not_interfere(self, broker):
        async with Live(broker, ["testserver"]) as live:
            client = live.client()
            results = await asyncio.gather(
                *[client.call_tool("synology_status", {}) for _ in range(6)]
            )
        assert all(r.is_error is False for r in results)

    @pytest.mark.asyncio
    async def test_a_host_the_broker_does_not_allow_is_a_refusal_not_a_crash(self, broker):
        async with Live(broker, ["only-this-host"]) as live:
            with pytest.raises(BrokerError) as error:
                await live.client(broker_url="http://rebound.example/mcp").list_tools()
        assert error.value.code == "BROKER_REFUSED"


class TestEveryFailureHasAFixedSentence:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "transport,code",
        [
            (Fails(error=httpx2.ConnectError), "BROKER_UNAVAILABLE"),
            (Fails(error=httpx2.ReadError), "BROKER_UNAVAILABLE"),
            (Fails(error=httpx2.RemoteProtocolError), "BROKER_UNAVAILABLE"),
            (Fails(error=httpx2.ConnectTimeout), "BROKER_TIMEOUT"),
            (Fails(error=httpx2.ReadTimeout), "BROKER_TIMEOUT"),
            (Fails(status=401), "BROKER_UNAUTHORIZED"),
            (Fails(status=403), "BROKER_REFUSED"),
            (Fails(status=421), "BROKER_REFUSED"),
            (Fails(status=429), "BROKER_BUSY"),
            (Fails(status=500), "BROKER_ERROR"),
            (Fails(status=503), "BROKER_ERROR"),
        ],
    )
    async def test_the_code_says_what_went_wrong_and_the_text_says_nothing_else(
        self, transport, code
    ):
        client = BrokerClient(_settings(), lambda: TOKEN, transport=transport)
        for operation in (client.list_tools(), client.call_tool("list_shares", {})):
            with pytest.raises(BrokerError) as error:
                await operation
            assert error.value.code == code
            text = error.value.text
            assert text.startswith(f"{code}: ")
            assert TOKEN not in text and "testserver" not in text and "boom" not in text

    @pytest.mark.asyncio
    async def test_a_broker_that_never_answers_times_out_at_the_configured_limit(self):
        import time

        client = BrokerClient(
            _settings(list_timeout=1.0, call_timeout=1.0), lambda: TOKEN, transport=Hangs()
        )
        started = time.monotonic()
        with pytest.raises(BrokerError) as error:
            await client.call_tool("list_shares", {})
        assert error.value.code == "BROKER_TIMEOUT"
        assert time.monotonic() - started < 6

    @pytest.mark.asyncio
    async def test_a_cancelled_call_is_cancelled_not_swallowed_as_a_broker_error(self):
        client = BrokerClient(_settings(call_timeout=30), lambda: TOKEN, transport=Hangs())
        task = asyncio.create_task(client.call_tool("list_shares", {}))
        await asyncio.sleep(0.3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    @pytest.mark.asyncio
    async def test_a_group_made_only_of_cancellations_is_not_turned_into_a_broker_error(self):
        """A task group can wrap a cancellation in an exception group. That is the
        caller being cancelled, so it must go on up, not be reported to a model as
        a broker failure."""

        class Cancelled(httpx2.AsyncBaseTransport):
            async def handle_async_request(self, request):
                raise BaseExceptionGroup("cancelled", [asyncio.CancelledError()])

        client = BrokerClient(_settings(), lambda: TOKEN, transport=Cancelled())
        with pytest.raises(BaseExceptionGroup) as error:
            await client.list_tools()
        assert not isinstance(error.value, BrokerError)

    @pytest.mark.asyncio
    async def test_a_group_with_a_real_failure_in_it_is_still_translated(self):
        class Mixed(httpx2.AsyncBaseTransport):
            async def handle_async_request(self, request):
                raise BaseExceptionGroup(
                    "mixed",
                    [asyncio.CancelledError(), httpx2.ConnectError("refused", request=request)],
                )

        client = BrokerClient(_settings(), lambda: TOKEN, transport=Mixed())
        with pytest.raises(BrokerError) as error:
            await client.list_tools()
        assert error.value.code == "BROKER_UNAVAILABLE"

    @pytest.mark.asyncio
    async def test_with_no_token_nothing_is_sent(self):
        transport = Fails(status=500)
        client = BrokerClient(_settings(), lambda: None, transport=transport)
        with pytest.raises(BrokerError) as error:
            await client.list_tools()
        assert error.value.code == "BROKER_TOKEN_MISSING"
        assert transport.requests == []

    @pytest.mark.asyncio
    async def test_a_redirect_is_never_followed_so_the_token_goes_nowhere_else(self):
        transport = Fails(status=307, headers={"location": "https://evil.example/steal"})
        client = BrokerClient(_settings(), lambda: TOKEN, transport=transport)
        with pytest.raises(Exception):
            await client.call_tool("list_shares", {})
        assert [str(r.url) for r in transport.requests] == [URL]

    @pytest.mark.asyncio
    async def test_the_broker_errors_text_is_fixed_whatever_the_status_body_said(self):
        client = BrokerClient(_settings(), lambda: TOKEN, transport=Fails(status=500))
        with pytest.raises(BrokerError) as error:
            await client.list_tools()
        assert "nope" not in error.value.text
        assert error.value.text == "BROKER_ERROR: The broker reported an error. (HTTP 500)"

    def test_the_known_secret_is_the_token_in_use_for_the_log_filter(self):
        client = BrokerClient(_settings(), lambda: TOKEN, transport=Fails(status=500))
        assert client.known_secrets() == []
        with pytest.raises(BrokerError):
            asyncio.run(client.list_tools())
        assert client.known_secrets() == [TOKEN]


class TestRealTls:
    """A fake endpoint over real TLS with a self-signed certificate."""

    @pytest.mark.asyncio
    async def test_a_certificate_that_does_not_verify_is_refused_before_anything_is_sent(
        self, tmp_path
    ):
        with FakeDsmServer(tmp_path) as server:
            client = BrokerClient(
                AdapterSettings(
                    broker_url=f"{server.base_url}/mcp",
                    token_env="X",
                    connect_timeout=3,
                    list_timeout=5,
                ),
                lambda: TOKEN,
            )
            with pytest.raises(BrokerError) as error:
                await client.list_tools()

        assert error.value.code == "BROKER_CERTIFICATE_ERROR"
        assert server.requests == []  # no request, so the token never reached it

    @pytest.mark.asyncio
    async def test_trusting_the_certificate_gets_past_tls(self, tmp_path):
        with FakeDsmServer(tmp_path) as server:
            client = BrokerClient(
                AdapterSettings(
                    broker_url=f"{server.base_url}/mcp",
                    token_env="X",
                    ca_file=str(server.cert_path),
                    connect_timeout=3,
                    list_timeout=5,
                ),
                lambda: TOKEN,
            )
            with pytest.raises(Exception) as error:
                await client.list_tools()

        # It is not a DSM, so the exchange fails — but not at the certificate.
        assert getattr(error.value, "code", "") != "BROKER_CERTIFICATE_ERROR"
        assert server.requests, "TLS succeeded and the request was made"


class TestLogging:
    """Standard output belongs to the protocol, so the adapter logs to standard
    error only, and the broker token is masked from every line even if some code
    path one day logs it."""

    @pytest.fixture
    def logging_restored(self):
        import logging

        root = logging.getLogger()
        handlers, level = root.handlers[:], root.level
        yield
        root.handlers[:], root.level = handlers, level

    def test_the_token_is_masked_and_nothing_goes_to_standard_output(
        self, capsys, logging_restored
    ):
        import logging

        import adapter_main

        adapter_main._prepare()
        client = BrokerClient(_settings(), lambda: TOKEN, transport=Fails(status=500))
        with pytest.raises(BrokerError):
            asyncio.run(client.list_tools())  # the token is now the one in use
        adapter_main._setup_logging(client)

        logging.getLogger("synology-adapter").warning(
            "oops %s and Authorization: Bearer %s", TOKEN, TOKEN
        )

        captured = capsys.readouterr()
        assert captured.out == ""
        assert TOKEN not in captured.err
        assert "oops" in captured.err and "***REDACTED***" in captured.err

    def test_the_chatty_libraries_are_quieted(self, logging_restored):
        import logging

        import adapter_main

        adapter_main._prepare()
        adapter_main._setup_logging(
            BrokerClient(_settings(), lambda: TOKEN, transport=Fails(status=500))
        )
        assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
        assert logging.getLogger("mcp").getEffectiveLevel() >= logging.WARNING
