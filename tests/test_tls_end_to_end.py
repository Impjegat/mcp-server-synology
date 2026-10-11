"""The broker and the adapter over TLS that is actually verified.

Everything else in the suite reaches the broker over plain loopback HTTP. This
starts the real broker with a real certificate (made fresh, signed by a throwaway
CA) and the private login on its own TLS port, and drives it with the real adapter
the way an AI application would: certificate chain and host name checked, the
token read from a file. It also runs the container health check script against it.

The NAS address is fake and no credential exists anywhere, so the broker is ready
and signed in to nothing, which is the state a newly deployed one is in.
"""

import os
import ssl
import subprocess
import sys

import httpx2
import pytest

from tests.test_broker_main import (
    ROOT,
    TOKEN,
    _environment,
    _free_port,
    _policy_document,
    _stop,
    _write_policy,
)
from tests.tls_support import adapter_session, make_pki

HEALTHCHECK = str(ROOT / "docker" / "broker_healthcheck.py")


def _trusting(path):
    return ssl.create_default_context(cafile=str(path))


class Running:
    """A broker process on a TLS port, with the private login on another."""

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.pki = make_pki(tmp_path / "pki")
        self.port = _free_port()
        self.private_port = _free_port()
        self.process = None
        self.output = ""

    @property
    def mcp_url(self):
        return f"https://localhost:{self.port}/mcp"

    def start(self):
        policy = _write_policy(self.tmp_path, _policy_document())
        workdir = self.tmp_path / "work"
        workdir.mkdir(exist_ok=True)
        self.process = subprocess.Popen(
            [
                sys.executable,
                str(ROOT / "broker_main.py"),
                "serve",
                "--policy",
                str(policy),
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--allowed-host",
                f"localhost:{self.port}",
                "--tls-cert",
                str(self.pki.cert),
                "--tls-key",
                str(self.pki.key),
                "--private-origin",
                f"https://localhost:{self.private_port}",
                "--private-port",
                str(self.private_port),
                "--private-allowed-host",
                f"localhost:{self.private_port}",
                "--owner-store",
                str(self.tmp_path / "owner.json"),
            ],
            cwd=workdir,
            env=_environment(self.tmp_path, SYNOLOGY_URL="https://nas.example.test:5001"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self._wait()

    def _wait(self, seconds=40):
        import time

        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f"the broker exited early:\n{self.process.stdout.read()}")
            try:
                ready = httpx2.get(
                    f"https://localhost:{self.port}/readyz",
                    verify=_trusting(self.pki.ca),
                    timeout=2,
                )
                private = httpx2.get(
                    f"https://localhost:{self.private_port}/healthz",
                    verify=_trusting(self.pki.ca),
                    timeout=2,
                )
                if ready.status_code == 200 and private.status_code == 200:
                    return
            except httpx2.HTTPError:
                time.sleep(0.2)
        self.process.kill()
        raise AssertionError(f"the broker did not come up:\n{self.process.stdout.read()}")

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.output = _stop(self.process)
        return self.output


@pytest.fixture
def broker(tmp_path):
    running = Running(tmp_path)
    running.start()
    yield running
    running.stop()


def _health(url, **env):
    return subprocess.run(
        [sys.executable, HEALTHCHECK],
        capture_output=True,
        text=True,
        timeout=30,
        env={
            **{k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "TEMP", "TMP")},
            "BROKER_HEALTH_URL": url,
            **env,
        },
    )


@pytest.mark.slow
class TestTheBrokerOverVerifiedTls:
    def test_it_is_ready_and_says_nothing_about_the_nas_or_anyone_signed_in(self, broker):
        for path in ("/healthz", "/readyz"):
            response = httpx2.get(
                f"https://localhost:{broker.port}{path}", verify=_trusting(broker.pki.ca), timeout=5
            )
            assert response.status_code == 200
            text = response.text.lower()
            for word in ("nas.example", "default", "session", "client", "smoke"):
                assert word not in text

    def test_a_client_that_does_not_trust_the_ca_cannot_connect(self, broker):
        with pytest.raises(httpx2.ConnectError):
            httpx2.get(f"https://localhost:{broker.port}/readyz", timeout=5)
        with pytest.raises(httpx2.ConnectError):
            httpx2.get(
                f"https://localhost:{broker.port}/readyz",
                verify=_trusting(broker.pki.other_ca),
                timeout=5,
            )

    def test_the_container_health_check_agrees_with_the_broker(self, broker):
        base = f"https://127.0.0.1:{broker.port}"
        # the certificate names localhost, not 127.0.0.1: the check does not verify, by design
        assert _health(f"{base}/readyz").returncode == 0
        # it looks at the answer, not just at whether something is listening
        assert _health(f"{base}/no-such-page").returncode == 1
        # nothing listening
        assert _health(f"https://127.0.0.1:{_free_port()}/readyz").returncode == 1

    def test_the_private_login_is_on_its_own_tls_port_with_its_protective_headers(self, broker):
        page = httpx2.get(
            f"https://localhost:{broker.private_port}/", verify=_trusting(broker.pki.ca), timeout=5
        )
        assert page.status_code == 200 and "No owner enrolled" in page.text
        headers = {k.lower(): v for k, v in page.headers.items()}
        assert "no-store" in headers["cache-control"]
        assert "default-src" in headers["content-security-policy"]
        assert "frame-ancestors 'none'" in headers["content-security-policy"]
        # and the MCP port does not serve it
        other = httpx2.get(
            f"https://localhost:{broker.port}/login/anything",
            verify=_trusting(broker.pki.ca),
            timeout=5,
        )
        assert other.status_code in (401, 404)
        assert "Sign in to the NAS" not in other.text

    @pytest.mark.asyncio
    async def test_a_real_adapter_lists_the_tools_with_their_titles_over_verified_tls(
        self, broker, tmp_path
    ):
        async with adapter_session(
            tmp_path / "ok", broker.mcp_url, token=TOKEN, ca_file=broker.pki.ca
        ) as session:
            listing = (await session.list_tools()).tools
            status = await session.call_tool("synology_status", {})
            shares = await session.call_tool("list_shares", {"nas_name": "default"})

        by_name = {t.name: t for t in listing}
        assert by_name["list_shares"].title == "Browse shared folders"
        assert "synology_login" not in by_name
        assert status.is_error is False and "manual" in status.content[0].text
        assert shares.is_error is True
        assert shares.content[0].text.startswith("AUTHENTICATION_REQUIRED")

    @pytest.mark.asyncio
    async def test_an_adapter_that_does_not_trust_the_ca_is_told_so_and_sends_nothing(
        self, broker, tmp_path
    ):
        async with adapter_session(
            tmp_path / "other", broker.mcp_url, token=TOKEN, ca_file=broker.pki.other_ca
        ) as session:
            result = await session.call_tool("synology_status", {})
        assert result.is_error is True
        assert result.content[0].text.startswith("BROKER_CERTIFICATE_ERROR")
        # the broker never saw a request carrying the token
        assert TOKEN not in broker.stop()

    @pytest.mark.asyncio
    async def test_a_certificate_for_another_name_is_refused(self, broker, tmp_path):
        async with adapter_session(
            tmp_path / "name",
            f"https://127.0.0.1:{broker.port}/mcp",
            token=TOKEN,
            ca_file=broker.pki.ca,
        ) as session:
            result = await session.call_tool("synology_status", {})
        assert result.is_error is True
        assert result.content[0].text.startswith("BROKER_CERTIFICATE_ERROR")

    @pytest.mark.asyncio
    async def test_a_token_the_broker_does_not_know_is_unauthorized(self, broker, tmp_path):
        async with adapter_session(
            tmp_path / "wrong",
            broker.mcp_url,
            token="not-the-token-0123456789abcdef",
            ca_file=broker.pki.ca,
        ) as session:
            result = await session.call_tool("synology_status", {})
        assert result.is_error is True
        assert result.content[0].text.startswith("BROKER_UNAUTHORIZED")

    @pytest.mark.asyncio
    async def test_the_token_never_reaches_the_brokers_output(self, broker, tmp_path):
        async with adapter_session(
            tmp_path / "log", broker.mcp_url, token=TOKEN, ca_file=broker.pki.ca
        ) as session:
            await session.list_tools()
            await session.call_tool("list_shares", {"nas_name": "default"})
        output = broker.stop()
        assert TOKEN not in output
        assert "Authorization" not in output
