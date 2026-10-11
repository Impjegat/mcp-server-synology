"""The broker runtime: each client's tool calls run against that client's own
NAS units, tools, folders and sessions, and nothing a client sends can widen
them. A fake clock drives the deadlines, a fake DSM stands behind File Station,
and a refused call must never reach the NAS."""

import json
from unittest.mock import patch

import mcp.types as types
import pytest
from mcp.shared.exceptions import MCPError

from broker.errors import AuthenticationRequired
from broker.policy import DEFAULT_TOOLS
from tests.broker_support import BASE_URLS, Broker, FakeDSM

CLIENTS = {
    "alice": {"nas": ["nas1"], "folders": {"nas1": ["/docs"]}},
    "bob": {
        "nas": ["nas1", "nas2"],
        "tools": ["list_shares", "synology_status", "synology_list_nas"],
        "disconnect": False,
        "folders": {"nas1": ["/docs"]},
    },
    "carol": {"nas": ["nas2"]},
}
SESSION = {"idle_seconds": 100, "absolute_seconds": 1000}


@pytest.fixture
def broker(monkeypatch):
    return Broker(monkeypatch, CLIENTS, session=SESSION)


def _text(result):
    assert len(result.content) == 1
    return result.content[0].text


async def _call(broker, client, name, arguments=None):
    return await broker.runtime.call_tool(client, name, dict(arguments or {}))


@pytest.fixture
def no_nas_traffic():
    """Fail loudly if a request reaches the NAS."""
    with (
        patch("filestation.synology_filestation.requests.get") as fs_get,
        patch("utils.synology_api.requests.get") as api_get,
        patch("utils.synology_api.requests.post") as api_post,
    ):
        yield (fs_get, api_get, api_post)
        for mock in (fs_get, api_get, api_post):
            mock.assert_not_called()


def _list_shares(result=None, side_effect=None):
    from filestation import SynologyFileStation

    return patch.object(
        SynologyFileStation,
        "list_shares",
        autospec=True,
        return_value=result if result is not None else [{"name": "docs", "path": "/docs"}],
        side_effect=side_effect,
    )


class TestToolScope:
    @pytest.mark.asyncio
    async def test_a_client_sees_its_tools_and_nothing_else(self, broker):
        alice = {t.name for t in await broker.runtime.list_tools("alice")}
        bob = {t.name for t in await broker.runtime.list_tools("bob")}

        assert alice == DEFAULT_TOOLS | {"synology_logout"}
        assert bob == {"list_shares", "synology_status", "synology_list_nas"}

    @pytest.mark.asyncio
    async def test_the_password_login_is_not_offered_to_anyone(self, broker):
        for client in CLIENTS:
            names = {t.name for t in await broker.runtime.list_tools(client)}
            assert "synology_login" not in names

    @pytest.mark.asyncio
    async def test_the_password_login_cannot_be_called(self, broker):
        with pytest.raises(MCPError) as error:
            await _call(
                broker,
                "alice",
                "synology_login",
                {"base_url": BASE_URLS["nas1"], "username": "u", "password": "Dummy-Password-1"},
            )
        assert error.value.error.code == types.INVALID_PARAMS
        assert "Dummy-Password-1" not in error.value.error.message

    @pytest.mark.asyncio
    async def test_a_tool_outside_the_clients_list_is_denied_before_any_request(
        self, broker, no_nas_traffic
    ):
        broker.sign_in("bob")
        result = await _call(broker, "bob", "synology_health_summary", {"nas_name": "nas1"})

        assert result.is_error is True
        assert _text(result).startswith("AUTHORIZATION_DENIED")

    @pytest.mark.asyncio
    async def test_a_tool_that_changes_things_is_denied_even_when_asked_for_by_name(
        self, broker, no_nas_traffic
    ):
        broker.sign_in("alice")
        for name, args in [
            ("delete", {"path": "/docs/a.txt"}),
            ("create_file", {"path": "/docs/a.txt"}),
            ("synology_container_stop", {"name": "x"}),
            ("synology_create_user", {"name": "x", "password": "y"}),
        ]:
            result = await _call(broker, "alice", name, {"nas_name": "nas1", **args})
            assert result.is_error is True
            assert _text(result).startswith("AUTHORIZATION_DENIED"), name

    @pytest.mark.asyncio
    async def test_a_tool_the_policy_grants_is_still_held_by_restricted_mode(self, monkeypatch):
        """Both limits apply: the policy cannot lift restricted mode."""
        broker = Broker(
            monkeypatch,
            {"alice": {"nas": ["nas1"], "tools": ["delete", "list_shares"]}},
            restricted_mode=True,
        )
        broker.sign_in("alice")
        result = await _call(broker, "alice", "delete", {"nas_name": "nas1", "path": "/docs/a"})
        assert result.is_error is True
        assert "restricted mode" in _text(result)


class TestNasScope:
    @pytest.mark.asyncio
    async def test_a_client_cannot_reach_another_nas_by_name(self, broker, no_nas_traffic):
        broker.sign_in("alice", "nas1")
        result = await _call(broker, "alice", "list_shares", {"nas_name": "nas2"})
        assert result.is_error is True
        assert "not found" in _text(result)

    @pytest.mark.asyncio
    async def test_a_client_cannot_reach_another_nas_by_address(self, broker, no_nas_traffic):
        result = await _call(broker, "alice", "list_shares", {"base_url": BASE_URLS["nas2"]})
        assert result.is_error is True
        assert _text(result).startswith("AUTHORIZATION_DENIED")

    @pytest.mark.asyncio
    async def test_an_address_that_is_not_configured_at_all_is_denied(self, broker, no_nas_traffic):
        result = await _call(
            broker, "alice", "list_shares", {"base_url": "https://evil.example.test:5001"}
        )
        assert result.is_error is True
        assert _text(result).startswith("AUTHORIZATION_DENIED")

    @pytest.mark.asyncio
    async def test_discovery_and_status_name_only_the_clients_own_nas_units(self, broker):
        alice = json.loads(_text(await _call(broker, "alice", "synology_list_nas")))
        bob = json.loads(_text(await _call(broker, "bob", "synology_list_nas")))
        status = _text(await _call(broker, "alice", "synology_status"))

        assert [entry["nas_name"] for entry in alice] == ["nas1"]
        assert sorted(entry["nas_name"] for entry in bob) == ["nas1", "nas2"]
        assert "nas1" in status and "nas2" not in status and BASE_URLS["nas2"] not in status


class TestSessions:
    @pytest.mark.asyncio
    async def test_without_a_sign_in_a_call_asks_for_one(self, broker, no_nas_traffic):
        result = await _call(broker, "alice", "list_shares", {"nas_name": "nas1"})
        assert result.is_error is True
        assert _text(result).startswith("AUTHENTICATION_REQUIRED")

    @pytest.mark.asyncio
    async def test_a_sign_in_serves_that_client_and_no_other(self, broker, no_nas_traffic):
        broker.sign_in("alice", "nas1")
        with _list_shares() as service:
            mine = await _call(broker, "alice", "list_shares", {"nas_name": "nas1"})
            other = await _call(broker, "bob", "list_shares", {"nas_name": "nas1"})

        assert mine.is_error is False
        assert other.is_error is True
        assert _text(other).startswith("AUTHENTICATION_REQUIRED")
        assert service.call_count == 1

    @pytest.mark.asyncio
    async def test_status_follows_the_session(self, broker):
        before = _text(await _call(broker, "alice", "synology_status"))
        broker.sign_in("alice")
        during = _text(await _call(broker, "alice", "synology_status"))
        broker.clock.advance(101)
        after = _text(await _call(broker, "alice", "synology_status"))

        assert "AUTHENTICATION_REQUIRED" in before
        assert (
            "nas1" in during and "connected" in during and "AUTHENTICATION_REQUIRED" not in during
        )
        assert "AUTHENTICATION_REQUIRED" in after

    @pytest.mark.asyncio
    async def test_a_session_that_has_been_idle_too_long_is_gone_and_logged_out(self, broker):
        broker.sign_in("alice", session_id="SID-OLD")
        with _list_shares():
            assert (
                await _call(broker, "alice", "list_shares", {"nas_name": "nas1"})
            ).is_error is False
            broker.clock.advance(101)
            result = await _call(broker, "alice", "list_shares", {"nas_name": "nas1"})

        assert result.is_error is True
        assert _text(result).startswith("AUTHENTICATION_REQUIRED")
        assert broker.logged_out.wait(2)
        assert broker.logouts == [(BASE_URLS["nas1"], "SID-OLD")]

    @pytest.mark.asyncio
    async def test_use_keeps_a_session_alive_but_only_until_its_absolute_limit(self, broker):
        broker.sign_in("alice")
        with _list_shares():
            for _ in range(11):
                broker.clock.advance(90)
                result = await _call(broker, "alice", "list_shares", {"nas_name": "nas1"})
                assert result.is_error is False
            broker.clock.advance(10)
            result = await _call(broker, "alice", "list_shares", {"nas_name": "nas1"})

        assert result.is_error is True
        assert _text(result).startswith("AUTHENTICATION_REQUIRED")

    @pytest.mark.asyncio
    async def test_a_new_login_replaces_the_old_and_the_old_is_logged_out(self, broker):
        seen = []

        def record(self):
            seen.append(self.session_id)
            return []

        broker.sign_in("alice", session_id="SID-1")
        with _list_shares(side_effect=record):
            await _call(broker, "alice", "list_shares", {"nas_name": "nas1"})
            broker.sign_in("alice", session_id="SID-2")
            await _call(broker, "alice", "list_shares", {"nas_name": "nas1"})

        assert seen == ["SID-1", "SID-2"]
        assert broker.logged_out.wait(2)
        assert broker.logouts == [(BASE_URLS["nas1"], "SID-1")]

    @pytest.mark.asyncio
    async def test_a_session_the_nas_has_dropped_is_forgotten_and_not_retried(self, broker):
        broker.sign_in("alice")

        with _list_shares(side_effect=AuthenticationRequired()) as service:
            first = await _call(broker, "alice", "list_shares", {"nas_name": "nas1"})
            second = await _call(broker, "alice", "list_shares", {"nas_name": "nas1"})
            status = _text(await _call(broker, "alice", "synology_status"))

        assert _text(first).startswith("AUTHENTICATION_REQUIRED")
        assert _text(second).startswith("AUTHENTICATION_REQUIRED")
        assert service.call_count == 1  # the second call never reached the NAS
        assert broker.sessions.get("alice", "nas1") is None
        assert "AUTHENTICATION_REQUIRED" in status

    @pytest.mark.asyncio
    async def test_a_failure_on_an_old_login_does_not_end_a_newer_one(self, broker):
        broker.sign_in("alice", session_id="SID-1")
        seen = []

        def new_login_arrives_then_the_old_session_fails(self):
            seen.append(self.session_id)
            if len(seen) == 1:
                broker.sign_in("alice", session_id="SID-2")
                raise AuthenticationRequired()
            return [{"name": "docs", "path": "/docs"}]

        with _list_shares(side_effect=new_login_arrives_then_the_old_session_fails):
            first = await _call(broker, "alice", "list_shares", {"nas_name": "nas1"})
            second = await _call(broker, "alice", "list_shares", {"nas_name": "nas1"})

        assert first.is_error is True
        assert second.is_error is False
        assert seen == ["SID-1", "SID-2"]
        assert broker.sessions.get("alice", "nas1", touch=False).session_id == "SID-2"


class TestDisconnect:
    @pytest.mark.asyncio
    async def test_it_closes_the_session_on_the_nas_and_says_so(self, broker):
        broker.sign_in("alice", session_id="SID-1")

        result = await _call(broker, "alice", "synology_logout", {"base_url": BASE_URLS["nas1"]})

        assert result.is_error is False
        assert "the NAS session was closed" in _text(result)
        assert broker.logouts == [(BASE_URLS["nas1"], "SID-1")]
        assert broker.sessions.get("alice", "nas1") is None

    @pytest.mark.asyncio
    async def test_it_says_when_the_nas_did_not_confirm(self, broker):
        broker.sign_in("alice")
        broker.set_logout_result(False)

        result = await _call(broker, "alice", "synology_logout", {"base_url": BASE_URLS["nas1"]})

        assert "did not confirm" in _text(result)
        assert broker.sessions.get("alice", "nas1") is None

    @pytest.mark.asyncio
    async def test_a_client_without_the_disconnect_right_cannot_use_it(self, broker):
        broker.sign_in("bob")
        result = await _call(broker, "bob", "synology_logout", {"base_url": BASE_URLS["nas1"]})

        assert result.is_error is True
        assert _text(result).startswith("AUTHORIZATION_DENIED")
        assert broker.sessions.get("bob", "nas1", touch=False) is not None

    @pytest.mark.asyncio
    async def test_disconnecting_never_touches_another_clients_session(self, broker):
        broker.sign_in("alice", session_id="SID-A")
        broker.sign_in("bob", session_id="SID-B")

        await _call(broker, "alice", "synology_logout", {"base_url": BASE_URLS["nas1"]})

        assert broker.sessions.get("bob", "nas1", touch=False).session_id == "SID-B"

    @pytest.mark.asyncio
    async def test_disconnecting_with_no_session_is_an_error_not_a_success(self, broker):
        result = await _call(broker, "alice", "synology_logout", {"base_url": BASE_URLS["nas1"]})
        assert result.is_error is True


class TestSecrets:
    @pytest.mark.asyncio
    async def test_a_session_id_in_an_error_is_masked_in_the_reply(self, broker):
        broker.sign_in("alice", session_id="RAW-SID-VALUE-7d3f9", token="RAW-TOKEN-VALUE-1b8e")

        with _list_shares(
            side_effect=Exception("boom RAW-SID-VALUE-7d3f9 and RAW-TOKEN-VALUE-1b8e")
        ):
            result = await _call(broker, "alice", "list_shares", {"nas_name": "nas1"})

        assert result.is_error is True
        assert "RAW-SID-VALUE" not in _text(result)
        assert "RAW-TOKEN-VALUE" not in _text(result)
        assert "***REDACTED***" in _text(result)

    @pytest.mark.asyncio
    async def test_status_replies_never_carry_a_session_value(self, broker):
        broker.sign_in("alice", session_id="RAW-SID-VALUE-7d3f9", token="RAW-TOKEN-VALUE-1b8e")
        for name in ("synology_status", "synology_list_nas"):
            text = _text(await _call(broker, "alice", name))
            assert "RAW-SID-VALUE" not in text and "RAW-TOKEN-VALUE" not in text

    def test_the_session_manager_is_a_redaction_source(self, broker):
        from auth import iter_all_secrets

        broker.sign_in("alice", session_id="RAW-SID-VALUE-7d3f9")
        assert "RAW-SID-VALUE-7d3f9" in set(iter_all_secrets())


class TestFoldersThroughTheExecutor:
    @pytest.mark.asyncio
    async def test_a_folder_outside_the_clients_roots_is_denied_before_the_nas(self, broker):
        from filestation import SynologyFileStation

        broker.sign_in("alice")
        fake = FakeDSM(real_paths={"/docs": "/volume1/docs"})
        with patch.object(SynologyFileStation, "_make_request", side_effect=fake):
            result = await _call(
                broker, "alice", "list_directory", {"nas_name": "nas1", "path": "/music"}
            )

        assert result.is_error is True
        assert _text(result).startswith("AUTHORIZATION_DENIED")
        assert fake.calls == []

    @pytest.mark.asyncio
    async def test_a_folder_inside_the_roots_is_served(self, broker):
        from filestation import SynologyFileStation

        broker.sign_in("alice")
        fake = FakeDSM(
            real_paths={"/docs": "/volume1/docs"},
            listing=[
                {
                    "name": "a.txt",
                    "path": "/docs/a.txt",
                    "isdir": False,
                    "additional": {"real_path": "/volume1/docs/a.txt"},
                },
                # A child whose real location DSM does not give is never shown.
                {"name": "b.txt", "path": "/docs/b.txt", "isdir": False},
            ],
        )
        with patch.object(SynologyFileStation, "_make_request", side_effect=fake):
            result = await _call(
                broker, "alice", "list_directory", {"nas_name": "nas1", "path": "/docs"}
            )

        assert result.is_error is False
        assert [entry["name"] for entry in json.loads(_text(result))] == ["a.txt"]

    @pytest.mark.asyncio
    async def test_a_client_with_no_folders_listed_reaches_no_files(self, broker, no_nas_traffic):
        broker.sign_in("carol", "nas2")
        result = await _call(
            broker, "carol", "list_directory", {"nas_name": "nas2", "path": "/docs"}
        )
        assert result.is_error is True
        assert _text(result).startswith("AUTHORIZATION_DENIED")

    @pytest.mark.asyncio
    async def test_each_clients_folders_are_its_own(self, broker):
        from filestation import SynologyFileStation

        broker.sign_in("alice")
        broker.sign_in("bob", session_id="SID-B")
        fake = FakeDSM(real_paths={"/docs": "/volume1/docs"}, listing=[])
        with patch.object(SynologyFileStation, "_make_request", side_effect=fake):
            alice = await _call(
                broker, "alice", "list_directory", {"nas_name": "nas1", "path": "/docs"}
            )

        assert alice.is_error is False
        # bob's tools do not include list_directory at all
        bob = await _call(broker, "bob", "list_directory", {"nas_name": "nas1", "path": "/docs"})
        assert _text(bob).startswith("AUTHORIZATION_DENIED")


class TestRuntime:
    def test_each_client_gets_its_own_executor(self, broker):
        a1 = broker.runtime.executor_for("alice")
        assert broker.runtime.executor_for("alice") is a1
        assert broker.runtime.executor_for("bob") is not a1

    def test_an_unknown_client_has_no_executor(self, broker):
        with pytest.raises(KeyError):
            broker.runtime.executor_for("mallory")

    def test_a_client_cannot_be_signed_in_to_a_nas_it_may_not_use(self, broker):
        with pytest.raises(KeyError):
            broker.runtime.install_login("alice", "nas2", "SID")
        assert broker.sessions.get("alice", "nas2") is None

    def test_revoking_ends_a_clients_sessions_everywhere(self, broker):
        broker.sign_in("bob", "nas1", "SID-1")
        broker.sign_in("bob", "nas2", "SID-2")
        broker.sign_in("alice", "nas1", "SID-A")

        assert broker.runtime.revoke("bob") == 2

        assert (
            broker.sessions.get("bob", "nas1") is None
            and broker.sessions.get("bob", "nas2") is None
        )
        assert broker.sessions.get("alice", "nas1", touch=False) is not None

    def test_shutdown_logs_every_session_out(self, broker):
        broker.sign_in("alice", "nas1", "SID-A")
        broker.sign_in("carol", "nas2", "SID-C")

        broker.runtime.shutdown()

        assert sorted(sid for _, sid in broker.logouts) == ["SID-A", "SID-C"]
        assert broker.sessions.get("alice", "nas1") is None

    def test_shutdown_waits_for_all_logouts_together_not_one_after_another(self, monkeypatch):
        """Ten sessions on an unreachable NAS must cost one wait, not ten."""
        import threading
        import time

        broker = Broker(monkeypatch, CLIENTS, session=SESSION)
        release = threading.Event()
        started = []

        def stuck(base_url, session_id, syno_token):
            started.append(session_id)
            release.wait(10)
            return False

        broker.runtime._remote_logout = stuck
        for index in range(6):
            broker.runtime.sessions.install(
                f"client{index}", "nas1", BASE_URLS["nas1"], f"SID-{index}"
            )

        begun = time.monotonic()
        try:
            broker.runtime.shutdown(timeout=0.5)
            elapsed = time.monotonic() - begun
        finally:
            release.set()

        assert elapsed < 2.0  # six serial waits of 0.5 s would be 3 s
        assert broker.sessions.revoke_all() == []  # the local sessions went first
        assert len(started) == 6  # and every logout was attempted

    def test_shutdown_returns_at_once_when_nothing_is_stuck(self, broker):
        broker.sign_in("alice", "nas1", "SID-A")
        broker.runtime.shutdown(timeout=5)
        assert broker.logouts == [(BASE_URLS["nas1"], "SID-A")]

    def test_a_logout_that_raises_is_not_fatal_and_leaks_nothing(self, monkeypatch, caplog):
        broker = Broker(monkeypatch, CLIENTS, session=SESSION)

        def explode(base_url, session_id, syno_token):
            raise RuntimeError(f"failed for {session_id}")

        broker.runtime._remote_logout = explode
        record = broker.sign_in("alice", session_id="RAW-SID-VALUE-7d3f9")

        assert broker.runtime.logout_and_wait(record) is False
        assert "RAW-SID-VALUE" not in caplog.text
