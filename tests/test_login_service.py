"""Running one private sign-in: the pending request, the account that is used,
the attempt limit that protects the NAS account, and what each outcome says.
The worker is replaced by a recording fake; its real behaviour is covered in
test_login_worker.py."""

import asyncio
import copy

import pytest

from private_auth.login import LoginService
from tests.broker_support import Broker

PASSWORD = "PRIVATE-PASSWORD-MARKER-4d2e"
OTP = "482913"
CLIENTS = {
    "alice": {"nas": ["nas1"]},
    "bob": {"nas": ["nas1", "nas2"]},
}


class Runner:
    """A fake worker: replies from a queue and records every request it gets."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.requests = []

    async def __call__(self, payload):
        self.requests.append(copy.deepcopy(payload))
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, Exception):
            raise reply
        return reply


OK = {"ok": True, "sid": "SID-FROM-WORKER", "synotoken": "TOK-FROM-WORKER"}


def fail(code):
    return {"ok": False, "code": code}


@pytest.fixture
def broker(monkeypatch):
    return Broker(
        monkeypatch,
        CLIENTS,
        session={"idle_seconds": 100, "absolute_seconds": 1000, "pending_seconds": 50},
    )


def _service(broker, *replies):
    runner = Runner(*replies)
    return LoginService(broker.runtime, runner=runner, clock=broker.clock), runner


def _pending(broker, client="alice", nas="nas1"):
    return broker.sessions.begin_pending(client, nas)


class TestSuccess:
    @pytest.mark.asyncio
    async def test_a_sign_in_gives_the_client_a_session_and_settles_the_request(self, broker):
        service, _ = _service(broker, OK)
        pending = _pending(broker)

        outcome = await service.attempt(pending, password=PASSWORD)

        assert (outcome.ok, outcome.code) == (True, "connected")
        record = broker.sessions.get("alice", "nas1", touch=False)
        assert (record.session_id, record.syno_token) == ("SID-FROM-WORKER", "TOK-FROM-WORKER")
        assert broker.sessions.pending("alice", "nas1") is None

    @pytest.mark.asyncio
    async def test_the_session_belongs_to_the_requesting_client_only(self, broker):
        service, _ = _service(broker, OK)
        await service.attempt(_pending(broker, "alice"), password=PASSWORD)

        assert broker.sessions.get("alice", "nas1", touch=False) is not None
        assert broker.sessions.get("bob", "nas1", touch=False) is None

    @pytest.mark.asyncio
    async def test_the_worker_is_given_the_nas_the_account_and_the_secrets_and_nothing_more(
        self, broker
    ):
        service, runner = _service(broker, OK)
        await service.attempt(_pending(broker), password=PASSWORD, otp=f" {OTP} ")

        (request,) = runner.requests
        assert request == {
            "base_url": "https://nas1.example.test:5001",
            "verify_ssl": True,
            "username": "reader",
            "password": PASSWORD,
            "otp": OTP,
        }

    @pytest.mark.asyncio
    async def test_a_blank_code_is_no_code(self, broker):
        service, runner = _service(broker, OK)
        await service.attempt(_pending(broker), password=PASSWORD, otp="  ")
        assert runner.requests[0]["otp"] is None

    @pytest.mark.asyncio
    async def test_a_new_sign_in_replaces_the_old_session_and_logs_it_out(self, broker):
        service, _ = _service(broker, OK)
        broker.sign_in("alice", "nas1", "SID-OLD")

        await service.attempt(_pending(broker), password=PASSWORD)

        assert broker.sessions.get("alice", "nas1", touch=False).session_id == "SID-FROM-WORKER"
        assert broker.logged_out.wait(2)
        assert broker.logouts == [("https://nas1.example.test:5001", "SID-OLD")]


class TestTheAccount:
    @pytest.mark.asyncio
    async def test_the_configured_account_is_used_whatever_is_submitted(self, broker):
        service, runner = _service(broker, OK)
        await service.attempt(_pending(broker), password=PASSWORD, username="admin")
        assert runner.requests[0]["username"] == "reader"

    @pytest.mark.asyncio
    async def test_an_account_typed_by_the_owner_is_used_only_when_none_is_configured(self, broker):
        broker.nas_configs["nas1"]["username"] = ""
        service, runner = _service(broker, OK)
        await service.attempt(_pending(broker), password=PASSWORD, username="  typed  ")
        assert runner.requests[0]["username"] == "typed"

    @pytest.mark.asyncio
    async def test_with_no_account_at_all_nothing_is_sent(self, broker):
        broker.nas_configs["nas1"]["username"] = ""
        service, runner = _service(broker, OK)
        outcome = await service.attempt(_pending(broker), password=PASSWORD, username="  ")

        assert outcome.code == "username_required"
        assert runner.requests == []

    def test_the_configured_account_is_reported_for_display(self, broker):
        service, _ = _service(broker, OK)
        assert service.account_for("nas1") == "reader"
        broker.nas_configs["nas2"]["username"] = ""
        assert service.account_for("nas2") == ""


class TestThePendingRequest:
    @pytest.mark.asyncio
    async def test_an_expired_request_is_refused_before_anything_is_sent(self, broker):
        service, runner = _service(broker, OK)
        pending = _pending(broker)
        broker.clock.advance(51)

        outcome = await service.attempt(pending, password=PASSWORD)

        assert (outcome.ok, outcome.code) == (False, "expired_request")
        assert runner.requests == []

    @pytest.mark.asyncio
    async def test_a_cancelled_request_is_refused(self, broker):
        service, runner = _service(broker, OK)
        pending = _pending(broker)
        broker.sessions.cancel_pending("alice", "nas1")
        assert (await service.attempt(pending, password=PASSWORD)).code == "expired_request"
        assert runner.requests == []

    @pytest.mark.asyncio
    async def test_a_request_survives_a_failed_attempt_so_the_owner_can_retry(self, broker):
        service, _ = _service(broker, fail("400"), OK)
        pending = _pending(broker)

        assert (await service.attempt(pending, password="wrong")).ok is False
        assert broker.sessions.pending("alice", "nas1") is not None
        assert (await service.attempt(pending, password=PASSWORD)).ok is True


class TestMessages:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "code,fragment",
        [
            ("400", "did not accept that account or password"),
            ("401", "disabled"),
            ("402", "not allowed"),
            ("403", "verification code is required"),
            ("404", "verification code was not accepted"),
            ("406", "two-factor"),
            ("407", "blocked this address"),
            ("408", "password has expired"),
            ("certificate_error", "certificate could not be verified"),
            ("redirect_refused", "answered with a redirect"),
            ("connection_timeout", "could not be reached"),
            ("connection_error", "could not be reached"),
            ("timeout", "did not answer in time"),
            ("worker_error", "did not complete"),
            ("unknown", "did not complete"),
            ("something_new", "did not complete"),
        ],
    )
    async def test_each_failure_has_a_fixed_value_free_sentence(self, broker, code, fragment):
        service, _ = _service(broker, fail(code))
        outcome = await service.attempt(_pending(broker), password=PASSWORD, otp=OTP)

        assert outcome.ok is False and outcome.code == code
        assert fragment in outcome.message
        assert PASSWORD not in outcome.message and OTP not in outcome.message

    @pytest.mark.asyncio
    async def test_a_worker_that_raises_is_a_generic_failure(self, broker):
        service, _ = _service(broker, RuntimeError(f"boom {PASSWORD}"))
        outcome = await service.attempt(_pending(broker), password=PASSWORD)
        assert (outcome.ok, outcome.code) == (False, "worker_error")
        assert PASSWORD not in outcome.message


class TestAttemptLimit:
    @pytest.mark.asyncio
    async def test_three_wrong_passwords_lock_that_client_and_nas_without_calling_the_worker(
        self, broker
    ):
        service, runner = _service(broker, fail("400"))
        pending = _pending(broker)
        for _ in range(3):
            assert (await service.attempt(pending, password="wrong")).code == "400"

        outcome = await service.attempt(pending, password=PASSWORD)

        assert (outcome.ok, outcome.code) == (False, "locked")
        assert "Wait about" in outcome.message
        assert len(runner.requests) == 3  # the fourth never reached the NAS

    @pytest.mark.asyncio
    async def test_the_lock_is_per_client_and_nas(self, broker):
        service, _ = _service(broker, fail("400"))
        for _ in range(3):
            await service.attempt(_pending(broker, "alice", "nas1"), password="wrong")

        assert (
            await service.attempt(_pending(broker, "alice", "nas1"), password=PASSWORD)
        ).code == "locked"
        # Another client, and another NAS of the same client, are untouched.
        assert (await service.attempt(_pending(broker, "bob", "nas1"), password="x")).code == "400"
        assert (await service.attempt(_pending(broker, "bob", "nas2"), password="x")).code == "400"

    @pytest.mark.asyncio
    async def test_the_lock_ends_after_ten_minutes(self, broker):
        service, _ = _service(broker, fail("400"), fail("400"), fail("400"), OK)
        for _ in range(3):
            await service.attempt(_pending(broker), password="wrong")
        broker.clock.advance(601)

        assert (await service.attempt(_pending(broker), password=PASSWORD)).ok is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "code",
        [
            "403",
            "certificate_error",
            "connection_error",
            "connection_timeout",
            "timeout",
            "redirect_refused",
        ],
    )
    async def test_failures_that_did_not_burn_a_nas_attempt_are_not_counted(self, broker, code):
        service, runner = _service(broker, fail(code))
        for _ in range(6):
            await service.attempt(_pending(broker), password=PASSWORD)
        assert len(runner.requests) == 6

    @pytest.mark.asyncio
    async def test_a_success_clears_the_count(self, broker):
        service, _ = _service(
            broker, fail("400"), fail("400"), OK, fail("400"), fail("400"), fail("400")
        )
        pending = _pending(broker)
        await service.attempt(pending, password="x")
        await service.attempt(pending, password="x")
        assert (await service.attempt(pending, password=PASSWORD)).ok is True
        # Two more wrong ones would have locked it had the earlier two still counted.
        for _ in range(2):
            assert (await service.attempt(_pending(broker), password="x")).code == "400"

    @pytest.mark.asyncio
    async def test_the_remaining_wait_is_reported(self, broker):
        service, _ = _service(broker, fail("400"))
        pending = _pending(broker)
        for _ in range(3):
            await service.attempt(pending, password="x")
        assert 0 < service.locked_for(pending) <= 601


class PausedRunner:
    """A worker that waits to be told it may answer, so a test can change the
    world while the NAS is still thinking."""

    def __init__(self, reply=None):
        self.reply = reply or {"ok": True, "sid": "SID-FROM-WORKER", "synotoken": "TOK-FROM-WORKER"}
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.requests = []

    async def __call__(self, payload):
        self.requests.append(copy.deepcopy(payload))
        self.started.set()
        await self.release.wait()
        return self.reply


NAS1_URL = "https://nas1.example.test:5001"


async def _in_flight(broker, runner, pending=None):
    """Start a sign-in and return once its worker is running."""
    service = LoginService(broker.runtime, runner=runner, clock=broker.clock)
    pending = pending or _pending(broker)
    task = asyncio.ensure_future(service.attempt(pending, password=PASSWORD, otp=OTP))
    await asyncio.wait_for(runner.started.wait(), 5)
    return service, pending, task


class TestTheRequestIsWithdrawnWhileTheWorkerRuns:
    """The request is checked before the worker starts. It must also still be the
    live one when the worker's session comes back (implementation review R05)."""

    async def _finish_withdrawn(self, broker, runner, task):
        runner.release.set()
        outcome = await asyncio.wait_for(task, 5)
        assert (outcome.ok, outcome.code) == (False, "request_withdrawn")
        assert "cancelled or expired" in outcome.message
        assert PASSWORD not in outcome.message and OTP not in outcome.message
        assert broker.sessions.get("alice", "nas1", touch=False) is None
        # The NAS did open a session for the worker; it is ended there, once.
        assert broker.logged_out.wait(2)
        assert broker.logouts == [(NAS1_URL, "SID-FROM-WORKER")]
        assert "SID-FROM-WORKER" not in set(broker.sessions.iter_secrets())

    @pytest.mark.asyncio
    async def test_r05_cancelling_while_the_worker_runs_leaves_no_session(self, broker):
        runner = PausedRunner()
        _, _, task = await _in_flight(broker, runner)
        broker.sessions.cancel_pending("alice", "nas1")
        await self._finish_withdrawn(broker, runner, task)

    @pytest.mark.asyncio
    async def test_r05_an_expiry_while_the_worker_runs_leaves_no_session(self, broker):
        runner = PausedRunner()
        _, _, task = await _in_flight(broker, runner)
        broker.clock.advance(51)  # the request lived 50 seconds
        await self._finish_withdrawn(broker, runner, task)

    @pytest.mark.asyncio
    async def test_r05_a_disconnect_while_the_worker_runs_leaves_no_session(self, broker):
        runner = PausedRunner()
        _, _, task = await _in_flight(broker, runner)
        broker.runtime.revoke("alice", "nas1")
        await self._finish_withdrawn(broker, runner, task)

    @pytest.mark.asyncio
    async def test_r05_a_disconnect_of_a_session_while_it_is_being_replaced(self, broker):
        """An old session exists and a new sign-in is running; the client's own
        disconnect ends the old one and withdraws the new one."""
        broker.sign_in("alice", "nas1", "SID-OLD")
        runner = PausedRunner()
        _, _, task = await _in_flight(broker, runner)
        broker.runtime.revoke("alice", "nas1")

        runner.release.set()
        outcome = await asyncio.wait_for(task, 5)

        assert outcome.code == "request_withdrawn"
        assert broker.sessions.get("alice", "nas1", touch=False) is None

    @pytest.mark.asyncio
    async def test_r05_the_clients_own_logout_tool_withdraws_a_sign_in_in_progress(self, broker):
        """The other disconnect path: the AI client calls `synology_logout` while
        the owner is typing a password for it."""
        broker.sign_in("alice", "nas1", "SID-OLD")
        runner = PausedRunner()
        _, _, task = await _in_flight(broker, runner)

        result = await broker.runtime.call_tool("alice", "synology_logout", {"base_url": NAS1_URL})
        assert result.is_error is False

        runner.release.set()
        outcome = await asyncio.wait_for(task, 5)
        assert outcome.code == "request_withdrawn"
        assert broker.sessions.get("alice", "nas1", touch=False) is None

    @pytest.mark.asyncio
    async def test_r05_a_newer_request_while_the_worker_runs_is_left_alone(self, broker):
        runner = PausedRunner()
        _, old, task = await _in_flight(broker, runner)
        broker.sessions.cancel_pending("alice", "nas1")
        newer = _pending(broker)
        assert newer.request_id != old.request_id

        runner.release.set()
        outcome = await asyncio.wait_for(task, 5)

        assert outcome.code == "request_withdrawn"
        assert broker.sessions.get("alice", "nas1", touch=False) is None
        assert broker.sessions.pending("alice", "nas1") == newer
        assert broker.sessions.begin_attempt(newer.request_id)[0] == "started"

    @pytest.mark.asyncio
    async def test_r05_an_older_result_cannot_replace_a_newer_session(self, broker):
        slow = PausedRunner({"ok": True, "sid": "SID-A", "synotoken": "TOK-A"})
        _, _, older = await _in_flight(broker, slow)
        broker.sessions.cancel_pending("alice", "nas1")

        newer_service, newer_runner = _service(
            broker, {"ok": True, "sid": "SID-B", "synotoken": "TOK-B"}
        )
        assert (await newer_service.attempt(_pending(broker), password=PASSWORD)).ok is True

        slow.release.set()
        outcome = await asyncio.wait_for(older, 5)

        assert outcome.code == "request_withdrawn"
        assert broker.sessions.get("alice", "nas1", touch=False).session_id == "SID-B"
        assert broker.logged_out.wait(2)
        assert broker.logouts == [(NAS1_URL, "SID-A")]  # only the withdrawn one was ended

    @pytest.mark.asyncio
    async def test_a_second_submission_while_one_runs_is_refused_without_a_second_worker(
        self, broker
    ):
        runner = PausedRunner()
        service, pending, first = await _in_flight(broker, runner)

        # Bounded: a second worker would wait for a release that comes after this.
        second = await asyncio.wait_for(service.attempt(pending, password="another"), 5)

        assert (second.ok, second.code) == (False, "in_progress")
        assert "already in progress" in second.message
        assert len(runner.requests) == 1

        runner.release.set()
        assert (await asyncio.wait_for(first, 5)).ok is True
        assert broker.sessions.get("alice", "nas1", touch=False).session_id == "SID-FROM-WORKER"

    @pytest.mark.asyncio
    async def test_a_refused_second_submission_is_not_counted_as_a_wrong_password(self, broker):
        runner = PausedRunner({"ok": False, "code": "400"})
        service, pending, first = await _in_flight(broker, runner)
        for _ in range(5):
            refused = await asyncio.wait_for(service.attempt(pending, password="x"), 5)
            assert refused.code == "in_progress"
        runner.release.set()
        assert (await asyncio.wait_for(first, 5)).code == "400"
        assert service.locked_for(pending) == 0  # one wrong password, not six

    @pytest.mark.asyncio
    async def test_a_failed_attempt_frees_the_request_for_another(self, broker):
        service, _ = _service(broker, fail("400"), OK)
        pending = _pending(broker)
        assert (await service.attempt(pending, password="wrong")).code == "400"
        assert (await service.attempt(pending, password=PASSWORD)).ok is True

    @pytest.mark.asyncio
    async def test_a_worker_that_raises_frees_the_request_for_another(self, broker):
        service, _ = _service(broker, RuntimeError("boom"), OK)
        pending = _pending(broker)
        assert (await service.attempt(pending, password=PASSWORD)).code == "worker_error"
        assert (await service.attempt(pending, password=PASSWORD)).ok is True

    @pytest.mark.asyncio
    async def test_a_handler_that_is_cancelled_frees_the_request(self, broker):
        runner = PausedRunner()
        _, pending, task = await _in_flight(broker, runner)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert broker.sessions.begin_attempt(pending.request_id)[0] == "started"

    @pytest.mark.asyncio
    async def test_a_locked_sign_in_frees_the_request(self, broker):
        service, _ = _service(broker, fail("400"))
        pending = _pending(broker)
        for _ in range(3):
            await service.attempt(pending, password="wrong")
        assert (await service.attempt(pending, password=PASSWORD)).code == "locked"
        assert broker.sessions.begin_attempt(pending.request_id)[0] == "started"

    @pytest.mark.asyncio
    async def test_a_missing_account_frees_the_request(self, broker):
        broker.nas_configs["nas1"]["username"] = ""
        service, _ = _service(broker, OK)
        pending = _pending(broker)
        assert (await service.attempt(pending, password=PASSWORD)).code == "username_required"
        assert broker.sessions.begin_attempt(pending.request_id)[0] == "started"

    @pytest.mark.asyncio
    async def test_a_nas_the_client_may_not_use_is_never_installed_and_is_logged_out(self, broker):
        """alice may use nas1 only; a request for nas2 (however it came to exist)
        must not become her session."""
        service, _ = _service(broker, OK)
        pending = _pending(broker, "alice", "nas2")

        outcome = await service.attempt(pending, password=PASSWORD)

        assert (outcome.ok, outcome.code) == (False, "request_withdrawn")
        assert broker.sessions.get("alice", "nas2", touch=False) is None
        assert broker.logged_out.wait(2)
        assert broker.logouts == [("https://nas2.example.test:5001", "SID-FROM-WORKER")]

    @pytest.mark.asyncio
    async def test_a_request_withdrawn_before_the_worker_starts_never_reaches_it(self, broker):
        service, runner = _service(broker, OK)
        pending = _pending(broker)
        broker.sessions.cancel_pending("alice", "nas1")
        outcome = await service.attempt(pending, password=PASSWORD)
        assert outcome.code == "expired_request"
        assert runner.requests == []

    @pytest.mark.asyncio
    async def test_a_session_that_is_adopted_is_not_logged_out(self, broker):
        service, _ = _service(broker, OK)
        await service.attempt(_pending(broker), password=PASSWORD)
        assert broker.logged_out.wait(0.2) is False
        assert broker.logouts == []


class TestNasConfigAccessor:
    def test_the_runtime_gives_a_nas_its_configuration(self, broker):
        config = broker.runtime.nas_config("nas1")
        assert config["base_url"] == "https://nas1.example.test:5001"
        assert config["username"] == "reader"

    def test_an_unknown_nas_is_refused_by_name(self, broker):
        with pytest.raises(ValueError, match="No NAS named 'nas9'"):
            broker.runtime.nas_config("nas9")

    def test_the_login_service_reports_an_unknown_nas_clearly_too(self, broker):
        service, _ = _service(broker, OK)
        with pytest.raises(ValueError, match="nas9"):
            service.account_for("nas9")

    def test_the_login_service_no_longer_reaches_into_a_private_attribute(self):
        import inspect

        import private_auth.login as login

        assert "_nas_configs" not in inspect.getsource(login)
