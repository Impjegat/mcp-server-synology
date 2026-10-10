"""Running one private sign-in: the pending request, the account that is used,
the attempt limit that protects the NAS account, and what each outcome says.
The worker is replaced by a recording fake; its real behaviour is covered in
test_login_worker.py."""

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
        "code", ["403", "certificate_error", "connection_error", "connection_timeout", "timeout"]
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
