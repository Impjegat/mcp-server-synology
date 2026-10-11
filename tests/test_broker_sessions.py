"""The broker's session manager: ownership, deadlines, generations, and pending
sign-in requests. A fake clock drives every deadline; nothing sleeps."""

import json

import pytest

from broker.policy import SessionPolicy
from broker.sessions import SessionManager
from tests.broker_support import FakeClock

URL = "https://nas1.example.test:5001"
POLICY = SessionPolicy(idle_seconds=100, absolute_seconds=1000, pending_seconds=50)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def manager(clock):
    return SessionManager(POLICY, clock=clock)


def _install(manager, owner="alice", nas="nas1", sid="SID-1", token="TOK-1"):
    return manager.install(owner, nas, URL, sid, token)


class TestInstallAndGet:
    def test_the_first_login_is_generation_one_and_replaces_nothing(self, manager):
        record, replaced = _install(manager)
        assert record.generation == 1
        assert replaced is None

    def test_a_new_login_replaces_the_old_one_atomically(self, manager):
        first, _ = _install(manager, sid="SID-1")
        second, replaced = _install(manager, sid="SID-2")

        assert second.generation == 2
        assert replaced.session_id == "SID-1"
        assert manager.get("alice", "nas1").session_id == "SID-2"

    def test_a_session_belongs_to_one_owner_and_one_nas(self, manager):
        _install(manager, owner="alice", nas="nas1", sid="SID-A")
        _install(manager, owner="bob", nas="nas1", sid="SID-B")

        assert manager.get("alice", "nas1").session_id == "SID-A"
        assert manager.get("bob", "nas1").session_id == "SID-B"
        assert manager.get("alice", "nas2") is None
        assert manager.get("carol", "nas1") is None

    def test_generations_are_never_reused(self, manager):
        first, _ = _install(manager)
        assert manager.invalidate("alice", "nas1", first.generation)
        second, _ = _install(manager)
        assert second.generation == 2


class TestDeadlines:
    def test_a_session_ends_after_the_idle_deadline(self, manager, clock):
        _install(manager)
        clock.advance(99)
        assert manager.get("alice", "nas1", touch=False) is not None
        clock.advance(1)
        assert manager.get("alice", "nas1") is None

    def test_use_moves_the_idle_deadline(self, manager, clock):
        _install(manager)
        for _ in range(5):
            clock.advance(90)
            assert manager.get("alice", "nas1") is not None

    def test_looking_without_using_does_not_move_it(self, manager, clock):
        _install(manager)
        for _ in range(2):
            clock.advance(60)
            manager.get("alice", "nas1", touch=False)
        assert manager.get("alice", "nas1") is None

    def test_nothing_extends_the_absolute_deadline(self, manager, clock):
        _install(manager)
        # Used every 90 s, so never idle for long: alive at 990 s ...
        for _ in range(11):
            clock.advance(90)
            assert manager.get("alice", "nas1") is not None
        # ... and gone at the 1000 s absolute limit, 10 s after its last use.
        clock.advance(10)
        assert manager.get("alice", "nas1") is None

    def test_a_session_that_ended_on_a_deadline_is_handed_back_once_for_logout(
        self, manager, clock
    ):
        _install(manager, sid="SID-OLD")
        clock.advance(101)

        expired = manager.take_expired()

        assert [r.session_id for r in expired] == ["SID-OLD"]
        assert manager.take_expired() == []
        assert manager.get("alice", "nas1") is None


class TestInvalidateAndRevoke:
    def test_a_late_failure_from_an_old_login_leaves_the_new_one_alone(self, manager):
        old, _ = _install(manager, sid="SID-1")
        new, _ = _install(manager, sid="SID-2")

        assert manager.invalidate("alice", "nas1", old.generation) is False
        assert manager.get("alice", "nas1").session_id == "SID-2"
        assert manager.invalidate("alice", "nas1", new.generation) is True
        assert manager.get("alice", "nas1") is None

    def test_invalidating_nothing_or_an_unknown_generation_does_nothing(self, manager):
        assert manager.invalidate("alice", "nas1", 1) is False
        _install(manager)
        assert manager.invalidate("alice", "nas1", None) is False
        assert manager.get("alice", "nas1") is not None

    def test_revoke_ends_one_owners_sessions_only(self, manager):
        _install(manager, owner="alice", nas="nas1", sid="A1")
        _install(manager, owner="alice", nas="nas2", sid="A2")
        _install(manager, owner="bob", nas="nas1", sid="B1")

        removed = manager.revoke("alice", "nas1")

        assert [r.session_id for r in removed] == ["A1"]
        assert manager.get("alice", "nas2") is not None
        assert manager.get("bob", "nas1") is not None
        assert {r.session_id for r in manager.revoke("alice")} == {"A2"}

    def test_revoke_all_empties_the_manager(self, manager):
        _install(manager, owner="alice")
        _install(manager, owner="bob")
        assert len(manager.revoke_all()) == 2
        assert manager.get("alice", "nas1") is None


class TestWhatItNeverShows:
    def test_status_carries_no_session_value(self, manager):
        _install(manager, sid="SID-SECRET-1", token="TOK-SECRET-1")
        status = manager.status("alice")

        assert status["nas1"]["connected"] is True
        text = json.dumps(status)
        assert "SECRET" not in text and URL not in text

    def test_status_counts_down(self, manager, clock):
        _install(manager)
        clock.advance(30)
        status = manager.status("alice")["nas1"]
        assert status["idle_seconds_left"] == 70
        assert status["absolute_seconds_left"] == 970

    def test_status_is_per_owner(self, manager):
        _install(manager, owner="alice")
        assert manager.status("bob") == {}

    def test_a_record_prints_without_its_session(self, manager):
        record, _ = _install(manager, sid="SID-SECRET-1", token="TOK-SECRET-1")
        assert "SECRET" not in repr(record)
        assert "SECRET" not in str([record])

    def test_secrets_are_listed_for_redaction(self, manager):
        _install(manager, owner="alice", sid="SID-1", token="TOK-1")
        _install(manager, owner="bob", sid="SID-2", token=None)
        assert set(manager.iter_secrets()) == {"SID-1", "TOK-1", "SID-2"}

    def test_a_removed_session_is_no_longer_a_secret_to_mask(self, manager):
        _install(manager, sid="SID-1", token="TOK-1")
        manager.revoke("alice")
        assert list(manager.iter_secrets()) == []


class TestPendingSignIn:
    def test_repeated_requests_share_one_pending_login(self, manager):
        first = manager.begin_pending("alice", "nas1")
        again = manager.begin_pending("alice", "nas1")
        assert again == first
        assert manager.begin_pending("alice", "nas2").request_id != first.request_id
        assert manager.begin_pending("bob", "nas1").request_id != first.request_id

    def test_a_pending_request_expires(self, manager, clock):
        first = manager.begin_pending("alice", "nas1")
        clock.advance(50)
        assert manager.pending("alice", "nas1") is None
        assert manager.begin_pending("alice", "nas1").request_id != first.request_id

    def test_a_request_can_be_found_by_id_until_it_expires(self, manager, clock):
        pending = manager.begin_pending("alice", "nas1")
        assert manager.find_pending(pending.request_id) == pending
        assert manager.find_pending("not-a-request") is None
        clock.advance(50)
        assert manager.find_pending(pending.request_id) is None

    def test_signing_in_settles_the_pending_request(self, manager):
        manager.begin_pending("alice", "nas1")
        _install(manager)
        assert manager.pending("alice", "nas1") is None

    def test_a_pending_request_can_be_cancelled(self, manager):
        manager.begin_pending("alice", "nas1")
        assert manager.cancel_pending("alice", "nas1") is True
        assert manager.cancel_pending("alice", "nas1") is False

    def test_a_pending_request_holds_no_credential(self, manager):
        pending = manager.begin_pending("alice", "nas1")
        assert set(vars(pending)) == {"request_id", "owner", "nas", "created_at", "expires_at"}


class TestLoginAttempts:
    """A sign-in takes time (the worker talks to the NAS). The request it answers
    must still be valid when the result comes back, or the session is not adopted
    (implementation review R05). Each attempt is one claim on one pending request."""

    @staticmethod
    def _begin(manager, request_id):
        return manager.begin_attempt(request_id)

    @staticmethod
    def _adopt(manager, attempt, sid="SID-NEW", token="TOK-NEW"):
        return manager.install_for_attempt(attempt, URL, sid, token)

    def _claimed(self, manager, owner="alice", nas="nas1"):
        pending = manager.begin_pending(owner, nas)
        status, attempt = self._begin(manager, pending.request_id)
        assert status == "started"
        return pending, attempt

    # -- claiming -----------------------------------------------------------

    def test_a_waiting_request_can_be_claimed_once_at_a_time(self, manager):
        pending = manager.begin_pending("alice", "nas1")
        status, attempt = self._begin(manager, pending.request_id)
        assert status == "started" and attempt is not None
        assert self._begin(manager, pending.request_id) == ("in_progress", None)

    def test_a_released_claim_can_be_made_again(self, manager):
        pending, attempt = self._claimed(manager)
        manager.release_attempt(attempt)
        assert self._begin(manager, pending.request_id)[0] == "started"

    def test_an_unknown_or_expired_request_cannot_be_claimed(self, manager, clock):
        assert self._begin(manager, "not-a-request") == ("expired", None)
        pending = manager.begin_pending("alice", "nas1")
        clock.advance(50)
        assert self._begin(manager, pending.request_id) == ("expired", None)

    def test_one_claim_per_request_even_when_many_ask_at_once(self, manager):
        import threading

        pending = manager.begin_pending("alice", "nas1")
        results, barrier = [], threading.Barrier(8)

        def claim():
            barrier.wait()
            results.append(self._begin(manager, pending.request_id)[0])

        threads = [threading.Thread(target=claim) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sorted(results) == ["in_progress"] * 7 + ["started"]

    def test_claims_on_different_requests_do_not_interfere(self, manager):
        a = manager.begin_pending("alice", "nas1")
        b = manager.begin_pending("bob", "nas1")
        assert self._begin(manager, a.request_id)[0] == "started"
        assert self._begin(manager, b.request_id)[0] == "started"

    def test_releasing_an_old_claim_does_not_release_a_newer_one(self, manager):
        _, old = self._claimed(manager)
        manager.cancel_pending("alice", "nas1")
        pending, _ = self._claimed(manager)  # a new request, claimed again
        manager.release_attempt(old)
        assert self._begin(manager, pending.request_id)[0] == "in_progress"

    # -- adopting ------------------------------------------------------------

    def test_a_valid_attempt_installs_the_session_and_settles_the_request(self, manager):
        pending, attempt = self._claimed(manager)
        record, replaced = self._adopt(manager, attempt)

        assert (record.session_id, record.generation, replaced) == ("SID-NEW", 1, None)
        assert manager.get("alice", "nas1", touch=False).session_id == "SID-NEW"
        assert manager.pending("alice", "nas1") is None
        assert self._begin(manager, pending.request_id) == ("expired", None)

    def test_a_claim_does_not_outlive_the_session_it_made(self, manager):
        """Without the caller releasing it: the manager itself leaves nothing
        behind that would make the next request for this owner and NAS unclaimable."""
        _, attempt = self._claimed(manager)
        assert self._adopt(manager, attempt) is not None

        fresh = manager.begin_pending("alice", "nas1")
        assert self._begin(manager, fresh.request_id)[0] == "started"

    def test_a_claim_does_not_outlive_a_session_installed_another_way(self, manager):
        _, attempt = self._claimed(manager)
        _install(manager, sid="SID-OTHER")

        fresh = manager.begin_pending("alice", "nas1")
        assert self._begin(manager, fresh.request_id)[0] == "started"
        assert self._adopt(manager, attempt) is None

    def test_an_attempt_adopts_only_once(self, manager):
        _, attempt = self._claimed(manager)
        assert self._adopt(manager, attempt) is not None
        assert self._adopt(manager, attempt, sid="SID-AGAIN") is None
        assert manager.get("alice", "nas1", touch=False).session_id == "SID-NEW"

    def test_r05_a_cancelled_request_is_not_adopted(self, manager):
        _, attempt = self._claimed(manager)
        manager.cancel_pending("alice", "nas1")
        assert self._adopt(manager, attempt) is None
        assert manager.get("alice", "nas1", touch=False) is None

    def test_r05_an_expired_request_is_not_adopted(self, manager, clock):
        _, attempt = self._claimed(manager)
        clock.advance(50)
        assert self._adopt(manager, attempt) is None
        assert manager.get("alice", "nas1", touch=False) is None

    def test_r05_a_disconnect_withdraws_a_login_in_progress(self, manager):
        _, attempt = self._claimed(manager)
        manager.revoke("alice", "nas1")
        assert self._adopt(manager, attempt) is None
        assert manager.get("alice", "nas1", touch=False) is None

    def test_a_disconnect_of_every_session_of_the_owner_withdraws_all_their_requests(self, manager):
        _, a1 = self._claimed(manager, "alice", "nas1")
        _, a2 = self._claimed(manager, "alice", "nas2")
        _, b1 = self._claimed(manager, "bob", "nas1")
        manager.revoke("alice")
        assert self._adopt(manager, a1) is None and self._adopt(manager, a2) is None
        assert self._adopt(manager, b1) is not None  # another owner's login is untouched

    def test_a_disconnect_of_one_nas_leaves_the_owners_other_request_alone(self, manager):
        _, a1 = self._claimed(manager, "alice", "nas1")
        _, a2 = self._claimed(manager, "alice", "nas2")
        manager.revoke("alice", "nas1")
        assert self._adopt(manager, a1) is None
        assert self._adopt(manager, a2) is not None

    def test_shutting_down_withdraws_every_login_in_progress(self, manager):
        _, attempt = self._claimed(manager)
        manager.revoke_all()
        assert self._adopt(manager, attempt) is None

    def test_r05_a_replaced_request_is_not_adopted_and_the_new_one_is_left_alone(self, manager):
        _, old = self._claimed(manager)
        manager.cancel_pending("alice", "nas1")
        new = manager.begin_pending("alice", "nas1")

        assert self._adopt(manager, old) is None
        assert manager.pending("alice", "nas1") == new
        assert self._begin(manager, new.request_id)[0] == "started"  # not consumed by the stale one

    def test_r05_an_older_result_cannot_replace_a_newer_session(self, manager):
        _, older = self._claimed(manager)
        manager.cancel_pending("alice", "nas1")
        _, newer = self._claimed(manager)
        assert self._adopt(manager, newer, sid="SID-NEWER") is not None

        assert self._adopt(manager, older, sid="SID-OLDER") is None
        assert manager.get("alice", "nas1", touch=False).session_id == "SID-NEWER"

    def test_a_login_installed_another_way_withdraws_the_one_in_progress(self, manager):
        _, attempt = self._claimed(manager)
        _install(manager, sid="SID-OTHER")
        assert self._adopt(manager, attempt) is None
        assert manager.get("alice", "nas1", touch=False).session_id == "SID-OTHER"

    def test_adopting_replaces_an_existing_session_and_reports_it(self, manager):
        _install(manager, sid="SID-OLD")
        _, attempt = self._claimed(manager)
        record, replaced = self._adopt(manager, attempt)
        assert (record.generation, replaced.session_id) == (2, "SID-OLD")

    def test_a_refused_adoption_changes_nothing_else(self, manager):
        _install(manager, sid="SID-LIVE")
        _, attempt = self._claimed(manager)
        manager.cancel_pending("alice", "nas1")
        assert self._adopt(manager, attempt) is None
        live = manager.get("alice", "nas1", touch=False)
        assert (live.session_id, live.generation) == ("SID-LIVE", 1)

    # -- withdrawing a request ----------------------------------------------

    def test_cancelling_a_request_clears_its_claim(self, manager):
        pending, _ = self._claimed(manager)
        manager.cancel_pending("alice", "nas1")
        again = manager.begin_pending("alice", "nas1")
        assert again.request_id != pending.request_id
        assert self._begin(manager, again.request_id)[0] == "started"

    def test_an_expired_request_takes_its_claim_with_it(self, manager, clock):
        _, attempt = self._claimed(manager)
        clock.advance(50)
        fresh = manager.begin_pending("alice", "nas1")
        assert self._begin(manager, fresh.request_id)[0] == "started"
        assert self._adopt(manager, attempt) is None

    def test_a_revoke_with_nothing_to_revoke_still_withdraws_a_request(self, manager):
        pending = manager.begin_pending("alice", "nas1")
        assert manager.revoke("alice", "nas1") == []
        assert manager.find_pending(pending.request_id) is None

    def test_a_revoke_leaves_another_owners_request_alone(self, manager):
        bob = manager.begin_pending("bob", "nas1")
        manager.begin_pending("alice", "nas1")
        manager.revoke("alice")
        assert manager.find_pending(bob.request_id) == bob
