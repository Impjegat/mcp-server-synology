"""Proving who the owner is: the passkey store, the one-time enrollment code and
the real WebAuthn ceremonies, run end to end against a software authenticator.
Every refusal is a plain False: the reason is never handed back."""

import hashlib
import json
import os
import stat
import sys

import pytest

pytest.importorskip("webauthn")

from private_auth.owner import OwnerStore, PasskeyOwnerAuth  # noqa: E402
from tests.broker_support import FakeClock  # noqa: E402
from tests.software_authenticator import SoftwareAuthenticator, b64  # noqa: E402

RP_ID = "broker.example"
ORIGIN = "https://broker.example:8444"


@pytest.fixture
def store(tmp_path):
    return OwnerStore(tmp_path / "owner.json")


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def owner(store, clock):
    return PasskeyOwnerAuth(store, rp_id=RP_ID, origin=ORIGIN, clock=clock)


@pytest.fixture
def device():
    return SoftwareAuthenticator(RP_ID, ORIGIN)


def _digest(code):
    """What the store keeps of an enrollment code, and what a begun enrollment holds."""
    return hashlib.sha256(code.encode()).hexdigest()


def _enroll(owner, store, device, **kwargs):
    code = store.new_enrollment_code(**kwargs)
    state, options = owner.begin_enrollment(code)
    assert owner.finish_enrollment(state, device.create(options), "test device") is True


class TestStore:
    def test_a_new_store_is_empty(self, store):
        assert store.credentials() == []
        assert store.enrollment_open() is False

    def test_the_owner_handle_is_made_once_and_kept(self, store):
        first = store.user_id()
        assert len(first) == 32 and store.user_id() == first

    def test_it_holds_public_material_only(self, store, owner, device, tmp_path):
        _enroll(owner, store, device)
        text = (tmp_path / "owner.json").read_text()
        data = json.loads(text)
        assert set(data) == {"user_id", "credentials", "enrollment"}
        assert set(data["credentials"][0]) == {"id", "public_key", "sign_count", "label", "created"}
        # Nothing that could sign in: not the device's private key.
        private = device.private_key.private_numbers().private_value.to_bytes(32, "big")
        assert b64(private) not in text

    def test_a_write_leaves_no_temporary_file(self, store, tmp_path):
        store.user_id()
        assert [p.name for p in tmp_path.iterdir()] == ["owner.json"]

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
    def test_the_file_is_private_to_its_owner(self, store, tmp_path):
        store.user_id()
        assert stat.S_IMODE(os.stat(tmp_path / "owner.json").st_mode) == 0o600

    def test_a_passkey_can_be_removed(self, store, owner, device):
        _enroll(owner, store, device)
        assert store.remove_credential(b64(device.credential_id)) is True
        assert store.credentials() == []
        assert store.remove_credential(b64(device.credential_id)) is False


class TestEnrollmentCode:
    def test_the_code_is_one_time_and_only_its_hash_is_stored(self, store, tmp_path):
        code = store.new_enrollment_code()
        assert store.check_enrollment_code(code)
        assert code not in (tmp_path / "owner.json").read_text()

    def test_a_wrong_code_does_not_work(self, store):
        store.new_enrollment_code()
        assert not store.check_enrollment_code("wrong")
        assert not store.check_enrollment_code("")

    def test_an_expired_code_does_not_work(self, store):
        code = store.new_enrollment_code(minutes=0)
        assert not store.check_enrollment_code(code)
        assert not store.enrollment_open()

    def test_a_second_passkey_needs_the_command_run_again_on_purpose(self, store, owner, device):
        _enroll(owner, store, device)
        with pytest.raises(PermissionError, match="already enrolled"):
            store.new_enrollment_code()
        assert store.new_enrollment_code(allow_additional=True)

    def test_a_new_code_replaces_the_old_one(self, store):
        first = store.new_enrollment_code()
        second = store.new_enrollment_code()
        assert not store.check_enrollment_code(first)
        assert store.check_enrollment_code(second)


class TestEnrolling:
    def test_a_valid_code_and_a_passkey_enrol_the_owner(self, owner, store, device):
        assert owner.has_owner() is False
        _enroll(owner, store, device)
        assert owner.has_owner() is True
        stored = store.credentials()[0]
        assert stored.credential_id == device.credential_id and stored.label == "test device"

    def test_a_wrong_code_gets_no_options(self, owner, store):
        store.new_enrollment_code()
        assert owner.begin_enrollment("wrong") is None
        assert owner.has_owner() is False

    def test_no_code_at_all_gets_no_options(self, owner):
        assert owner.begin_enrollment("anything") is None

    def test_the_code_works_once(self, owner, store, device):
        code = store.new_enrollment_code()
        state, options = owner.begin_enrollment(code)
        assert owner.finish_enrollment(state, device.create(options))
        assert owner.begin_enrollment(code) is None

    def test_a_challenge_is_single_use_even_when_a_new_code_is_open(self, owner, store, device):
        """Isolated from the code check: a new code is made between the two
        finishes, so only the single-use challenge can stop the second."""
        state, options = owner.begin_enrollment(store.new_enrollment_code())
        assert owner.finish_enrollment(state, device.create(options)) is True
        store.new_enrollment_code(allow_additional=True)
        second = SoftwareAuthenticator(RP_ID, ORIGIN)
        assert owner.finish_enrollment(state, second.create(options)) is False
        assert len(store.credentials()) == 1

    def test_two_enrollments_started_with_one_code_cannot_both_finish(self, owner, store):
        code = store.new_enrollment_code()
        first, second = SoftwareAuthenticator(RP_ID, ORIGIN), SoftwareAuthenticator(RP_ID, ORIGIN)
        (s1, o1), (s2, o2) = owner.begin_enrollment(code), owner.begin_enrollment(code)

        assert owner.finish_enrollment(s1, first.create(o1)) is True
        assert owner.finish_enrollment(s2, second.create(o2)) is False
        assert len(store.credentials()) == 1

    def test_an_expired_challenge_is_refused(self, owner, store, device, clock):
        state, options = owner.begin_enrollment(store.new_enrollment_code())
        clock.advance(121)
        assert owner.finish_enrollment(state, device.create(options)) is False

    def test_a_response_from_the_wrong_origin_is_refused(self, owner, store, device):
        state, options = owner.begin_enrollment(store.new_enrollment_code())
        response = device.create(options, origin="https://evil.example")
        assert owner.finish_enrollment(state, response) is False
        assert owner.has_owner() is False

    def test_a_response_that_skipped_user_verification_is_refused(self, owner, store):
        lax = SoftwareAuthenticator(RP_ID, ORIGIN, user_verified=False)
        state, options = owner.begin_enrollment(store.new_enrollment_code())
        assert owner.finish_enrollment(state, lax.create(options)) is False

    def test_an_unknown_state_is_refused(self, owner, store, device):
        _, options = owner.begin_enrollment(store.new_enrollment_code())
        assert owner.finish_enrollment("made-up", device.create(options)) is False

    def test_a_challenge_cannot_be_used_twice(self, owner, store, device):
        state, options = owner.begin_enrollment(store.new_enrollment_code())
        response = device.create(options)
        assert owner.finish_enrollment(state, response) is True
        assert owner.finish_enrollment(state, response) is False

    def test_garbage_is_refused_without_an_exception(self, owner, store):
        state, _ = owner.begin_enrollment(store.new_enrollment_code())
        assert owner.finish_enrollment(state, {"nonsense": True}) is False

    def test_an_added_device_is_excluded_from_registering_twice(self, owner, store, device):
        _enroll(owner, store, device)
        _, options = owner.begin_enrollment(store.new_enrollment_code(allow_additional=True))
        assert [c["id"] for c in options["excludeCredentials"]] == [b64(device.credential_id)]


class TestAuthenticating:
    @pytest.fixture
    def enrolled(self, owner, store, device):
        _enroll(owner, store, device)

    def test_there_is_nothing_to_authenticate_before_enrollment(self, owner):
        assert owner.begin_authentication() is None

    def test_the_owner_signs_in_with_the_enrolled_passkey(self, owner, device, enrolled):
        state, options = owner.begin_authentication()
        assert options["userVerification"] == "required"
        assert owner.finish_authentication(state, device.get(options)) is True

    def test_the_counter_moves_forward(self, owner, store, device, enrolled):
        for expected in (1, 2, 3):
            state, options = owner.begin_authentication()
            assert owner.finish_authentication(state, device.get(options))
            assert store.credentials()[0].sign_count == expected

    def test_a_response_cannot_be_replayed(self, owner, device, enrolled):
        state, options = owner.begin_authentication()
        response = device.get(options)
        assert owner.finish_authentication(state, response) is True
        assert owner.finish_authentication(state, response) is False
        state2, _ = owner.begin_authentication()
        assert owner.finish_authentication(state2, response) is False  # nor against a new challenge

    def test_a_fresh_valid_response_to_a_challenge_already_used_is_refused(
        self, owner, device, enrolled
    ):
        """Isolated from the counter check: the second response is newly signed
        with a higher counter, so only the single-use challenge can stop it."""
        state, options = owner.begin_authentication()
        assert owner.finish_authentication(state, device.get(options)) is True
        assert owner.finish_authentication(state, device.get(options)) is False

    def test_a_counter_that_goes_backwards_is_refused(self, owner, device, enrolled):
        for _ in range(3):
            state, options = owner.begin_authentication()
            assert owner.finish_authentication(state, device.get(options))
        state, options = owner.begin_authentication()
        assert owner.finish_authentication(state, device.get(options, count=1)) is False

    def test_another_device_with_the_same_credential_id_is_refused(self, owner, device, enrolled):
        impostor = SoftwareAuthenticator(RP_ID, ORIGIN)
        impostor.credential_id = device.credential_id  # same id, different key
        state, options = owner.begin_authentication()
        assert owner.finish_authentication(state, impostor.get(options)) is False

    def test_an_unknown_credential_is_refused(self, owner, enrolled):
        stranger = SoftwareAuthenticator(RP_ID, ORIGIN)
        state, options = owner.begin_authentication()
        assert owner.finish_authentication(state, stranger.get(options)) is False

    def test_a_response_for_another_origin_or_site_is_refused(self, owner, device, enrolled):
        state, options = owner.begin_authentication()
        assert (
            owner.finish_authentication(state, device.get(options, origin="https://evil.example"))
            is False
        )
        state, options = owner.begin_authentication()
        assert (
            owner.finish_authentication(state, device.get(options, rp_id="evil.example")) is False
        )

    def test_a_response_that_skipped_user_verification_is_refused(self, owner, device, enrolled):
        device.user_verified = False
        state, options = owner.begin_authentication()
        assert owner.finish_authentication(state, device.get(options)) is False

    def test_an_expired_challenge_is_refused(self, owner, device, clock, enrolled):
        state, options = owner.begin_authentication()
        clock.advance(121)
        assert owner.finish_authentication(state, device.get(options)) is False

    def test_an_unknown_state_is_refused(self, owner, device, enrolled):
        _, options = owner.begin_authentication()
        assert owner.finish_authentication("made-up", device.get(options)) is False

    def test_garbage_is_refused_without_an_exception(self, owner, enrolled):
        state, _ = owner.begin_authentication()
        assert owner.finish_authentication(state, {"nonsense": True}) is False

    def test_a_failed_attempt_does_not_move_the_counter(self, owner, store, device, enrolled):
        state, options = owner.begin_authentication()
        assert (
            owner.finish_authentication(state, device.get(options, origin="https://evil.example"))
            is False
        )
        assert store.credentials()[0].sign_count == 0


class TestEnrollmentIsAtomic:
    """Checking the code, adding the passkey and using the code up happen as one
    step. The write is slowed down so that, if they were separate steps, the
    threads below would all get past the check before any of them used the code."""

    @staticmethod
    def _slow_writes(store, monkeypatch):
        import time

        real_write = store._write

        def slow(data):
            time.sleep(0.05)
            real_write(data)

        monkeypatch.setattr(store, "_write", slow)

    def test_the_store_lets_exactly_one_of_many_simultaneous_enrollments_through(
        self, store, monkeypatch
    ):
        import threading

        digest = _digest(store.new_enrollment_code())
        self._slow_writes(store, monkeypatch)
        results, barrier = [], threading.Barrier(8)

        def attempt(index):
            barrier.wait()
            results.append(
                store.add_credential_consuming_code(
                    bytes([index]), b"key", 0, f"device {index}", code_sha256=digest
                )
            )

        threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert results.count(True) == 1
        assert len(store.credentials()) == 1
        assert store.enrollment_open() is False

    def test_two_enrollments_begun_with_one_code_cannot_both_finish_at_once(
        self, owner, store, monkeypatch
    ):
        import threading
        import time

        code = store.new_enrollment_code()
        devices = [SoftwareAuthenticator(RP_ID, ORIGIN) for _ in range(2)]
        begun = [owner.begin_enrollment(code) for _ in devices]
        self._slow_writes(store, monkeypatch)
        # If finishing still asked "is the code open?" as a separate step, this
        # makes both threads hear "yes" before either has added anything.
        real_open = store.enrollment_open

        def open_then_dawdle(*args, **kwargs):
            answer = real_open(*args, **kwargs)
            time.sleep(0.1)
            return answer

        monkeypatch.setattr(store, "enrollment_open", open_then_dawdle)
        results, barrier = [], threading.Barrier(2)

        def finish(device, state, options):
            barrier.wait()
            results.append(owner.finish_enrollment(state, device.create(options)))

        threads = [
            threading.Thread(target=finish, args=(device, state, options))
            for device, (state, options) in zip(devices, begun)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sorted(results) == [False, True]
        assert len(store.credentials()) == 1

    def test_without_an_open_code_nothing_is_added(self, store):
        assert (
            store.add_credential_consuming_code(b"id", b"key", 0, "x", code_sha256=_digest("any"))
            is False
        )
        assert store.credentials() == []

    def test_an_expired_code_adds_nothing(self, store):
        digest = _digest(store.new_enrollment_code(minutes=0))
        assert (
            store.add_credential_consuming_code(b"id", b"key", 0, "x", code_sha256=digest) is False
        )
        assert store.credentials() == []

    def test_a_valid_code_adds_one_passkey_and_is_used_up(self, store):
        digest = _digest(store.new_enrollment_code())
        assert (
            store.add_credential_consuming_code(b"id", b"key", 0, "x", code_sha256=digest) is True
        )
        assert (
            store.add_credential_consuming_code(b"id2", b"key2", 0, "y", code_sha256=digest)
            is False
        )
        assert [c.label for c in store.credentials()] == ["x"]


class TestEnrollmentIsBoundToItsCode:
    """Sign-in and enrollment each make a challenge, and anyone who can reach the
    page can ask for either. A challenge made for one must not finish the other, and
    an enrollment must finish only while the code it began with is still the open
    one (implementation review R01)."""

    @pytest.fixture
    def enrolled(self, owner, store, device):
        _enroll(owner, store, device)

    def test_r01_a_sign_in_challenge_cannot_complete_enrollment(self, owner, store, enrolled):
        # The owner has an add-device code open; the attacker does not know it.
        store.new_enrollment_code(allow_additional=True)
        state, options = owner.begin_authentication()  # a challenge anyone can ask for
        attacker = SoftwareAuthenticator(RP_ID, ORIGIN)

        assert owner.finish_enrollment(state, attacker.create(options)) is False

        assert len(store.credentials()) == 1
        assert store.enrollment_open() is True  # the real code was not used up
        state, options = owner.begin_authentication()
        assert owner.finish_authentication(state, attacker.get(options)) is False

    def test_an_enrollment_challenge_cannot_complete_a_sign_in(
        self, owner, store, device, enrolled
    ):
        state, options = owner.begin_enrollment(store.new_enrollment_code(allow_additional=True))
        assert owner.finish_authentication(state, device.get(options)) is False

    def test_a_wrong_use_burns_the_challenge(self, owner, store, device, enrolled):
        """Presented for the wrong purpose, a state is spent, not kept for a retry:
        not even the owner's valid signature can then redeem it."""
        store.new_enrollment_code(allow_additional=True)
        state, options = owner.begin_authentication()
        attacker = SoftwareAuthenticator(RP_ID, ORIGIN)
        assert owner.finish_enrollment(state, attacker.create(options)) is False
        assert owner.finish_authentication(state, device.get(options)) is False

    def test_r01_an_enrollment_begun_under_a_replaced_code_cannot_finish(
        self, owner, store, device
    ):
        state, options = owner.begin_enrollment(store.new_enrollment_code())
        second = store.new_enrollment_code()  # the owner asked for a new code meanwhile

        assert owner.finish_enrollment(state, device.create(options)) is False

        assert store.credentials() == []
        assert store.check_enrollment_code(second)  # the new code is untouched

    def test_r01_an_enrollment_cannot_finish_after_its_code_was_used_by_another(self, owner, store):
        code = store.new_enrollment_code()
        first, second = SoftwareAuthenticator(RP_ID, ORIGIN), SoftwareAuthenticator(RP_ID, ORIGIN)
        (s1, o1), (s2, o2) = owner.begin_enrollment(code), owner.begin_enrollment(code)
        assert owner.finish_enrollment(s1, first.create(o1)) is True

        store.new_enrollment_code(allow_additional=True)  # a different code is open now
        assert owner.finish_enrollment(s2, second.create(o2)) is False
        assert [c.credential_id for c in store.credentials()] == [first.credential_id]

    def test_r01_the_store_refuses_a_passkey_under_a_different_code(self, store):
        store.new_enrollment_code()
        other = _digest("a code that was never issued")
        assert (
            store.add_credential_consuming_code(b"id", b"key", 0, "x", code_sha256=other) is False
        )
        assert store.credentials() == []
        assert store.enrollment_open() is True

    def test_r01_the_store_will_not_add_a_passkey_without_naming_the_code(self, store):
        store.new_enrollment_code()
        with pytest.raises(TypeError):
            store.add_credential_consuming_code(b"id", b"key", 0, "x")
        assert store.credentials() == []

    def test_the_first_and_an_additional_device_still_enrol(self, owner, store, device):
        _enroll(owner, store, device)
        second = SoftwareAuthenticator(RP_ID, ORIGIN)
        _enroll(owner, store, second, allow_additional=True)
        assert [c.credential_id for c in store.credentials()] == [
            device.credential_id,
            second.credential_id,
        ]
        state, options = owner.begin_authentication()
        assert owner.finish_authentication(state, second.get(options)) is True


class TestOutstandingChallenges:
    def test_the_table_cannot_grow_past_its_cap_and_the_newest_stays_valid(
        self, owner, store, device
    ):
        from private_auth.owner import MAX_OUTSTANDING_CHALLENGES

        _enroll(owner, store, device)
        for _ in range(MAX_OUTSTANDING_CHALLENGES * 3):
            owner.begin_authentication()
        assert len(owner._challenges) <= MAX_OUTSTANDING_CHALLENGES

        state, options = owner.begin_authentication()
        assert owner.finish_authentication(state, device.get(options)) is True

    def test_the_oldest_challenge_is_the_one_that_goes(self, owner, store, device):
        from private_auth.owner import MAX_OUTSTANDING_CHALLENGES

        _enroll(owner, store, device)
        oldest_state, oldest_options = owner.begin_authentication()
        for _ in range(MAX_OUTSTANDING_CHALLENGES):
            owner.begin_authentication()
        assert owner.finish_authentication(oldest_state, device.get(oldest_options)) is False
