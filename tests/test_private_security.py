"""The private interface's building blocks: attempt limits, owner sessions, the
Origin check and the response headers. A fake clock drives every deadline."""

import pytest

from private_auth.security import (
    CONTENT_SECURITY_POLICY,
    SECURITY_HEADERS,
    OwnerSessions,
    RateLimiter,
    constant_time_equal,
    origin_allowed,
)
from tests.broker_support import FakeClock


class TestRateLimiter:
    def test_it_allows_up_to_the_limit_then_refuses(self):
        clock = FakeClock()
        limiter = RateLimiter(3, 60, clock=clock)
        for _ in range(3):
            assert limiter.allow("k")
            limiter.record("k")
        assert not limiter.allow("k")
        assert limiter.retry_after("k") > 0

    def test_asking_does_not_count(self):
        limiter = RateLimiter(2, 60, clock=FakeClock())
        for _ in range(10):
            assert limiter.allow("k")

    def test_events_age_out_of_the_window(self):
        clock = FakeClock()
        limiter = RateLimiter(2, 60, clock=clock)
        limiter.record("k")
        limiter.record("k")
        assert not limiter.allow("k")
        clock.advance(61)
        assert limiter.allow("k")

    def test_a_lockout_outlasts_the_window(self):
        clock = FakeClock()
        limiter = RateLimiter(3, 60, lockout_seconds=120, clock=clock)
        for _ in range(3):
            limiter.record("k")
        clock.advance(61)  # the events are old now, the lockout is not
        assert not limiter.allow("k")
        assert 0 < limiter.retry_after("k") <= 60
        clock.advance(60)
        assert limiter.allow("k")

    def test_keys_are_independent(self):
        limiter = RateLimiter(1, 60, clock=FakeClock())
        limiter.record("a")
        assert not limiter.allow("a")
        assert limiter.allow("b")

    def test_reset_forgives(self):
        limiter = RateLimiter(1, 60, lockout_seconds=300, clock=FakeClock())
        limiter.record("k")
        assert not limiter.allow("k")
        limiter.reset("k")
        assert limiter.allow("k")


class TestOwnerSessions:
    def test_a_session_is_found_by_its_cookie_value(self):
        sessions = OwnerSessions(clock=FakeClock())
        token, created = sessions.create()
        assert sessions.get(token).csrf_token == created.csrf_token
        assert sessions.get("not-a-token") is None
        assert sessions.get(None) is None
        assert sessions.get("") is None

    def test_each_session_gets_its_own_token_and_csrf_token(self):
        sessions = OwnerSessions(clock=FakeClock())
        (t1, s1), (t2, s2) = sessions.create(), sessions.create()
        assert t1 != t2 and s1.csrf_token != s2.csrf_token

    def test_the_cookie_value_is_not_kept(self):
        sessions = OwnerSessions(clock=FakeClock())
        token, _ = sessions.create()
        assert token not in sessions._sessions

    def test_it_ends_after_the_idle_limit(self):
        clock = FakeClock()
        sessions = OwnerSessions(idle_seconds=100, absolute_seconds=1000, clock=clock)
        token, _ = sessions.create()
        clock.advance(99)
        assert sessions.get(token) is not None
        clock.advance(100)
        assert sessions.get(token) is None

    def test_use_keeps_it_alive_but_never_past_the_absolute_limit(self):
        clock = FakeClock()
        sessions = OwnerSessions(idle_seconds=100, absolute_seconds=1000, clock=clock)
        token, _ = sessions.create()
        for _ in range(11):
            clock.advance(90)
            assert sessions.get(token) is not None
        clock.advance(10)
        assert sessions.get(token) is None

    def test_it_can_be_ended(self):
        sessions = OwnerSessions(clock=FakeClock())
        token, _ = sessions.create()
        sessions.end(token)
        assert sessions.get(token) is None
        sessions.end("never-existed")  # harmless
        sessions.end(None)

    def test_all_can_be_ended(self):
        sessions = OwnerSessions(clock=FakeClock())
        tokens = [sessions.create()[0] for _ in range(3)]
        sessions.end_all()
        assert all(sessions.get(t) is None for t in tokens)

    def test_it_prints_without_its_secret(self):
        _, session = OwnerSessions(clock=FakeClock()).create()
        assert session.csrf_token not in repr(session)


class TestOrigin:
    ALLOWED = ["https://broker.example:8444"]

    @pytest.mark.parametrize(
        "origin",
        [
            "https://broker.example:8444",
            "https://broker.example:8444/",
            "HTTPS://BROKER.EXAMPLE:8444",
            " https://broker.example:8444 ",
        ],
    )
    def test_the_allowed_origin_is_accepted_however_it_is_spelled(self, origin):
        assert origin_allowed(origin, self.ALLOWED)

    @pytest.mark.parametrize(
        "origin",
        [
            None,
            "",
            "null",
            "https://broker.example",
            "https://broker.example:8445",
            "http://broker.example:8444",
            "https://evil.example:8444",
            "https://broker.example:8444.evil.example",
            "https://broker.example:8444@evil.example",
        ],
    )
    def test_anything_else_is_refused(self, origin):
        assert not origin_allowed(origin, self.ALLOWED)


def test_constant_time_equal():
    assert constant_time_equal("abc", "abc")
    assert not constant_time_equal("abc", "abd")
    assert not constant_time_equal("abc", "abcd")
    assert not constant_time_equal("", "x")


class TestHeaders:
    def test_every_protection_is_present(self):
        assert SECURITY_HEADERS["Cache-Control"] == "no-store"
        assert SECURITY_HEADERS["Referrer-Policy"] == "no-referrer"
        assert SECURITY_HEADERS["X-Content-Type-Options"] == "nosniff"
        assert SECURITY_HEADERS["X-Frame-Options"] == "DENY"
        assert SECURITY_HEADERS["Content-Security-Policy"] == CONTENT_SECURITY_POLICY

    def test_the_policy_allows_nothing_inline_and_nothing_from_elsewhere(self):
        assert "unsafe-inline" not in CONTENT_SECURITY_POLICY
        assert "unsafe-eval" not in CONTENT_SECURITY_POLICY
        assert "http" not in CONTENT_SECURITY_POLICY and "*" not in CONTENT_SECURITY_POLICY
        for directive in (
            "default-src 'none'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'self'",
        ):
            assert directive in CONTENT_SECURITY_POLICY
