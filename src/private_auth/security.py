# src/private_auth/security.py - Rate limits, owner sessions and request checks
# for the private login interface (plans/2026-10-06-manual-authentication/
# PLAN.md §5.1).
#
# None of this holds a NAS credential. The owner session is the proof that the
# person at the browser passed the passkey check; it is what lets them reach the
# login form, and it is never given to an MCP client.

import hashlib
import hmac
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, Iterable, Optional

# Applied to every response from the private interface. Nothing on it loads
# anything from another origin, and nothing on it should be cached, framed or
# leak its address in a Referer.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)
# Above this many tracked keys, a rate limiter sweeps out the expired ones.
_SWEEP_ABOVE = 4096

SECURITY_HEADERS: Dict[str, str] = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
}


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def normalise_origin(origin: str) -> str:
    return origin.strip().rstrip("/").lower()


def origin_allowed(origin_header: Optional[str], allowed: Iterable[str]) -> bool:
    """Whether a request's `Origin` header names one of the allowed origins. A
    missing header is refused: every browser sends one on a form post, so its
    absence is not a browser submitting our form."""
    if not origin_header:
        return False
    return normalise_origin(origin_header) in {normalise_origin(o) for o in allowed}


class RateLimiter:
    """At most `max_events` recorded events per key in any `window_seconds`.

    `allow` asks without recording and `record` notes an event, so a caller can
    count only failures. Once a key reaches the limit it stays refused until the
    oldest counted event ages out of the window, or for `lockout_seconds` from
    the event that reached the limit, whichever is longer.
    """

    def __init__(
        self,
        max_events: int,
        window_seconds: float,
        *,
        lockout_seconds: float = 0.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._max = max_events
        self._window = window_seconds
        self._lockout = lockout_seconds
        self._clock = clock
        self._events: Dict[str, Deque[float]] = {}
        self._locked_until: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _trim(self, key: str, now: float) -> Deque[float]:
        """The key's recent events. Asking about a key never creates an entry for
        it, and an entry whose events have all aged out is dropped, so a stream of
        distinct addresses cannot grow the table without end."""
        events = self._events.get(key)
        if events is None:
            return deque()
        while events and now - events[0] >= self._window:
            events.popleft()
        if not events and key not in self._locked_until:
            del self._events[key]
            return deque()
        return events

    def _sweep(self, now: float) -> None:
        for key in list(self._events):
            self._trim(key, now)
        for key in [k for k, until in self._locked_until.items() if until <= now]:
            del self._locked_until[key]

    def retry_after(self, key: str) -> int:
        """Seconds until `key` may try again; 0 if it may now."""
        with self._lock:
            now = self._clock()
            events = self._trim(key, now)
            waits = []
            if len(events) >= self._max:
                waits.append(events[0] + self._window - now)
            locked = self._locked_until.get(key)
            if locked is not None:
                waits.append(locked - now)
            wait = max(waits) if waits else 0
            if wait <= 0:
                self._locked_until.pop(key, None)
                return 0
            return int(wait) + 1

    def allow(self, key: str) -> bool:
        return self.retry_after(key) == 0

    def record(self, key: str) -> None:
        with self._lock:
            now = self._clock()
            if len(self._events) > _SWEEP_ABOVE:
                self._sweep(now)
            events = self._trim(key, now)
            if key not in self._events:
                self._events[key] = events
            events.append(now)
            if len(events) >= self._max and self._lockout:
                self._locked_until[key] = now + self._lockout

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)
            self._locked_until.pop(key, None)


@dataclass(frozen=True)
class OwnerSession:
    csrf_token: str
    created_at: float
    last_seen: float

    def __repr__(self) -> str:
        return "OwnerSession()"


class OwnerSessions:
    """Sessions of the person who passed the passkey check. Held in memory only,
    keyed by a digest of the cookie value, ended by an idle or an absolute
    deadline, and never extended past the absolute one."""

    def __init__(
        self,
        idle_seconds: float = 600,
        absolute_seconds: float = 3600,
        *,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._idle = idle_seconds
        self._absolute = absolute_seconds
        self._clock = clock
        self._sessions: Dict[str, OwnerSession] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create(self) -> "tuple[str, OwnerSession]":
        """A new session: the cookie value (shown once) and the session."""
        token = secrets.token_urlsafe(32)
        now = self._clock()
        session = OwnerSession(secrets.token_urlsafe(24), now, now)
        with self._lock:
            # Expired sessions are removed whenever one is made, not only when
            # their own cookie happens to be presented again.
            for key in [
                k
                for k, s in self._sessions.items()
                if now - s.created_at >= self._absolute or now - s.last_seen >= self._idle
            ]:
                del self._sessions[key]
            self._sessions[self._key(token)] = session
        return token, session

    def get(self, token: Optional[str]) -> Optional[OwnerSession]:
        if not token:
            return None
        key = self._key(token)
        with self._lock:
            now = self._clock()
            session = self._sessions.get(key)
            if session is None:
                return None
            if now - session.created_at >= self._absolute or now - session.last_seen >= self._idle:
                del self._sessions[key]
                return None
            session = OwnerSession(session.csrf_token, session.created_at, now)
            self._sessions[key] = session
            return session

    def end(self, token: Optional[str]) -> None:
        if token:
            with self._lock:
                self._sessions.pop(self._key(token), None)

    def end_all(self) -> None:
        with self._lock:
            self._sessions.clear()
