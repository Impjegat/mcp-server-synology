# src/broker/sessions.py - The broker's DSM sessions, held in memory only.
#
# One record per (owner, NAS): the client that may use it and the NAS alias it
# is for. A record holds the DSM session id and SynoToken, lives only in this
# process's memory, and is never written anywhere, put in a status reply or
# shown by `repr` (plans/2026-10-06-manual-authentication/PLAN.md §4.2, §5.3).
#
# - A session ends at its idle deadline or its absolute deadline, whichever
#   comes first. Using a session for a permitted call moves the idle deadline;
#   nothing moves the absolute one, so restarting a client cannot extend it.
# - Each login gets a new generation number, and numbers are never reused. A
#   failure reported late by a request that used an older generation can
#   therefore never end a newer login (`invalidate` checks it).
# - A broker restart loses every session: nothing is stored to restore.

import itertools
import secrets
import threading
import time
from dataclasses import dataclass, replace
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from broker.policy import SessionPolicy


@dataclass(frozen=True)
class SessionRecord:
    owner: str
    nas: str
    base_url: str
    session_id: str
    syno_token: Optional[str]
    generation: int
    created_at: float
    last_used: float

    def __repr__(self) -> str:
        return (
            f"SessionRecord(owner={self.owner!r}, nas={self.nas!r}, generation={self.generation})"
        )


@dataclass(frozen=True)
class PendingLogin:
    """A request for the user to sign in privately. It holds no password and
    no code: those are never kept while waiting for a person."""

    request_id: str
    owner: str
    nas: str
    created_at: float
    expires_at: float


@dataclass(frozen=True)
class LoginAttempt:
    """One claim on a pending sign-in request: the request, and which attempt holds
    it. It holds no credential. A session that a login produces may be adopted only
    while this attempt still holds a request that is still the live one."""

    pending: PendingLogin
    attempt_id: int


# What `begin_attempt` can say.
ATTEMPT_STARTED = "started"
ATTEMPT_EXPIRED = "expired"  # unknown, expired, cancelled or replaced
ATTEMPT_IN_PROGRESS = "in_progress"  # another attempt already holds it

Key = Tuple[str, str]


class SessionManager:
    def __init__(self, policy: SessionPolicy, *, clock: Callable[[], float] = time.monotonic):
        self._policy = policy
        self._clock = clock
        self._lock = threading.RLock()
        self._sessions: Dict[Key, SessionRecord] = {}
        # Never reset or reused, even after a session is removed.
        self._generations: Dict[Key, int] = {}
        self._pending: Dict[Key, PendingLogin] = {}
        # The attempt (a sign-in whose worker is running) that holds each pending
        # request. It lives and dies with the request: whatever withdraws the
        # request withdraws the attempt, so a result that arrives late finds
        # nothing to adopt it.
        self._attempts: Dict[Key, int] = {}
        self._attempt_ids = itertools.count(1)
        # Sessions that ended on a deadline, waiting for their remote logout.
        self._expired: List[SessionRecord] = []

    # -- internals ---------------------------------------------------------

    def _is_expired(self, record: SessionRecord, now: float) -> bool:
        return (
            now - record.created_at >= self._policy.absolute_seconds
            or now - record.last_used >= self._policy.idle_seconds
        )

    def _expire_locked(self, now: float) -> None:
        for key in [k for k, r in self._sessions.items() if self._is_expired(r, now)]:
            self._expired.append(self._sessions.pop(key))
        for key in [k for k, p in self._pending.items() if p.expires_at <= now]:
            del self._pending[key]
            self._attempts.pop(key, None)

    def _withdraw_locked(self, owner: str, nas: Optional[str] = None) -> None:
        """Withdraw the owner's pending requests (and the attempts holding them): all
        of them, or just the one for `nas`."""
        for key in [k for k in self._pending if k[0] == owner and (nas is None or k[1] == nas)]:
            del self._pending[key]
            self._attempts.pop(key, None)

    def _install_locked(
        self, key: Key, base_url: str, session_id: str, syno_token: Optional[str], now: float
    ) -> Tuple[SessionRecord, Optional[SessionRecord]]:
        generation = self._generations.get(key, 0) + 1
        self._generations[key] = generation
        record = SessionRecord(
            key[0], key[1], base_url, session_id, syno_token, generation, now, now
        )
        replaced = self._sessions.get(key)
        self._sessions[key] = record
        # Signing in settles the request, and ends the attempt that made it.
        self._pending.pop(key, None)
        self._attempts.pop(key, None)
        return record, replaced

    # -- sessions ----------------------------------------------------------

    def install(
        self,
        owner: str,
        nas: str,
        base_url: str,
        session_id: str,
        syno_token: Optional[str] = None,
    ) -> Tuple[SessionRecord, Optional[SessionRecord]]:
        """Record a new login, replacing any earlier one atomically. Returns the
        new record and the one it replaced (whose DSM session the caller should
        end), and settles any pending sign-in request for this owner and NAS."""
        key = (owner, nas)
        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            return self._install_locked(key, base_url, session_id, syno_token, now)

    def install_for_attempt(
        self,
        attempt: LoginAttempt,
        base_url: str,
        session_id: str,
        syno_token: Optional[str] = None,
    ) -> Optional[Tuple[SessionRecord, Optional[SessionRecord]]]:
        """Adopt the session a login produced, but only while the request it answered
        is still the live one and `attempt` still holds it. Returns what `install`
        does, or None when the request was cancelled, expired, replaced, or ended by
        a disconnect while the worker ran. Nothing is installed then, and the caller
        ends `session_id` on the NAS.

        This is one step under one lock. Checking the request before the worker
        starts is not enough: the worker takes seconds, and everything above can
        happen in them."""
        pending = attempt.pending
        key = (pending.owner, pending.nas)
        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            current = self._pending.get(key)
            if (
                current is None
                or current.request_id != pending.request_id
                or self._attempts.get(key) != attempt.attempt_id
            ):
                return None
            return self._install_locked(key, base_url, session_id, syno_token, now)

    def get(self, owner: str, nas: str, *, touch: bool = True) -> Optional[SessionRecord]:
        """The live session, or None when there is none or it has expired. A
        permitted call passes `touch=True`, which moves the idle deadline; a
        status check passes False."""
        key = (owner, nas)
        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            record = self._sessions.get(key)
            if record is None:
                return None
            if touch:
                record = replace(record, last_used=now)
                self._sessions[key] = record
            return record

    def invalidate(self, owner: str, nas: str, generation: Optional[int]) -> bool:
        """End the session, but only if it is still the one with `generation`.
        A failure reported late by a request on an older login leaves a newer
        login alone. True if a session was removed."""
        key = (owner, nas)
        with self._lock:
            record = self._sessions.get(key)
            if record is None or generation is None or record.generation != generation:
                return False
            del self._sessions[key]
            return True

    def revoke(self, owner: str, nas: Optional[str] = None) -> List[SessionRecord]:
        """End every session of `owner` (or just the one for `nas`), and withdraw
        any sign-in still waiting for, or being made for, the same. A disconnect
        means "no connection", so a login that was running must not complete it
        afterwards. Returns the removed records so their DSM sessions can be ended."""
        with self._lock:
            keys = [k for k in self._sessions if k[0] == owner and (nas is None or k[1] == nas)]
            removed = [self._sessions.pop(k) for k in keys]
            self._withdraw_locked(owner, nas)
            return removed

    def revoke_all(self) -> List[SessionRecord]:
        with self._lock:
            removed = list(self._sessions.values())
            self._sessions.clear()
            self._pending.clear()
            self._attempts.clear()
            return removed

    def take_expired(self) -> List[SessionRecord]:
        """Sessions that ended on a deadline since the last call, so the caller
        can end them on the NAS too. The local copy is already gone."""
        with self._lock:
            self._expire_locked(self._clock())
            taken, self._expired = self._expired, []
            return taken

    def status(self, owner: str) -> Dict[str, Dict[str, object]]:
        """A secret-free view of `owner`'s sessions, by NAS alias."""
        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            view: Dict[str, Dict[str, object]] = {}
            for (record_owner, nas), record in self._sessions.items():
                if record_owner != owner:
                    continue
                view[nas] = {
                    "connected": True,
                    "idle_seconds_left": max(
                        0, int(self._policy.idle_seconds - (now - record.last_used))
                    ),
                    "absolute_seconds_left": max(
                        0, int(self._policy.absolute_seconds - (now - record.created_at))
                    ),
                }
            return view

    def iter_secrets(self) -> Iterator[str]:
        """Every live session id and SynoToken, for the redaction filter."""
        with self._lock:
            records = list(self._sessions.values())
        for record in records:
            yield record.session_id
            if record.syno_token:
                yield record.syno_token

    # -- pending sign-in requests -------------------------------------------

    def begin_pending(self, owner: str, nas: str) -> PendingLogin:
        """Ask for a private sign-in. A request already waiting for this owner
        and NAS is returned as it is, so repeated calls from a model cannot
        produce a stream of prompts or of login attempts."""
        key = (owner, nas)
        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            existing = self._pending.get(key)
            if existing is not None:
                return existing
            pending = PendingLogin(
                request_id=secrets.token_urlsafe(16),
                owner=owner,
                nas=nas,
                created_at=now,
                expires_at=now + self._policy.pending_seconds,
            )
            self._pending[key] = pending
            return pending

    def pending(self, owner: str, nas: str) -> Optional[PendingLogin]:
        with self._lock:
            self._expire_locked(self._clock())
            return self._pending.get((owner, nas))

    def find_pending(self, request_id: str) -> Optional[PendingLogin]:
        """The pending request with this id, if it has not expired."""
        with self._lock:
            self._expire_locked(self._clock())
            for pending in self._pending.values():
                if secrets.compare_digest(pending.request_id, request_id):
                    return pending
            return None

    def cancel_pending(self, owner: str, nas: str) -> bool:
        """Withdraw the request, and with it any attempt that is running for it."""
        with self._lock:
            self._attempts.pop((owner, nas), None)
            return self._pending.pop((owner, nas), None) is not None

    # -- attempts -------------------------------------------------------------

    def begin_attempt(self, request_id: str) -> Tuple[str, Optional[LoginAttempt]]:
        """Claim the pending request `request_id` for one sign-in. Returns
        `(ATTEMPT_STARTED, attempt)`, or `(ATTEMPT_EXPIRED, None)` when there is no
        such live request, or `(ATTEMPT_IN_PROGRESS, None)` when another attempt
        already holds it: a second submission cannot start a second worker for the
        same request, or race the first to install a session."""
        with self._lock:
            self._expire_locked(self._clock())
            for key, pending in self._pending.items():
                if secrets.compare_digest(pending.request_id, request_id):
                    if key in self._attempts:
                        return ATTEMPT_IN_PROGRESS, None
                    attempt_id = next(self._attempt_ids)
                    self._attempts[key] = attempt_id
                    return ATTEMPT_STARTED, LoginAttempt(pending, attempt_id)
            return ATTEMPT_EXPIRED, None

    def release_attempt(self, attempt: LoginAttempt) -> None:
        """Let go of a claim that did not end in a session, so the owner can try
        again. Releases only this attempt's own claim: an old attempt that was
        withdrawn never frees a newer one, and releasing after a success is a no-op."""
        key = (attempt.pending.owner, attempt.pending.nas)
        with self._lock:
            if self._attempts.get(key) == attempt.attempt_id:
                del self._attempts[key]
