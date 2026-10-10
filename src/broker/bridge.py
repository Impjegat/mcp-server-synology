# src/broker/bridge.py - How a tool executor asks the broker for its session.
#
# In broker mode the executor (`SynologyMCPServer`) never holds the authority
# over a session: the broker's session manager does. The executor only asks,
# at the moment it needs one, whether a session currently exists, and tells
# the broker when the NAS says the session is gone. Keeping this a small
# interface means the executor needs no knowledge of owners, deadlines or
# generations, and the legacy single-process mode simply has no bridge.

from dataclasses import dataclass
from typing import Optional, Protocol


@dataclass(frozen=True)
class SessionView:
    """What the executor may know about a session: enough to talk to DSM."""

    session_id: str
    syno_token: Optional[str]
    generation: int

    def __repr__(self) -> str:
        # Never put the session id or token into a log line or a traceback.
        return f"SessionView(generation={self.generation})"


class SessionBridge(Protocol):
    def current(self, base_url: str, *, touch: bool = True) -> Optional[SessionView]:
        """The live session for `base_url`, or None when there is none (never
        signed in, expired, revoked). `touch` counts the call as use for the
        idle deadline; a status check passes False."""

    def lost(self, base_url: str, generation: Optional[int]) -> None:
        """DSM said the session with this `generation` is gone. A session that
        has since been replaced by a newer login is left alone."""

    def close(self, base_url: str, session_id: str, syno_token: Optional[str]) -> bool:
        """End the session on the NAS as well as locally. True when the NAS
        confirmed it, False when that could not be confirmed; the local copy
        is gone either way."""
