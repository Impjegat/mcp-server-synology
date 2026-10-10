# src/broker/errors.py - Stable, value-free errors shared by every service module.
#
# In manual (broker) authentication mode the server never holds a password, so
# it cannot renew a lost DSM session by itself. Instead of returning a raw DSM
# error code that looks like a bug, the service layer raises
# `AuthenticationRequired`: a typed error whose message tells the caller to
# have the user sign in privately. None of these messages ever carry a
# submitted value, a session id or a token.

from typing import Any, Optional

# DSM codes that mean "this session is gone", as opposed to "this session is
# not allowed to do that" (105) or an error specific to one API:
#   106  session timeout
#   107  session interrupted by a duplicate login
#   119  SID not found
SESSION_LOST_CODES = frozenset({106, 107, 119})

AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"

_AUTHENTICATION_REQUIRED_MESSAGE = (
    f"{AUTHENTICATION_REQUIRED}: this NAS has no active session. Ask the user to sign in "
    "through the private login page. Never ask for, or accept, the NAS password or a "
    "verification code in chat or in a tool call."
)


def is_session_lost(code: Any) -> bool:
    """Whether a DSM error `code` (an int, or the string form some APIs use)
    says the session no longer exists."""
    try:
        return int(code) in SESSION_LOST_CODES
    except (TypeError, ValueError):
        return False


class AuthenticationRequired(Exception):  # noqa: N818
    """No usable DSM session exists, and a new private login is needed."""

    code = AUTHENTICATION_REQUIRED

    def __init__(self, message: Optional[str] = None):
        super().__init__(message or _AUTHENTICATION_REQUIRED_MESSAGE)


class AuthorizationDenied(Exception):  # noqa: N818
    """The request is not permitted by policy, whatever the session state."""

    code = AUTHORIZATION_DENIED

    def __init__(self, message: Optional[str] = None):
        super().__init__(message or f"{AUTHORIZATION_DENIED}: this operation is not permitted.")
