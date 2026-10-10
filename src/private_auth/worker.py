# src/private_auth/worker.py - The short-lived process that signs in to DSM.
#
# It is started for one sign-in, receives the account, password and any one-time
# code as a single JSON object on standard input (never in arguments, the
# environment or a file), signs in over verified HTTPS, writes ONE JSON line to
# standard output and exits. That line carries a DSM session and its SynoToken on
# success and only a stable error code on failure; never the password, the code,
# or any message text that could echo them. Standard error is not read and is
# discarded by the caller.
#
# Isolation is the control here, not erasure: Python strings cannot be wiped, so
# what protects the password is that the process lives for seconds, holds one
# copy of it, writes nothing to disk and then ends (plans/2026-10-06-manual-
# authentication/PLAN.md §5.2). A host administrator can still read its memory.

import json
import os
import re
import sys
import tempfile
from typing import Any, Callable, Dict, Optional

MAX_INPUT_BYTES = 64 * 1024
_CODE = re.compile(r"^[A-Za-z0-9_]{1,40}$")
_SAFE_TEXT = re.compile(r"^[\x21-\x7e]{1,2048}$")


def harden() -> None:
    """Make a crash write nothing, and an uncaught exception print nothing."""
    try:
        import resource  # POSIX only

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:  # Windows has no `resource`; crash dumps are a host setting there
        pass
    sys.excepthook = lambda *args: None


def _failure(code: str) -> Dict[str, Any]:
    return {"ok": False, "code": code if _CODE.match(code) else "unknown"}


def validate(payload: Any) -> Optional[Dict[str, Any]]:
    """The request, or None if it is not a well-formed sign-in request."""
    if not isinstance(payload, dict):
        return None
    base_url = payload.get("base_url")
    username = payload.get("username")
    password = payload.get("password")
    otp = payload.get("otp")
    verify = payload.get("verify_ssl", True)
    if not isinstance(base_url, str) or not base_url.lower().startswith("https://"):
        return None
    if not isinstance(username, str) or not username or len(username) > 256:
        return None
    if not isinstance(password, str) or not password or len(password) > 1024:
        return None
    if otp is not None and (not isinstance(otp, str) or not re.fullmatch(r"[0-9]{4,10}", otp)):
        return None
    if not isinstance(verify, (bool, str)):
        return None
    return {
        "base_url": base_url,
        "username": username,
        "password": password,
        "otp": otp or None,
        "verify_ssl": verify,
    }


def run(payload: Any, auth_factory: Optional[Callable[..., Any]] = None) -> Dict[str, Any]:
    """Sign in and return the single result object. Never raises, and the result
    never contains anything but a session, its token, or an error code."""
    request = validate(payload)
    if request is None:
        return _failure("invalid_request")
    try:
        if auth_factory is None:
            from auth.synology_auth import SynologyAuth

            auth_factory = SynologyAuth
        auth = auth_factory(request["base_url"], verify_ssl=request["verify_ssl"], manual_mode=True)
        result = auth.login(request["username"], request["password"], otp_code=request["otp"])
    except Exception:
        return _failure("worker_error")

    if isinstance(result, dict) and result.get("success"):
        data = result.get("data") or {}
        sid = data.get("sid")
        token = data.get("synotoken")
        if not isinstance(sid, str) or not _SAFE_TEXT.match(sid):
            return _failure("worker_error")
        if token is not None and (not isinstance(token, str) or not _SAFE_TEXT.match(token)):
            return _failure("worker_error")
        # Only these two leave the process: nothing reusable (no device token).
        return {"ok": True, "sid": sid, "synotoken": token}

    error = result.get("error") if isinstance(result, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    return _failure(str(code) if code is not None else "unknown")


def _prepare_environment() -> None:
    """Import-time settings for the modules this process loads: manual mode, and
    an empty configuration directory, so it never reads a user's settings file or
    a .env. The caller already sends a minimal environment; this does not rely on
    it."""
    os.environ["SYNOLOGY_AUTH_MODE"] = "broker"
    os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="synology-login-")
    for name in list(os.environ):
        if name.startswith("SYNOLOGY_") and name != "SYNOLOGY_AUTH_MODE":
            del os.environ[name]
    os.environ.pop("AUTO_LOGIN", None)
    src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if src not in sys.path:
        sys.path.insert(0, src)


def main() -> int:
    harden()
    _prepare_environment()
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        payload = json.loads(raw) if len(raw) <= MAX_INPUT_BYTES else None
    except Exception:
        payload = None
    outcome = run(payload)
    sys.stdout.write(json.dumps(outcome) + "\n")
    sys.stdout.flush()
    return 0 if outcome.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
