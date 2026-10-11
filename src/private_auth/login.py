# src/private_auth/login.py - Runs one private sign-in, end to end.
#
# The owner has passed the passkey check and filled in the login form. This
# checks that the request they are answering is still pending, counts attempts so
# that a typo cannot get the account locked or the address blocked by DSM, hands
# the credentials to a short-lived worker process over a pipe, and gives the
# session the worker returns to the broker. The password, the code and any
# message text that could echo them never leave this module: outcomes are stable
# codes and fixed sentences.

import asyncio
import json
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional

from broker.errors import RedirectRefused
from broker.runtime import BrokerRuntime
from broker.sessions import ATTEMPT_IN_PROGRESS, LoginAttempt, PendingLogin
from private_auth.security import RateLimiter

Runner = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]

WORKER_PATH = Path(__file__).with_name("worker.py")
DEFAULT_DEADLINE_SECONDS = 25.0

# Outcomes that show the NAS did not get a wrong credential, so they do not count
# towards the attempt limit: asking for a code, an unreachable NAS, a certificate
# we refused before sending anything, a redirect we refused to follow.
_NOT_COUNTED = {
    "403",
    "certificate_error",
    "connection_timeout",
    "connection_error",
    "timeout",
    "redirect_refused",
}

_MESSAGES = {
    "400": "The NAS did not accept that account or password.",
    "401": "That account is disabled on the NAS.",
    "402": "That account is not allowed to sign in (permission denied).",
    "403": "A verification code is required. Enter the current code and try again.",
    "404": "The verification code was not accepted. Wait for the next code and try again.",
    "406": "The NAS requires two-factor authentication for this account, and it is not set up.",
    "407": "The NAS has blocked this address after failed attempts. Wait, or unblock it in DSM.",
    "408": "The account's password has expired. Change it in DSM first.",
    "409": "The account's password has expired. Change it in DSM first.",
    "410": "The account's password must be changed in DSM first.",
    "certificate_error": "The NAS's certificate could not be verified, so nothing was sent.",
    "redirect_refused": str(RedirectRefused()),
    "connection_timeout": "The NAS could not be reached in time.",
    "connection_error": "The NAS could not be reached.",
    "timeout": "The NAS did not answer in time.",
    "invalid_request": "The sign-in details were not valid.",
    "username_required": "Enter the NAS account name.",
}
_GENERIC_FAILURE = "The sign-in did not complete."
_IN_PROGRESS = "A sign-in for this request is already in progress. Wait for it to finish."
_WITHDRAWN = (
    "This sign-in request was cancelled or expired before it finished, so the session "
    "was not used. Ask for a new one."
)
_SAFE_CODE = re.compile(r"^[A-Za-z0-9_]{1,40}$")
_SAFE_VALUE = re.compile(r"^[\x21-\x7e]{1,2048}$")


@dataclass(frozen=True)
class LoginOutcome:
    ok: bool
    code: str
    message: str


def _minimal_environment() -> Dict[str, str]:
    """What the worker may inherit: where to find things and how to verify TLS,
    and nothing else.

    The certificate-trust settings are kept because a NAS behind a private CA
    depends on them, exactly as the rest of this project does (they name files,
    not secrets). Dropped on purpose: every SYNOLOGY_* setting and any credential,
    whatever this process was started with, and proxy settings, because the worker
    talks straight to the NAS and a proxy would see the password's TLS endpoint
    and could be pointed anywhere by the environment. A NAS reachable only through
    a proxy needs the proxy to be transparent."""
    keep = (
        "PATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    )
    env = {name: os.environ[name] for name in keep if name in os.environ}
    env["SYNOLOGY_AUTH_MODE"] = "broker"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


async def run_worker(
    payload: Dict[str, Any], *, deadline: float = DEFAULT_DEADLINE_SECONDS
) -> Dict[str, Any]:
    """Run the worker for one sign-in and return its result object.

    The credentials go in on standard input only. Standard error is discarded.
    The worker is killed if it outlives `deadline`, and a result that is not the
    expected shape is treated as a failure.
    """
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-I",
        str(WORKER_PATH),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env=_minimal_environment(),
        cwd=tempfile.gettempdir(),
    )
    try:
        stdout, _ = await asyncio.wait_for(
            process.communicate(json.dumps(payload).encode("utf-8")), timeout=deadline
        )
    except asyncio.TimeoutError:
        return {"ok": False, "code": "timeout"}
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    return parse_worker_output(stdout)


def parse_worker_output(stdout: bytes) -> Dict[str, Any]:
    """The worker's one JSON line, checked: a session (two safe strings) or a
    safe error code. Anything else is a failure, never passed on."""
    try:
        line = [ln for ln in stdout.decode("utf-8", "replace").splitlines() if ln.strip()][-1]
        data = json.loads(line)
    except Exception:
        return {"ok": False, "code": "worker_error"}
    if not isinstance(data, dict):
        return {"ok": False, "code": "worker_error"}
    if data.get("ok") is True:
        sid, token = data.get("sid"), data.get("synotoken")
        if not isinstance(sid, str) or not _SAFE_VALUE.match(sid):
            return {"ok": False, "code": "worker_error"}
        if token is not None and (not isinstance(token, str) or not _SAFE_VALUE.match(token)):
            return {"ok": False, "code": "worker_error"}
        return {"ok": True, "sid": sid, "synotoken": token}
    code = data.get("code")
    return {
        "ok": False,
        "code": code if isinstance(code, str) and _SAFE_CODE.match(code) else "unknown",
    }


class LoginService:
    def __init__(
        self,
        runtime: BrokerRuntime,
        *,
        runner: Optional[Runner] = None,
        deadline: float = DEFAULT_DEADLINE_SECONDS,
        limiter: Optional[RateLimiter] = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._runtime = runtime
        self._deadline = deadline
        self._runner = runner or (lambda payload: run_worker(payload, deadline=deadline))
        # Three wrong answers in five minutes locks that client and NAS for ten:
        # well inside what DSM's own auto-block tolerates.
        self._limiter = limiter or RateLimiter(3, 300, lockout_seconds=600, clock=clock)

    @staticmethod
    def _key(pending: PendingLogin) -> str:
        return f"{pending.owner}\x00{pending.nas}"

    def account_for(self, nas: str) -> str:
        """The account the NAS is signed in as, from the broker's configuration.
        Empty means it is not configured and the owner types it."""
        return str(self._runtime.nas_config(nas).get("username") or "")

    def locked_for(self, pending: PendingLogin) -> int:
        """Seconds the owner must wait before trying again; 0 if not locked."""
        return self._limiter.retry_after(self._key(pending))

    async def attempt(
        self,
        pending: PendingLogin,
        *,
        password: str,
        otp: Optional[str] = None,
        username: Optional[str] = None,
    ) -> LoginOutcome:
        """Sign in for `pending`. The account is the configured one; only if none
        is configured is a typed one used. Never raises.

        The request is claimed for the whole attempt. Whatever the outcome (a wrong
        password, an exception, the handler being cancelled) the claim is released,
        so the owner can try again; a request that is withdrawn while the worker
        runs (cancelled, expired, replaced, or its client disconnected) has no claim
        left to adopt the worker's session with."""
        status, claim = self._runtime.sessions.begin_attempt(pending.request_id)
        if status == ATTEMPT_IN_PROGRESS:
            return LoginOutcome(False, "in_progress", _IN_PROGRESS)
        if claim is None:  # the request is gone: unknown, expired, cancelled or replaced
            return LoginOutcome(
                False, "expired_request", "This sign-in request has expired. Ask for a new one."
            )
        try:
            return await self._attempt_claimed(claim, password=password, otp=otp, username=username)
        finally:
            self._runtime.sessions.release_attempt(claim)

    async def _attempt_claimed(
        self,
        claim: LoginAttempt,
        *,
        password: str,
        otp: Optional[str],
        username: Optional[str],
    ) -> LoginOutcome:
        pending = claim.pending
        wait = self.locked_for(pending)
        if wait:
            minutes = max(1, (wait + 59) // 60)
            return LoginOutcome(
                False,
                "locked",
                f"Too many attempts. Wait about {minutes} minute(s) before trying again.",
            )

        account = self.account_for(pending.nas) or (username or "").strip()
        if not account:
            return LoginOutcome(False, "username_required", _MESSAGES["username_required"])

        cfg = self._runtime.nas_config(pending.nas)
        payload = {
            "base_url": cfg["base_url"],
            "verify_ssl": cfg.get("verify_ssl", True),
            "username": account,
            "password": password,
            "otp": (otp or "").strip() or None,
        }
        try:
            result = await self._runner(payload)
        except Exception:
            result = {"ok": False, "code": "worker_error"}
        finally:
            payload.clear()

        if result.get("ok") is True:
            sid, token = result["sid"], result.get("synotoken")
            try:
                adopted = self._runtime.install_login_for_attempt(claim, sid, token)
            except KeyError:  # the client may no longer use this NAS
                adopted = None
            if adopted is None:
                # The sign-in worked on the NAS, but nobody wants it any more. It
                # is never installed, and the NAS is told to end it. That is not a
                # wrong password, so it does not count against the attempt limit.
                self._runtime.end_unadopted_session(pending.owner, pending.nas, sid, token)
                return LoginOutcome(False, "request_withdrawn", _WITHDRAWN)
            self._limiter.reset(self._key(pending))
            return LoginOutcome(True, "connected", "Connected.")

        code = str(result.get("code", "unknown"))
        if code not in _NOT_COUNTED:
            self._limiter.record(self._key(pending))
        return LoginOutcome(False, code, _MESSAGES.get(code, _GENERIC_FAILURE))
