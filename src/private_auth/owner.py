# src/private_auth/owner.py - Proving that the person at the browser is the owner.
#
# The owner signs in to the private interface with a passkey (WebAuthn) held on a
# trusted device: a phone or laptop that no AI application can operate. The
# broker stores only the passkey's PUBLIC key and a counter, so the file holds
# nothing that could be used to sign in.
#
# Enrollment is a human administration step on the broker host: `broker_main.py
# enroll new-code` prints a one-time code, the owner opens the enrollment page on
# the trusted device, types it, and registers the passkey. Once a passkey exists,
# no further one can be added without running that command again, on the host
# (plans/2026-10-06-manual-authentication/PLAN.md §3.2, §5.1).

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

STATE_TTL_SECONDS = 120
DEFAULT_CODE_MINUTES = 10


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class StoredCredential:
    credential_id: bytes
    public_key: bytes
    sign_count: int
    label: str
    created: str


class OwnerStore:
    """The owner's passkeys, and the pending enrollment code, in one JSON file.

    Written atomically and readable only by the account running the broker where
    the platform supports that. It holds public keys and the hash of a short-lived
    enrollment code, never a secret that grants access.
    """

    def __init__(self, path: Path):
        self._path = Path(path)
        self._lock = threading.RLock()

    def _read(self) -> Dict[str, Any]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"user_id": None, "credentials": [], "enrollment": None}
        if not isinstance(data, dict):
            raise ValueError("the owner store is not a JSON object")
        data.setdefault("credentials", [])
        data.setdefault("enrollment", None)
        data.setdefault("user_id", None)
        return data

    def _write(self, data: Dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(dir=self._path.parent, prefix=".owner-", suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(data, stream, indent=2)
            try:
                os.chmod(temp_name, 0o600)
            except OSError:
                pass
            os.replace(temp_name, self._path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def user_id(self) -> bytes:
        """A stable random handle for the owner, made on first use."""
        with self._lock:
            data = self._read()
            if not data["user_id"]:
                data["user_id"] = _b64(secrets.token_bytes(32))
                self._write(data)
            return _unb64(data["user_id"])

    def credentials(self) -> List[StoredCredential]:
        with self._lock:
            return [
                StoredCredential(
                    _unb64(c["id"]),
                    _unb64(c["public_key"]),
                    int(c["sign_count"]),
                    c.get("label", ""),
                    c.get("created", ""),
                )
                for c in self._read()["credentials"]
            ]

    def add_credential(
        self, credential_id: bytes, public_key: bytes, sign_count: int, label: str
    ) -> None:
        with self._lock:
            data = self._read()
            data["credentials"].append(
                {
                    "id": _b64(credential_id),
                    "public_key": _b64(public_key),
                    "sign_count": sign_count,
                    "label": label,
                    "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            )
            self._write(data)

    def update_sign_count(self, credential_id: bytes, sign_count: int) -> None:
        with self._lock:
            data = self._read()
            for entry in data["credentials"]:
                if entry["id"] == _b64(credential_id):
                    entry["sign_count"] = sign_count
            self._write(data)

    def remove_credential(self, credential_id_b64: str) -> bool:
        with self._lock:
            data = self._read()
            kept = [c for c in data["credentials"] if c["id"] != credential_id_b64]
            if len(kept) == len(data["credentials"]):
                return False
            data["credentials"] = kept
            self._write(data)
            return True

    # -- the one-time enrollment code ---------------------------------------

    def new_enrollment_code(
        self, *, minutes: int = DEFAULT_CODE_MINUTES, allow_additional: bool = False
    ) -> str:
        """Make a one-time code, valid for `minutes`, and return it (the only time
        it exists in clear). Refused if a passkey already exists, unless an
        additional device is being added on purpose."""
        with self._lock:
            data = self._read()
            if data["credentials"] and not allow_additional:
                raise PermissionError(
                    "a passkey is already enrolled; pass --add-device to add another"
                )
            code = secrets.token_urlsafe(9)
            data["enrollment"] = {
                "code_sha256": hashlib.sha256(code.encode()).hexdigest(),
                "expires_at": time.time() + minutes * 60,
            }
            self._write(data)
            return code

    def check_enrollment_code(self, code: str, *, now: Optional[float] = None) -> bool:
        with self._lock:
            enrollment = self._read()["enrollment"]
        if not enrollment or (now if now is not None else time.time()) >= enrollment["expires_at"]:
            return False
        return hmac.compare_digest(
            hashlib.sha256(code.encode()).hexdigest(), enrollment["code_sha256"]
        )

    def enrollment_open(self, *, now: Optional[float] = None) -> bool:
        """Whether an enrollment code exists and has not expired or been used."""
        with self._lock:
            enrollment = self._read()["enrollment"]
        return (
            bool(enrollment)
            and (now if now is not None else time.time()) < enrollment["expires_at"]
        )

    def consume_enrollment_code(self) -> None:
        with self._lock:
            data = self._read()
            data["enrollment"] = None
            self._write(data)


class PasskeyOwnerAuth:
    """Registers and checks the owner's passkey with the `webauthn` library.

    Challenges are single-use and expire after two minutes. User verification
    (a fingerprint, face or device PIN) is required, so possession of the device
    alone is not enough. Every failure is reported as a plain False: the reason
    is never given to the caller.
    """

    def __init__(
        self,
        store: OwnerStore,
        *,
        rp_id: str,
        origin: str,
        rp_name: str = "Synology MCP broker",
        clock: Callable[[], float] = time.monotonic,
    ):
        self._store = store
        self._rp_id = rp_id
        self._origin = origin.rstrip("/")
        self._rp_name = rp_name
        self._clock = clock
        self._challenges: Dict[str, Tuple[bytes, float]] = {}
        self._lock = threading.Lock()

    def has_owner(self) -> bool:
        return bool(self._store.credentials())

    # -- challenge bookkeeping ----------------------------------------------

    def _remember(self, challenge: bytes) -> str:
        state = secrets.token_urlsafe(24)
        now = self._clock()
        with self._lock:
            self._challenges = {k: v for k, v in self._challenges.items() if v[1] > now}
            self._challenges[state] = (challenge, now + STATE_TTL_SECONDS)
        return state

    def _take(self, state: str) -> Optional[bytes]:
        with self._lock:
            challenge, expires = self._challenges.pop(state, (None, 0.0))
        return challenge if challenge is not None and expires > self._clock() else None

    # -- authenticating the owner -------------------------------------------

    def begin_authentication(self) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Options for the browser to sign, or None if no passkey is enrolled."""
        from webauthn import generate_authentication_options, options_to_json
        from webauthn.helpers.structs import (
            PublicKeyCredentialDescriptor,
            UserVerificationRequirement,
        )

        credentials = self._store.credentials()
        if not credentials:
            return None
        options = generate_authentication_options(
            rp_id=self._rp_id,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=c.credential_id) for c in credentials
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return self._remember(options.challenge), json.loads(options_to_json(options))

    def finish_authentication(self, state: str, credential: Dict[str, Any]) -> bool:
        from webauthn import verify_authentication_response

        challenge = self._take(state)
        if challenge is None:
            return False
        try:
            raw_id = _unb64(str(credential.get("rawId") or credential.get("id")))
            stored = next((c for c in self._store.credentials() if c.credential_id == raw_id), None)
            if stored is None:
                return False
            verified = verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=self._rp_id,
                expected_origin=self._origin,
                credential_public_key=stored.public_key,
                credential_current_sign_count=stored.sign_count,
                require_user_verification=True,
            )
        except Exception:
            return False
        self._store.update_sign_count(stored.credential_id, verified.new_sign_count)
        return True

    # -- enrolling a passkey ------------------------------------------------

    def begin_enrollment(self, code: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Options for the browser to create a passkey, if `code` is the valid
        one-time code."""
        from webauthn import generate_registration_options, options_to_json
        from webauthn.helpers.structs import (
            AuthenticatorSelectionCriteria,
            PublicKeyCredentialDescriptor,
            ResidentKeyRequirement,
            UserVerificationRequirement,
        )

        if not self._store.check_enrollment_code(code):
            return None
        options = generate_registration_options(
            rp_id=self._rp_id,
            rp_name=self._rp_name,
            user_name="owner",
            user_id=self._store.user_id(),
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=c.credential_id) for c in self._store.credentials()
            ],
        )
        return self._remember(options.challenge), json.loads(options_to_json(options))

    def finish_enrollment(
        self, state: str, credential: Dict[str, Any], label: str = "passkey"
    ) -> bool:
        from webauthn import verify_registration_response

        challenge = self._take(state)
        # The code is single-use: if another enrollment finished first, or the
        # code has expired since this one began, this one does not count.
        if challenge is None or not self._store.enrollment_open():
            return False
        try:
            verified = verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=self._rp_id,
                expected_origin=self._origin,
                require_user_verification=True,
            )
        except Exception:
            return False
        self._store.add_credential(
            verified.credential_id, verified.credential_public_key, verified.sign_count, label[:64]
        )
        self._store.consume_enrollment_code()
        return True
