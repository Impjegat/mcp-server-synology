"""A software passkey for tests: does what a phone or laptop authenticator does
(creates a P-256 credential with "none" attestation, signs assertions, counts),
so the real `webauthn` verification runs end to end without a browser."""

import base64
import hashlib
import json
import os
from typing import Any, Dict

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SoftwareAuthenticator:
    def __init__(self, rp_id: str, origin: str, *, user_verified: bool = True):
        self.rp_id = rp_id
        self.origin = origin
        self.user_verified = user_verified
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0

    def _flags(self, extra: int = 0) -> int:
        return FLAG_UP | (FLAG_UV if self.user_verified else 0) | extra

    def _client_data(self, kind: str, challenge: str, origin: str = None) -> bytes:
        return json.dumps(
            {
                "type": kind,
                "challenge": challenge,
                "origin": origin or self.origin,
                "crossOrigin": False,
            }
        ).encode()

    def _cose_key(self) -> bytes:
        numbers = self.private_key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    def create(self, options: Dict[str, Any], *, origin: str = None) -> Dict[str, Any]:
        """The response a browser sends after navigator.credentials.create()."""
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        credential_data = (
            bytes(16)
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id
            + self._cose_key()
        )
        auth_data = (
            rp_hash
            + bytes([self._flags(FLAG_AT)])
            + self.sign_count.to_bytes(4, "big")
            + credential_data
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        return {
            "id": b64(self.credential_id),
            "rawId": b64(self.credential_id),
            "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": b64(client_data),
                "attestationObject": b64(attestation),
                "transports": [],
            },
        }

    def get(
        self, options: Dict[str, Any], *, origin: str = None, rp_id: str = None, count: int = None
    ) -> Dict[str, Any]:
        """The response a browser sends after navigator.credentials.get()."""
        self.sign_count = self.sign_count + 1 if count is None else count
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode()).digest()
        auth_data = rp_hash + bytes([self._flags()]) + self.sign_count.to_bytes(4, "big")
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        signature = self.private_key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": b64(self.credential_id),
            "rawId": b64(self.credential_id),
            "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": b64(client_data),
                "authenticatorData": b64(auth_data),
                "signature": b64(signature),
                "userHandle": None,
            },
        }
