"""A fake DSM over real TLS, for exercising the sign-in worker for real.

It serves one endpoint, /webapi/auth.cgi, over HTTPS with a self-signed
certificate made for the test, so the worker's certificate verification (against
that certificate as the CA) is the real thing. It records every request line and
form body so a test can show where the password travelled and where it did not.
"""

import datetime
import ipaddress
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_certificate(directory: Path):
    """A self-signed certificate valid for 127.0.0.1, written as PEM files."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake-dsm.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "dsm-cert.pem", directory / "dsm-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class FakeDsmServer:
    """HTTPS fake of DSM's login endpoint. `accounts` maps name -> password;
    `otp_accounts` maps name -> the current one-time code."""

    def __init__(self, directory: Path, accounts=None, otp_accounts=None):
        self.accounts = dict(accounts or {})
        self.otp_accounts = dict(otp_accounts or {})
        self.requests = []  # (method, path-with-query, form dict)
        self.cert_path, key_path = make_certificate(directory)
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep test output quiet
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                form = {k: v[-1] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
                owner.requests.append(("POST", self.path, form))
                self._reply(
                    owner._login(form) if form.get("method") == "login" else {"success": True}
                )

            def do_GET(self):
                owner.requests.append(("GET", self.path, {}))
                self._reply({"success": False, "error": {"code": 101}})

            def _reply(self, payload):
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.cert_path), str(key_path))
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def _login(self, form):
        account, password = form.get("account"), form.get("passwd")
        if self.accounts.get(account) != password:
            return {"success": False, "error": {"code": 400}}
        if account in self.otp_accounts:
            if not form.get("otp_code"):
                return {"success": False, "error": {"code": 403}}
            if form["otp_code"] != self.otp_accounts[account]:
                return {"success": False, "error": {"code": 404}}
        data = {"sid": "FAKE-SID-from-dsm", "synotoken": "FAKE-TOKEN-from-dsm"}
        if form.get("enable_device_token") == "yes":
            data["did"] = "FAKE-DEVICE-TOKEN"
        return {"success": True, "data": data}

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
