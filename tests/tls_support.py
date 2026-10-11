"""Throwaway certificates and a real adapter session, for the tests that check the
broker and the adapter over TLS that is actually verified.

Everything is made fresh in a temporary directory and thrown away; none of it
resembles a real key. The certificates satisfy Python 3.13's strict verification
(key identifiers, key usage), so a failure here is about the code under test, not
about how the test certificate was made.
"""

import contextlib
import datetime
import ipaddress
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parent.parent


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _write_key(path, key):
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _make_ca(directory: Path, filename: str, common_name: str):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    path = directory / filename
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert, path


def make_pki(directory: Path, dns=("localhost",), ips=()) -> SimpleNamespace:
    """A private CA, a server certificate it signed for `dns` and `ips`, and a
    second, unrelated CA that did not sign it."""
    directory.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert, ca_path = _make_ca(directory, "ca.pem", "Test CA")
    _other_key, _other_cert, other_path = _make_ca(directory, "other-ca.pem", "Some Other CA")

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    names = [x509.DNSName(n) for n in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(dns[0]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_key(key_path, key)
    os.chmod(key_path, 0o600)
    return SimpleNamespace(ca=ca_path, other_ca=other_path, cert=cert_path, key=key_path)


@contextlib.asynccontextmanager
async def adapter_session(
    workdir: Path,
    broker_url: str,
    *,
    token: str,
    ca_file=None,
    config_name="adapter.json",
    **settings,
):
    """A client session on a real adapter process that reads its token from a
    file (mode 0600) and verifies the broker's certificate against `ca_file`.
    Its standard error goes to `workdir/adapter.err`."""
    workdir.mkdir(parents=True, exist_ok=True)
    token_path = workdir / "broker.token"
    token_path.write_text(token, encoding="utf-8")
    os.chmod(token_path, 0o600)
    config = {
        "broker_url": broker_url,
        "token_file": str(token_path),
        "connect_timeout": 5,
        "list_timeout": 30,
        "call_timeout": 30,
        **settings,
    }
    if ca_file is not None:
        config["ca_file"] = str(ca_file)
    config_path = workdir / config_name
    config_path.write_text(json.dumps(config), encoding="utf-8")
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(ROOT / "adapter_main.py"), "--config", str(config_path)],
        env={},
        cwd=str(workdir),
    )
    with open(workdir / "adapter.err", "w", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
