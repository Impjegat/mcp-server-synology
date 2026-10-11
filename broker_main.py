#!/usr/bin/env python3
# broker_main.py - Entry point for the protected Synology MCP broker.

"""
Synology MCP broker

Serves the Synology tools over authenticated HTTPS to clients that hold no NAS
credentials. It runs in manual-authentication mode only: it never holds a NAS
password, never signs in by itself, and takes its DSM sessions from a private
login that a person completes.

Usage:
    python broker_main.py serve --policy PATH [--host HOST] [--port PORT]
        [--allowed-host NAME[:PORT]]... [--tls-cert FILE --tls-key FILE]
        [--private-origin URL [--private-port PORT] [--owner-store PATH]]
    python broker_main.py new-token
    python broker_main.py enroll {new-code|list|revoke ID} [--owner-store PATH]

Run it on the host that holds the policy file and the TLS key, under an
account the AI applications cannot read or administer. See
plans/2026-10-06-manual-authentication/PLAN.md §3.1.
"""

import argparse
import datetime
import ipaddress
import os
import sys
import time

DEFAULT_POLICY = os.path.join("~", ".config", "synology-mcp", "broker-policy.json")


def _prepare_environment() -> None:
    """Make this process a broker: manual authentication is the only mode the
    entry point runs in, whatever the environment says, and it never reads a
    .env file (no dotenv call is made here). This must happen before anything
    imports `config`, so it runs when the entry point starts, not when the
    module is imported: importing `broker_main` has no side effects."""
    os.environ["SYNOLOGY_AUTH_MODE"] = "broker"
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


DEFAULT_OWNER_STORE = os.path.join("~", ".config", "synology-mcp", "owner.json")


def enroll(args: argparse.Namespace) -> int:
    """Owner passkey administration. Run on the broker host: it needs the owner
    store, which is exactly why an AI application on another machine cannot do it."""
    from private_auth.owner import OwnerStore

    store = OwnerStore(os.path.expanduser(args.owner_store))
    if args.enroll_command == "new-code":
        try:
            code = store.new_enrollment_code(minutes=args.minutes, allow_additional=args.add_device)
        except PermissionError as error:
            print(str(error), file=sys.stderr)
            return 2
        print(f"One-time enrollment code (valid {args.minutes} minutes, works once):")
        print(f"  {code}")
        print("Open the private interface's /enroll page on your trusted device and type it there.")
        return 0
    if args.enroll_command == "list":
        credentials = store.credentials()
        if not credentials:
            print("No passkey is enrolled.")
        for credential in credentials:
            import base64

            ident = base64.urlsafe_b64encode(credential.credential_id).rstrip(b"=").decode()
            print(f"{ident}  {credential.label}  created {credential.created}")
        return 0
    removed = store.remove_credential(args.credential_id)
    print("Removed." if removed else "No such passkey.")
    return 0 if removed else 1


def new_token() -> int:
    from broker.policy import generate_token

    token, digest = generate_token()
    print("Give this token to the client, once, over a private channel:")
    print(f"  {token}")
    print('Put only this digest in the policy file, under the client\'s "token_sha256":')
    print(f"  {digest}")
    ends = datetime.date.today() + datetime.timedelta(days=365)
    print('A grant also says when it ends, at most a year ahead, under the client\'s "expires":')
    print(f'  "expires": "{ends.isoformat()}"')
    return 0


def _private_settings(args: argparse.Namespace):
    """The private login's settings, None if it is not configured, or an exit code
    if they are unsafe. It has its own address, port and TLS: it is never served
    from the MCP listener."""
    if not args.private_origin:
        return None
    from urllib.parse import urlparse

    origin = urlparse(args.private_origin)
    host = args.private_host or args.host
    port = args.private_port
    cert = args.private_tls_cert or args.tls_cert
    key = args.private_tls_key or args.tls_key
    plain_ok = _is_loopback(host) and args.allow_plain_http_loopback
    if bool(cert) != bool(key):
        print("Give both --private-tls-cert and --private-tls-key, or neither.", file=sys.stderr)
        return 2
    if not (cert and key) and not plain_ok:
        print(
            "Refusing to start the private login without TLS: give --private-tls-cert and "
            "--private-tls-key (or --tls-cert and --tls-key). Plain HTTP is for loopback testing only.",
            file=sys.stderr,
        )
        return 2
    if origin.scheme not in ("https", "http") or not origin.hostname:
        print("--private-origin must be a URL such as https://broker.example:8444", file=sys.stderr)
        return 2
    if origin.scheme == "http" and not plain_ok:
        print("--private-origin must be https unless this is loopback testing.", file=sys.stderr)
        return 2
    allowed_hosts = list(args.private_allowed_host) or (
        ["127.0.0.1", "localhost"] if _is_loopback(host) else []
    )
    if not allowed_hosts:
        print(
            "A private login that is not on loopback needs --private-allowed-host.", file=sys.stderr
        )
        return 2
    return {
        "host": host,
        "port": port,
        "cert": cert,
        "key": key,
        "origin": args.private_origin.rstrip("/"),
        "rp_id": args.rp_id or origin.hostname,
        "allowed_hosts": allowed_hosts,
        "store": os.path.expanduser(args.owner_store),
        "secure_cookies": origin.scheme == "https",
    }


def _start_private_login(runtime, private, logger):
    """Run the private login on its own port, in a background thread, and return
    `(server, thread)`. Its sessions, passkeys and attempt limits live only in
    this process; it shares nothing with the MCP listener but the broker's own
    session manager."""
    import threading

    import uvicorn

    from private_auth.app import create_private_app
    from private_auth.login import LoginService
    from private_auth.owner import OwnerStore, PasskeyOwnerAuth

    owner = PasskeyOwnerAuth(
        OwnerStore(private["store"]), rp_id=private["rp_id"], origin=private["origin"]
    )
    app = create_private_app(
        runtime,
        LoginService(runtime),
        owner,
        allowed_origins=[private["origin"]],
        allowed_hosts=private["allowed_hosts"],
        secure_cookies=private["secure_cookies"],
    )
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=private["host"],
            port=private["port"],
            ssl_certfile=private["cert"],
            ssl_keyfile=private["key"],
            log_config=None,
        )
    )
    thread = threading.Thread(target=server.run, name="private-login", daemon=True)
    thread.start()
    logger.info(
        "The private login is on %s:%s (origin %s)",
        private["host"],
        private["port"],
        private["origin"],
    )
    return server, thread


def serve(args: argparse.Namespace) -> int:
    import logging

    import uvicorn

    from broker.policy import PolicyError, load_policy
    from broker.runtime import BrokerRuntime
    from broker.server import create_broker_app
    from broker.sessions import SessionManager
    from config import config
    from mcp_server import SynologyMCPServer

    loopback = _is_loopback(args.host)
    has_tls = bool(args.tls_cert and args.tls_key)
    if bool(args.tls_cert) != bool(args.tls_key):
        print("Give both --tls-cert and --tls-key, or neither.", file=sys.stderr)
        return 2
    if not has_tls and not (loopback and args.allow_plain_http_loopback):
        print(
            "Refusing to start without TLS. Give --tls-cert and --tls-key. Plain HTTP is only "
            "for local testing: bind to a loopback address and pass --allow-plain-http-loopback.",
            file=sys.stderr,
        )
        return 2
    if not loopback and not args.allowed_host:
        print(
            "A broker that is not on loopback needs at least one --allowed-host.", file=sys.stderr
        )
        return 2

    private = _private_settings(args)
    if isinstance(private, int):
        return private

    import main as entry

    entry.setup_logging(config.log_level)
    logger = logging.getLogger("synology-broker")

    errors = config.validate_config()
    if errors:
        print("Configuration errors: " + "; ".join(errors), file=sys.stderr)
        return 2

    known_tools = set(SynologyMCPServer()._tool_registry)
    try:
        policy = load_policy(
            os.path.expanduser(args.policy),
            known_nas=config.get_nas_names(),
            known_tools=known_tools,
        )
    except PolicyError as error:
        print(f"Policy error: {error}", file=sys.stderr)
        return 2
    # A grant that has ended is refused, and one about to end is worth a word now
    # rather than a client's first refusal. These name the client, never its token.
    for note in policy.grant_warnings(time.time()):
        logger.warning(note)

    allowed_hosts = list(args.allowed_host) or [f"127.0.0.1:{args.port}", f"localhost:{args.port}"]
    sessions = SessionManager(policy.session)
    runtime = BrokerRuntime(policy, sessions, config.nas_configs, verify_ssl=config.verify_ssl)
    app = create_broker_app(runtime, policy, allowed_hosts=allowed_hosts)
    private_server = _start_private_login(runtime, private, logger) if private else None
    if private is None:
        logger.warning(
            "No private login is configured (no --private-origin): sessions cannot be signed in "
            "to, so every NAS call will ask for authentication."
        )

    logger.info(
        "Starting the broker on %s:%s for %d client(s); sessions end after %ds idle or %ds in all",
        args.host,
        args.port,
        len(policy.clients),
        policy.session.idle_seconds,
        policy.session.absolute_seconds,
    )
    try:
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            ssl_certfile=args.tls_cert,
            ssl_keyfile=args.tls_key,
            # Use the logging already set up, which redacts secrets.
            log_config=None,
        )
    finally:
        if private_server is not None:
            private_server[0].should_exit = True
            private_server[1].join(10)
        runtime.shutdown()
    return 0


def main(argv=None) -> int:
    _prepare_environment()
    parser = argparse.ArgumentParser(description="Synology MCP broker")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("new-token", help="make a client token and print its digest")

    enroll_parser = commands.add_parser(
        "enroll", help="manage the owner's passkey (run on the host)"
    )
    enroll_parser.add_argument("--owner-store", default=DEFAULT_OWNER_STORE)
    enroll_commands = enroll_parser.add_subparsers(dest="enroll_command", required=True)
    new_code = enroll_commands.add_parser("new-code", help="print a one-time enrollment code")
    new_code.add_argument("--minutes", type=int, default=10)
    new_code.add_argument("--add-device", action="store_true", help="allow adding another passkey")
    enroll_commands.add_parser("list", help="list enrolled passkeys")
    revoke = enroll_commands.add_parser("revoke", help="remove an enrolled passkey")
    revoke.add_argument("credential_id")

    serve_parser = commands.add_parser("serve", help="run the broker")
    serve_parser.add_argument("--policy", default=DEFAULT_POLICY, help="path of the policy file")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8443)
    serve_parser.add_argument(
        "--allowed-host",
        action="append",
        default=[],
        help="a Host header value clients may use (repeatable), e.g. broker.example:8443",
    )
    serve_parser.add_argument("--tls-cert")
    serve_parser.add_argument("--tls-key")
    serve_parser.add_argument(
        "--private-origin",
        help="enable the private login, reached at this origin (e.g. https://broker.example:8444)",
    )
    serve_parser.add_argument(
        "--private-host", help="bind address for the private login (default: --host)"
    )
    serve_parser.add_argument("--private-port", type=int, default=8444)
    serve_parser.add_argument(
        "--private-allowed-host",
        action="append",
        default=[],
        help="a Host header the private login accepts",
    )
    serve_parser.add_argument("--private-tls-cert")
    serve_parser.add_argument("--private-tls-key")
    serve_parser.add_argument(
        "--rp-id", help="WebAuthn relying-party id (default: the origin's host)"
    )
    serve_parser.add_argument("--owner-store", default=DEFAULT_OWNER_STORE)
    serve_parser.add_argument(
        "--allow-plain-http-loopback",
        action="store_true",
        help="allow plain HTTP, on a loopback address only, for local testing",
    )

    args = parser.parse_args(argv)
    if args.command == "new-token":
        return new_token()
    if args.command == "enroll":
        return enroll(args)
    return serve(args)


if __name__ == "__main__":
    sys.exit(main())
