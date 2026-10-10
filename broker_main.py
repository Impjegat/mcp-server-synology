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
    python broker_main.py new-token

Run it on the host that holds the policy file and the TLS key, under an
account the AI applications cannot read or administer. See
plans/2026-10-06-manual-authentication/PLAN.md §3.1.
"""

import argparse
import ipaddress
import os
import sys

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


def new_token() -> int:
    from broker.policy import generate_token

    token, digest = generate_token()
    print("Give this token to the client, once, over a private channel:")
    print(f"  {token}")
    print('Put only this digest in the policy file, under the client\'s "token_sha256":')
    print(f"  {digest}")
    return 0


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

    allowed_hosts = list(args.allowed_host) or [f"127.0.0.1:{args.port}", f"localhost:{args.port}"]
    sessions = SessionManager(policy.session)
    runtime = BrokerRuntime(policy, sessions, config.nas_configs, verify_ssl=config.verify_ssl)
    app = create_broker_app(runtime, policy, allowed_hosts=allowed_hosts)

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
        runtime.shutdown()
    return 0


def main(argv=None) -> int:
    _prepare_environment()
    parser = argparse.ArgumentParser(description="Synology MCP broker")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("new-token", help="make a client token and print its digest")

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
        "--allow-plain-http-loopback",
        action="store_true",
        help="allow plain HTTP, on a loopback address only, for local testing",
    )

    args = parser.parse_args(argv)
    return new_token() if args.command == "new-token" else serve(args)


if __name__ == "__main__":
    sys.exit(main())
