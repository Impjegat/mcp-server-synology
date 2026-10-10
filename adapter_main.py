#!/usr/bin/env python3
# adapter_main.py - Entry point for the credential-free Synology MCP adapter.

"""
Synology MCP adapter

A local stdio MCP server for an AI application to launch. It forwards every tool
list and tool call to the Synology broker over HTTPS with this client's broker
token, and returns what the broker answers. It holds no NAS password, no
one-time code, no session and no device token, never signs in by itself, and
has no fallback: if the broker cannot be reached, the model is told so.

Usage (in the application's MCP registration):
    python adapter_main.py [--config PATH]

Configuration is a small JSON file (default ~/.config/synology-mcp/adapter.json,
or the path in SYNOLOGY_ADAPTER_CONFIG) naming the broker's address, how to trust
its certificate and where this client's token is kept. See
plans/2026-10-06-manual-authentication/PLAN.md §3 and §6.1.
"""

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path


def _prepare() -> None:
    """Make `src` importable. Done when the entry point starts, not when the
    module is imported, so importing it has no side effects."""
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _setup_logging(client) -> None:
    """Log to standard error only: standard output belongs to the protocol, and
    a stray byte on it would corrupt the stream. The broker token is masked from
    every line."""
    from utils.redact import RedactingFilter

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    handler.addFilter(RedactingFilter(client.known_secrets))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    for noisy in ("httpx", "httpx2", "httpcore", "httpcore2", "mcp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


async def _serve(server) -> None:
    import mcp.server.stdio
    from mcp.server import NotificationOptions

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options(NotificationOptions())
        )


def main(argv=None) -> int:
    _prepare()
    from adapter.client import BrokerClient
    from adapter.config import (
        AdapterConfigError,
        default_config_path,
        load_settings,
        make_token_provider,
        prohibited_environment,
    )
    from adapter.server import build_adapter_server

    parser = argparse.ArgumentParser(description="Synology MCP adapter")
    parser.add_argument("--config", help="path of the adapter configuration file")
    args = parser.parse_args(argv)

    present = prohibited_environment()
    if present:
        print(
            "The adapter holds no NAS credentials, and its environment has: "
            + ", ".join(present)
            + ". It does not use them, and a credential in an application's registration is "
            "exactly what manual authentication removes. Delete them from the registration.",
            file=sys.stderr,
        )
        return 2

    path = Path(args.config).expanduser() if args.config else default_config_path()
    try:
        settings = load_settings(path)
    except AdapterConfigError as error:
        print(f"Adapter configuration error: {error}", file=sys.stderr)
        return 2

    client = BrokerClient(settings, make_token_provider(settings))
    _setup_logging(client)
    logging.getLogger("synology-adapter").info(
        "Starting the adapter (the broker is contacted on use)"
    )
    try:
        asyncio.run(_serve(build_adapter_server(client, name=settings.server_name)))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
