#!/usr/bin/env python3
# main.py - Entry point for Synology MCP Server

"""
Synology MCP Server

A Model Context Protocol (MCP) server that provides tools for interacting with Synology NAS devices.
This server enables secure authentication and session management with Synology NAS systems.

Usage:
    python main.py

Configuration:
    All settings are loaded from ~/.config/synology-mcp/settings.json
"""

import asyncio
import logging
import os
import sys

from dotenv import load_dotenv

# Legacy .env support (deprecated - use settings.json instead)
load_dotenv()

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))


def check_requirements():
    """Check if all requirements are met."""
    return []


def setup_logging(level: str = "INFO"):
    """Setup logging configuration.

    Attaches a redaction filter to every handler so session IDs, SynoTokens,
    device tokens, and passwords never reach the log output, however they
    got embedded in a log message (a deliberate log line, or an exception's
    str() picking up a URL that had `_sid=` in it).
    """
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    from auth import iter_all_secrets
    from utils.redact import RedactingFilter

    redacting_filter = RedactingFilter(iter_all_secrets)
    for handler in logging.getLogger().handlers:
        handler.addFilter(redacting_filter)


if __name__ == "__main__":
    from config import config

    # Setup logging
    setup_logging(config.log_level)
    logger = logging.getLogger("synology-mcp")

    logger.info("Starting Synology MCP Server")

    # Check requirements
    errors = check_requirements()
    if errors:
        logger.error("Requirements check failed:")
        for error in errors:
            logger.error(f"  - {error}")
        sys.exit(1)

    logger.info("Requirements check passed")

    try:
        logger.info("Client Support: Claude/Cursor (stdio)")
        logger.info("Starting MCP server... Press Ctrl+C to stop")

        # Import and run standard MCP server
        from mcp_server import main as server_main

        asyncio.run(server_main())

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Server error: {e}")
        logger.debug("Full traceback:", exc_info=True)
        sys.exit(1)
