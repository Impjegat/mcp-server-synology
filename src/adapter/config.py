# src/adapter/config.py - What the credential-free adapter is told.
#
# The adapter runs on the same computer as the AI application and forwards its
# requests to the broker. It holds no NAS password, one-time code, session or
# device token, and its configuration has no place to put one. All it needs is
# where the broker is, how to trust its certificate, and a reference to this
# client's broker token (the bearer token the broker's policy recognises).
#
# The token is the client's own grant, which the plan allows an AI-side process
# to hold, but it is still referenced, never written into the file: a path to a
# file that holds it, or the name of an environment variable. Nothing in this
# module imports the server, the NAS modules or the project's `config`, so the
# adapter cannot fall back to signing in by itself
# (plans/2026-10-06-manual-authentication/PLAN.md §3, §6.1).

import ipaddress
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlparse

DEFAULT_CONFIG_NAME = "adapter.json"
CONFIG_ENV = "SYNOLOGY_ADAPTER_CONFIG"

# Settings that would put a NAS credential, or the adapter's own token, where an AI
# application can read it. Refused if found in the environment of the adapter
# process: a registration that still carries one is exactly what manual
# authentication removes.
PROHIBITED_ENVIRONMENT = ("SYNOLOGY_PASSWORD", "SYNOLOGY_OTP_CODE", "SYNOLOGY_DEVICE_ID")

_KEYS = {
    "broker_url",
    "ca_file",
    "token_file",
    "token_env",
    "connect_timeout",
    "list_timeout",
    "call_timeout",
    "allow_insecure_loopback",
    "server_name",
}
_SECRET_LOOKING = re.compile(
    r"(token|password|passwd|secret|otp|sid|cookie|session|bearer|device)", re.I
)
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_TOKEN_SHAPE = re.compile(r"^[\x21-\x7e]{16,4096}$")


class AdapterConfigError(ValueError):
    """The adapter's configuration is unusable. Messages name the setting and
    never a value."""


class MalformedTokenError(ValueError):
    """A token is present but is not shaped like one. Carries no value."""


@dataclass(frozen=True)
class AdapterSettings:
    broker_url: str
    ca_file: Optional[str] = None
    token_file: Optional[str] = None
    token_env: Optional[str] = None
    # How long to wait to establish the TCP and TLS connection, so a host that is
    # down is reported in seconds. The two limits below are overall: they bound a
    # whole operation, connecting and the MCP handshake included.
    connect_timeout: float = 5.0
    list_timeout: float = 30.0
    # Searches on the NAS can run for two minutes; the broker bounds them too.
    call_timeout: float = 180.0
    allow_insecure_loopback: bool = False
    server_name: str = "synology"

    def __repr__(self) -> str:
        return f"AdapterSettings(server_name={self.server_name!r})"


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AdapterConfigError(message)


def _number(data: Mapping[str, Any], key: str, default: float, low: float, high: float) -> float:
    value = data.get(key, default)
    _expect(
        isinstance(value, (int, float)) and not isinstance(value, bool) and low <= value <= high,
        f"{key}: must be a number of seconds between {low:g} and {high:g}",
    )
    return float(value)


def parse_settings(data: Any) -> AdapterSettings:
    """Validate a decoded configuration. Every refusal names the setting and never
    its value, so a mistake in the file cannot put a secret in an error message."""
    _expect(isinstance(data, dict), "the adapter configuration must be a JSON object")
    for key in data:
        _expect(
            key in _KEYS,
            f"unknown setting '{key}'"
            + (
                " (the adapter holds no NAS credential and no token; a token is given as a "
                "file or an environment-variable name)"
                if _SECRET_LOOKING.search(str(key))
                else ""
            ),
        )

    url = data.get("broker_url")
    _expect(isinstance(url, str) and url, "broker_url: required")
    parsed = urlparse(url)
    _expect(
        parsed.scheme in ("https", "http") and bool(parsed.hostname),
        "broker_url: must be an https URL",
    )
    _expect(
        not parsed.username and not parsed.password and "@" not in parsed.netloc,
        "broker_url: must not contain a user name or password",
    )
    _expect(
        not parsed.query and not parsed.fragment, "broker_url: must not contain a query or fragment"
    )
    insecure = data.get("allow_insecure_loopback", False)
    _expect(isinstance(insecure, bool), "allow_insecure_loopback: must be true or false")
    if parsed.scheme == "http":
        _expect(
            insecure and _is_loopback(parsed.hostname or ""),
            "broker_url: plain http is allowed only to a loopback address with allow_insecure_loopback",
        )
    path = parsed.path.rstrip("/") or "/mcp"
    normalised = f"{parsed.scheme}://{parsed.netloc}{path}"

    token_file, token_env = data.get("token_file"), data.get("token_env")
    _expect(
        (token_file is None) != (token_env is None),
        "give exactly one of token_file and token_env",
    )
    if token_file is not None:
        _expect(isinstance(token_file, str) and token_file, "token_file: must be a path")
    if token_env is not None:
        _expect(
            isinstance(token_env, str) and _ENV_NAME.match(token_env) is not None,
            "token_env: must be the name of an environment variable",
        )
        _expect(
            token_env not in PROHIBITED_ENVIRONMENT,
            "token_env: must not be a NAS credential setting",
        )

    ca_file = data.get("ca_file")
    if ca_file is not None:
        _expect(isinstance(ca_file, str) and ca_file, "ca_file: must be a path")
        _expect(Path(ca_file).is_file(), "ca_file: no such file")

    name = data.get("server_name", "synology")
    _expect(
        isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name) is not None,
        "server_name: invalid",
    )

    return AdapterSettings(
        broker_url=normalised,
        ca_file=ca_file,
        token_file=token_file,
        token_env=token_env,
        connect_timeout=_number(data, "connect_timeout", 5.0, 1, 60),
        list_timeout=_number(data, "list_timeout", 30.0, 1, 600),
        call_timeout=_number(data, "call_timeout", 180.0, 1, 900),
        allow_insecure_loopback=insecure,
        server_name=name,
    )


def default_config_path(environ: Mapping[str, str] = os.environ) -> Path:
    """Where the configuration is looked for when none is named. Resolved here,
    lazily, so the home directory is only consulted when it is needed."""
    named = environ.get(CONFIG_ENV)
    if named:
        return Path(named).expanduser()
    base = environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "synology-mcp" / DEFAULT_CONFIG_NAME


def load_settings(path: Path) -> AdapterSettings:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise AdapterConfigError(f"the configuration file {path} does not exist") from None
    except (OSError, ValueError) as error:
        raise AdapterConfigError(
            f"the configuration file {path} cannot be read as JSON: {type(error).__name__}"
        ) from None
    return parse_settings(data)


def prohibited_environment(environ: Mapping[str, str] = os.environ) -> list:
    """The names (never the values) of any NAS-credential settings present in the
    environment of this process."""
    return [name for name in PROHIBITED_ENVIRONMENT if environ.get(name)]


def make_token_provider(
    settings: AdapterSettings, environ: Mapping[str, str] = os.environ
) -> Callable[[], Optional[str]]:
    """A function returning this client's broker token, or None if there is none to
    be had (no file, no variable, or nothing in it). A token that is there but
    malformed raises `MalformedTokenError`, so the two can be told apart. A file is read
    each time, so a token can be replaced without restarting the AI application."""

    def provider() -> Optional[str]:
        if settings.token_env is not None:
            raw = environ.get(settings.token_env)
        else:
            try:
                raw = Path(settings.token_file or "").expanduser().read_text(encoding="utf-8")
            except OSError:
                return None
        token = (raw or "").strip()
        if not token:
            return None
        if not _TOKEN_SHAPE.match(token):
            raise MalformedTokenError()
        return token

    return provider


def token_file_warning(settings: AdapterSettings) -> Optional[str]:
    """A warning if the token file can be read by other accounts, or None. The
    token is this client's own grant, not a NAS secret, but it should still be
    private to the account that runs the application. Only where file modes mean
    something (not Windows, whose permissions are ACLs); never reads the file."""
    if settings.token_file is None or os.name == "nt":
        return None
    try:
        mode = Path(settings.token_file).expanduser().stat().st_mode & 0o777
    except OSError:
        return None
    return _mode_warning(settings.token_file, mode)


def _mode_warning(token_file: str, mode: int) -> Optional[str]:
    if mode & 0o077:
        return (
            f"The token file {token_file} is readable by other accounts "
            f"(mode {mode:04o}); restrict it to its owner, for example chmod 600."
        )
    return None
