# src/broker/policy.py - What each broker client may do.
#
# The administrator writes one policy file on the broker host. It names each
# client and lists, for that client, the NAS aliases it may use, the tools it
# may call and the folder roots it may reach, plus the session deadlines. It is
# read once at startup and never changed by a request, and nothing a client
# sends can enlarge it (plans/2026-10-06-manual-authentication/PLAN.md §3.2,
# §6.2).
#
# The file holds only a SHA-256 digest of each client's bearer token, never the
# token. A file that looks as if it contains a token, a password or anything
# else unrecognised is rejected rather than half-read: a typo in a security
# policy must fail closed.
#
# Each client's entry also says when its grant ends (`expires`, at most a year
# ahead), and the broker stops honouring the token then. That is the lifetime
# of the grant that may call the broker's tools. It is not a DSM session's
# deadline, which is `session` below and which a renewal never extends: renewing
# a grant means editing this file and restarting the broker, and a restart ends
# every session, because they live only in memory.

import datetime as _datetime
import hashlib
import hmac
import json
import math
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

from mcp.server.auth.provider import AccessToken

from broker.file_policy import FolderPolicy


class PolicyError(ValueError):
    """The policy file is invalid. Messages name the setting, never a value."""


# What a client may call when its entry does not say. A fixed list, on purpose:
# a tool added to the server later must be listed here (or in a client's entry)
# before any client can use it, so the broker's scope never widens silently.
#
# Left out, with the reason:
#   container get / project_get / image_get  show environment variables and
#                                            compose files, which can hold secrets
#   container logs, synology_system_log      free text that may hold anything
#   ds_*                                     task lists name files and URLs that
#                                            are not filtered by folder
#   account, group and permission tools      a different trust tier than
#                                            browsing and monitoring
#   every tool that changes something
DEFAULT_TOOLS: FrozenSet[str] = frozenset(
    {
        # Connection
        "synology_status",
        "synology_list_nas",
        # Files (limited to the client's folders)
        "list_shares",
        "list_directory",
        "get_file_info",
        "search_files",
        "get_file_content",
        # Health and monitoring
        "synology_system_info",
        "synology_utilization",
        "synology_disk_health",
        "synology_disk_smart",
        "synology_volume_status",
        "synology_storage_pool",
        "synology_network",
        "synology_ups",
        "synology_services",
        "synology_health_summary",
        "synology_nfs_status",
        "synology_nfs_list_shares",
        # Containers: inventory only
        "synology_container_list",
        "synology_container_resource",
        "synology_container_project_list",
        "synology_container_image_list",
        "synology_container_registry_list",
        "synology_container_registry_search",
        "synology_container_registry_tags",
        "synology_container_network_list",
        "synology_container_network_get",
    }
)

# Never a client's to call, whatever its entry lists: no tool may take a
# password, and these two would let a client change what the broker holds.
NEVER_TOOLS: FrozenSet[str] = frozenset({"synology_login"})

_DISCONNECT_TOOL = "synology_logout"

_CLIENT_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ROOT_KEYS = {"clients", "session", "deny_paths"}
_SESSION_KEYS = {"idle_seconds", "absolute_seconds", "pending_seconds"}
_CLIENT_KEYS = {"token_sha256", "nas", "tools", "folders", "disconnect", "expires"}
# How far ahead a grant may end, and how soon before it ends the broker says so.
_MAX_GRANT_SECONDS = 366 * 86400
_WARN_SECONDS = 14 * 86400
_DAY_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Keys that suggest someone put a secret where a digest belongs.
_SECRET_LOOKING = re.compile(r"(token|password|passwd|secret|otp|sid|cookie|session)", re.I)


@dataclass(frozen=True)
class SessionPolicy:
    """Session lifetimes, in seconds. Idle time advances each time a session is
    used for a permitted call; the absolute lifetime never does."""

    idle_seconds: int = 900
    absolute_seconds: int = 28800
    pending_seconds: int = 300


@dataclass(frozen=True)
class ClientPolicy:
    name: str
    token_sha256: str
    nas: FrozenSet[str]
    tools: FrozenSet[str]
    folders: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    disconnect: bool = True
    # When the grant ends, in epoch seconds (UTC). The policy parser always sets
    # it; a grant without one is never honoured (`PolicyTokenVerifier`).
    expires_at: Optional[float] = None

    def allowed_tools(self) -> FrozenSet[str]:
        """The tools this client may call, including disconnect if allowed."""
        return self.tools | ({_DISCONNECT_TOOL} if self.disconnect else frozenset())

    def __repr__(self) -> str:
        return f"ClientPolicy(name={self.name!r})"


@dataclass(frozen=True)
class Policy:
    clients: Mapping[str, ClientPolicy]
    session: SessionPolicy = SessionPolicy()
    deny_paths: Tuple[str, ...] = ()

    def folder_policy_for(self, client: ClientPolicy) -> FolderPolicy:
        """The folder policy for one client: its roots plus the shared denials."""
        return FolderPolicy(dict(client.folders), deny=self.deny_paths)

    def grant_warnings(self, now: float) -> List[str]:
        """Start-up notes about grants that have ended or end within two weeks. They
        name the client and the moment, never the token or its digest."""
        notes = []
        for client in self.clients.values():
            if client.expires_at is None:
                continue
            left = client.expires_at - now
            when = _datetime.datetime.fromtimestamp(
                client.expires_at, _datetime.timezone.utc
            ).strftime("%Y-%m-%d %H:%M UTC")
            if left <= 0:
                notes.append(
                    f"The grant for client '{client.name}' ended on {when}: its token is "
                    "refused until the policy carries a new expiry and the broker is restarted."
                )
            elif left <= _WARN_SECONDS:
                days = math.ceil(left / 86400)
                notes.append(
                    f"The grant for client '{client.name}' ends in {days} day(s), on {when}: "
                    "renew it in the policy before then."
                )
        return notes


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def _check_keys(where: str, data: Mapping[str, Any], allowed: Iterable[str]) -> None:
    allowed = set(allowed)
    for key in data:
        _expect(
            key in allowed,
            f"{where}: unknown setting '{key}'"
            + (
                " (a bearer token, password or session value never belongs in this file)"
                if _SECRET_LOOKING.search(str(key))
                else ""
            ),
        )


def _string_list(where: str, value: Any) -> List[str]:
    _expect(
        isinstance(value, list) and all(isinstance(v, str) and v for v in value),
        f"{where}: must be a list of non-empty strings",
    )
    return list(value)


def _expiry_example(now: float) -> str:
    """A date a good way inside the one-year limit, to show in a message."""
    return (
        _datetime.datetime.fromtimestamp(now + 300 * 86400, _datetime.timezone.utc)
        .date()
        .isoformat()
    )


def _parse_expiry(where: str, value: Any, now: float) -> float:
    """When a client's grant ends, in epoch seconds (UTC).

    A date (`2027-06-30`) lasts through the whole of that day in UTC; a datetime
    must carry its time zone (`2027-06-30T12:00:00Z`), because one without is
    ambiguous. The grant may end at most a year after `now`, the moment the
    policy is loaded. A date already in the past is accepted (the client's token
    is simply refused, and the start-up notes say so), so one forgotten renewal
    does not stop the broker serving everyone else.

    The messages never repeat what was written: a token pasted here by mistake
    must not be echoed."""
    hint = f'a date such as "{_expiry_example(now)}", or a datetime with a time zone'
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{where}.expires: must be {hint}")
    text = value.strip()
    try:
        if _DAY_ONLY.match(text):
            day = _datetime.date.fromisoformat(text)
            ends = _datetime.datetime.combine(
                day, _datetime.time(0), tzinfo=_datetime.timezone.utc
            ) + _datetime.timedelta(days=1)
        else:
            ends = _datetime.datetime.fromisoformat(
                text[:-1] + "+00:00" if text[-1] in "Zz" else text
            )
            if ends.tzinfo is None:
                raise ValueError("no time zone")
    except (ValueError, OverflowError):
        raise PolicyError(f"{where}.expires: must be {hint}") from None
    expires_at = ends.timestamp()
    if expires_at > now + _MAX_GRANT_SECONDS:
        raise PolicyError(
            f"{where}.expires: is more than a year away; a grant may last at most a year, "
            f"so pick {hint.split(', or')[0]} or sooner and renew it then"
        )
    return expires_at


def parse_policy(
    data: Any,
    *,
    known_nas: Iterable[str],
    known_tools: Iterable[str],
    now: Optional[float] = None,
) -> Policy:
    """Validate and build a `Policy`. `known_nas` are the NAS aliases the broker
    has configured and `known_tools` the tools the server registers: a policy
    naming anything else is refused, so a misspelt alias or tool cannot quietly
    grant or deny the wrong thing. `now` (epoch seconds, default the present) is
    what each grant's `expires` is judged against."""
    now = time.time() if now is None else now
    known_nas = set(known_nas)
    known_tools = set(known_tools)
    _expect(isinstance(data, dict), "the policy must be a JSON object")
    _check_keys("policy", data, _ROOT_KEYS)

    session_data = data.get("session", {})
    _expect(isinstance(session_data, dict), "session: must be an object")
    _check_keys("session", session_data, _SESSION_KEYS)
    defaults = SessionPolicy()
    values: Dict[str, int] = {}
    for key in _SESSION_KEYS:
        value = session_data.get(key, getattr(defaults, key))
        _expect(
            isinstance(value, int) and not isinstance(value, bool) and value > 0,
            f"session.{key}: must be a positive whole number of seconds",
        )
        values[key] = value
    _expect(
        values["idle_seconds"] <= values["absolute_seconds"],
        "session.idle_seconds may not exceed session.absolute_seconds",
    )
    _expect(
        values["absolute_seconds"] <= 7 * 24 * 3600,
        "session.absolute_seconds may not exceed seven days",
    )
    session = SessionPolicy(**values)

    deny_paths = tuple(_string_list("deny_paths", data.get("deny_paths", [])))

    clients_data = data.get("clients")
    _expect(
        isinstance(clients_data, dict) and clients_data, "clients: at least one client is required"
    )
    clients: Dict[str, ClientPolicy] = {}
    seen_digests: Dict[str, str] = {}
    for name, entry in clients_data.items():
        where = f"clients.{name}"
        _expect(_CLIENT_NAME.match(str(name)) is not None, f"{where}: invalid client name")
        _expect(isinstance(entry, dict), f"{where}: must be an object")
        _check_keys(where, entry, _CLIENT_KEYS)

        digest = entry.get("token_sha256")
        _expect(
            isinstance(digest, str) and _DIGEST.match(digest) is not None,
            f"{where}.token_sha256: must be the 64-character lowercase hex SHA-256 of the token",
        )
        _expect(
            digest not in seen_digests,
            f"{where}.token_sha256: the same token is already used by '{seen_digests.get(digest)}'",
        )
        seen_digests[digest] = name

        nas = _string_list(f"{where}.nas", entry.get("nas"))
        _expect(bool(nas), f"{where}.nas: at least one NAS is required")
        for alias in nas:
            _expect(alias in known_nas, f"{where}.nas: '{alias}' is not a configured NAS")

        if "tools" in entry:
            tools = set(_string_list(f"{where}.tools", entry["tools"]))
        else:
            tools = set(DEFAULT_TOOLS)
        for tool in tools:
            _expect(tool in known_tools, f"{where}.tools: '{tool}' is not a known tool")
            _expect(tool not in NEVER_TOOLS, f"{where}.tools: '{tool}' may not be granted")
        # Disconnect has its own switch; it is not part of the tool list.
        tools.discard(_DISCONNECT_TOOL)

        folders_data = entry.get("folders", {})
        _expect(isinstance(folders_data, dict), f"{where}.folders: must be an object")
        folders: Dict[str, Tuple[str, ...]] = {}
        for alias, roots in folders_data.items():
            _expect(
                alias in nas, f"{where}.folders: '{alias}' is not one of this client's NAS units"
            )
            roots = _string_list(f"{where}.folders.{alias}", roots)
            for root in roots:
                _expect(
                    root.startswith("/") and root.strip("/") != "",
                    f"{where}.folders.{alias}: each folder must be a share path such as /docs",
                )
            folders[alias] = tuple(roots)

        disconnect = entry.get("disconnect", True)
        _expect(isinstance(disconnect, bool), f"{where}.disconnect: must be true or false")

        # Required, with no default: a grant that never ends is a decision to be
        # made on purpose, not by leaving a line out.
        if entry.get("expires") is None:
            raise PolicyError(
                f"{where}.expires: required. Say when this client's grant ends, at most a "
                f'year ahead, as a date such as "{_expiry_example(now)}"'
            )
        expires_at = _parse_expiry(where, entry["expires"], now)

        clients[name] = ClientPolicy(
            name=name,
            token_sha256=digest,
            nas=frozenset(nas),
            tools=frozenset(tools),
            folders=folders,
            disconnect=disconnect,
            expires_at=expires_at,
        )

    policy = Policy(clients=clients, session=session, deny_paths=deny_paths)
    # Building each client's folder policy now rejects an unusable root (such as
    # "/") at startup instead of on the first request.
    for client in clients.values():
        try:
            policy.folder_policy_for(client)
        except ValueError as error:
            raise PolicyError(f"clients.{client.name}.folders: {error}") from None
    return policy


def load_policy(
    path: Path,
    *,
    known_nas: Iterable[str],
    known_tools: Iterable[str],
    now: Optional[float] = None,
) -> Policy:
    """Read and validate the policy file at `path`. `now` is as for `parse_policy`."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise PolicyError(f"the policy file {path} does not exist") from None
    except (OSError, ValueError) as error:
        raise PolicyError(
            f"the policy file {path} cannot be read as JSON: {type(error).__name__}"
        ) from None
    return parse_policy(data, known_nas=known_nas, known_tools=known_tools, now=now)


def hash_token(token: str) -> str:
    """The digest of a bearer token as it is written in the policy file."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> Tuple[str, str]:
    """A new bearer token and its digest. The token is shown once, to be given
    to the client; only the digest goes in the policy file."""
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


class PolicyTokenVerifier:
    """Checks a presented bearer token against the digests in the policy.

    Implements the SDK's `TokenVerifier`. The comparison is constant-time and
    visits every client, so how long a check takes does not say which digest
    was close. A token never leaves this method: the `AccessToken` it returns
    carries a short fingerprint in place of it, so it cannot reach a log line
    or a stored request.

    A token is honoured only until its grant ends (`expires`, in the policy), and
    never when the grant says nothing about it: the answer carries the moment it
    ends, so the SDK's own bearer check refuses it then too. `clock` gives the
    present in epoch seconds.
    """

    def __init__(self, policy: Policy, clock: Callable[[], float] = time.time):
        self._clients = tuple(policy.clients.values())
        self._clock = clock

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        digest = hash_token(token)
        match: Optional[ClientPolicy] = None
        for client in self._clients:
            if hmac.compare_digest(digest, client.token_sha256):
                match = client
        if match is None:
            return None
        # Judged after the comparison, which has visited every client, so how long
        # a check takes does not say whether the digest matched an ended grant.
        expires_at = match.expires_at
        if expires_at is None or self._clock() >= expires_at:
            return None
        return AccessToken(
            token=f"sha256:{digest[:12]}",
            client_id=match.name,
            scopes=[],
            expires_at=int(expires_at),
        )
