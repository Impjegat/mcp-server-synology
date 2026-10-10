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

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

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
_CLIENT_KEYS = {"token_sha256", "nas", "tools", "folders", "disconnect"}
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


def parse_policy(data: Any, *, known_nas: Iterable[str], known_tools: Iterable[str]) -> Policy:
    """Validate and build a `Policy`. `known_nas` are the NAS aliases the broker
    has configured and `known_tools` the tools the server registers: a policy
    naming anything else is refused, so a misspelt alias or tool cannot quietly
    grant or deny the wrong thing."""
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

        clients[name] = ClientPolicy(
            name=name,
            token_sha256=digest,
            nas=frozenset(nas),
            tools=frozenset(tools),
            folders=folders,
            disconnect=disconnect,
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


def load_policy(path: Path, *, known_nas: Iterable[str], known_tools: Iterable[str]) -> Policy:
    """Read and validate the policy file at `path`."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise PolicyError(f"the policy file {path} does not exist") from None
    except (OSError, ValueError) as error:
        raise PolicyError(
            f"the policy file {path} cannot be read as JSON: {type(error).__name__}"
        ) from None
    return parse_policy(data, known_nas=known_nas, known_tools=known_tools)


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
    """

    def __init__(self, policy: Policy):
        self._clients = tuple(policy.clients.values())

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        digest = hash_token(token)
        match: Optional[ClientPolicy] = None
        for client in self._clients:
            if hmac.compare_digest(digest, client.token_sha256):
                match = client
        if match is None:
            return None
        return AccessToken(
            token=f"sha256:{digest[:12]}",
            client_id=match.name,
            scopes=[],
            expires_at=None,
        )
