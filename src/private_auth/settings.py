# src/private_auth/settings.py - What the owner may change from the private page.
#
# Three things, and only these: how long sessions last (the owner's own sign-in to
# the page, and the NAS sessions the broker holds), which folders each client may
# reach, and whether each client may change files (and, separately, delete them).
# Everything else in the policy (who the clients are, their token digests, which
# NAS they use, when their grant ends, the denied folders, any tool outside the
# file-changing set) is carried over exactly as the administrator wrote it.
#
# A change is worked out on the policy file's JSON, validated by `parse_policy`
# before anything is written, and applied only after the owner has confirmed that
# exact change with a fresh passkey check (the caller does that: `prepare` returns
# the change's digest, which the passkey challenge is bound to, and `commit` takes
# the digest back). Messages name a setting and never repeat a value that was typed.

import copy
import hashlib
import json
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Tuple

from broker.policy import (
    DEFAULT_TOOLS,
    DELETE_TOOLS,
    WRITE_TOOLS,
    PolicyError,
    SessionPolicy,
)
from broker.policy_store import PolicyStore
from broker.runtime import BrokerRuntime


class SettingsError(ValueError):
    """Safe to show to the owner: names a setting, never a value."""


# proposal field -> (policy key, seconds in one unit, least seconds, most seconds, label)
_DAY = 86400
_SESSION_FIELDS: Dict[str, Tuple[str, int, int, int, str]] = {
    "owner_idle_minutes": (
        "owner_idle_seconds",
        60,
        60,
        _DAY,
        "Sign out of this page after being unused for",
    ),
    "owner_absolute_hours": (
        "owner_absolute_seconds",
        3600,
        300,
        _DAY,
        "Sign out of this page after",
    ),
    "idle_minutes": (
        "idle_seconds",
        60,
        60,
        7 * _DAY,
        "End a NAS session after being unused for",
    ),
    "absolute_hours": ("absolute_seconds", 3600, 300, 7 * _DAY, "End a NAS session after"),
}
_MAX_FOLDERS = 50
_MAX_FOLDER_LENGTH = 1024


def _seconds_text(seconds: int) -> str:
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return f"{hours} h"
    if seconds % 60 == 0:
        return f"{seconds // 60} min"
    return f"{seconds} s"


def _tools_of(entry: Mapping[str, Any]) -> set:
    return set(entry["tools"]) if "tools" in entry else set(DEFAULT_TOOLS)


def _clean_roots(label: str, value: Any) -> List[str]:
    if not isinstance(value, list) or len(value) > _MAX_FOLDERS:
        raise SettingsError(f"{label}: give a list of at most {_MAX_FOLDERS} folders")
    roots: List[str] = []
    for item in value:
        if not isinstance(item, str):
            raise SettingsError(f"{label}: each folder must be text")
        text = item.strip()
        if not text:
            continue
        if len(text) > _MAX_FOLDER_LENGTH or "\\" in text or any(ord(c) < 32 for c in text):
            raise SettingsError(f"{label}: a folder is too long or has a character not allowed")
        if text not in roots:
            roots.append(text)
    return roots


def apply_proposal(
    document: Mapping[str, Any],
    proposal: Any,
    *,
    restricted_allows: Callable[[str], bool],
) -> Dict[str, Any]:
    """The policy document with `proposal` applied, as a new dict; `document` is not
    changed. Raises `SettingsError` for anything the page may not change.

    `proposal` is `{"session": {...}, "clients": {name: {"folders": {nas: [...]},
    "write": bool, "delete": bool}}}`, every part optional."""
    if not isinstance(proposal, dict) or set(proposal) - {"session", "clients"}:
        raise SettingsError("the change is not in the expected shape")
    new = copy.deepcopy(dict(document))

    session_in = proposal.get("session", {})
    if not isinstance(session_in, dict) or set(session_in) - set(_SESSION_FIELDS):
        raise SettingsError("session: an unexpected setting was given")
    if session_in:
        session = new.setdefault("session", {})
        if not isinstance(session, dict):
            raise SettingsError("session: the policy's session section is not an object")
        for field, value in session_in.items():
            key, unit, least, most, label = _SESSION_FIELDS[field]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise SettingsError(f"{label}: enter a number")
            seconds = round(value * unit)
            if not least <= seconds <= most:
                raise SettingsError(
                    f"{label}: must be between {_seconds_text(least)} and {_seconds_text(most)}"
                )
            session[key] = seconds

    clients_in = proposal.get("clients", {})
    if not isinstance(clients_in, dict):
        raise SettingsError("clients: an unexpected setting was given")
    clients = new.get("clients")
    touched_tools = False
    for name, change in clients_in.items():
        entry = clients.get(name) if isinstance(clients, dict) else None
        if not isinstance(entry, dict):
            raise SettingsError("a client that is not in the policy was named")
        if not isinstance(change, dict) or set(change) - {"folders", "write", "delete"}:
            raise SettingsError(f"{name}: an unexpected setting was given")

        folders_in = change.get("folders", {})
        if not isinstance(folders_in, dict):
            raise SettingsError(f"{name}: folders must be given per NAS")
        for nas, roots in folders_in.items():
            if nas not in entry.get("nas", []):
                raise SettingsError(f"{name}: a NAS that this client does not use was named")
            cleaned = _clean_roots(f"{name} on {nas}", roots)
            folders = entry.setdefault("folders", {})
            if cleaned:
                folders[nas] = cleaned
            else:
                folders.pop(nas, None)

        if "write" in change or "delete" in change:
            for flag in ("write", "delete"):
                if flag in change and not isinstance(change[flag], bool):
                    raise SettingsError(f"{name}: {flag} must be on or off")
            had_tools_key = "tools" in entry
            tools = _tools_of(entry)
            write = change.get("write", WRITE_TOOLS <= tools)
            # Deleting without being allowed to write makes no sense, and is not offered.
            delete = change.get("delete", DELETE_TOOLS <= tools) and write
            tools = (tools | WRITE_TOOLS) if write else (tools - WRITE_TOOLS)
            tools = (tools | DELETE_TOOLS) if delete else (tools - DELETE_TOOLS)
            if had_tools_key or tools != set(DEFAULT_TOOLS):
                entry["tools"] = sorted(tools)
            touched_tools = True

    if touched_tools:
        # A tool that restricted mode hides needs restricted mode off. The policy says
        # so itself, so a grant made here takes effect without a second file edited.
        needs_unrestricted = any(
            not restricted_allows(tool)
            for entry in (clients or {}).values()
            if isinstance(entry, dict)
            for tool in _tools_of(entry)
        )
        if needs_unrestricted:
            new["restricted_mode"] = False
        elif new.get("restricted_mode") is False:
            del new["restricted_mode"]
    return new


def _roots_text(roots: Any) -> str:
    return ", ".join(roots) if roots else "none"


def describe_changes(old: Mapping[str, Any], new: Mapping[str, Any]) -> List[str]:
    """Plain sentences for what differs between two policy documents, in the three
    areas the page edits. Empty means there is nothing to save."""
    lines: List[str] = []
    defaults = SessionPolicy()
    old_session, new_session = old.get("session") or {}, new.get("session") or {}
    for _, (key, _, _, _, label) in _SESSION_FIELDS.items():
        before = old_session.get(key, getattr(defaults, key))
        after = new_session.get(key, getattr(defaults, key))
        if before != after:
            lines.append(f"{label} {_seconds_text(after)} (was {_seconds_text(before)})")

    old_clients, new_clients = old.get("clients") or {}, new.get("clients") or {}
    for name, entry in new_clients.items():
        before = old_clients.get(name) or {}
        for nas in entry.get("nas", []):
            old_roots = (before.get("folders") or {}).get(nas, [])
            new_roots = (entry.get("folders") or {}).get(nas, [])
            if old_roots != new_roots:
                lines.append(
                    f"{name} on {nas}: folders {_roots_text(new_roots)} "
                    f"(was {_roots_text(old_roots)})"
                )
        for label, group in (("write access", WRITE_TOOLS), ("delete", DELETE_TOOLS)):
            was, now = group <= _tools_of(before), group <= _tools_of(entry)
            if was != now:
                lines.append(f"{name}: {label} {'ON' if now else 'off'}")
    if old.get("restricted_mode") != new.get("restricted_mode"):
        lines.append(
            "The broker leaves restricted mode (a client now has tools it hides)"
            if new.get("restricted_mode") is False
            else "The broker's restricted mode is no longer overridden by the policy"
        )
    return lines


def digest_of(document: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class Prepared:
    digest: str
    changes: List[str]


class SettingsService:
    """Prepares, and after a passkey confirmation applies, one change at a time."""

    PENDING_SECONDS = 120.0
    MAX_PENDING = 8

    def __init__(
        self,
        store: PolicyStore,
        runtime: BrokerRuntime,
        restricted_allows: Callable[[str], bool],
        *,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._store = store
        self._runtime = runtime
        self._restricted_allows = restricted_allows
        self._clock = clock
        self._lock = threading.Lock()
        # digest -> (new document, the document it was based on, changes, expires)
        self._pending: Dict[str, Tuple[Dict[str, Any], Dict[str, Any], List[str], float]] = {}

    def writable(self) -> bool:
        return self._store.writable()

    def view(self) -> Dict[str, Any]:
        """What the page shows: the live policy, not a re-read of the file."""
        policy = self._runtime.policy
        session = policy.session
        clients = []
        for client in policy.clients.values():
            clients.append(
                {
                    "name": client.name,
                    "nas": [
                        {"alias": nas, "roots": list(client.folders.get(nas, ()))}
                        for nas in sorted(client.nas)
                    ],
                    "write": WRITE_TOOLS <= client.tools,
                    "delete": DELETE_TOOLS <= client.tools,
                }
            )
        return {
            "owner_idle_minutes": session.owner_idle_seconds / 60,
            "owner_absolute_hours": session.owner_absolute_seconds / 3600,
            "idle_minutes": session.idle_seconds / 60,
            "absolute_hours": session.absolute_seconds / 3600,
            "clients": clients,
            "restricted_mode": policy.restricted_mode,
        }

    def prepare(self, proposal: Any) -> Prepared:
        """Check `proposal` and hold it for the passkey confirmation. An empty digest
        means it changes nothing. Nothing is written yet."""
        try:
            base = self._store.read()
        except PolicyError as error:
            raise SettingsError(str(error)) from None
        new = apply_proposal(base, proposal, restricted_allows=self._restricted_allows)
        changes = describe_changes(base, new)
        if not changes:
            return Prepared("", [])
        if not self._store.writable():
            raise SettingsError(
                "The policy file is read-only here, so settings cannot be saved from this page."
            )
        try:
            self._store.validate(new)
        except PolicyError as error:
            raise SettingsError(str(error)) from None
        digest = digest_of(new)
        with self._lock:
            now = self._clock()
            self._pending = {k: v for k, v in self._pending.items() if v[3] > now}
            while len(self._pending) >= self.MAX_PENDING:
                del self._pending[next(iter(self._pending))]
            self._pending[digest] = (new, base, changes, now + self.PENDING_SECONDS)
        return Prepared(digest, changes)

    def commit(self, digest: str) -> List[str]:
        """Save and apply the change `digest` names, after the passkey confirmed it.
        A digest can be used once."""
        with self._lock:
            held = self._pending.pop(digest, None)
        if held is None or held[3] <= self._clock():
            raise SettingsError(
                "That change has expired, or a newer one from another open Settings page "
                "replaced it. Make it again."
            )
        new, base, changes, _ = held
        try:
            policy = self._store.save(new, based_on=base)
        except PolicyError as error:
            raise SettingsError(str(error)) from None
        except OSError:
            raise SettingsError("The policy file could not be written.") from None
        self._runtime.apply_policy(policy)
        return changes
