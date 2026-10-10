# src/broker/file_policy.py - Which NAS folders a broker client may reach.
#
# The administrator lists, per client and per NAS, the folder roots that client
# may use. A path is allowed only if it is one of those roots or lies under
# one; everything else is denied, including a path that merely climbs back out
# of a root. Judging the path *lexically* is the first control. The second is
# checking where DSM says the path really resolves: a symbolic link inside a
# root must not lead outside it, and where that cannot be established the path
# is refused rather than assumed safe.
#
# This governs the NAS's own contents. It cannot limit what another, separately
# authorised tool on the same computer can read, and it is not a substitute for
# keeping the broker's own files out of reach (plans/2026-10-06-manual-
# authentication/PLAN.md §3.1, §6.3).

import posixpath
import re
import threading
import time
import unicodedata
from typing import Callable, Dict, Mapping, Optional, Sequence, Tuple

from broker.errors import AuthorizationDenied

_DENIED = "AUTHORIZATION_DENIED: that location is outside the folders this client may use."

# A NUL or other control character, or a backslash, can be read differently by
# DSM than by this check; such a path cannot be judged safely, so it is refused.
_UNJUDGEABLE = re.compile(r"[\x00-\x1f\x7f\\]")

# Names that mean a credential or a secret wherever they sit, checked on every
# path component whatever the roots are. This is a backstop for the obvious
# cases, not the control: a root that does not contain a secret is.
_DENIED_NAMES = frozenset(
    {
        "secret",
        "secrets",
        "credential",
        "credentials",
        "synology-mcp",
        ".ssh",
        ".gnupg",
        ".aws",
        ".netrc",
        ".git-credentials",
        ".htpasswd",
    }
)
_DENIED_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx")
# A file such as `secrets.yaml` or `credentials.json`, whatever the extension.
_DENIED_PREFIXES = (".env.", "secrets.", "credentials.")


def canonicalize(path: str) -> str:
    """The path as File Station will see it: one leading slash, `.` and `..`
    resolved, NFC Unicode. Mirrors `SynologyFileStation._format_path`, so a path
    is judged in the form the NAS receives. Raises `AuthorizationDenied` for a
    value that cannot be judged (not text, control characters, a backslash)."""
    if not isinstance(path, str) or _UNJUDGEABLE.search(path):
        raise AuthorizationDenied(_DENIED)
    path = "/" + path.lstrip("/")
    path = posixpath.normpath(path)
    return unicodedata.normalize("NFC", path)


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


class FolderPolicy:
    """Folder roots per NAS alias, plus extra denied locations.

    `roots` maps a NAS alias to the roots allowed on it. `deny` lists further
    locations that are refused even inside a root (for example a folder that
    holds the broker's own state). A root of `/` is refused: it would allow
    everything, and a policy that wants that should say so with real shares.
    """

    def __init__(
        self,
        roots: Mapping[str, Sequence[str]],
        deny: Sequence[str] = (),
        *,
        clock: Callable[[], float] = time.monotonic,
        real_root_ttl: float = 300.0,
    ):
        self._roots: Dict[str, Tuple[str, ...]] = {}
        for alias, values in roots.items():
            canonical_roots = []
            for value in values:
                root = canonicalize(value)
                if root == "/":
                    raise ValueError(
                        f"folder root for NAS '{alias}' may not be '/'; list the shares to allow"
                    )
                canonical_roots.append(root)
            self._roots[alias] = tuple(sorted(set(canonical_roots)))
        self._deny = tuple(canonicalize(value).casefold() for value in deny)
        self._clock = clock
        self._real_root_ttl = real_root_ttl
        self._real_roots: Dict[Tuple[str, str], Tuple[float, str]] = {}
        self._real_lock = threading.Lock()

    def aliases(self) -> Tuple[str, ...]:
        return tuple(self._roots)

    def roots(self, alias: str) -> Tuple[str, ...]:
        return self._roots.get(alias, ())

    def is_denied(self, canonical: str) -> bool:
        """Whether `canonical` is a location that is never allowed."""
        folded = canonical.casefold()
        for prefix in self._deny:
            if folded == prefix or folded.startswith(prefix + "/"):
                return True
        for part in folded.split("/"):
            if part == ".env" or part.startswith(_DENIED_PREFIXES):
                return True
            if part in _DENIED_NAMES or part.endswith(_DENIED_SUFFIXES):
                return True
        return False

    def root_for(self, alias: str, canonical: str) -> Optional[str]:
        """The longest root of `alias` that contains `canonical`, if any."""
        matches = [root for root in self.roots(alias) if _within(canonical, root)]
        return max(matches, key=len) if matches else None

    def check(self, alias: str, path: str) -> str:
        """The canonical form of `path`, or `AuthorizationDenied` if it is not
        inside an allowed root."""
        canonical = canonicalize(path)
        if self.is_denied(canonical) or self.root_for(alias, canonical) is None:
            raise AuthorizationDenied(_DENIED)
        return canonical

    def allows(self, alias: str, path: str) -> bool:
        try:
            self.check(alias, path)
        except AuthorizationDenied:
            return False
        return True

    def share_visible(self, alias: str, share_path: str) -> bool:
        """Whether a share should appear in discovery: it is, or contains, or
        sits inside, an allowed root. A share holding only an allowed
        sub-folder is visible by name; its other contents are not."""
        try:
            share = canonicalize(share_path)
        except AuthorizationDenied:
            return False
        # A share with no usable path would read as "/", which contains every root.
        if share == "/" or self.is_denied(share):
            return False
        return any(_within(share, root) or _within(root, share) for root in self.roots(alias))

    def real_root(
        self, alias: str, root: str, resolve: Callable[[str], Optional[str]]
    ) -> Optional[str]:
        """Where DSM says `root` really lives, asked through `resolve` and
        remembered briefly: roots rarely move, and asking on every request
        would double the traffic.

        Only an answer is remembered, never a failure: one transient error from
        the NAS must not block a root for the whole lifetime of the cache. The
        cache is touched from request threads, so it is guarded by a lock; the
        lookup itself runs outside it, so a slow NAS never holds the lock."""
        key = (alias, root)
        with self._real_lock:
            cached = self._real_roots.get(key)
            if cached is not None and self._clock() - cached[0] < self._real_root_ttl:
                return cached[1]
        real = resolve(root)
        if real is not None:
            with self._real_lock:
                self._real_roots[key] = (self._clock(), real)
        return real

    def guard(self, alias: str) -> "FolderGuard":
        return FolderGuard(self, alias)


class FolderGuard:
    """A `FolderPolicy` bound to one NAS alias: what the service modules hold."""

    def __init__(self, policy: FolderPolicy, alias: str):
        self._policy = policy
        self.alias = alias

    def check(self, path: str) -> str:
        return self._policy.check(self.alias, path)

    def allows(self, path: str) -> bool:
        return self._policy.allows(self.alias, path)

    def share_visible(self, share_path: str) -> bool:
        return self._policy.share_visible(self.alias, share_path)

    def verify_real(
        self,
        canonical: str,
        real_path: Optional[str],
        resolve_root_real: Callable[[str], Optional[str]],
    ) -> None:
        """Refuse unless DSM's resolved `real_path` for `canonical` is inside
        the real location of the allowed root that contains it.

        `canonical` has already passed `check`. If either real location is
        unknown the answer is refusal: a symbolic link cannot be shown to stay
        inside the root, so it is not assumed to.
        """
        root = self._policy.root_for(self.alias, canonical)
        if root is None:
            raise AuthorizationDenied(_DENIED)
        root_real = self._policy.real_root(self.alias, root, resolve_root_real)
        if not real_path or not root_real:
            raise AuthorizationDenied(_DENIED)
        real = canonicalize(real_path)
        if not _within(real, canonicalize(root_real)) or self._policy.is_denied(real):
            raise AuthorizationDenied(_DENIED)
