# src/broker/policy_store.py - Reading and rewriting the policy file.
#
# The broker reads its policy once at start-up (`load_policy`). The private page's
# settings are the one thing that rewrites it afterwards. This works on the file's
# JSON as the administrator wrote it, not on the parsed `Policy`, so that what the
# page does not edit (every client's token digest, its `expires`, anything the
# administrator added later) is carried over exactly.
#
# A change is validated with `parse_policy` before anything is written, written to
# a temporary file in the same folder with the owner-only mode and moved into place
# in one step, so a crash leaves either the old file or the new one and never half
# of each. The old file is kept beside it as `<name>.previous`.

import json
import os
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from broker.policy import Policy, PolicyError, parse_policy


class PolicyStore:
    def __init__(self, path: Path, *, known_nas: Iterable[str], known_tools: Iterable[str]):
        self._path = Path(path)
        self._known_nas = frozenset(known_nas)
        self._known_tools = frozenset(known_tools)
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def read(self) -> Dict[str, Any]:
        """The policy file's JSON. Messages name the problem, never a value."""
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise PolicyError("the policy file does not exist") from None
        except (OSError, ValueError) as error:
            raise PolicyError(
                f"the policy file cannot be read as JSON: {type(error).__name__}"
            ) from None
        if not isinstance(data, dict):
            raise PolicyError("the policy must be a JSON object")
        return data

    def validate(self, document: Dict[str, Any], *, now: Optional[float] = None) -> Policy:
        return parse_policy(
            document, known_nas=self._known_nas, known_tools=self._known_tools, now=now
        )

    def writable(self) -> bool:
        """Whether a change can be saved here. A policy mounted read-only (a container
        template may) cannot be changed from the page, and says so rather than failing
        at the last step."""
        return os.access(self._path, os.W_OK) and os.access(self._path.parent, os.W_OK)

    def save(
        self, document: Dict[str, Any], *, based_on: Optional[Dict[str, Any]] = None
    ) -> Policy:
        """Validate `document`, then replace the file with it. If `based_on` is given
        and the file no longer matches it, nothing is written: someone else changed
        the file after this change was prepared, and overwriting would lose that."""
        policy = self.validate(document)
        with self._lock:
            if based_on is not None and self.read() != based_on:
                raise PolicyError("the policy file changed on disk after this change was prepared")
            handle, temp_name = tempfile.mkstemp(
                dir=self._path.parent, prefix=".policy-", suffix=".tmp"
            )
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as stream:
                    json.dump(document, stream, indent=2)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.chmod(temp_name, 0o600)
                except OSError:
                    pass
                try:
                    shutil.copy2(self._path, self._path.with_name(self._path.name + ".previous"))
                except OSError:
                    pass  # a missing backup must not stop a valid change
                os.replace(temp_name, self._path)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
        return policy
