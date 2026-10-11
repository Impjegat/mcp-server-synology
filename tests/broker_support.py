"""Helpers for building a broker in tests: a fake clock, a fake remote logout and
a policy written from plain dictionaries. Nothing here touches a network."""

import datetime
import posixpath
import sys
import threading
from typing import Any, Dict, List, Optional, Tuple

BASE_URLS = {
    "nas1": "https://nas1.example.test:5001",
    "nas2": "https://nas2.example.test:5001",
}


def future_expiry(days: int = 200) -> str:
    """A client grant's `expires` (an ISO date) comfortably inside the one-year
    limit, whenever the tests happen to run."""
    return (datetime.date.today() + datetime.timedelta(days=days)).isoformat()


class FakeClock:
    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class Broker:
    """A policy, session manager and runtime wired together, with the process's
    config put into broker mode and two NAS units configured."""

    def __init__(
        self,
        monkeypatch,
        clients: Dict[str, Dict[str, Any]],
        *,
        session: Optional[Dict[str, int]] = None,
        logout_result: bool = True,
        restricted_mode: bool = True,
    ):
        import auth.synology_auth  # noqa: F401
        import mcp_server  # noqa: F401
        import utils.synology_api  # noqa: F401
        from broker.policy import hash_token, parse_policy
        from broker.runtime import BrokerRuntime
        from broker.sessions import SessionManager

        self.nas_configs = {
            alias: {"base_url": url, "username": "reader", "verify_ssl": True, "note": ""}
            for alias, url in BASE_URLS.items()
        }
        # Each module holds its own reference to `config`; a test that reloads
        # `config` can leave them pointing at different instances.
        for module_name in ("mcp_server", "utils.synology_api", "auth.synology_auth"):
            module_config = sys.modules[module_name].config
            monkeypatch.setattr(module_config, "auth_mode", "broker")
        server_config = sys.modules["mcp_server"].config
        monkeypatch.setattr(server_config, "auto_login", False)
        monkeypatch.setattr(server_config, "restricted_mode", restricted_mode)
        monkeypatch.setattr(server_config, "nas_configs", self.nas_configs)

        self.tokens: Dict[str, str] = {}
        policy_clients = {}
        for name, entry in clients.items():
            entry = dict(entry)
            token = entry.pop("token", f"token-for-{name}")
            self.tokens[name] = token
            policy_clients[name] = {
                "token_sha256": hash_token(token),
                "expires": future_expiry(),
                **entry,
            }
        document: Dict[str, Any] = {"clients": policy_clients}
        if session:
            document["session"] = session

        known_tools = set(sys.modules["mcp_server"].SynologyMCPServer()._tool_registry)
        self.policy = parse_policy(document, known_nas=BASE_URLS, known_tools=known_tools)

        self.clock = FakeClock()
        self.sessions = SessionManager(self.policy.session, clock=self.clock)
        self.logouts: List[Tuple[str, str]] = []
        self.logged_out = threading.Event()
        self._logout_result = logout_result

        def remote_logout(base_url: str, session_id: str, syno_token: Optional[str]) -> bool:
            self.logouts.append((base_url, session_id))
            self.logged_out.set()
            return self._logout_result

        self.runtime = BrokerRuntime(
            self.policy, self.sessions, self.nas_configs, remote_logout=remote_logout
        )

    def sign_in(
        self, client: str, nas: str = "nas1", session_id: str = "SID-1", token: str = "TOK-1"
    ):
        return self.runtime.install_login(client, nas, session_id, token)

    def set_logout_result(self, result: bool) -> None:
        self._logout_result = result


class FakeDSM:
    """A stand-in for `SynologyFileStation._make_request`. Records every call, so
    a test can show that a refused request never reached the NAS."""

    def __init__(self, real_paths=None, listing=None, shares=None, hits=None):
        self.real_paths = real_paths if real_paths is not None else {}
        self.listing = listing or []
        self.shares = shares or []
        self.hits = hits or []
        self.calls = []

    def __call__(self, api, version, method, use_post=False, **params):
        self.calls.append((api, method, params))
        if (api, method) == ("SYNO.FileStation.List", "getinfo"):
            path = params["path"]
            real = self.real_paths.get(path)
            if real is None:
                return {"files": [{"code": 408, "path": path}]}
            return {
                "files": [
                    {
                        "path": path,
                        "name": posixpath.basename(path),
                        "isdir": True,
                        "additional": {"real_path": real, "size": 7},
                    }
                ]
            }
        if (api, method) == ("SYNO.FileStation.List", "list"):
            return {"files": self.listing}
        if (api, method) == ("SYNO.FileStation.List", "list_share"):
            return {"shares": self.shares}
        if (api, method) == ("SYNO.FileStation.Search", "start"):
            return {"taskid": "task-1"}
        if (api, method) == ("SYNO.FileStation.Search", "status"):
            return {"finished": True}
        if (api, method) == ("SYNO.FileStation.Search", "list"):
            return {"files": self.hits}
        if method == "stop":
            return {}
        return {}

    def methods(self):
        return [(api, method) for api, method, _ in self.calls]

    def changed_something(self):
        return any(
            api.startswith(("SYNO.FileStation.Rename", "SYNO.FileStation.CopyMove"))
            or api.endswith(("CreateFolder", "Delete", "Upload"))
            for api, _, _ in self.calls
        )
