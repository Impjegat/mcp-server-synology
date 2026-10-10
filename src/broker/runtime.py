# src/broker/runtime.py - Runs each client's tool calls against its own sessions.
#
# The runtime keeps one tool executor (`SynologyMCPServer`) per client. Each is
# limited to that client's NAS units, tools and folders, and gets its DSM
# sessions from the session manager through a bridge, so one client can never
# see or use another's, and the manager stays the only authority over when a
# session starts and ends.

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Mapping, Optional

import mcp.types as types

from auth import register_secret_source
from broker.bridge import SessionBridge, SessionView
from broker.policy import ClientPolicy, Policy
from broker.sessions import SessionManager, SessionRecord

logger = logging.getLogger(__name__)

RemoteLogout = Callable[[str, str, Optional[str]], bool]

# How long an explicit disconnect waits for the NAS to confirm a logout. The
# local session is gone either way; this only decides what the reply says.
_LOGOUT_WAIT_SECONDS = 10.0


def _default_remote_logout(verify_ssl: Any) -> RemoteLogout:
    def logout(base_url: str, session_id: str, syno_token: Optional[str]) -> bool:
        from auth.synology_auth import SynologyAuth

        result = SynologyAuth(base_url, verify_ssl=verify_ssl, manual_mode=True).logout(session_id)
        return bool(result.get("success"))

    return logout


class _ClientBridge:
    """The session bridge for one client: its view of the session manager."""

    def __init__(self, runtime: "BrokerRuntime", client: ClientPolicy):
        self._runtime = runtime
        self._client = client

    def _alias(self, base_url: str) -> Optional[str]:
        for alias in self._client.nas:
            cfg = self._runtime._nas_configs.get(alias)
            if cfg and cfg["base_url"] == base_url:
                return alias
        return None

    def current(self, base_url: str, *, touch: bool = True) -> Optional[SessionView]:
        alias = self._alias(base_url)
        if alias is None:
            return None
        self._runtime.reap_expired()
        record = self._runtime.sessions.get(self._client.name, alias, touch=touch)
        if record is None:
            return None
        return SessionView(record.session_id, record.syno_token, record.generation)

    def lost(self, base_url: str, generation: Optional[int]) -> None:
        alias = self._alias(base_url)
        if alias is not None:
            # The NAS already says it is gone; there is nothing to log out.
            self._runtime.sessions.invalidate(self._client.name, alias, generation)

    def close(self, base_url: str, session_id: str, syno_token: Optional[str]) -> bool:
        alias = self._alias(base_url)
        if alias is None:
            return False
        removed = self._runtime.sessions.revoke(self._client.name, alias)
        if not removed:
            return False
        return all(self._runtime.logout_and_wait(record) for record in removed)


class BrokerRuntime:
    def __init__(
        self,
        policy: Policy,
        sessions: SessionManager,
        nas_configs: Mapping[str, Mapping[str, Any]],
        *,
        remote_logout: Optional[RemoteLogout] = None,
        verify_ssl: Any = True,
        executor_factory: Optional[Callable[..., Any]] = None,
    ):
        self.policy = policy
        self.sessions = sessions
        self._nas_configs = nas_configs
        self._remote_logout = remote_logout or _default_remote_logout(verify_ssl)
        self._executor_factory = executor_factory
        self._executors: Dict[str, Any] = {}
        self._lock = threading.Lock()
        # Session ids held here are not in any SynologyAuth, so the redaction
        # that masks them from logs and tool output has to be told about them.
        register_secret_source(sessions.iter_secrets)

    # -- executors ---------------------------------------------------------

    def executor_for(self, client_id: str) -> Any:
        client = self.policy.clients.get(client_id)
        if client is None:
            raise KeyError(client_id)
        with self._lock:
            executor = self._executors.get(client_id)
            if executor is None:
                factory = self._executor_factory
                if factory is None:
                    from mcp_server import SynologyMCPServer

                    factory = SynologyMCPServer
                executor = factory(
                    allowed_nas=client.nas,
                    allowed_tools=client.allowed_tools(),
                    folder_policy=self.policy.folder_policy_for(client),
                    session_bridge=_ClientBridge(self, client),
                )
                self._executors[client_id] = executor
            return executor

    async def list_tools(self, client_id: str) -> List[types.Tool]:
        return await self.executor_for(client_id)._list_tools()

    async def call_tool(self, client_id: str, name: str, arguments: dict) -> types.CallToolResult:
        return await self.executor_for(client_id)._call_tool(name, arguments)

    def bridge_for(self, client_id: str) -> SessionBridge:
        return _ClientBridge(self, self.policy.clients[client_id])

    # -- sessions ----------------------------------------------------------

    def install_login(
        self, client_id: str, nas: str, session_id: str, syno_token: Optional[str] = None
    ) -> SessionRecord:
        """Adopt a session that the private login established for `client_id` on
        `nas`. A session it replaces is ended on the NAS."""
        client = self.policy.clients[client_id]
        if nas not in client.nas:
            raise KeyError(nas)
        record, replaced = self.sessions.install(
            client_id, nas, self._nas_configs[nas]["base_url"], session_id, syno_token
        )
        if replaced is not None:
            self._logout_in_background(replaced)
        return record

    def reap_expired(self) -> None:
        """End, on the NAS, every session that has reached a deadline."""
        for record in self.sessions.take_expired():
            self._logout_in_background(record)

    def revoke(self, client_id: str, nas: Optional[str] = None) -> int:
        """End a client's sessions on the NAS and here. Returns how many."""
        removed = self.sessions.revoke(client_id, nas)
        for record in removed:
            self._logout_in_background(record)
        return len(removed)

    def shutdown(self, timeout: float = _LOGOUT_WAIT_SECONDS) -> None:
        """End every session on the NAS, all at once, waiting at most `timeout`
        seconds in total for the NAS to answer. Serial waits would add up (ten
        sessions on an unreachable NAS is a hundred seconds) and could outlast a
        container or service stop timeout, ending in a kill before the rest were
        logged out. The local sessions are gone before any wait begins."""
        threads = [
            threading.Thread(target=self._logout, args=(record,), daemon=True)
            for record in self.sessions.revoke_all()
        ]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + timeout
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))

    # -- remote logout -----------------------------------------------------

    def _logout(self, record: SessionRecord) -> bool:
        try:
            return bool(self._remote_logout(record.base_url, record.session_id, record.syno_token))
        except Exception:
            # Never log the exception: it may carry the session id.
            logger.warning("Logging a session out on the NAS failed (%s)", record.nas)
            return False

    def _logout_in_background(self, record: SessionRecord) -> None:
        threading.Thread(target=self._logout, args=(record,), daemon=True).start()

    def logout_and_wait(self, record: SessionRecord) -> bool:
        """End `record` on the NAS, waiting at most a few seconds for the answer.
        False means unconfirmed, not that the local session survives."""
        outcome: List[bool] = []
        thread = threading.Thread(target=lambda: outcome.append(self._logout(record)), daemon=True)
        thread.start()
        thread.join(_LOGOUT_WAIT_SECONDS)
        return bool(outcome and outcome[0])
