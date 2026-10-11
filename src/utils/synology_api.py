# src/utils/synology_api.py - Shared API client for all Synology modules

import logging
from typing import Any, Dict, Optional, Tuple

import requests

from broker.errors import (
    AuthenticationRequired,
    RedirectRefused,
    SessionRenewedNotRepeated,
    is_session_lost,
)
from config import config
from utils.redact import redact

logger = logging.getLogger(__name__)

# DSM methods that only read. After a lost session is renewed from the stored login
# (legacy mode), a request is repeated only if its method is one of these. The HTTP
# verb says nothing about it: some DSM changes are sent as GET (a rename, a folder
# created, the start of a delete or a move) and some reads as POST (every container
# call). A method not listed here is treated as a change and never repeated; the
# cost of listing too little is that a read has to be asked for again.
READ_ONLY_METHODS = frozenset(
    {
        "get",
        "getconfig",
        "getinfo",
        "get_smart_info",
        "info",
        "list",
        "list_by_user",
        "list_share",
        "load_info",
        "search",
        "status",
        "tags",
    }
)


def raise_unless_read_only(method: str) -> None:
    """Called once a lost session has been renewed: let a read be repeated, and
    stop a change with `SessionRenewedNotRepeated`."""
    if method not in READ_ONLY_METHODS:
        raise SessionRenewedNotRepeated()


def refuse_redirect(response: Any) -> None:
    """Raise `RedirectRefused` if the NAS answered with a redirect.

    Every request to the NAS is sent with `allow_redirects=False`, because
    following a redirect would repeat the request, body and session headers
    included, at whatever address the answer names. A login carries the
    password and the one-time code; every other request carries the session id
    and token. With redirects off, `requests` hands the 3xx answer back, and
    `raise_for_status()` does not treat it as an error, so each call checks it
    here, before it reads the answer.

    The address the NAS gave is deliberately not in the error.
    """
    status = getattr(response, "status_code", None)
    if isinstance(status, int) and 300 <= status < 400:
        raise RedirectRefused()


def raise_if_authentication_required(code: Any) -> None:
    """In manual (broker) mode, a DSM code that says the session is gone means
    a new private login is needed: raise the typed error instead of letting a
    bare numeric code surface. A no-op in legacy mode and for any other code."""
    if config.auth_mode == "broker" and is_session_lost(code):
        raise AuthenticationRequired()


def recover_session(
    base_url: str, stale_session_id: Optional[str], code: Any
) -> Optional[Tuple[str, Optional[str]]]:
    """Session-loss handling for service modules that make their own HTTP calls.

    Manual mode raises `AuthenticationRequired`. Legacy mode renews the
    session once, from the credentials cached at login, but only for DSM's
    "SID not found" (119) — the one code the shared client has always
    recovered from. Returns `(session_id, syno_token)` when the session was
    renewed, otherwise None and the caller reports the original error.
    """
    raise_if_authentication_required(code)
    if str(code) != "119":
        return None
    new_sid, new_token = _try_relogin(base_url, stale_session_id)
    return (new_sid, new_token) if new_sid else None


def _try_relogin(
    base_url: str, stale_session_id: Optional[str] = None
) -> Tuple[Optional[str], Optional[str]]:
    """Lookup the SynologyAuth registered for this URL and trigger a relogin.

    Used internally by SynologyAPIClient.request() to silently recover from
    DSM error 119 (SID expired). Returns (new_session_id, new_syno_token) on
    success, (None, None) if no auth instance is registered for this URL or
    if the relogin attempt fails. `stale_session_id` is the SID that just got
    the 119; it lets concurrent recoveries collapse into a single relogin.

    Import is deferred to runtime to avoid a circular import (auth → utils).
    """
    try:
        from auth.synology_auth import get_auth_for_url
    except ImportError as exc:
        # Deferred to dodge a circular import; a real failure here (e.g. a
        # syntax error introduced in synology_auth) would otherwise silently
        # leave the caller stuck on the 119. Log it so it's observable.
        logger.warning("Cannot recover from DSM error 119 — auth module unavailable: %s", exc)
        return (None, None)
    auth = get_auth_for_url(base_url)
    if auth is None or not auth.relogin(stale_session_id):
        return (None, None)
    return (auth.current_session_id, auth.current_syno_token)


class SynologyAPIClient:
    """Shared API client for all Synology modules.

    Provides standardized API calls with timeout, SSL verification,
    and error handling across all Synology services.

    Transparently recovers from DSM error code 119 ("SID not found") — the
    error DSM returns when the server-side session has expired (typically
    after ~1h of inactivity for SYNO.Core.* APIs). When that happens, the
    client looks up the SynologyAuth instance registered for its base_url,
    triggers a relogin, refreshes its local SID/token, and retries the call
    once. If no auth is registered (e.g. in standalone tests), the 119 is
    returned to the caller unchanged.
    """

    def __init__(
        self,
        base_url: str,
        session_id: str,
        verify_ssl: bool = True,
        syno_token: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.session_id = session_id
        self.verify_ssl = verify_ssl
        self.syno_token = syno_token
        self._api_url = f"{self.base_url}/webapi/entry.cgi"

    def request(
        self,
        api: str,
        method: str,
        version: int = 1,
        extra_params: Optional[Dict] = None,
        use_post: bool = False,
    ) -> Dict[str, Any]:
        """Make an authenticated API call to /webapi/entry.cgi.

        Args:
            api: Synology API name (e.g., 'SYNO.Core.System')
            method: API method name (e.g., 'info')
            version: API version number
            extra_params: Additional parameters for the API call
            use_post: Use POST instead of GET

        Returns:
            Dict with API response or error information
        """
        result = self._do_request(api, method, version, extra_params, use_post)
        # DSM error 119 = "SID not found" → server-side session has expired.
        # Try a single transparent re-auth via the SynologyAuth registered for
        # this base_url. If it succeeds, refresh local SID/token and retry once.
        # If no auth is registered, return the original 119 to the caller.
        if not result.get("success"):
            code = result.get("error", {}).get("code")
            # Manual mode: a lost session is reported as AuthenticationRequired
            # (raised here) and never renewed from a stored password.
            raise_if_authentication_required(code)
            if code == 119:
                new_sid, new_token = _try_relogin(self.base_url, self.session_id)
                if new_sid:
                    self.session_id = new_sid
                    self.syno_token = new_token
                    if method not in READ_ONLY_METHODS:
                        # The session is renewed for the next call, but a change is
                        # not repeated on the strength of a guess about the verb.
                        return {
                            "success": False,
                            "error": {
                                "code": "session_renewed",
                                "message": str(SessionRenewedNotRepeated()),
                            },
                        }
                    result = self._do_request(api, method, version, extra_params, use_post)
        return result

    def _do_request(
        self,
        api: str,
        method: str,
        version: int = 1,
        extra_params: Optional[Dict] = None,
        use_post: bool = False,
    ) -> Dict[str, Any]:
        """Internal: perform the HTTP call without any retry logic."""
        params = {
            "api": api,
            "version": str(version),
            "method": method,
            "_sid": self.session_id,
        }
        if extra_params:
            params.update(extra_params)

        # DSM 7.3.2+ enforces CSRF on mutating endpoints via X-SYNO-TOKEN.
        # Harmless to send on reads and on older DSM (header is ignored there).
        headers = {"X-SYNO-TOKEN": self.syno_token} if self.syno_token else None

        try:
            if use_post:
                resp = requests.post(
                    self._api_url,
                    data=params,
                    headers=headers,
                    timeout=15,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                )
            else:
                resp = requests.get(
                    self._api_url,
                    params=params,
                    headers=headers,
                    timeout=15,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                )
            refuse_redirect(resp)
            resp.raise_for_status()
            return resp.json()
        except RedirectRefused as e:
            return {
                "success": False,
                "error": {"code": "redirect_refused", "message": str(e)},
            }
        except requests.RequestException as e:
            # `str(e)` commonly embeds the full request URL — which carries
            # `_sid=<session_id>` on every GET call — so redact before
            # returning it to the caller. This is a backstop; the
            # tool-response boundary in mcp_server.py also redacts.
            return {
                "success": False,
                "error": {"code": "network_error", "message": self._redact(str(e))},
            }
        except Exception as e:
            return {
                "success": False,
                "error": {"code": "unknown_error", "message": self._redact(str(e))},
            }

    def _redact(self, message: str) -> str:
        """Redact this client's live secrets from an error message."""
        return redact(message, live_secrets=[self.session_id, self.syno_token])

    def get(
        self, api: str, method: str, version: int = 1, extra_params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make a GET request to the API."""
        return self.request(api, method, version, extra_params, use_post=False)

    def post(
        self, api: str, method: str, version: int = 1, extra_params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make a POST request to the API."""
        return self.request(api, method, version, extra_params, use_post=True)
