"""Authentication functionality tests."""

import pytest


@pytest.mark.real_nas
class TestSynologyAuth:
    """Test Synology authentication operations."""

    def test_filestation_login_success(self, env_check):
        """Test successful FileStation authentication."""
        from auth.synology_auth import SynologyAuth
        from config import config

        auth = SynologyAuth(config.synology_url)
        result = auth.login(config.synology_username, config.synology_password)

        assert isinstance(result, dict)
        assert result.get("success") is True, f"Login failed: {result}"
        assert "data" in result
        assert "sid" in result["data"]

        session_id = result["data"]["sid"]
        assert session_id is not None
        assert len(session_id) > 0

        print("✅ FileStation login successful")
        print(f"   Session ID: {session_id[:10]}...")

        # Test logout
        logout_result = auth.logout(session_id, "FileStation")
        print(f"✅ Logout result: {logout_result.get('success', 'Unknown')}")

    def test_download_station_login_success(self, env_check):
        """Test successful Download Station authentication."""
        from auth.synology_auth import SynologyAuth
        from config import config

        auth = SynologyAuth(config.synology_url)
        result = auth.login_download_station(config.synology_username, config.synology_password)

        assert isinstance(result, dict)
        assert result.get("success") is True, f"Download Station login failed: {result}"
        assert "data" in result
        assert "sid" in result["data"]

        session_id = result["data"]["sid"]
        assert session_id is not None
        assert len(session_id) > 0

        print("✅ Download Station login successful")
        print(f"   Session ID: {session_id[:10]}...")

        # Test logout
        logout_result = auth.logout(session_id, "DownloadStation")
        print(f"✅ Logout result: {logout_result.get('success', 'Unknown')}")

    def test_api_version_fallback(self, env_check):
        """Test that authentication tries multiple API versions."""
        from auth.synology_auth import SynologyAuth
        from config import config

        auth = SynologyAuth(config.synology_url)

        # This should work with automatic version fallback
        result = auth.login_with_session(
            config.synology_username, config.synology_password, "FileStation"
        )

        assert isinstance(result, dict)
        if result.get("success"):
            print("✅ Version fallback worked - got session")
            session_id = result["data"]["sid"]
            auth.logout(session_id, "FileStation")
        else:
            print(f"⚠️  Version fallback couldn't authenticate: {result}")

    def test_invalid_credentials(self, env_check):
        """Test authentication with invalid credentials."""
        from auth.synology_auth import SynologyAuth
        from config import config

        auth = SynologyAuth(config.synology_url)

        # Test with wrong password
        result = auth.login("invalid_user", "wrong_password")

        assert isinstance(result, dict)
        assert result.get("success") is False
        assert "error" in result

        error_code = result["error"].get("code")
        print("✅ Invalid credentials correctly rejected")
        print(f"   Error code: {error_code}")

    def test_invalid_base_url(self):
        """Test authentication with invalid base URL."""
        from auth.synology_auth import SynologyAuth

        # Test with clearly invalid URL
        auth = SynologyAuth("https://invalid.url.example.com:5001")
        result = auth.login("testuser", "testpass")

        assert isinstance(result, dict)
        assert result.get("success") is False

        print("✅ Invalid URL correctly handled")
        print(f"   Result: {result}")

    def test_session_types(self, env_check):
        """Test different session types."""
        from auth.synology_auth import SynologyAuth
        from config import config

        auth = SynologyAuth(config.synology_url)

        # Test different session types
        session_types = ["FileStation", "DownloadStation"]
        successful_sessions = []

        for session_type in session_types:
            try:
                result = auth.login_with_session(
                    config.synology_username, config.synology_password, session_type
                )

                if result.get("success"):
                    session_id = result["data"]["sid"]
                    successful_sessions.append((session_type, session_id))
                    print(f"✅ {session_type} session: {session_id[:10]}...")
                else:
                    print(f"⚠️  {session_type} session failed: {result}")

            except Exception as e:
                print(f"⚠️  {session_type} session error: {e}")

        # Cleanup sessions
        for session_type, session_id in successful_sessions:
            try:
                auth.logout(session_id, session_type)
                print(f"✅ Logged out from {session_type}")
            except Exception:
                print(f"⚠️  Logout from {session_type} failed")

        # At least one session type should work
        assert len(successful_sessions) > 0, "No session types worked"

    def test_session_expiration_handling(self, env_check):
        """Test handling of expired/invalid sessions during logout."""
        from auth.synology_auth import SynologyAuth
        from config import config

        auth = SynologyAuth(config.synology_url)

        # Test logout with invalid session ID
        fake_session_id = "invalid_session_12345"
        result = auth.logout(fake_session_id, "FileStation")

        assert isinstance(result, dict)

        # Synology API might return success even for invalid sessions
        # Let's examine the actual behavior
        print(f"📋 Logout with invalid session result: {result}")

        if result.get("success"):
            print(
                "⚠️  Synology API returned success for invalid session (this is unusual but not an error)"
            )
        else:
            error_info = result.get("error", {})
            error_code = error_info.get("code", "unknown")
            print("✅ Invalid session correctly handled")
            print(f"   Error code: {error_code}")
            print(f"   Error message: {error_info.get('message', 'No message')}")

        # Test logout with no session (should use current session if available)
        result = auth.logout()  # No parameters

        assert isinstance(result, dict)
        assert result.get("success") is False

        error_info = result.get("error", {})
        assert error_info.get("code") == "no_session"

        print("✅ No session correctly handled")
        print(f"   Message: {error_info.get('message')}")

        # Test session tracking features
        assert not auth.is_logged_in(), "Should not be logged in initially"

        session_info = auth.get_session_info()
        assert session_info["logged_in"] is False
        assert session_info["session_id"] is None

        print("✅ Session tracking working correctly")
        print(f"   Session info: {session_info}")


# Quick connectivity test
def test_auth_connectivity(env_check):
    """Quick test to verify auth service is reachable."""
    from auth.synology_auth import SynologyAuth
    from config import config

    auth = SynologyAuth(config.synology_url)

    # Just test that we can reach the auth endpoint
    # Even failed auth means the service is reachable
    result = auth.login("test", "test")

    assert isinstance(result, dict)
    print(f"🔗 Auth service reachable: {config.synology_url}/webapi/auth.cgi")

    if result.get("success"):
        print("⚠️  Test credentials unexpectedly worked")
    else:
        print("✅ Auth service responding (test credentials rejected as expected)")


def test_auth_url_construction():
    """Test URL construction for different base URLs."""
    from auth.synology_auth import SynologyAuth

    # Test different URL formats
    test_urls = [
        "https://192.168.1.100:5001",
        "https://192.168.1.100:5001/",
        "http://nas.local:5000",
        "https://mynas.synology.me",
    ]

    for url in test_urls:
        auth = SynologyAuth(url)
        expected_base = url.rstrip("/")
        assert auth.base_url == expected_base
        print(f"✅ URL '{url}' → '{auth.base_url}'")

    print("✅ URL construction tests passed")


def test_relogin_without_credentials_returns_false():
    """relogin() is a no-op (False) before any successful login caches creds."""
    from auth.synology_auth import SynologyAuth

    auth = SynologyAuth("https://nas.example.test:5001")
    assert auth._credentials is None
    assert auth.relogin() is False


def test_relogin_skips_when_session_already_refreshed():
    """Concurrent DSM-119 recovery: if another caller already refreshed the
    session while this one waited on the lock, relogin() must NOT log in again
    (which would open a second, orphaned session)."""
    from auth.synology_auth import SynologyAuth

    auth = SynologyAuth("https://nas.example.test:5001")
    auth._credentials = ("user", "pass")
    # Simulate another thread having already re-authenticated under the lock.
    auth.current_session_id = "NEW_SID"

    def _fail(*args, **kwargs):
        raise AssertionError("login_with_session should not be called on a no-op relogin")

    auth.login_with_session = _fail  # type: ignore[assignment]

    # This caller saw OLD_SID get the 119; current is already NEW_SID → skip.
    assert auth.relogin(stale_session_id="OLD_SID") is True
    assert auth.current_session_id == "NEW_SID"


# ---------------------------------------------------------------------------
# OTP + device-token unit tests (no live NAS required)
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Minimal stand-in for requests.Response used by the OTP payload tests."""

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _patch_requests_get(monkeypatch, payloads):
    """Replace requests.get AND requests.post in synology_auth with a recorder.

    `payloads` is a list of dicts; each call (whichever verb the code under
    test used) pops the head in call order. Both login and logout send their
    payload via POST (`data=`) — both are recorded under the same `params`
    key in the returned call record, plus a `method` key, so existing
    assertions like `calls[i]["params"][...]` keep working regardless of
    which verb was used, while a test can also assert on `calls[i]["method"]`
    when the verb itself matters (e.g. confirming login/logout no longer
    send credentials/session ids as a URL query string).
    """
    import auth.synology_auth as mod

    calls = []

    def _record(method, url, params, verify):
        calls.append({"url": url, "params": dict(params or {}), "verify": verify, "method": method})
        return _FakeResponse(payloads.pop(0) if payloads else {"success": False})

    def _fake_get(url, params=None, verify=None, timeout=None, **kwargs):
        return _record("GET", url, params, verify)

    def _fake_post(url, data=None, verify=None, timeout=None, **kwargs):
        return _record("POST", url, data, verify)

    monkeypatch.setattr(mod.requests, "get", _fake_get)
    monkeypatch.setattr(mod.requests, "post", _fake_post)
    return calls


def test_login_with_otp_code_adds_otp_and_device_token_request(monkeypatch):
    """First-time 2FA login: payload includes `otp_code` + `enable_device_token=yes`
    so DSM both accepts the OTP AND returns a `did` for future reuse."""
    from auth.synology_auth import SynologyAuth

    success_payload = {
        "success": True,
        "data": {"sid": "SID_123", "synotoken": "SYNO_TOK", "did": "DID_abc"},
    }
    calls = _patch_requests_get(monkeypatch, [success_payload])

    auth = SynologyAuth("https://nas.example.test:5001")
    auth.login("alice", "pw", otp_code="123456")

    assert len(calls) == 1
    params = calls[0]["params"]
    assert params["otp_code"] == "123456"
    assert params["enable_device_token"] == "yes"
    # Device-id path must NOT be taken when we're sending an OTP.
    assert "device_id" not in params


def test_login_with_device_id_trusted_device_path(monkeypatch):
    """Returning trusted device: payload includes `device_id` and skips both
    `otp_code` and `enable_device_token` — DSM treats the call as already
    authenticated."""
    from auth.synology_auth import SynologyAuth

    success_payload = {"success": True, "data": {"sid": "SID_456", "synotoken": "T"}}
    calls = _patch_requests_get(monkeypatch, [success_payload])

    auth = SynologyAuth("https://nas.example.test:5001")
    auth.login("alice", "pw", device_id="DID_abc")

    assert len(calls) == 1
    params = calls[0]["params"]
    assert params["device_id"] == "DID_abc"
    assert "otp_code" not in params
    assert "enable_device_token" not in params


def test_device_id_wins_over_otp_code(monkeypatch):
    """When both are passed, device_id wins — DSM won't ask for OTP on a
    trusted device, so we don't send one."""
    from auth.synology_auth import SynologyAuth

    success_payload = {"success": True, "data": {"sid": "SID_789", "synotoken": "T"}}
    calls = _patch_requests_get(monkeypatch, [success_payload])

    auth = SynologyAuth("https://nas.example.test:5001")
    auth.login("alice", "pw", otp_code="123456", device_id="DID_abc")

    params = calls[0]["params"]
    assert params["device_id"] == "DID_abc"
    assert "otp_code" not in params
    assert "enable_device_token" not in params


def test_successful_otp_login_caches_did_for_relogin(monkeypatch):
    """A login that returns `did` must cache it so relogin() can reuse the
    trusted-device path instead of asking the user for OTP again."""
    from auth.synology_auth import SynologyAuth

    success_payload = {
        "success": True,
        "data": {"sid": "SID_1", "synotoken": "T", "did": "DID_persisted"},
    }
    _patch_requests_get(monkeypatch, [success_payload])

    auth = SynologyAuth("https://nas.example.test:5001")
    auth.login("alice", "pw", otp_code="123456")

    assert auth.current_device_id == "DID_persisted"
    assert auth._cached_device_id == "DID_persisted"


def test_successful_login_without_device_token_leaves_cache_empty(monkeypatch):
    """Plain 2FA-off login must not populate the device-id cache — relogin
    should fall back to plain password auth (legacy behavior)."""
    from auth.synology_auth import SynologyAuth

    success_payload = {"success": True, "data": {"sid": "SID_2", "synotoken": "T"}}
    _patch_requests_get(monkeypatch, [success_payload])

    auth = SynologyAuth("https://nas.example.test:5001")
    auth.login("alice", "pw")

    assert auth.current_device_id is None
    assert auth._cached_device_id is None


def test_login_with_explicit_device_id_seeds_cache_for_relogin(monkeypatch):
    """Steady-state 2FA config: user has pasted `did` into settings.json as
    `device_id`. The returning-device login path doesn't get `did` echoed
    back by DSM, so the cache must be seeded from the INPUT device_id —
    otherwise the next relogin() would silently fall through to plain
    password auth (which DSM rejects for 2FA accounts)."""
    from auth.synology_auth import SynologyAuth

    # DSM response on the device_id path: no `did` field echoed.
    success_payload = {"success": True, "data": {"sid": "SID_steady", "synotoken": "T"}}
    calls = _patch_requests_get(monkeypatch, [success_payload, success_payload])

    auth = SynologyAuth("https://nas.example.test:5001")
    auth.login("alice", "pw", device_id="DID_from_settings")

    # Cache seeded from input despite no `did` in response.
    assert auth.current_device_id == "DID_from_settings"
    assert auth._cached_device_id == "DID_from_settings"

    # Relogin must reuse the cached did — not fall through to password-only.
    auth.current_session_id = "SID_ABOUT_TO_EXPIRE"
    assert auth.relogin() is True

    relogin_params = calls[1]["params"]
    assert relogin_params["device_id"] == "DID_from_settings"
    assert "otp_code" not in relogin_params


def test_relogin_reuses_cached_device_id(monkeypatch):
    """relogin() after a 2FA login must pass the cached did as `device_id`
    so DSM doesn't ask for OTP on session recovery (error 119 path)."""
    from auth.synology_auth import SynologyAuth

    initial = {
        "success": True,
        "data": {"sid": "SID_OLD", "synotoken": "T_OLD", "did": "DID_reuse"},
    }
    refreshed = {
        "success": True,
        "data": {"sid": "SID_NEW", "synotoken": "T_NEW", "did": "DID_reuse"},
    }
    calls = _patch_requests_get(monkeypatch, [initial, refreshed])

    auth = SynologyAuth("https://nas.example.test:5001")
    auth.login("alice", "pw", otp_code="111222")
    # Pre-arm a different SID so relogin doesn't no-op under the "already
    # refreshed" guard.
    stale = auth.current_session_id
    auth.current_session_id = stale  # unchanged; relogin sees no change

    # Force a relogin call that actually hits login_with_session.
    assert auth.relogin() is True

    # Second call (relogin) must include device_id; no otp_code/enable_device_token.
    relogin_params = calls[1]["params"]
    assert relogin_params["device_id"] == "DID_reuse"
    assert "otp_code" not in relogin_params
    assert "enable_device_token" not in relogin_params


def test_logout_clears_device_id_cache(monkeypatch):
    """User-initiated logout forgets the trusted-device token, mirroring the
    cached-credentials drop — otherwise a later 119 would silently re-auth
    against the user's explicit logout."""
    from auth.synology_auth import SynologyAuth

    login_payload = {
        "success": True,
        "data": {"sid": "SID_3", "synotoken": "T", "did": "DID_forget_me"},
    }
    logout_payload = {"success": True}
    _patch_requests_get(monkeypatch, [login_payload, logout_payload])

    auth = SynologyAuth("https://nas.example.test:5001")
    auth.login("alice", "pw", otp_code="333444")
    assert auth._cached_device_id == "DID_forget_me"

    auth.logout()
    assert auth.current_device_id is None
    assert auth._cached_device_id is None


def test_get_session_info_includes_device_id():
    """get_session_info surfaces device_id so callers (e.g. mcp_server status
    tool) can show the operator whether the session is OTP-exempt."""
    from auth.synology_auth import SynologyAuth

    auth = SynologyAuth("https://nas.example.test:5001")
    auth.current_device_id = "DID_visible"
    info = auth.get_session_info()
    assert info["device_id"] == "DID_visible"


# ---------------------------------------------------------------------------
# Credential-and-session-leak hardening (PR 1) unit tests
# ---------------------------------------------------------------------------


def test_login_sends_credentials_via_post_not_url(monkeypatch):
    """The password/OTP/device-token must travel in the POST body, never the
    URL query string — a GET would put them in DSM's access log, any
    intermediate proxy's log, and in `requests`' own exception text."""
    from auth.synology_auth import SynologyAuth

    success_payload = {"success": True, "data": {"sid": "SID_post", "synotoken": "T"}}
    calls = _patch_requests_get(monkeypatch, [success_payload])

    auth = SynologyAuth("https://nas.example.test:5001")
    auth.login("alice", "hunter2", otp_code="123456")

    assert len(calls) == 1
    assert calls[0]["method"] == "POST"
    assert "hunter2" not in calls[0]["url"]
    assert "passwd=" not in calls[0]["url"]
    # The password is still sent — just in the body, not the URL.
    assert calls[0]["params"]["passwd"] == "hunter2"


def test_logout_sends_session_id_via_post_not_url(monkeypatch):
    """logout() must carry `_sid` in the POST body too — the same leak
    vector login() was fixed for (visible in DSM's own access log and any
    intermediate proxy's log) applies equally to logout's session id."""
    from auth.synology_auth import SynologyAuth

    login_payload = {"success": True, "data": {"sid": "SID_to_logout", "synotoken": "T"}}
    logout_payload = {"success": True}
    calls = _patch_requests_get(monkeypatch, [login_payload, logout_payload])

    auth = SynologyAuth("https://nas.example.test:5001")
    auth.login("alice", "pw")
    auth.logout()

    assert len(calls) == 2
    assert calls[1]["method"] == "POST"
    assert "SID_to_logout" not in calls[1]["url"]
    assert "_sid=" not in calls[1]["url"]
    assert calls[1]["params"]["_sid"] == "SID_to_logout"


def test_auth_outcome_error_does_not_retry_other_api_versions(monkeypatch):
    """A DSM auth-outcome error (account disabled, IP auto-blocked, 2SV
    required, ...) means DSM already made its decision on these credentials.
    Retrying with another API version would just resubmit the same password
    again, feeding exactly the pattern DSM's Auto Block watches for."""
    from auth.synology_auth import SynologyAuth

    # Only one payload queued: if the code tries a second API version, the
    # fake will hand back the default `{"success": False}` instead, and the
    # call-count assertion below catches it either way.
    calls = _patch_requests_get(monkeypatch, [{"success": False, "error": {"code": 401}}])

    auth = SynologyAuth("https://nas.example.test:5001")
    result = auth.login("alice", "pw")

    assert result["success"] is False
    assert len(calls) == 1, "a 401 (account disabled) must not trigger a version-fallback retry"


def test_unsupported_version_error_retries_next_api_version(monkeypatch):
    """A parameter/API/method/version-not-supported error (102) is a reason
    to try the next API version — unlike an auth-outcome error, DSM hasn't
    made an authentication decision yet."""
    from auth.synology_auth import SynologyAuth

    calls = _patch_requests_get(
        monkeypatch,
        [
            {"success": False, "error": {"code": 102}},
            {"success": True, "data": {"sid": "SID_v_fallback", "synotoken": "T"}},
        ],
    )

    auth = SynologyAuth("https://nas.example.test:5001")
    result = auth.login("alice", "pw")

    assert result["success"] is True
    assert len(calls) == 2, "an unsupported-API error should fall back to the next API version"


# ---------------------------------------------------------------------------
# Distinguished connection errors (PR 3): certificate/unreachable/timeout
# failures get a specific, sanitized message instead of a blanket
# "Authentication failed" — and none of them retry other API versions,
# since a transport-level failure isn't fixed by changing the payload.
# ---------------------------------------------------------------------------


def _patch_requests_post_raises(monkeypatch, exception):
    """Make every requests.post call in synology_auth raise `exception`."""
    import auth.synology_auth as mod

    calls = []

    def _fake_post(url, data=None, verify=None, timeout=None, **kwargs):
        calls.append({"url": url, "data": dict(data or {})})
        raise exception

    monkeypatch.setattr(mod.requests, "post", _fake_post)
    return calls


def test_certificate_error_stops_immediately_with_a_specific_message(monkeypatch):
    import requests

    from auth.synology_auth import SynologyAuth

    calls = _patch_requests_post_raises(
        monkeypatch, requests.exceptions.SSLError("certificate verify failed")
    )

    auth = SynologyAuth("https://nas.example.test:5001")
    result = auth.login("alice", "hunter2")

    assert result["success"] is False
    assert result["error"]["code"] == "certificate_error"
    assert "certificate" in result["error"]["message"].lower()
    assert "hunter2" not in result["error"]["message"]
    assert len(calls) == 1, "a certificate error must not retry other API versions"


def test_connection_error_stops_immediately_with_a_specific_message(monkeypatch):
    import requests

    from auth.synology_auth import SynologyAuth

    calls = _patch_requests_post_raises(
        monkeypatch, requests.exceptions.ConnectionError("Connection refused")
    )

    auth = SynologyAuth("https://nas.example.test:5001")
    result = auth.login("alice", "hunter2")

    assert result["success"] is False
    assert result["error"]["code"] == "connection_error"
    assert "hunter2" not in result["error"]["message"]
    assert len(calls) == 1, "a connection error must not retry other API versions"


def test_timeout_error_stops_immediately_with_a_specific_message(monkeypatch):
    import requests

    from auth.synology_auth import SynologyAuth

    calls = _patch_requests_post_raises(monkeypatch, requests.exceptions.Timeout("timed out"))

    auth = SynologyAuth("https://nas.example.test:5001")
    result = auth.login("alice", "pw")

    assert result["success"] is False
    assert result["error"]["code"] == "connection_timeout"
    assert "timed out" in result["error"]["message"].lower()
    assert len(calls) == 1, "a timeout must not retry other API versions"


def test_unexpected_transport_exception_still_retries_other_versions(monkeypatch):
    """A non-SSL/connection/timeout exception (e.g. a malformed response)
    keeps the old fall-through-to-next-version behavior."""
    from auth.synology_auth import SynologyAuth

    calls = _patch_requests_post_raises(monkeypatch, ValueError("unexpected"))

    auth = SynologyAuth("https://nas.example.test:5001")
    result = auth.login("alice", "pw")

    assert result["success"] is False
    assert result["error"]["code"] == "unknown"
    assert len(calls) == 4, "an unrecognized exception should still try every API version"
