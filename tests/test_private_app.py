"""The private login interface, end to end, in-process (no sockets).

What is checked is what the source plan promises of it: only the owner reaches
it, every state-changing request needs the owner session, a CSRF token and the
right Origin, every response carries the security headers, an MCP client's token
opens nothing here, and no password, code or session ever appears in a response,
a cookie, a redirect or a log line.
"""

import contextlib
import logging
import re
from unittest.mock import patch

import httpx2
import pytest

from broker.server import create_broker_app
from private_auth.app import create_private_app
from private_auth.login import LoginService
from private_auth.security import SECURITY_HEADERS, OwnerSessions, RateLimiter
from tests.broker_support import Broker

ORIGIN = "https://private.test"
JSON_HEADERS = {"Origin": ORIGIN}
PASSWORD = "PRIVATE-PASSWORD-MARKER-4d2e"
OTP = "482913"
CLIENTS = {
    "alice": {
        "token": "alice-token-value",
        "nas": ["nas1"],
        "folders": {"nas1": ["/docs", "/photos/2026"]},
    },
    "bob": {
        "token": "bob-token-value",
        "nas": ["nas1", "nas2"],
        "tools": ["list_shares", "synology_status"],
    },
}
OK = {"ok": True, "sid": "SID-FROM-WORKER", "synotoken": "TOK-FROM-WORKER"}


class FakeOwner:
    """Stands in for the passkey check: the credential {"proof": "ok"} is the owner."""

    def __init__(self, enrolled=True):
        self.enrolled = enrolled

    def has_owner(self):
        return self.enrolled

    def begin_authentication(self):
        return ("state-1", {"challenge": "c"}) if self.enrolled else None

    def finish_authentication(self, state, credential):
        return state == "state-1" and credential == {"proof": "ok"}

    def begin_enrollment(self, code):
        return None

    def finish_enrollment(self, state, credential, label="passkey"):
        return False


class Runner:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.requests = []

    async def __call__(self, payload):
        self.requests.append(dict(payload))
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


class Private:
    """The app plus everything a test wants to look at."""

    def __init__(self, broker, runner, owner):
        self.broker, self.runner, self.owner = broker, runner, owner
        self.login = LoginService(broker.runtime, runner=runner, clock=broker.clock)
        self.owner_sessions = OwnerSessions(
            idle_seconds=600, absolute_seconds=3600, clock=broker.clock
        )
        self.auth_limiter = RateLimiter(10, 300, lockout_seconds=300, clock=broker.clock)
        self.app = create_private_app(
            broker.runtime,
            self.login,
            owner,
            allowed_origins=[ORIGIN],
            allowed_hosts=["private.test"],
            sessions=self.owner_sessions,
            auth_limiter=self.auth_limiter,
        )

    @contextlib.asynccontextmanager
    async def client(self):
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=self.app), base_url=ORIGIN
        ) as http:
            yield http


@pytest.fixture
def broker(monkeypatch):
    return Broker(
        monkeypatch,
        CLIENTS,
        session={"idle_seconds": 100, "absolute_seconds": 1000, "pending_seconds": 50},
    )


@pytest.fixture
def private(broker):
    return Private(broker, Runner(OK), FakeOwner())


async def sign_in(http):
    begin = await http.post("/auth/begin", headers=JSON_HEADERS, json={})
    done = await http.post(
        "/auth/finish",
        headers=JSON_HEADERS,
        json={"state": begin.json()["state"], "credential": {"proof": "ok"}},
    )
    assert done.status_code == 200
    return done


def csrf_of(page: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


async def csrf(http) -> str:
    return csrf_of((await http.get("/")).text)


def form(token, **fields):
    return {"csrf": token, **fields}


async def start_pending(http, client="alice", nas="nas1"):
    token = await csrf(http)
    response = await http.post(
        "/pending/new", headers=JSON_HEADERS, data=form(token, client=client, nas=nas)
    )
    assert response.status_code == 303
    return response.headers["location"], token


def text_of(*responses) -> str:
    """Everything a response shows: its body, headers and cookies."""
    return "\n".join(
        r.text + str(dict(r.headers)) + str(dict(r.cookies)) + str(r.url) for r in responses
    )


class TestNotSignedIn:
    @pytest.mark.asyncio
    async def test_the_front_page_asks_for_a_passkey_and_shows_nothing_else(self, private):
        async with private.client() as http:
            page = (await http.get("/")).text

        assert "Sign in with passkey" in page
        for private_fact in ("alice", "bob", "nas1", "nas2", "docs", "reader"):
            assert private_fact not in page

    @pytest.mark.asyncio
    async def test_a_login_page_is_not_shown_to_anyone_who_has_not_signed_in(self, private):
        pending = private.broker.sessions.begin_pending("alice", "nas1")
        async with private.client() as http:
            response = await http.get(f"/login/{pending.request_id}")

        assert response.status_code == 303 and response.headers["location"] == "/"
        assert "alice" not in response.text and "reader" not in response.text

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "path", ["/pending/new", "/pending/cancel", "/disconnect", "/logout", "/login/anything"]
    )
    async def test_every_action_refuses_a_request_with_no_origin(self, private, path):
        async with private.client() as http:
            response = await http.post(path, data={"csrf": "x"})
        assert response.status_code == 403

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "path", ["/pending/new", "/pending/cancel", "/disconnect", "/logout", "/login/anything"]
    )
    async def test_every_action_refuses_an_unauthenticated_request_even_with_the_right_origin(
        self, private, path
    ):
        async with private.client() as http:
            response = await http.post(path, headers=JSON_HEADERS, data={"csrf": "x"})
        assert response.status_code == 401
        assert private.runner.requests == []

    @pytest.mark.asyncio
    async def test_an_mcp_clients_token_opens_nothing(self, private):
        bearer = {"Authorization": "Bearer alice-token-value"}
        async with private.client() as http:
            page = await http.get("/", headers=bearer)
            post = await http.post(
                "/pending/new", headers={**JSON_HEADERS, **bearer}, data={"csrf": "x"}
            )
            login = await http.get("/login/abc", headers=bearer)

        assert "Sign in with passkey" in page.text and "alice" not in page.text
        assert post.status_code == 401
        assert login.status_code == 303

    @pytest.mark.asyncio
    async def test_with_no_owner_enrolled_it_says_how_to_enrol_and_offers_no_sign_in(self, broker):
        private = Private(broker, Runner(OK), FakeOwner(enrolled=False))
        async with private.client() as http:
            page = await http.get("/")
            begin = await http.post("/auth/begin", headers=JSON_HEADERS, json={})

        assert "No owner enrolled" in page.text and "Enroll a passkey" in page.text
        assert begin.status_code == 409


class TestHostNames:
    """TrustedHostMiddleware compares the Host header without its port, so a name
    written with one used to match nothing and every request was refused."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("configured", ["private.test", "private.test:8444"])
    async def test_a_host_may_be_configured_with_or_without_its_port(self, broker, configured):
        app = create_private_app(
            broker.runtime,
            LoginService(broker.runtime, runner=Runner(OK), clock=broker.clock),
            FakeOwner(),
            allowed_origins=[ORIGIN],
            allowed_hosts=[configured],
        )
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url=ORIGIN
        ) as http:
            ok = await http.get("/healthz", headers={"Host": "private.test:8444"})
            bare = await http.get("/healthz", headers={"Host": "private.test"})
            other = await http.get("/healthz", headers={"Host": "other.test:8444"})

        assert (ok.status_code, bare.status_code, other.status_code) == (200, 200, 400)

    def test_the_entry_point_defaults_name_hosts_without_a_port(self):
        import argparse

        import broker_main

        args = argparse.Namespace(
            private_origin="http://127.0.0.1:9999",
            private_host=None,
            host="127.0.0.1",
            private_port=9999,
            private_tls_cert=None,
            private_tls_key=None,
            tls_cert=None,
            tls_key=None,
            allow_plain_http_loopback=True,
            private_allowed_host=[],
            rp_id=None,
            owner_store="o.json",
        )
        settings = broker_main._private_settings(args)
        assert settings["allowed_hosts"] == ["127.0.0.1", "localhost"]
        assert settings["secure_cookies"] is False


class TestEveryResponseIsGuarded:
    @pytest.mark.asyncio
    async def test_the_security_headers_are_on_every_kind_of_response(self, private):
        async with private.client() as http:
            responses = [
                await http.get("/"),
                await http.get("/enroll"),
                await http.get("/healthz"),
                await http.get("/static/app.css"),
                await http.get("/static/passkey.js"),
                await http.get("/no/such/page"),
                await http.post("/logout", data={}),  # refused: no origin
                await http.post("/auth/begin", json={}),  # refused: no origin
                await http.get("/", headers={"Host": "evil.example"}),  # refused: wrong host
            ]
            await sign_in(http)
            responses += [await http.get("/"), await http.get("/login/unknown")]

        statuses = [r.status_code for r in responses]
        assert {200, 303, 400, 403, 404} <= set(statuses) or {200, 400, 403, 404} <= set(statuses)
        for response in responses:
            for name, value in SECURITY_HEADERS.items():
                assert response.headers.get(name) == value, (response.url, name)

    @pytest.mark.asyncio
    async def test_a_wrong_host_is_refused(self, private):
        async with private.client() as http:
            response = await http.get("/", headers={"Host": "rebound.example"})
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_no_page_has_inline_script_or_style_or_loads_anything_from_elsewhere(
        self, private
    ):
        async with private.client() as http:
            await sign_in(http)
            pending_url, _ = await start_pending(http)
            pages = [(await http.get(path)).text for path in ("/", "/enroll", pending_url)]
            script = (await http.get("/static/passkey.js")).text
            style = (await http.get("/static/app.css")).text

        for page in pages:
            assert not re.search(r"<script(?![^>]*\bsrc=)", page), "inline script"
            assert "style=" not in page and "<style" not in page
            assert " onclick=" not in page and "javascript:" not in page
            assert not re.search(r"""(?:src|href|action)=["']https?://""", page)
        assert "http://" not in script and "https://" not in script
        assert "@import" not in style and "url(" not in style


class TestOwnerSignIn:
    @pytest.mark.asyncio
    async def test_the_cookie_is_host_only_secure_http_only_and_strict(self, private):
        async with private.client() as http:
            response = await sign_in(http)

        cookie = response.headers["set-cookie"]
        assert cookie.startswith("__Host-owner=")
        for flag in ("Secure", "HttpOnly", "SameSite=strict", "Path=/"):
            assert flag in cookie
        assert "Domain" not in cookie

    @pytest.mark.asyncio
    async def test_a_passkey_that_is_not_accepted_gives_no_session(self, private):
        async with private.client() as http:
            begin = await http.post("/auth/begin", headers=JSON_HEADERS, json={})
            bad = await http.post(
                "/auth/finish",
                headers=JSON_HEADERS,
                json={"state": begin.json()["state"], "credential": {"proof": "forged"}},
            )
            page = (await http.get("/")).text

        assert bad.status_code == 401 and "set-cookie" not in bad.headers
        assert "Sign in with passkey" in page

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "origin", [None, "https://evil.example", "http://private.test", "null"]
    )
    async def test_sign_in_needs_the_right_origin(self, private, origin):
        headers = {} if origin is None else {"Origin": origin}
        async with private.client() as http:
            begin = await http.post("/auth/begin", headers=headers, json={})
            finish = await http.post(
                "/auth/finish",
                headers=headers,
                json={"state": "state-1", "credential": {"proof": "ok"}},
            )
        assert begin.status_code == 403 and finish.status_code == 403
        assert "set-cookie" not in finish.headers

    @pytest.mark.asyncio
    async def test_repeated_failures_lock_the_address_even_against_the_right_passkey(self, private):
        async with private.client() as http:
            for _ in range(10):
                bad = await http.post(
                    "/auth/finish",
                    headers=JSON_HEADERS,
                    json={"state": "state-1", "credential": {"proof": "no"}},
                )
                assert bad.status_code == 401
            locked = await http.post(
                "/auth/finish",
                headers=JSON_HEADERS,
                json={"state": "state-1", "credential": {"proof": "ok"}},
            )
            private.broker.clock.advance(301)
            begin = await http.post("/auth/begin", headers=JSON_HEADERS, json={})
            again = await http.post(
                "/auth/finish",
                headers=JSON_HEADERS,
                json={"state": begin.json()["state"], "credential": {"proof": "ok"}},
            )

        assert locked.status_code == 429 and "set-cookie" not in locked.headers
        assert again.status_code == 200

    @pytest.mark.asyncio
    async def test_malformed_input_is_refused_not_a_crash(self, private):
        async with private.client() as http:
            for body in ("not json", "[]", '{"state": 5, "credential": "x"}', "{}"):
                response = await http.post(
                    "/auth/finish",
                    headers={**JSON_HEADERS, "Content-Type": "application/json"},
                    content=body,
                )
                assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_the_session_ends_when_idle(self, private):
        async with private.client() as http:
            await sign_in(http)
            assert "Synology broker" in (await http.get("/")).text
            private.broker.clock.advance(601)
            assert "Sign in with passkey" in (await http.get("/")).text

    @pytest.mark.asyncio
    async def test_signing_out_ends_the_session_and_clears_the_cookie(self, private):
        async with private.client() as http:
            await sign_in(http)
            token = await csrf(http)
            refused = await http.post("/logout", headers=JSON_HEADERS, data={})
            out = await http.post("/logout", headers=JSON_HEADERS, data=form(token))
            http.cookies.clear()  # a browser would drop the expired cookie
            after = await http.get("/")

        assert refused.status_code == 403
        assert out.status_code == 303 and "Max-Age=0" in out.headers["set-cookie"]
        assert "Sign in with passkey" in after.text


class TestDashboard:
    @pytest.mark.asyncio
    async def test_it_lists_every_client_and_nas_with_its_state(self, private):
        async with private.client() as http:
            await sign_in(http)
            page = (await http.get("/")).text

        rows = re.findall(r"<tr><td>(\w+)</td><td>(\w+)</td><td>([^<]+)</td>", page)
        assert rows == [
            ("alice", "nas1", "not connected"),
            ("bob", "nas1", "not connected"),
            ("bob", "nas2", "not connected"),
        ]

    @pytest.mark.asyncio
    async def test_it_shows_connected_and_waiting_states(self, private):
        private.broker.sign_in("alice", "nas1")
        private.broker.sessions.begin_pending("bob", "nas1")
        async with private.client() as http:
            await sign_in(http)
            page = (await http.get("/")).text

        assert re.search(r"<td>alice</td><td>nas1</td><td>connected \(idle limit", page)
        assert "waiting for you to sign in" in page
        assert "SID-1" not in page and "TOK-1" not in page

    @pytest.mark.asyncio
    async def test_every_form_carries_the_csrf_token(self, private):
        async with private.client() as http:
            await sign_in(http)
            page = (await http.get("/")).text
        forms = re.findall(r"<form .*?</form>", page, flags=re.S)
        assert forms and all('name="csrf"' in f for f in forms)


class TestStartingASignIn:
    @pytest.mark.asyncio
    async def test_it_needs_a_csrf_token_that_matches_the_session(self, private):
        async with private.client() as http:
            await sign_in(http)
            fields = {"client": "alice", "nas": "nas1"}
            missing = await http.post("/pending/new", headers=JSON_HEADERS, data=fields)
            wrong = await http.post(
                "/pending/new", headers=JSON_HEADERS, data=form("not-the-token", **fields)
            )

        assert (missing.status_code, wrong.status_code) == (403, 403)
        assert private.broker.sessions.pending("alice", "nas1") is None

    @pytest.mark.asyncio
    async def test_a_csrf_token_from_another_session_is_refused(self, private):
        async with private.client() as first, private.client() as second:
            await sign_in(first)
            await sign_in(second)
            other = await csrf(second)
            response = await first.post(
                "/pending/new", headers=JSON_HEADERS, data=form(other, client="alice", nas="nas1")
            )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_it_opens_the_request_for_that_client_and_nas(self, private):
        async with private.client() as http:
            await sign_in(http)
            location, _ = await start_pending(http, "bob", "nas2")

        pending = private.broker.sessions.pending("bob", "nas2")
        assert location == f"/login/{pending.request_id}"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "client,nas",
        [("mallory", "nas1"), ("alice", "nas2"), ("alice", "nope"), ("", ""), ("alice", "")],
    )
    async def test_an_unknown_pair_is_not_found_and_creates_nothing(self, private, client, nas):
        async with private.client() as http:
            await sign_in(http)
            token = await csrf(http)
            response = await http.post(
                "/pending/new", headers=JSON_HEADERS, data=form(token, client=client, nas=nas)
            )
        assert response.status_code == 404
        assert private.broker.sessions.pending("alice", "nas2") is None

    @pytest.mark.asyncio
    async def test_a_models_call_without_a_session_leaves_a_request_for_the_owner_to_see(
        self, private
    ):
        result = await private.broker.runtime.call_tool(
            "alice", "list_shares", {"nas_name": "nas1"}
        )
        pending = private.broker.sessions.pending("alice", "nas1")

        assert result.is_error is True and result.content[0].text.startswith(
            "AUTHENTICATION_REQUIRED"
        )
        assert pending is not None
        # What the model is told carries nothing that could be used to sign in.
        reply = result.content[0].text
        assert (
            pending.request_id not in reply
            and "http" not in reply.lower()
            and "/login" not in reply
        )
        async with private.client() as http:
            await sign_in(http)
            page = (await http.get("/")).text
        assert "waiting for you to sign in" in page and pending.request_id in page

    @pytest.mark.asyncio
    async def test_repeated_calls_leave_one_request_and_a_status_check_leaves_none(self, private):
        for _ in range(5):
            await private.broker.runtime.call_tool("alice", "list_shares", {"nas_name": "nas1"})
        first = private.broker.sessions.pending("alice", "nas1")
        await private.broker.runtime.call_tool("alice", "list_shares", {"nas_name": "nas1"})
        assert private.broker.sessions.pending("alice", "nas1") == first

        await private.broker.runtime.call_tool("bob", "synology_status", {})
        assert private.broker.sessions.pending("bob", "nas1") is None


class TestTheLoginPage:
    @pytest.mark.asyncio
    async def test_it_says_which_nas_which_account_which_client_and_what_access(self, private):
        async with private.client() as http:
            await sign_in(http)
            location, _ = await start_pending(http, "alice", "nas1")
            page = (await http.get(location)).text

        facts = dict(re.findall(r"<dt>([^<]+)</dt><dd>([^<]*)</dd>", page))
        assert facts["NAS"] == "nas1"
        assert facts["Account"] == "reader"
        assert facts["Requested by"] == "alice"
        assert facts["Folders it may reach"] == "/docs, /photos/2026"
        assert facts["Tools it may use"].isdigit()

    @pytest.mark.asyncio
    async def test_the_password_field_is_a_password_field_a_manager_can_fill(self, private):
        async with private.client() as http:
            await sign_in(http)
            location, _ = await start_pending(http)
            page = (await http.get(location)).text

        assert re.search(
            r'<input id="password" name="password" type="password" autocomplete="current-password"',
            page,
        )
        assert 'autocomplete="one-time-code"' in page
        assert 'name="username"' not in page  # the account is the configured one

    @pytest.mark.asyncio
    async def test_when_no_account_is_configured_the_owner_types_it(self, private):
        private.broker.nas_configs["nas1"]["username"] = ""
        async with private.client() as http:
            await sign_in(http)
            location, _ = await start_pending(http)
            page = (await http.get(location)).text
        assert 'name="username"' in page and "not set; you will type it" in page

    @pytest.mark.asyncio
    async def test_what_comes_from_configuration_is_escaped(self, private):
        private.broker.nas_configs["nas1"]["username"] = '<img src=x onerror="alert(1)">'
        async with private.client() as http:
            await sign_in(http)
            location, _ = await start_pending(http)
            page = (await http.get(location)).text
        assert "<img src=x" not in page and "&lt;img src=x" in page

    @pytest.mark.asyncio
    async def test_an_unknown_or_expired_request_shows_nothing(self, private):
        async with private.client() as http:
            await sign_in(http)
            location, _ = await start_pending(http)
            private.broker.clock.advance(51)
            expired = await http.get(location)
            unknown = await http.get("/login/not-a-request")

        for response in (expired, unknown):
            assert response.status_code == 404
            assert "alice" not in response.text and "reader" not in response.text

    @pytest.mark.asyncio
    async def test_a_password_in_the_url_is_not_submitted_or_shown(self, private):
        async with private.client() as http:
            await sign_in(http)
            location, _ = await start_pending(http)
            response = await http.get(f"{location}?password={PASSWORD}&otp={OTP}")

        assert (
            response.status_code == 200
            and PASSWORD not in response.text
            and OTP not in response.text
        )
        assert private.runner.requests == []


class TestSubmittingTheLogin:
    async def _submit(self, http, location, token, **fields):
        return await http.post(location, headers=JSON_HEADERS, data=form(token, **fields))

    @pytest.mark.asyncio
    async def test_a_good_password_connects_and_the_client_can_then_use_the_nas(self, private):
        from filestation import SynologyFileStation

        async with private.client() as http:
            await sign_in(http)
            location, token = await start_pending(http)
            done = await self._submit(http, location, token, password=PASSWORD, otp=OTP)
            page = (await http.get(done.headers["location"])).text

        assert done.status_code == 303 and done.headers["location"] == "/?m=connected"
        assert "Connected. The client can use the NAS now." in page
        assert re.search(r"<td>alice</td><td>nas1</td><td>connected", page)

        with patch.object(SynologyFileStation, "list_shares", return_value=[{"name": "docs"}]):
            result = await private.broker.runtime.call_tool(
                "alice", "list_shares", {"nas_name": "nas1"}
            )
        assert result.is_error is False

    @pytest.mark.asyncio
    async def test_the_worker_gets_the_typed_secrets_and_the_configured_account(self, private):
        async with private.client() as http:
            await sign_in(http)
            location, token = await start_pending(http)
            await self._submit(http, location, token, password=PASSWORD, otp=OTP, username="admin")

        (request,) = private.runner.requests
        assert (request["password"], request["otp"], request["username"]) == (
            PASSWORD,
            OTP,
            "reader",
        )

    @pytest.mark.asyncio
    async def test_a_wrong_password_shows_a_message_and_does_not_echo_anything(self, broker):
        private = Private(broker, Runner({"ok": False, "code": "400"}), FakeOwner())
        async with private.client() as http:
            await sign_in(http)
            location, token = await start_pending(http)
            response = await self._submit(http, location, token, password=PASSWORD, otp=OTP)

        assert response.status_code == 200
        assert "did not accept that account or password" in response.text
        assert PASSWORD not in text_of(response) and OTP not in text_of(response)
        assert "value=" not in re.sub(
            r'name="csrf" value="[^"]+"', "", response.text
        )  # fields come back empty
        assert broker.sessions.pending("alice", "nas1") is not None  # the owner may try again

    @pytest.mark.asyncio
    async def test_the_third_wrong_password_locks_the_sign_in(self, broker):
        private = Private(broker, Runner({"ok": False, "code": "400"}), FakeOwner())
        async with private.client() as http:
            await sign_in(http)
            location, token = await start_pending(http)
            for _ in range(3):
                await self._submit(http, location, token, password="wrong")
            locked = await self._submit(http, location, token, password=PASSWORD)

        assert locked.status_code == 429 and "Too many attempts" in locked.text
        assert len(private.runner.requests) == 3
        assert PASSWORD not in text_of(locked)

    @pytest.mark.asyncio
    async def test_a_missing_or_wrong_csrf_token_stops_it_before_the_worker(self, private):
        async with private.client() as http:
            await sign_in(http)
            location, _ = await start_pending(http)
            missing = await http.post(location, headers=JSON_HEADERS, data={"password": PASSWORD})
            wrong = await self._submit(http, location, "forged", password=PASSWORD)

        assert (missing.status_code, wrong.status_code) == (403, 403)
        assert private.runner.requests == []

    @pytest.mark.asyncio
    async def test_a_cross_site_post_is_refused_whatever_it_carries(self, private):
        async with private.client() as http:
            await sign_in(http)
            location, token = await start_pending(http)
            response = await http.post(
                location,
                headers={"Origin": "https://evil.example"},
                data=form(token, password=PASSWORD),
            )
        assert response.status_code == 403 and private.runner.requests == []

    @pytest.mark.asyncio
    async def test_a_request_that_expired_meanwhile_goes_back_to_the_start(self, private):
        async with private.client() as http:
            await sign_in(http)
            location, token = await start_pending(http)
            private.broker.clock.advance(51)
            response = await self._submit(http, location, token, password=PASSWORD)
        assert response.status_code == 303 and response.headers["location"] == "/?m=expired"
        assert private.runner.requests == []

    @pytest.mark.asyncio
    async def test_an_oversized_body_is_refused_unread(self, private):
        async with private.client() as http:
            await sign_in(http)
            location, token = await start_pending(http)
            response = await self._submit(http, location, token, password="x" * 9000)
        assert response.status_code == 400 and private.runner.requests == []

    @pytest.mark.asyncio
    async def test_notices_after_a_redirect_are_fixed_sentences_never_values(self, private):
        async with private.client() as http:
            await sign_in(http)
            page = (await http.get(f"/?m={PASSWORD}")).text
            known = (await http.get("/?m=cancelled")).text
        assert PASSWORD not in page
        assert "Sign-in request cancelled." in known


class TestDisconnectAndCancel:
    @pytest.mark.asyncio
    async def test_disconnect_ends_the_session_on_the_nas_and_only_that_clients(self, private):
        private.broker.sign_in("alice", "nas1", "SID-A")
        private.broker.sign_in("bob", "nas1", "SID-B")
        async with private.client() as http:
            await sign_in(http)
            token = await csrf(http)
            done = await http.post(
                "/disconnect", headers=JSON_HEADERS, data=form(token, client="alice", nas="nas1")
            )

        assert done.headers["location"] == "/?m=disconnected"
        assert private.broker.sessions.get("alice", "nas1", touch=False) is None
        assert private.broker.sessions.get("bob", "nas1", touch=False).session_id == "SID-B"
        assert private.broker.logged_out.wait(2)
        assert private.broker.logouts == [("https://nas1.example.test:5001", "SID-A")]

    @pytest.mark.asyncio
    async def test_cancel_withdraws_a_waiting_request(self, private):
        async with private.client() as http:
            await sign_in(http)
            location, token = await start_pending(http)
            done = await http.post(
                "/pending/cancel",
                headers=JSON_HEADERS,
                data=form(token, client="alice", nas="nas1"),
            )
            after = await http.get(location)

        assert done.headers["location"] == "/?m=cancelled"
        assert private.broker.sessions.pending("alice", "nas1") is None
        assert after.status_code == 404

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path", ["/disconnect", "/pending/cancel"])
    async def test_both_need_the_csrf_token(self, private, path):
        private.broker.sign_in("alice", "nas1")
        async with private.client() as http:
            await sign_in(http)
            response = await http.post(
                path, headers=JSON_HEADERS, data={"client": "alice", "nas": "nas1"}
            )
        assert response.status_code == 403
        assert private.broker.sessions.get("alice", "nas1", touch=False) is not None


class TestNothingSecretLeaks:
    @pytest.mark.asyncio
    async def test_the_password_and_code_appear_nowhere_but_the_workers_input(self, broker, caplog):
        caplog.set_level(logging.DEBUG)
        private = Private(broker, Runner({"ok": False, "code": "404"}, OK), FakeOwner())
        responses = []
        async with private.client() as http:
            responses.append(await sign_in(http))
            location, token = await start_pending(http)
            responses.append(await http.get(location))
            responses.append(await self._submit(http, location, token, password=PASSWORD, otp=OTP))
            responses.append(await self._submit(http, location, token, password=PASSWORD, otp=OTP))
            responses.append(await http.get("/?m=connected"))

        # It really was submitted, twice: the worker received it ...
        assert [r["password"] for r in private.runner.requests] == [PASSWORD, PASSWORD]
        # ... and it is in nothing else a person, a proxy or a log could see.
        shown = text_of(*responses)
        for secret in (PASSWORD, OTP):
            assert secret not in shown
            assert secret not in caplog.text
            assert secret not in repr(vars(private.login)) and secret not in repr(
                vars(private.owner_sessions)
            )
            assert secret not in repr(vars(broker.sessions)) and secret not in repr(
                vars(broker.runtime)
            )

    async def _submit(self, http, location, token, **fields):
        return await http.post(location, headers=JSON_HEADERS, data=form(token, **fields))

    @pytest.mark.asyncio
    async def test_the_session_it_obtains_is_not_shown_to_the_owner_either(self, private):
        async with private.client() as http:
            await sign_in(http)
            location, token = await start_pending(http)
            done = await http.post(
                location, headers=JSON_HEADERS, data=form(token, password=PASSWORD)
            )
            page = await http.get(done.headers["location"])
        for secret in ("SID-FROM-WORKER", "TOK-FROM-WORKER"):
            assert secret not in text_of(done, page)


class TestMcpCannotReachIt:
    CLIENT_AUTH = {"Authorization": "Bearer alice-token-value"}

    @pytest.mark.asyncio
    async def test_the_mcp_listener_serves_none_of_the_private_pages(self, broker):
        app = create_broker_app(broker.runtime, broker.policy, allowed_hosts=["testserver"])
        paths = [
            "/login/abc",
            "/auth/begin",
            "/pending/new",
            "/enroll",
            "/static/passkey.js",
            "/disconnect",
            "/",
        ]
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app),
                base_url="http://testserver",
                headers=self.CLIENT_AUTH,
            ) as http:
                statuses = {}
                for path in paths:
                    statuses[path] = (await http.get(path)).status_code
                    statuses["POST " + path] = (await http.post(path, json={})).status_code

        assert set(statuses.values()) <= {404, 405}, statuses

    @pytest.mark.asyncio
    async def test_no_tool_offers_to_sign_in_or_takes_a_password(self, broker):
        for client in CLIENTS:
            tools = await broker.runtime.list_tools(client)
            for tool in tools:
                assert "login" not in tool.name and "auth" not in tool.name, tool.name
                assert not {"password", "otp", "otp_code", "device_id"} & set(
                    tool.input_schema.get("properties", {})
                ), tool.name

    @pytest.mark.asyncio
    async def test_disconnecting_is_the_only_session_action_a_model_has(self, broker):
        names = {t.name for t in await broker.runtime.list_tools("alice")}
        assert {n for n in names if "logout" in n or "session" in n} == {"synology_logout"}
