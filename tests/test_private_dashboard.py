"""The private interface's dashboard, status endpoints, sign-in-all page and log.

These sit on top of the private login (see test_private_app.py, whose helpers are
reused): the same owner-session, Origin and CSRF rules apply, and what they show
or accept must never include a credential or a session value.
"""

import logging
import re

import httpx2
import pytest

from private_auth.app import create_private_app
from private_auth.logbuffer import RingLogHandler, attach
from private_auth.login import LoginService
from tests.broker_support import Broker
from tests.test_private_app import (
    CLIENTS,
    JSON_HEADERS,
    ORIGIN,
    OTP,
    PASSWORD,
    FakeOwner,
    Private,
    Runner,
    csrf,
    sign_in,
)

OK = {"ok": True, "sid": "SID-FROM-WORKER", "synotoken": "TOK-FROM-WORKER"}
WRONG_PASSWORD = {"ok": False, "code": "400"}
CODE_NEEDED = {"ok": False, "code": "403"}


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


async def step(http, token, client="alice", nas="nas1", **fields):
    body = {"csrf": token, "client": client, "nas": nas, "password": PASSWORD, "otp": ""}
    body.update(fields)
    return await http.post("/api/login-all/step", headers=JSON_HEADERS, json=body)


class TestSessionCounts:
    def test_counts_name_nobody_and_follow_the_session_clock(self, broker):
        broker.sign_in("alice", "nas1")
        broker.sessions.begin_pending("bob", "nas1")

        assert broker.sessions.counts(600) == {
            "waiting": 1,
            "connected": 1,
            "sessions_ending_soon": 0,
        }
        broker.clock.advance(1000 - 100)  # inside the last ten minutes of 1000 s, but idle first
        # idle (100 s) has run out by now, so the session is gone and is not "ending"
        assert broker.sessions.counts(600)["connected"] == 0

    def test_a_session_near_its_absolute_deadline_is_ending_soon(self, broker):
        broker.sign_in("alice", "nas1")
        for _ in range(9):  # keep it in use so only the absolute deadline matters
            broker.clock.advance(90)
            assert broker.sessions.get("alice", "nas1") is not None
        assert broker.sessions.counts(600)["sessions_ending_soon"] == 1


class TestAttention:
    @pytest.mark.asyncio
    async def test_it_answers_without_a_sign_in_and_with_numbers_only(self, private):
        private.broker.sign_in("alice", "nas1")
        private.broker.sessions.begin_pending("bob", "nas1")
        async with private.client() as http:
            response = await http.get("/attention")

        assert response.status_code == 200
        assert response.json() == {
            "waiting": 1,
            "connected": 1,
            "sessions_ending_soon": 0,
            "grants_ending_soon": 0,
        }
        for name in ("alice", "bob", "nas1", "nas2", "SID-1", "TOK-1", "docs"):
            assert name not in response.text
        assert response.headers["cache-control"] == "no-store"

    @pytest.mark.asyncio
    async def test_grants_that_end_within_two_weeks_are_counted(self, broker):
        import time

        private = Private(broker, Runner(OK), FakeOwner())
        # Re-create the app with a calendar clock 190 days ahead: the test grants
        # last 200 days, so they all end within the next fortnight from there.
        app = create_private_app(
            broker.runtime,
            private.login,
            private.owner,
            allowed_origins=[ORIGIN],
            allowed_hosts=["private.test"],
            wall_clock=lambda: time.time() + 190 * 86400,
        )
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url=ORIGIN
        ) as http:
            counts = (await http.get("/attention")).json()

        assert counts["grants_ending_soon"] == len(CLIENTS)


class TestApiState:
    @pytest.mark.asyncio
    async def test_it_needs_the_owner_session(self, private):
        async with private.client() as http:
            assert (await http.get("/api/state")).status_code == 401
            await sign_in(http)
            response = await http.get("/api/state")

        assert response.status_code == 200
        data = response.json()
        assert [(r["client"], r["nas"], r["state"]) for r in data["rows"]] == [
            ("alice", "nas1", "not connected"),
            ("bob", "nas1", "not connected"),
            ("bob", "nas2", "not connected"),
        ]
        assert data["signature"]

    @pytest.mark.asyncio
    async def test_it_shows_time_left_and_never_a_session_value(self, private):
        private.broker.sign_in("alice", "nas1")
        async with private.client() as http:
            await sign_in(http)
            response = await http.get("/api/state")

        row = response.json()["rows"][0]
        assert row["state"] == "connected" and row["left"].startswith("ends in ")
        assert "SID-1" not in response.text and "TOK-1" not in response.text

    @pytest.mark.asyncio
    async def test_polling_does_not_keep_the_owner_signed_in(self, private):
        async with private.client() as http:
            await sign_in(http)
            for _ in range(2):
                private.broker.clock.advance(400)  # the owner's idle limit is 600
                assert (await http.get("/api/state")).status_code in (200, 401)
            page = (await http.get("/")).text

        assert "Sign in with passkey" in page

    @pytest.mark.asyncio
    async def test_a_person_using_the_page_does_keep_it(self, private):
        async with private.client() as http:
            await sign_in(http)
            for _ in range(2):
                private.broker.clock.advance(400)
                assert (await http.get("/")).status_code == 200
            page = (await http.get("/")).text

        assert "Synology broker" in page


class TestDashboardAdditions:
    @pytest.mark.asyncio
    async def test_disconnect_all_is_offered_only_when_something_is_connected(self, private):
        async with private.client() as http:
            await sign_in(http)
            idle = (await http.get("/")).text
            private.broker.sign_in("alice", "nas1")
            live = (await http.get("/")).text

        assert "Disconnect all" not in idle and "Disconnect all" in live

    @pytest.mark.asyncio
    async def test_the_page_has_the_signature_and_the_refresh_script(self, private):
        async with private.client() as http:
            await sign_in(http)
            page = (await http.get("/")).text
            script = await http.get("/static/dashboard.js")

        assert 'id="rows"' in page and "data-signature=" in page
        assert '<script src="/static/dashboard.js" defer></script>' in page
        assert script.status_code == 200 and "/api/state" in script.text

    @pytest.mark.asyncio
    async def test_a_grant_that_ends_soon_is_flagged(self, broker):
        import time

        private = Private(broker, Runner(OK), FakeOwner())
        app = create_private_app(
            broker.runtime,
            private.login,
            private.owner,
            allowed_origins=[ORIGIN],
            allowed_hosts=["private.test"],
            sessions=private.owner_sessions,
            wall_clock=lambda: time.time() + 195 * 86400,
        )
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url=ORIGIN
        ) as http:
            await sign_in(http)
            page = (await http.get("/")).text

        assert "renew soon" in page and 'class="warn"' in page

    @pytest.mark.asyncio
    async def test_disconnect_all_ends_every_session_and_needs_the_csrf_token(self, private):
        private.broker.sign_in("alice", "nas1")
        private.broker.sign_in("bob", "nas2", session_id="SID-2")
        async with private.client() as http:
            await sign_in(http)
            token = await csrf(http)
            no_origin = await http.post("/disconnect-all", data={"csrf": token})
            bad_csrf = await http.post("/disconnect-all", headers=JSON_HEADERS, data={"csrf": "x"})
            assert private.broker.sessions.get("alice", "nas1", touch=False) is not None
            done = await http.post("/disconnect-all", headers=JSON_HEADERS, data={"csrf": token})

        assert no_origin.status_code == 403 and bad_csrf.status_code == 403
        assert done.status_code == 303 and done.headers["location"] == "/?m=all_disconnected"
        assert private.broker.sessions.get("alice", "nas1", touch=False) is None
        assert private.broker.sessions.get("bob", "nas2", touch=False) is None

    @pytest.mark.asyncio
    async def test_disconnect_all_refuses_a_request_with_no_session(self, private):
        async with private.client() as http:
            response = await http.post("/disconnect-all", headers=JSON_HEADERS, data={"csrf": "x"})
        assert response.status_code == 401


class TestSignInAllPage:
    @pytest.mark.asyncio
    async def test_it_is_for_the_signed_in_owner_only(self, private):
        async with private.client() as http:
            response = await http.get("/login-all")
        assert response.status_code == 303 and response.headers["location"] == "/"

    @pytest.mark.asyncio
    async def test_it_shows_what_each_client_gets_before_the_password_is_typed(self, private):
        private.broker.sign_in("bob", "nas2", session_id="SID-2")
        async with private.client() as http:
            await sign_in(http)
            page = (await http.get("/login-all")).text

        assert "/docs, /photos/2026" in page  # alice's folders
        assert page.count('class="pair"') == 3
        assert 'data-client="bob" data-nas="nas2" disabled' in page  # already connected
        assert 'data-client="alice" data-nas="nas1" checked' in page
        assert "reader" in page  # the account it signs in as
        assert 'name="csrf"' in page and 'type="password"' in page
        assert '<script src="/static/login_all.js" defer></script>' in page
        assert "SID-2" not in page

    @pytest.mark.asyncio
    async def test_posting_the_form_without_the_script_keeps_nothing(self, private):
        async with private.client() as http:
            response = await http.post("/login-all", data={"password": PASSWORD})
        assert response.status_code == 400
        assert PASSWORD not in response.text and private.runner.requests == []

    @pytest.mark.asyncio
    async def test_the_script_is_served_and_has_no_foreign_addresses(self, private):
        async with private.client() as http:
            script = await http.get("/static/login_all.js")
        assert script.status_code == 200 and "/api/login-all/step" in script.text
        assert "http://" not in script.text and "https://" not in script.text


class TestSignInAllStep:
    @pytest.mark.asyncio
    async def test_it_signs_one_client_in_and_hands_the_password_only_to_the_worker(self, private):
        async with private.client() as http:
            await sign_in(http)
            token = await csrf(http)
            response = await step(http, token, otp=OTP)

        assert response.json() == {"ok": True, "code": "connected", "message": "Connected."}
        assert private.broker.sessions.get("alice", "nas1", touch=False) is not None
        assert private.runner.requests[0]["password"] == PASSWORD
        assert private.runner.requests[0]["otp"] == OTP
        shown = response.text + str(dict(response.headers))
        assert PASSWORD not in shown and OTP not in shown and "SID-FROM-WORKER" not in shown

    @pytest.mark.asyncio
    async def test_one_password_signs_in_each_client_in_turn(self, private):
        async with private.client() as http:
            await sign_in(http)
            token = await csrf(http)
            results = [
                (await step(http, token, client=c, nas=n)).json()["ok"]
                for c, n in (("alice", "nas1"), ("bob", "nas1"), ("bob", "nas2"))
            ]

        assert results == [True, True, True]
        assert len(private.runner.requests) == 3
        assert private.broker.sessions.counts(600)["connected"] == 3

    @pytest.mark.asyncio
    async def test_a_wrong_password_is_reported_by_code_and_connects_nothing(self, broker):
        private = Private(broker, Runner(WRONG_PASSWORD), FakeOwner())
        async with private.client() as http:
            await sign_in(http)
            token = await csrf(http)
            response = await step(http, token)

        data = response.json()
        assert data["ok"] is False and data["code"] == "400"
        assert "password" in data["message"].lower()
        assert PASSWORD not in response.text
        assert broker.sessions.counts(600)["connected"] == 0

    @pytest.mark.asyncio
    async def test_a_code_that_is_needed_is_not_counted_as_a_wrong_answer(self, broker):
        private = Private(broker, Runner(CODE_NEEDED, OK), FakeOwner())
        async with private.client() as http:
            await sign_in(http)
            token = await csrf(http)
            first = await step(http, token)
            second = await step(http, token, otp=OTP)

        assert first.json()["code"] == "403" and second.json()["ok"] is True

    @pytest.mark.asyncio
    async def test_three_wrong_answers_lock_that_pair_and_not_the_next(self, broker):
        private = Private(broker, Runner(WRONG_PASSWORD), FakeOwner())
        async with private.client() as http:
            await sign_in(http)
            token = await csrf(http)
            codes = [(await step(http, token)).json()["code"] for _ in range(4)]
            other = (await step(http, token, client="bob")).json()["code"]

        assert codes == ["400", "400", "400", "locked"]
        assert other == "400"  # bob's pair has its own count
        assert len(private.runner.requests) == 4

    @pytest.mark.asyncio
    async def test_it_refuses_a_missing_origin_session_or_csrf_token(self, private):
        async with private.client() as http:
            no_origin = await http.post(
                "/api/login-all/step", json={"csrf": "x", "client": "alice", "nas": "nas1"}
            )
            no_session = await step(http, "x")
            await sign_in(http)
            bad_csrf = await step(http, "wrong")
            missing_csrf = await http.post(
                "/api/login-all/step",
                headers=JSON_HEADERS,
                json={"client": "alice", "nas": "nas1", "password": PASSWORD},
            )

        assert (no_origin.status_code, no_session.status_code) == (403, 401)
        assert (bad_csrf.status_code, missing_csrf.status_code) == (403, 403)
        assert private.runner.requests == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "fields, status",
        [
            ({"client": "mallory"}, 404),
            ({"nas": "nas2"}, 404),  # alice may not use nas2
            ({"nas": "nowhere"}, 404),
            ({"password": ""}, 400),
            ({"password": 5}, 400),
            ({"client": ["alice"]}, 400),
        ],
    )
    async def test_it_refuses_a_pair_or_body_that_is_not_valid(self, private, fields, status):
        async with private.client() as http:
            await sign_in(http)
            token = await csrf(http)
            response = await step(http, token, **fields)

        assert response.status_code == status
        assert private.runner.requests == []

    @pytest.mark.asyncio
    async def test_an_mcp_clients_token_cannot_use_it(self, private):
        async with private.client() as http:
            response = await http.post(
                "/api/login-all/step",
                headers={**JSON_HEADERS, "Authorization": "Bearer alice-token-value"},
                json={"csrf": "x", "client": "alice", "nas": "nas1", "password": PASSWORD},
            )
        assert response.status_code == 401 and private.runner.requests == []

    @pytest.mark.asyncio
    async def test_the_password_never_reaches_a_log_line(self, private, caplog):
        with caplog.at_level(logging.DEBUG):
            async with private.client() as http:
                await sign_in(http)
                token = await csrf(http)
                await step(http, token, otp=OTP)
        assert PASSWORD not in caplog.text and OTP not in caplog.text


class TestLogBuffer:
    def test_it_keeps_only_the_newest_lines(self):
        handler = RingLogHandler(capacity=3)
        logger = logging.getLogger("test-ring-capacity")
        logger.propagate = False
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        for number in range(5):
            logger.info("line %d", number)
        assert [line.split()[-1] for line in handler.lines()] == ["2", "3", "4"]

    def test_requests_the_app_makes_by_itself_are_left_out(self):
        handler = RingLogHandler()
        logger = logging.getLogger("uvicorn.access")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        try:
            logger.info('127.0.0.1 - "GET /attention HTTP/1.1" 200')
            logger.info('127.0.0.1 - "GET /api/state HTTP/1.1" 200')
            logger.info('127.0.0.1 - "POST /disconnect HTTP/1.1" 303')
        finally:
            logger.removeHandler(handler)
        assert len(handler.lines()) == 1 and "/disconnect" in handler.lines()[0]

    def test_it_takes_the_format_and_the_redaction_of_the_handlers_already_there(self):
        class Mask(logging.Filter):
            def filter(self, record):
                record.msg = str(record.msg).replace("SECRET-VALUE", "***")
                return True

        root = logging.getLogger()
        existing = logging.StreamHandler()
        existing.setFormatter(logging.Formatter("FMT %(message)s"))
        existing.addFilter(Mask())
        # Only this handler on the root, as in the broker: pytest's own capture
        # handler would otherwise be the one whose format is copied.
        before = list(root.handlers)
        root.handlers[:] = [existing]
        try:
            handler = attach()
            logging.getLogger("redaction-check").warning("token SECRET-VALUE here")
            lines = handler.lines()
        finally:
            root.handlers[:] = before

        assert lines and lines[-1] == "FMT token *** here"


class TestLogPage:
    def make(self, broker, lines):
        buffer = RingLogHandler()
        logger = logging.getLogger("test-log-page")
        logger.propagate = False
        logger.addHandler(buffer)
        logger.setLevel(logging.INFO)
        for line in lines:
            logger.info(line)
        private = Private(broker, Runner(OK), FakeOwner())
        app = create_private_app(
            broker.runtime,
            LoginService(broker.runtime, runner=Runner(OK), clock=broker.clock),
            private.owner,
            allowed_origins=[ORIGIN],
            allowed_hosts=["private.test"],
            sessions=private.owner_sessions,
            log_buffer=buffer,
        )
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=ORIGIN)

    @pytest.mark.asyncio
    async def test_it_is_for_the_signed_in_owner_only(self, broker):
        async with self.make(broker, ["a line"]) as http:
            page = await http.get("/log")
            api = await http.get("/api/log")

        assert page.status_code == 303 and page.headers["location"] == "/"
        assert api.status_code == 401

    @pytest.mark.asyncio
    async def test_it_shows_the_lines_escaped(self, broker):
        async with self.make(broker, ["started", "<script>alert(1)</script>"]) as http:
            await sign_in(http)
            page = (await http.get("/log")).text
            api = (await http.get("/api/log")).json()

        assert "started" in page
        assert "<script>alert" not in page and "&lt;script&gt;" in page
        assert not re.search(r"<script(?![^>]*\bsrc=)", page)
        assert api["lines"][-1] == "<script>alert(1)</script>"

    @pytest.mark.asyncio
    async def test_a_broker_with_no_buffer_says_so(self, private):
        async with private.client() as http:
            await sign_in(http)
            page = (await http.get("/log")).text
            api = await http.get("/api/log")

        assert "keeps no log" in page and api.status_code == 401
