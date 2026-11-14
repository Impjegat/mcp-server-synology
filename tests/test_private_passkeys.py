"""Adding a passkey from the settings page, through the private app itself, with the
real WebAuthn library and software authenticators.

The rules: only the signed-in owner can start it; the addition needs a fresh check of a
passkey the owner already holds, begun for exactly this and good for nothing else; the
new passkey is stored only if it answers the challenge that check handed out; and a
wrong, replayed or borrowed step adds nothing.
"""

import contextlib
import logging
import re

import httpx2
import pytest

pytest.importorskip("webauthn")

from private_auth.app import PRIVATE_PAGE_LEVEL, _passkey_label, create_private_app  # noqa: E402
from private_auth.login import LoginService  # noqa: E402
from private_auth.owner import (  # noqa: E402
    ADD_PASSKEY_BINDING,
    STATE_TTL_SECONDS,
    OwnerStore,
    PasskeyOwnerAuth,
)
from private_auth.security import OwnerSessions, RateLimiter  # noqa: E402
from tests.broker_support import Broker  # noqa: E402
from tests.software_authenticator import SoftwareAuthenticator  # noqa: E402

ORIGIN = "https://private.test"
RP_ID = "private.test"
HEADERS = {"Origin": ORIGIN}
CLIENTS = {"alice": {"nas": ["nas1"]}}


class World:
    def __init__(self, monkeypatch, tmp_path):
        self.broker = Broker(monkeypatch, CLIENTS)
        self.store = OwnerStore(tmp_path / "owner.json")
        self.owner = PasskeyOwnerAuth(
            self.store, rp_id=RP_ID, origin=ORIGIN, clock=self.broker.clock
        )
        self.app = create_private_app(
            self.broker.runtime,
            LoginService(self.broker.runtime, clock=self.broker.clock),
            self.owner,
            allowed_origins=[ORIGIN],
            allowed_hosts=["private.test"],
            sessions=OwnerSessions(clock=self.broker.clock),
            auth_limiter=RateLimiter(10, 300, lockout_seconds=300, clock=self.broker.clock),
            begin_limiter=RateLimiter(30, 60, clock=self.broker.clock),
        )
        # The passkey the owner already has (in a password manager, say)...
        self.first = SoftwareAuthenticator(RP_ID, ORIGIN)
        # ...and the device that will hold the new one (Windows Hello, say).
        self.second = SoftwareAuthenticator(RP_ID, ORIGIN)
        code = self.store.new_enrollment_code()
        state, options = self.owner.begin_enrollment(code)
        assert self.owner.finish_enrollment(state, self.first.create(options), "password manager")

    @contextlib.asynccontextmanager
    async def client(self):
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=self.app), base_url=ORIGIN
        ) as http:
            yield http

    def labels(self):
        return [c.label for c in self.store.credentials()]


@pytest.fixture
def world(monkeypatch, tmp_path):
    return World(monkeypatch, tmp_path)


async def sign_in(http, device):
    begun = (await http.post("/auth/begin", headers=HEADERS, json={})).json()
    done = await http.post(
        "/auth/finish",
        headers=HEADERS,
        json={"state": begun["state"], "credential": device.get(begun["options"])},
    )
    return done


async def token_of(http):
    page = (await http.get("/settings")).text
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


async def begin(http, token):
    return await http.post("/api/passkeys/begin", headers=HEADERS, json={"csrf": token})


async def confirm(http, token, state, credential):
    return await http.post(
        "/api/passkeys/confirm",
        headers=HEADERS,
        json={"csrf": token, "state": state, "credential": credential},
    )


async def finish(http, token, state, credential, label="Windows Hello"):
    return await http.post(
        "/api/passkeys/finish",
        headers=HEADERS,
        json={"csrf": token, "state": state, "credential": credential, "label": label},
    )


async def confirmed(http, world, token):
    """Begin and confirm with the passkey the owner already has; the options for the
    new one."""
    begun = (await begin(http, token)).json()
    reply = await confirm(http, token, begun["state"], world.first.get(begun["options"]))
    assert reply.status_code == 200, reply.text
    return reply.json()


class TestAddingAPasskey:
    @pytest.mark.asyncio
    async def test_the_owner_adds_a_second_passkey_and_signs_in_with_it(self, world):
        async with world.client() as http:
            assert (await sign_in(http, world.first)).status_code == 200
            token = await token_of(http)
            make = await confirmed(http, world, token)
            done = await finish(http, token, make["state"], world.second.create(make["options"]))

        assert done.status_code == 200
        assert done.json() == {"ok": True, "label": "Windows Hello"}
        assert world.labels() == ["password manager", "Windows Hello"]

        async with world.client() as fresh:
            assert (await sign_in(fresh, world.second)).status_code == 200
            assert "Sign in all" in (await fresh.get("/settings")).text
        async with world.client() as fresh:
            assert (await sign_in(fresh, world.first)).status_code == 200

    @pytest.mark.asyncio
    async def test_the_new_passkey_must_not_be_one_that_is_already_there(self, world):
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            make = await confirmed(http, world, token)

        # The device is told which passkeys exist, so it can refuse to make a duplicate.
        excluded = [entry["id"] for entry in make["options"]["excludeCredentials"]]
        assert len(excluded) == 1
        assert make["options"]["authenticatorSelection"]["userVerification"] == "required"

    @pytest.mark.asyncio
    async def test_the_settings_page_lists_the_passkeys_and_offers_to_add_one(self, world):
        async with world.client() as http:
            signed_out = await http.get("/settings")
            await sign_in(http, world.first)
            page = (await http.get("/settings")).text
            script = await http.get("/static/passkeys.js")

        assert signed_out.status_code == 303
        assert "<h2>Passkeys</h2>" in page
        assert re.search(r"<li>password manager \(added \d{4}-\d\d-\d\d\)</li>", page)
        assert '<button id="add-passkey" type="submit">Add a passkey</button>' in page
        assert '<script src="/static/passkeys.js" defer></script>' in page
        assert "<script>" not in page and "onclick" not in page
        assert script.status_code == 200
        assert "navigator.credentials.create" in script.text
        assert "http://" not in script.text and "https://" not in script.text

    @pytest.mark.asyncio
    async def test_a_name_is_shown_as_text_never_as_markup(self, world):
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            make = await confirmed(http, world, token)
            await finish(
                http,
                token,
                make["state"],
                world.second.create(make["options"]),
                label="<img src=x onerror=alert(1)>",
            )
            page = (await http.get("/settings")).text

        assert "<img" not in page
        assert "&lt;img src=x onerror=alert(1)&gt;" in page


class TestWhoMayStartIt:
    @pytest.mark.asyncio
    async def test_every_step_needs_origin_session_and_csrf_token(self, world):
        steps = ("/api/passkeys/begin", "/api/passkeys/confirm", "/api/passkeys/finish")
        async with world.client() as stranger:
            for path in steps:
                reply = await stranger.post(path, headers=HEADERS, json={"csrf": "x"})
                assert reply.status_code == 401, path

        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            for path in steps:
                no_origin = await http.post(path, json={"csrf": token})
                wrong_origin = await http.post(
                    path, headers={"Origin": "https://evil.example"}, json={"csrf": token}
                )
                no_token = await http.post(path, headers=HEADERS, json={})
                wrong_token = await http.post(path, headers=HEADERS, json={"csrf": "guess"})
                not_json = await http.post(path, headers=HEADERS, content=b"csrf=" + token.encode())
                assert [
                    r.status_code
                    for r in (no_origin, wrong_origin, no_token, wrong_token, not_json)
                ] == [403, 403, 403, 403, 400], path

        assert world.labels() == ["password manager"]

    @pytest.mark.asyncio
    async def test_a_session_alone_is_not_enough(self, world):
        """Someone holding the owner's signed-in browser, but not a passkey, gets as far
        as being asked for one."""
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            begun = (await begin(http, token)).json()
            stranger = SoftwareAuthenticator(RP_ID, ORIGIN)
            # They cannot answer the check...
            refused = await confirm(http, token, begun["state"], {"id": "x", "rawId": "x"})
            # ...and cannot skip it either.
            skipped = await finish(
                http, token, begun["state"], stranger.create(_registration(world))
            )

        assert refused.status_code == 401
        assert skipped.status_code == 400
        assert world.labels() == ["password manager"]

    @pytest.mark.asyncio
    async def test_asking_over_and_over_is_slowed_down(self, world):
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            replies = [(await begin(http, token)).status_code for _ in range(31)]

        assert replies[:30] == [200] * 30
        assert replies[30] == 429


def _registration(world):
    """Registration options of the right shape, made outside any confirmation."""
    return {
        "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "rp": {"id": RP_ID, "name": "x"},
        "user": {"id": "AAAA", "name": "owner", "displayName": "owner"},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
    }


class TestTheConfirmation:
    @pytest.mark.asyncio
    async def test_a_wrong_passkey_adds_nothing_and_counts_as_a_failed_sign_in(self, world):
        stranger = SoftwareAuthenticator(RP_ID, ORIGIN)
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            for _ in range(10):
                begun = (await begin(http, token)).json()
                answer = stranger.get(begun["options"])
                assert (await confirm(http, token, begun["state"], answer)).status_code == 401
            begun = (await begin(http, token)).json()
            locked = await confirm(http, token, begun["state"], world.first.get(begun["options"]))

        assert locked.status_code == 429
        assert world.labels() == ["password manager"]

    @pytest.mark.asyncio
    async def test_it_cannot_be_replayed(self, world):
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            begun = (await begin(http, token)).json()
            answer = world.first.get(begun["options"])
            first = await confirm(http, token, begun["state"], answer)
            again = await confirm(http, token, begun["state"], answer)

        assert (first.status_code, again.status_code) == (200, 401)

    @pytest.mark.asyncio
    async def test_it_expires(self, world):
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            begun = (await begin(http, token)).json()
            answer = world.first.get(begun["options"])
            world.broker.clock.advance(STATE_TTL_SECONDS + 1)
            late = await confirm(http, token, begun["state"], answer)

        assert late.status_code in (401, 403)  # the challenge, or the session, has ended
        assert world.labels() == ["password manager"]

    @pytest.mark.asyncio
    async def test_a_check_begun_for_something_else_does_not_approve_an_addition(self, world):
        """A settings change and a sign-in each have their own challenge. Neither can be
        spent here."""
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)

            state, options = world.owner.begin_confirmation("a" * 64)  # a settings change
            for_settings = await confirm(http, token, state, world.first.get(options))

            state, options = world.owner.begin_authentication()
            for_sign_in = await confirm(http, token, state, world.first.get(options))

        assert (for_settings.status_code, for_sign_in.status_code) == (401, 401)
        assert world.store.enrollment_open() is False
        assert world.labels() == ["password manager"]

    @pytest.mark.asyncio
    async def test_a_body_with_the_wrong_types_is_a_refusal_not_an_error(self, world):
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            for path in ("/api/passkeys/confirm", "/api/passkeys/finish"):
                for body in (
                    {"state": 7, "credential": {}},
                    {"state": "s", "credential": "c"},
                    {"state": None, "credential": None},
                    {},
                ):
                    reply = await http.post(path, headers=HEADERS, json={"csrf": token, **body})
                    assert reply.status_code in (400, 401), (path, body)
                    assert reply.json()["ok"] is False


class TestTheNewPasskey:
    @pytest.mark.asyncio
    async def test_it_must_answer_the_challenge_that_was_handed_out(self, world):
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            make = await confirmed(http, world, token)
            other_challenge = dict(make["options"], challenge=_registration(world)["challenge"])
            wrong = await finish(http, token, make["state"], world.second.create(other_challenge))
            # The state was spent by the failed try: the right answer is now too late.
            late = await finish(http, token, make["state"], world.second.create(make["options"]))

        assert (wrong.status_code, late.status_code) == (400, 400)
        assert world.labels() == ["password manager"]

    @pytest.mark.asyncio
    async def test_one_confirmation_adds_one_passkey(self, world):
        third = SoftwareAuthenticator(RP_ID, ORIGIN)
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            make = await confirmed(http, world, token)
            first = await finish(http, token, make["state"], world.second.create(make["options"]))
            again = await finish(http, token, make["state"], third.create(make["options"]))

        assert (first.status_code, again.status_code) == (200, 400)
        assert world.labels() == ["password manager", "Windows Hello"]

    @pytest.mark.asyncio
    async def test_it_must_be_made_while_the_challenge_lives(self, world):
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            make = await confirmed(http, world, token)
            answer = world.second.create(make["options"])
            world.broker.clock.advance(STATE_TTL_SECONDS + 1)
            late = await finish(http, token, make["state"], answer)

        assert late.status_code in (400, 403)
        assert world.labels() == ["password manager"]

    @pytest.mark.asyncio
    async def test_a_device_that_skips_user_verification_is_refused(self, world):
        careless = SoftwareAuthenticator(RP_ID, ORIGIN, user_verified=False)
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            make = await confirmed(http, world, token)
            reply = await finish(http, token, make["state"], careless.create(make["options"]))

        assert reply.status_code == 400
        assert world.labels() == ["password manager"]

    @pytest.mark.asyncio
    async def test_a_second_confirmation_ends_the_first_addition(self, world):
        """Only the newest addition can finish, as with codes printed on the host."""
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            older = await confirmed(http, world, token)
            newer = await confirmed(http, world, token)
            stale = await finish(http, token, older["state"], world.second.create(older["options"]))
            good = await finish(http, token, newer["state"], world.second.create(newer["options"]))

        assert (stale.status_code, good.status_code) == (400, 200)
        assert world.labels() == ["password manager", "Windows Hello"]

    @pytest.mark.asyncio
    async def test_a_code_from_the_host_that_was_still_open_stops_working(self, world):
        host_code = world.store.new_enrollment_code(allow_additional=True)
        async with world.client() as http:
            await sign_in(http, world.first)
            token = await token_of(http)
            await confirmed(http, world, token)
            reply = await http.post("/enroll/begin", headers=HEADERS, json={"code": host_code})

        assert reply.status_code == 403

    @pytest.mark.asyncio
    async def test_the_addition_is_logged_without_its_name(self, world, caplog):
        with caplog.at_level(logging.DEBUG):
            async with world.client() as http:
                await sign_in(http, world.first)
                token = await token_of(http)
                make = await confirmed(http, world, token)
                await finish(
                    http, token, make["state"], world.second.create(make["options"]), "My-Laptop"
                )

        assert "The owner added a passkey" in caplog.text
        assert "My-Laptop" not in caplog.text
        assert make["state"] not in caplog.text


class TestNames:
    @pytest.mark.parametrize(
        "given, kept",
        [
            ("Windows Hello", "Windows Hello"),
            ("  spaced  ", "spaced"),
            ("", "passkey"),
            ("   ", "passkey"),
            (None, "passkey"),
            (7, "passkey"),
            (["a"], "passkey"),
            ("line\nbreak\tand\x00nul", "linebreakandnul"),
            ("x" * 200, "x" * 64),
            ("x" * 63 + " y", "x" * 63),
        ],
    )
    def test_a_name_is_made_safe_to_store_and_show(self, given, kept):
        assert _passkey_label(given) == kept


class TestOwnerSide:
    """`PasskeyOwnerAuth` itself, without the page."""

    def test_no_passkey_yet_means_nothing_can_be_added_this_way(self, monkeypatch, tmp_path):
        broker = Broker(monkeypatch, CLIENTS)
        store = OwnerStore(tmp_path / "empty.json")
        owner = PasskeyOwnerAuth(store, rp_id=RP_ID, origin=ORIGIN, clock=broker.clock)

        assert owner.passkeys() == []
        assert owner.begin_additional_enrollment() is None
        # And it did not leave a code open for a stranger to guess at.
        assert store.enrollment_open() is False

    def test_the_passkeys_are_listed_by_name_and_day(self, world):
        (entry,) = world.owner.passkeys()
        assert entry[0] == "password manager"
        assert re.fullmatch(r"\d{4}-\d\d-\d\d", entry[1])

    def test_the_binding_cannot_be_mistaken_for_a_settings_change(self):
        # A settings change is confirmed against a 64-digit digest.
        assert not re.fullmatch(r"[0-9a-f]{64}", ADD_PASSKEY_BINDING)


class TestLevel:
    @pytest.mark.asyncio
    async def test_healthz_says_how_new_the_page_is(self, world):
        async with world.client() as http:
            reply = await http.get("/healthz")

        assert reply.status_code == 200
        assert reply.json() == {"status": "ok", "level": PRIVATE_PAGE_LEVEL}
        assert isinstance(PRIVATE_PAGE_LEVEL, int) and PRIVATE_PAGE_LEVEL >= 1
