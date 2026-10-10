"""Enrolling and signing in with a passkey through the private app itself, using
the real WebAuthn library and a software authenticator: the same requests a
browser makes, with nothing faked on the owner side."""

import contextlib

import httpx2
import pytest

pytest.importorskip("webauthn")

from private_auth.app import create_private_app  # noqa: E402
from private_auth.login import LoginService  # noqa: E402
from private_auth.owner import OwnerStore, PasskeyOwnerAuth  # noqa: E402
from private_auth.security import OwnerSessions, RateLimiter  # noqa: E402
from tests.broker_support import Broker  # noqa: E402
from tests.software_authenticator import SoftwareAuthenticator  # noqa: E402

ORIGIN = "https://private.test"
RP_ID = "private.test"
HEADERS = {"Origin": ORIGIN}
CLIENTS = {"alice": {"nas": ["nas1"]}}


@pytest.fixture
def world(monkeypatch, tmp_path):
    broker = Broker(monkeypatch, CLIENTS)
    store = OwnerStore(tmp_path / "owner.json")
    owner = PasskeyOwnerAuth(store, rp_id=RP_ID, origin=ORIGIN, clock=broker.clock)
    enroll_limiter = RateLimiter(5, 600, lockout_seconds=600, clock=broker.clock)
    app = create_private_app(
        broker.runtime,
        LoginService(broker.runtime, clock=broker.clock),
        owner,
        allowed_origins=[ORIGIN],
        allowed_hosts=["private.test"],
        sessions=OwnerSessions(clock=broker.clock),
        auth_limiter=RateLimiter(10, 300, clock=broker.clock),
        enroll_limiter=enroll_limiter,
    )

    class World:
        pass

    w = World()
    w.broker, w.store, w.owner, w.app = broker, store, owner, app
    w.device = SoftwareAuthenticator(RP_ID, ORIGIN)

    @contextlib.asynccontextmanager
    async def client():
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url=ORIGIN
        ) as http:
            yield http

    w.client = client
    return w


async def enrol(http, world, code=None, device=None):
    code = code or world.store.new_enrollment_code()
    begun = await http.post("/enroll/begin", headers=HEADERS, json={"code": code})
    if begun.status_code != 200:
        return begun, None
    data = begun.json()
    finished = await http.post(
        "/enroll/finish",
        headers=HEADERS,
        json={
            "state": data["state"],
            "label": "my phone",
            "credential": (device or world.device).create(data["options"]),
        },
    )
    return begun, finished


async def sign_in(http, device, **overrides):
    begun = await http.post("/auth/begin", headers=HEADERS, json={})
    data = begun.json()
    return await http.post(
        "/auth/finish",
        headers=HEADERS,
        json={"state": data["state"], "credential": device.get(data["options"], **overrides)},
    )


class TestEnrolling:
    @pytest.mark.asyncio
    async def test_the_owner_enrols_with_the_code_printed_on_the_host(self, world):
        async with world.client() as http:
            _, finished = await enrol(http, world)

        assert finished.status_code == 200
        assert world.owner.has_owner()
        assert world.store.credentials()[0].label == "my phone"

    @pytest.mark.asyncio
    async def test_the_page_does_not_give_a_way_in_without_the_code(self, world):
        async with world.client() as http:
            page = (await http.get("/enroll")).text
            begun = await http.post("/enroll/begin", headers=HEADERS, json={"code": "guess"})
            blank = await http.post("/enroll/begin", headers=HEADERS, json={})

        assert "one-time code" in page
        assert (begun.status_code, blank.status_code) == (403, 403)
        assert not world.owner.has_owner()

    @pytest.mark.asyncio
    async def test_enrolment_needs_the_right_origin(self, world):
        code = world.store.new_enrollment_code()
        async with world.client() as http:
            for headers in ({}, {"Origin": "https://evil.example"}):
                assert (
                    await http.post("/enroll/begin", headers=headers, json={"code": code})
                ).status_code == 403
            assert (await http.post("/enroll/finish", json={})).status_code == 403

    @pytest.mark.asyncio
    async def test_the_code_works_once_and_a_second_passkey_needs_it_made_again(self, world):
        code = world.store.new_enrollment_code()
        async with world.client() as http:
            _, first = await enrol(http, world, code)
            again, _ = await enrol(http, world, code, SoftwareAuthenticator(RP_ID, ORIGIN))

        assert first.status_code == 200 and again.status_code == 403
        assert len(world.store.credentials()) == 1

    @pytest.mark.asyncio
    async def test_five_wrong_codes_lock_enrolment_even_for_the_right_one(self, world):
        code = world.store.new_enrollment_code()
        async with world.client() as http:
            for _ in range(5):
                await http.post("/enroll/begin", headers=HEADERS, json={"code": "wrong"})
            locked = await http.post("/enroll/begin", headers=HEADERS, json={"code": code})
            world.broker.clock.advance(601)
            later = await http.post("/enroll/begin", headers=HEADERS, json={"code": code})

        assert locked.status_code == 429 and later.status_code == 200

    @pytest.mark.asyncio
    async def test_a_passkey_from_another_site_cannot_be_enrolled(self, world):
        phisher = SoftwareAuthenticator("evil.example", "https://evil.example")
        async with world.client() as http:
            _, finished = await enrol(http, world, device=phisher)
        assert finished.status_code == 403 and not world.owner.has_owner()


class TestSigningIn:
    @pytest.fixture
    def enrolled(self, world):
        state, options = world.owner.begin_enrollment(world.store.new_enrollment_code())
        assert world.owner.finish_enrollment(state, world.device.create(options))

    @pytest.mark.asyncio
    async def test_the_enrolled_passkey_signs_the_owner_in(self, world, enrolled):
        async with world.client() as http:
            done = await sign_in(http, world.device)
            page = (await http.get("/")).text

        assert done.status_code == 200 and "__Host-owner" in done.headers["set-cookie"]
        assert "Synology broker" in page and "alice" in page

    @pytest.mark.asyncio
    async def test_a_signed_response_cannot_be_replayed(self, world, enrolled):
        async with world.client() as http:
            begun = (await http.post("/auth/begin", headers=HEADERS, json={})).json()
            payload = {"state": begun["state"], "credential": world.device.get(begun["options"])}
            first = await http.post("/auth/finish", headers=HEADERS, json=payload)
            http.cookies.clear()
            replay = await http.post("/auth/finish", headers=HEADERS, json=payload)
            page = (await http.get("/")).text

        assert (first.status_code, replay.status_code) == (200, 401)
        assert "Sign in with passkey" in page

    @pytest.mark.asyncio
    async def test_another_device_cannot_sign_in(self, world, enrolled):
        async with world.client() as http:
            done = await sign_in(http, SoftwareAuthenticator(RP_ID, ORIGIN))
        assert done.status_code == 401 and "set-cookie" not in done.headers

    @pytest.mark.asyncio
    async def test_a_response_for_another_site_cannot_sign_in(self, world, enrolled):
        async with world.client() as http:
            wrong_origin = await sign_in(http, world.device, origin="https://evil.example")
            wrong_site = await sign_in(http, world.device, rp_id="evil.example")
        assert wrong_origin.status_code == 401 and wrong_site.status_code == 401

    @pytest.mark.asyncio
    async def test_a_challenge_that_has_expired_cannot_be_used(self, world, enrolled):
        async with world.client() as http:
            begun = (await http.post("/auth/begin", headers=HEADERS, json={})).json()
            world.broker.clock.advance(121)
            done = await http.post(
                "/auth/finish",
                headers=HEADERS,
                json={"state": begun["state"], "credential": world.device.get(begun["options"])},
            )
        assert done.status_code == 401

    @pytest.mark.asyncio
    async def test_the_options_ask_for_user_verification_and_only_the_enrolled_passkey(
        self, world, enrolled
    ):
        async with world.client() as http:
            options = (await http.post("/auth/begin", headers=HEADERS, json={})).json()["options"]

        assert options["userVerification"] == "required"
        assert len(options["allowCredentials"]) == 1
        assert options["rpId"] == RP_ID

    @pytest.mark.asyncio
    async def test_sign_in_is_not_offered_until_a_passkey_exists(self, world):
        async with world.client() as http:
            begun = await http.post("/auth/begin", headers=HEADERS, json={})
        assert begun.status_code == 409
