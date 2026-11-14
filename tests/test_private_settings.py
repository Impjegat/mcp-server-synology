"""The settings page and its save, over HTTP and in-process.

The rules: only the signed-in owner reaches it; a save is two steps, the second of
which needs a fresh passkey that was begun for exactly that change; a wrong or
replayed passkey changes nothing; and the page says nothing that is not already
the owner's to see.
"""

import json
import re

import httpx2
import pytest

from broker.policy import WRITE_TOOLS
from broker.policy_store import PolicyStore
from private_auth.app import create_private_app
from private_auth.login import LoginService
from private_auth.security import OwnerSessions
from private_auth.settings import SettingsService
from tests.broker_support import BASE_URLS, Broker
from tests.test_private_app import (
    JSON_HEADERS,
    ORIGIN,
    FakeOwner,
    Runner,
    csrf,
    sign_in,
)

CLIENTS = {
    "alice": {
        "token": "alice-token-value",
        "nas": ["nas1"],
        "folders": {"nas1": ["/docs", "/photos/2026"]},
    },
    "bob": {"token": "bob-token-value", "nas": ["nas1", "nas2"], "tools": ["list_shares"]},
}
OK = {"ok": True, "sid": "SID-FROM-WORKER", "synotoken": "TOK-FROM-WORKER"}
PROOF = {"proof": "ok"}


class ConfirmingOwner(FakeOwner):
    """Stands in for the passkey: a confirmation is good only for the change it was
    begun for, and only with the credential {"proof": "ok"}."""

    def __init__(self):
        super().__init__()
        self.bindings = {}
        self.begun = 0

    def begin_confirmation(self, binding):
        self.begun += 1
        state = f"confirm-{self.begun}"
        self.bindings[state] = binding
        return state, {"challenge": "c", "allowCredentials": []}

    def finish_confirmation(self, state, credential):
        binding = self.bindings.pop(state, None)
        return binding if binding and credential == PROOF else None


class Rig:
    def __init__(self, broker, tmp_path, *, with_settings=True):
        from mcp_server import SynologyMCPServer

        self.broker = broker
        self.owner = ConfirmingOwner()
        self.path = tmp_path / "broker-policy.json"
        self.path.write_text(json.dumps(broker.document), encoding="utf-8")
        registry = SynologyMCPServer()
        self.store = PolicyStore(
            self.path, known_nas=BASE_URLS, known_tools=set(registry._tool_registry)
        )
        self.restricted = []
        broker.runtime._set_restricted_mode = self.restricted.append
        self.settings = (
            SettingsService(
                self.store, broker.runtime, registry._is_tool_allowed, clock=broker.clock
            )
            if with_settings
            else None
        )
        self.owner_sessions = OwnerSessions(
            idle_seconds=600, absolute_seconds=3600, clock=broker.clock
        )
        self.app = create_private_app(
            broker.runtime,
            LoginService(broker.runtime, runner=Runner(OK), clock=broker.clock),
            self.owner,
            allowed_origins=[ORIGIN],
            allowed_hosts=["private.test"],
            sessions=self.owner_sessions,
            settings=self.settings,
        )

    def client(self):
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=self.app), base_url=ORIGIN)

    def policy_on_disk(self):
        return json.loads(self.path.read_text(encoding="utf-8"))


@pytest.fixture
def broker(monkeypatch):
    return Broker(
        monkeypatch,
        CLIENTS,
        session={"idle_seconds": 100, "absolute_seconds": 1000, "pending_seconds": 50},
    )


@pytest.fixture
def rig(broker, tmp_path):
    return Rig(broker, tmp_path)


async def begin(http, token, proposal):
    return await http.post(
        "/api/settings/begin", headers=JSON_HEADERS, json={"csrf": token, "proposal": proposal}
    )


async def commit(http, token, state, credential=PROOF):
    return await http.post(
        "/api/settings/commit",
        headers=JSON_HEADERS,
        json={"csrf": token, "state": state, "credential": credential},
    )


async def save(http, token, proposal):
    begun = (await begin(http, token, proposal)).json()
    assert begun["ok"] and begun["changes"], begun
    return await commit(http, token, begun["state"])


class TestPage:
    @pytest.mark.asyncio
    async def test_it_is_for_the_signed_in_owner_only(self, rig):
        async with rig.client() as http:
            response = await http.get("/settings")
        assert response.status_code == 303 and response.headers["location"] == "/"
        assert "alice" not in response.text

    @pytest.mark.asyncio
    async def test_it_shows_the_live_values_for_each_client(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            page = (await http.get("/settings")).text

        assert 'data-field="idle_minutes" value="1.666667"' in page
        assert 'data-field="owner_idle_minutes" value="10"' in page
        assert 'data-field="owner_absolute_hours" value="1"' in page
        assert page.count("<fieldset") == 2
        assert "/docs\n/photos/2026</textarea>" in page
        assert 'data-nas="nas2"' in page
        assert page.count('data-kind="write"') == 2 and "checked" not in re.sub(
            r'data-kind="(write|delete)">', "", page.split("<h2>Clients</h2>")[1]
        )
        assert '<script src="/static/settings.js" defer></script>' in page
        assert "Settings" in page and 'name="csrf"' in page

    @pytest.mark.asyncio
    async def test_a_client_with_write_access_shows_it_ticked(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            await save(http, await csrf(http), {"clients": {"alice": {"write": True}}})
            page = (await http.get("/settings")).text
        assert re.search(r'<input type="checkbox" data-kind="write" checked>', page)

    @pytest.mark.asyncio
    async def test_a_read_only_policy_is_said_to_be_read_only(self, rig, monkeypatch):
        monkeypatch.setattr(rig.store, "writable", lambda: False)
        async with rig.client() as http:
            await sign_in(http)
            page = (await http.get("/settings")).text
        assert "read-only here" in page

    @pytest.mark.asyncio
    async def test_a_broker_with_no_settings_says_so(self, broker, tmp_path):
        bare = Rig(broker, tmp_path, with_settings=False)
        async with bare.client() as http:
            await sign_in(http)
            page = (await http.get("/settings")).text
            begun = await begin(http, await csrf(http), {})
        assert "started without settings" in page and begun.status_code == 404

    @pytest.mark.asyncio
    async def test_the_page_and_script_load_nothing_from_elsewhere(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            page = (await http.get("/settings")).text
            script = await http.get("/static/settings.js")
        assert not re.search(r"<script(?![^>]*\bsrc=)", page)
        assert "style=" not in page and " onclick=" not in page
        assert "http://" not in script.text and "https://" not in script.text
        assert "/api/settings/begin" in script.text and "b64.toBuf" in script.text

    @pytest.mark.asyncio
    async def test_posting_the_form_without_the_script_changes_nothing(self, rig):
        before = rig.path.read_bytes()
        async with rig.client() as http:
            response = await http.post("/settings", data={"idle_minutes": "1"})
        assert response.status_code == 400 and rig.path.read_bytes() == before

    @pytest.mark.asyncio
    async def test_the_navigation_links_to_it(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            page = (await http.get("/")).text
        assert '<a href="/settings">Settings</a>' in page


class TestBegin:
    @pytest.mark.asyncio
    async def test_it_needs_origin_session_and_csrf_token(self, rig):
        proposal = {"clients": {"alice": {"write": True}}}
        async with rig.client() as http:
            no_origin = await http.post(
                "/api/settings/begin", json={"csrf": "x", "proposal": proposal}
            )
            no_session = await begin(http, "x", proposal)
            await sign_in(http)
            bad_csrf = await begin(http, "wrong", proposal)
        assert (no_origin.status_code, no_session.status_code, bad_csrf.status_code) == (
            403,
            401,
            403,
        )
        assert rig.owner.begun == 0

    @pytest.mark.asyncio
    async def test_an_mcp_clients_token_cannot_use_it(self, rig):
        async with rig.client() as http:
            response = await http.post(
                "/api/settings/begin",
                headers={**JSON_HEADERS, "Authorization": "Bearer alice-token-value"},
                json={"csrf": "x", "proposal": {"clients": {"alice": {"write": True}}}},
            )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_it_says_what_would_change_and_changes_nothing(self, rig):
        before = rig.path.read_bytes()
        async with rig.client() as http:
            await sign_in(http)
            response = await begin(http, await csrf(http), {"clients": {"alice": {"write": True}}})
        data = response.json()
        assert data["ok"] and "alice: write access ON" in data["changes"]
        assert data["state"].startswith("confirm-") and data["options"]["challenge"]
        assert rig.path.read_bytes() == before
        assert not WRITE_TOOLS & set(rig.broker.runtime.policy.clients["alice"].tools)

    @pytest.mark.asyncio
    async def test_a_proposal_that_changes_nothing_asks_for_no_passkey(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            response = await begin(http, await csrf(http), {"session": {"owner_idle_minutes": 10}})
        assert response.json() == {"ok": True, "changes": []}
        assert rig.owner.begun == 0

    @pytest.mark.asyncio
    async def test_a_proposal_that_is_not_allowed_is_refused_in_words(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            token = await csrf(http)
            too_long = await begin(http, token, {"session": {"idle_minutes": 600}})
            shape = await begin(http, token, {"deny_paths": []})
            client = await begin(http, token, {"clients": {"mallory": {"write": True}}})
        for response in (too_long, shape, client):
            assert response.status_code == 400 and response.json()["ok"] is False
            assert response.json()["message"]
        assert rig.owner.begun == 0

    @pytest.mark.asyncio
    async def test_a_body_that_is_not_json_is_refused(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            response = await http.post(
                "/api/settings/begin", headers=JSON_HEADERS, content=b"not json"
            )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_asking_over_and_over_is_slowed_down(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            token = await csrf(http)
            statuses = [
                (await begin(http, token, {"session": {"owner_idle_minutes": 5}})).status_code
                for _ in range(40)
            ]
        assert 429 in statuses


class TestCommit:
    @pytest.mark.asyncio
    async def test_the_right_passkey_applies_exactly_the_change_that_was_shown(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            token = await csrf(http)
            done = await save(
                http,
                token,
                {
                    "session": {"idle_minutes": 1, "absolute_hours": 0.25},
                    "clients": {"alice": {"write": True, "folders": {"nas1": ["/docs"]}}},
                },
            )

        assert done.status_code == 200 and done.json()["ok"] is True
        assert "alice: write access ON" in done.json()["changes"]
        alice = rig.broker.runtime.policy.clients["alice"]
        assert WRITE_TOOLS <= alice.tools and alice.folders["nas1"] == ("/docs",)
        assert rig.broker.runtime.policy.session.idle_seconds == 60
        saved = rig.policy_on_disk()
        assert saved["clients"]["alice"]["folders"] == {"nas1": ["/docs"]}
        assert saved["restricted_mode"] is False and rig.restricted == [False]

    @pytest.mark.asyncio
    async def test_a_passkey_that_is_not_accepted_changes_nothing(self, rig):
        before = rig.path.read_bytes()
        policy = rig.broker.runtime.policy
        async with rig.client() as http:
            await sign_in(http)
            token = await csrf(http)
            begun = (await begin(http, token, {"clients": {"alice": {"write": True}}})).json()
            refused = await commit(http, token, begun["state"], {"proof": "forged"})
            retry = await commit(http, token, begun["state"])
        assert refused.status_code == 401 and "not accepted" in refused.json()["message"]
        assert retry.status_code == 401  # the challenge was spent
        assert rig.path.read_bytes() == before and rig.broker.runtime.policy is policy

    @pytest.mark.asyncio
    async def test_a_confirmation_cannot_be_replayed(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            token = await csrf(http)
            begun = (await begin(http, token, {"clients": {"alice": {"write": True}}})).json()
            first = await commit(http, token, begun["state"])
            again = await commit(http, token, begun["state"])
        assert first.status_code == 200 and again.status_code == 401

    @pytest.mark.asyncio
    async def test_a_confirmation_applies_only_the_change_it_was_begun_for(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            token = await csrf(http)
            first = (await begin(http, token, {"clients": {"alice": {"write": True}}})).json()
            second = (await begin(http, token, {"clients": {"bob": {"write": True}}})).json()
            done = await commit(http, token, second["state"])

        assert "bob: write access ON" in done.json()["changes"]
        assert not any("alice" in line for line in done.json()["changes"])
        assert not WRITE_TOOLS & set(rig.broker.runtime.policy.clients["alice"].tools)
        assert WRITE_TOOLS <= rig.broker.runtime.policy.clients["bob"].tools
        assert first["state"] != second["state"]

    @pytest.mark.asyncio
    async def test_it_needs_origin_session_and_csrf_token_as_well(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            token = await csrf(http)
            begun = (await begin(http, token, {"clients": {"alice": {"write": True}}})).json()
            no_origin = await http.post(
                "/api/settings/commit",
                json={"csrf": token, "state": begun["state"], "credential": PROOF},
            )
            bad_csrf = await commit(http, "wrong", begun["state"])
        assert no_origin.status_code == 403 and bad_csrf.status_code == 403
        assert "restricted_mode" not in rig.policy_on_disk()

    @pytest.mark.asyncio
    async def test_a_body_with_the_wrong_types_is_a_refusal_not_an_error(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            token = await csrf(http)
            for state, credential in ((5, PROOF), ("confirm-1", "x"), (None, None)):
                response = await http.post(
                    "/api/settings/commit",
                    headers=JSON_HEADERS,
                    json={"csrf": token, "state": state, "credential": credential},
                )
                assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_repeated_wrong_passkeys_lock_the_address_out(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            token = await csrf(http)
            statuses = [
                (await commit(http, token, f"nope-{n}", {"proof": "no"})).status_code
                for n in range(12)
            ]
        assert statuses[0] == 401 and statuses[-1] == 429

    @pytest.mark.asyncio
    async def test_the_owners_own_session_limits_follow_the_setting(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            token = await csrf(http)
            await save(
                http,
                token,
                {"session": {"owner_idle_minutes": 2, "owner_absolute_hours": 2}},
            )
        assert rig.owner_sessions._idle == 120 and rig.owner_sessions._absolute == 7200

    @pytest.mark.asyncio
    async def test_a_file_edited_meanwhile_is_not_overwritten(self, rig):
        async with rig.client() as http:
            await sign_in(http)
            token = await csrf(http)
            begun = (await begin(http, token, {"clients": {"alice": {"write": True}}})).json()
            edited = rig.policy_on_disk()
            edited["deny_paths"] = ["/by-hand"]
            rig.path.write_text(json.dumps(edited), encoding="utf-8")
            done = await commit(http, token, begun["state"])
        assert done.status_code == 409 and "changed on disk" in done.json()["message"]
        assert rig.policy_on_disk()["deny_paths"] == ["/by-hand"]

    @pytest.mark.asyncio
    async def test_the_save_is_logged_by_count_and_never_by_value(self, rig, caplog):
        import logging

        with caplog.at_level(logging.INFO, logger="synology-private-login"):
            async with rig.client() as http:
                await sign_in(http)
                token = await csrf(http)
                await save(
                    http, token, {"clients": {"alice": {"folders": {"nas1": ["/secret-folder"]}}}}
                )
        assert "changed the broker's settings (1 change(s))" in caplog.text
        assert "secret-folder" not in caplog.text

    @pytest.mark.asyncio
    async def test_a_client_keeps_its_token_and_its_session_through_a_save(self, rig):
        rig.broker.sign_in("alice", "nas1")
        digest = rig.broker.runtime.policy.clients["alice"].token_sha256
        async with rig.client() as http:
            await sign_in(http)
            await save(http, await csrf(http), {"clients": {"alice": {"write": True}}})
        assert rig.broker.runtime.policy.clients["alice"].token_sha256 == digest
        assert rig.broker.sessions.get("alice", "nas1", touch=False) is not None


class TestNumberFields:
    """A value that is shown and saved back untouched must be the same value."""

    @pytest.mark.parametrize(
        "value, text",
        [(10.0, "10"), (0.5, "0.5"), (0.125, "0.125"), (1234567.0, "1234567"), (0.0, "0")],
    )
    def test_the_text_is_as_short_as_it_can_be_without_losing_anything(self, value, text):
        from private_auth.app import _number_text

        assert _number_text(value) == text

    @pytest.mark.parametrize("unit", [60, 3600])
    def test_every_whole_number_of_seconds_comes_back_as_itself(self, unit):
        from private_auth.app import _number_text

        for seconds in list(range(1, 400)) + [28799, 28800, 28801, 86399, 604799, 604800]:
            shown = _number_text(seconds / unit)
            assert round(float(shown) * unit) == seconds, (seconds, shown)

    @pytest.mark.asyncio
    async def test_a_value_the_page_shows_and_sends_back_changes_nothing(
        self, monkeypatch, tmp_path
    ):
        # 604799 s is 167.999722 hours: more than six significant figures to show.
        odd = Broker(
            monkeypatch,
            CLIENTS,
            session={"idle_seconds": 900, "absolute_seconds": 604799, "pending_seconds": 50},
        )
        rig = Rig(odd, tmp_path)
        async with rig.client() as http:
            await sign_in(http)
            page = (await http.get("/settings")).text
            shown = re.search(r'data-field="absolute_hours" value="([^"]+)"', page).group(1)
            begun = await begin(
                http, await csrf(http), {"session": {"absolute_hours": float(shown)}}
            )
        assert begun.json() == {"ok": True, "changes": []}
