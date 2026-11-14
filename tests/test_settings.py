"""What the owner may change from the private page, and how a change is made safe.

Three layers: turning a proposal into a new policy document (`apply_proposal`),
the policy file that is validated and rewritten (`PolicyStore`), and the service
that holds a change for the passkey and then applies it to the running broker.
"""

import copy
import json
import os
import stat
import sys

import pytest

from broker.policy import (
    DEFAULT_TOOLS,
    DELETE_TOOLS,
    WRITE_TOOLS,
    PolicyError,
)
from broker.policy_store import PolicyStore
from private_auth.settings import (
    SettingsError,
    SettingsService,
    apply_proposal,
    describe_changes,
    digest_of,
)
from tests.broker_support import BASE_URLS, Broker, future_expiry

DIGEST = "a" * 64


def allows(tool: str) -> bool:
    """Stands in for restricted mode's allowlist: the default tools and sign-out."""
    return tool in DEFAULT_TOOLS or tool == "synology_logout"


def base_document():
    return {
        "session": {"idle_seconds": 900},
        "clients": {
            "alice": {
                "token_sha256": DIGEST,
                "expires": "2027-06-30",
                "nas": ["nas1"],
                "folders": {"nas1": ["/docs"]},
            },
            "bob": {
                "token_sha256": "b" * 64,
                "expires": "2027-06-30",
                "nas": ["nas1", "nas2"],
                "tools": ["list_shares", "synology_status"],
            },
        },
    }


def apply(proposal, document=None):
    return apply_proposal(document or base_document(), proposal, restricted_allows=allows)


class TestSessionTimes:
    def test_minutes_and_hours_become_seconds(self):
        new = apply(
            {
                "session": {
                    "idle_minutes": 30,
                    "absolute_hours": 4,
                    "owner_idle_minutes": 5,
                    "owner_absolute_hours": 1.5,
                }
            }
        )
        assert new["session"] == {
            "idle_seconds": 1800,
            "absolute_seconds": 14400,
            "owner_idle_seconds": 300,
            "owner_absolute_seconds": 5400,
        }

    def test_the_document_given_is_not_changed(self):
        original = base_document()
        before = copy.deepcopy(original)
        apply_proposal(original, {"session": {"idle_minutes": 5}}, restricted_allows=allows)
        assert original == before

    @pytest.mark.parametrize(
        "field, value",
        [
            ("idle_minutes", 0),
            ("idle_minutes", 7 * 24 * 60 + 1),
            ("absolute_hours", 0),
            ("absolute_hours", 24 * 7 + 1),
            ("owner_idle_minutes", 0),
            ("owner_absolute_hours", 25),
            ("idle_minutes", True),
            ("idle_minutes", "30"),
            ("idle_minutes", None),
            ("idle_minutes", [30]),
        ],
    )
    def test_a_value_out_of_range_or_not_a_number_is_refused(self, field, value):
        with pytest.raises(SettingsError):
            apply({"session": {field: value}})

    def test_the_message_names_the_setting_and_never_repeats_the_value(self):
        with pytest.raises(SettingsError) as error:
            apply({"session": {"idle_minutes": "my-secret-value"}})
        assert "unused" in str(error.value) and "my-secret-value" not in str(error.value)

    def test_a_setting_that_is_not_offered_is_refused(self):
        for session in ({"pending_seconds": 5}, {"idle_seconds": 5}, {"nonsense": 1}):
            with pytest.raises(SettingsError):
                apply({"session": session})


class TestShape:
    @pytest.mark.parametrize(
        "proposal",
        [
            None,
            [],
            "x",
            {"deny_paths": ["/"]},
            {"clients": []},
            {"session": []},
            {"restricted_mode": False},
        ],
    )
    def test_only_the_session_and_the_clients_can_be_changed(self, proposal):
        with pytest.raises(SettingsError):
            apply(proposal)

    def test_an_empty_proposal_changes_nothing(self):
        assert apply({}) == base_document()

    def test_a_client_that_is_not_in_the_policy_is_refused(self):
        with pytest.raises(SettingsError):
            apply({"clients": {"mallory": {"write": True}}})

    def test_a_client_cannot_have_its_token_nas_or_expiry_changed_here(self):
        for field in ("token_sha256", "nas", "expires", "tools", "disconnect"):
            with pytest.raises(SettingsError):
                apply({"clients": {"alice": {field: "x"}}})

    def test_a_nas_the_client_does_not_use_is_refused(self):
        with pytest.raises(SettingsError):
            apply({"clients": {"alice": {"folders": {"nas2": ["/docs"]}}}})


class TestFolders:
    def test_folders_are_replaced_trimmed_and_deduplicated(self):
        new = apply(
            {"clients": {"alice": {"folders": {"nas1": [" /docs ", "", "/photos", "/docs", "  "]}}}}
        )
        assert new["clients"]["alice"]["folders"] == {"nas1": ["/docs", "/photos"]}

    def test_no_folders_removes_the_entry(self):
        new = apply({"clients": {"alice": {"folders": {"nas1": ["", " "]}}}})
        assert new["clients"]["alice"]["folders"] == {}

    def test_folders_can_be_added_for_a_nas_that_had_none(self):
        new = apply({"clients": {"bob": {"folders": {"nas2": ["/media"]}}}})
        assert new["clients"]["bob"]["folders"] == {"nas2": ["/media"]}

    @pytest.mark.parametrize(
        "roots",
        [
            "/docs",
            ["C:\\secret-value\\x"],
            ["/a\x00b"],
            [5],
            [None],
            ["/x"] * 51,
            ["/" + "x" * 1030],
        ],
    )
    def test_a_folder_list_that_is_not_valid_is_refused(self, roots):
        with pytest.raises(SettingsError) as error:
            apply({"clients": {"alice": {"folders": {"nas1": roots}}}})
        assert "secret-value" not in str(error.value)

    def test_nothing_else_about_the_client_is_touched(self):
        new = apply({"clients": {"alice": {"folders": {"nas1": ["/photos"]}}}})
        alice = new["clients"]["alice"]
        assert alice["token_sha256"] == DIGEST and alice["expires"] == "2027-06-30"
        assert alice["nas"] == ["nas1"] and "tools" not in alice
        assert new["clients"]["bob"] == base_document()["clients"]["bob"]


class TestWriteAccess:
    def test_write_access_adds_the_file_changing_tools_and_leaves_restricted_mode(self):
        new = apply({"clients": {"alice": {"write": True}}})
        assert set(new["clients"]["alice"]["tools"]) == set(DEFAULT_TOOLS) | WRITE_TOOLS
        assert not DELETE_TOOLS & set(new["clients"]["alice"]["tools"])
        assert new["restricted_mode"] is False

    def test_delete_is_its_own_switch_and_needs_write(self):
        both = apply({"clients": {"alice": {"write": True, "delete": True}}})
        assert DELETE_TOOLS <= set(both["clients"]["alice"]["tools"])
        only_delete = apply({"clients": {"alice": {"write": False, "delete": True}}})
        assert "tools" not in only_delete["clients"]["alice"]
        assert "restricted_mode" not in only_delete

    def test_turning_it_off_again_restores_the_default_set_and_restricted_mode(self):
        on = apply({"clients": {"alice": {"write": True, "delete": True}}})
        off = apply({"clients": {"alice": {"write": False}}}, on)
        assert set(off["clients"]["alice"]["tools"]) == set(DEFAULT_TOOLS)
        assert "restricted_mode" not in off

    def test_a_client_with_its_own_tool_list_keeps_it(self):
        new = apply({"clients": {"bob": {"write": True}}})
        assert (
            set(new["clients"]["bob"]["tools"]) == {"list_shares", "synology_status"} | WRITE_TOOLS
        )
        back = apply({"clients": {"bob": {"write": False}}}, new)
        assert back["clients"]["bob"]["tools"] == ["list_shares", "synology_status"]

    def test_a_tool_granted_by_hand_outside_the_page_is_not_removed(self):
        document = base_document()
        document["clients"]["bob"]["tools"] = ["list_shares", "synology_container_stop"]
        new = apply({"clients": {"bob": {"write": True, "delete": False}}}, document)
        assert "synology_container_stop" in new["clients"]["bob"]["tools"]

    def test_restricted_mode_stays_off_while_another_tool_still_needs_it(self):
        document = base_document()
        document["restricted_mode"] = False
        document["clients"]["bob"]["tools"] = ["list_shares", "synology_container_stop"]
        new = apply({"clients": {"alice": {"write": False}}}, document)
        assert new["restricted_mode"] is False

    def test_a_policy_that_turned_restricted_mode_off_by_hand_is_left_alone_otherwise(self):
        document = base_document()
        document["restricted_mode"] = False
        new = apply({"clients": {"alice": {"folders": {"nas1": ["/photos"]}}}}, document)
        assert new["restricted_mode"] is False

    @pytest.mark.parametrize("flag", ["write", "delete"])
    def test_a_switch_must_be_on_or_off(self, flag):
        with pytest.raises(SettingsError):
            apply({"clients": {"alice": {flag: "yes"}}})

    def test_every_tool_the_page_can_grant_is_one_the_policy_accepts(self):
        # A name the broker does not register would make every later save fail.
        sys.modules.get("mcp_server") or __import__("mcp_server")
        registered = set(sys.modules["mcp_server"].SynologyMCPServer()._tool_registry)
        assert (WRITE_TOOLS | DELETE_TOOLS) <= registered


class TestDescribe:
    def test_a_change_to_each_area_is_said_in_words(self):
        old = base_document()
        new = apply(
            {
                "session": {"idle_minutes": 30},
                "clients": {"alice": {"write": True, "folders": {"nas1": ["/docs", "/photos"]}}},
            }
        )
        lines = describe_changes(old, new)
        assert "End a NAS session after being unused for 30 min (was 15 min)" in lines
        assert "alice on nas1: folders /docs, /photos (was /docs)" in lines
        assert "alice: write access ON" in lines
        assert any("leaves restricted mode" in line for line in lines)

    def test_no_difference_is_no_lines(self):
        assert describe_changes(base_document(), apply({})) == []

    def test_turning_something_off_says_off(self):
        on = apply({"clients": {"alice": {"write": True, "delete": True}}})
        off = apply({"clients": {"alice": {"write": False}}}, on)
        lines = describe_changes(on, off)
        assert "alice: write access off" in lines and "alice: delete off" in lines

    def test_the_digest_follows_the_content_and_not_the_order(self):
        a = {"x": 1, "y": [1, 2]}
        b = {"y": [1, 2], "x": 1}
        assert digest_of(a) == digest_of(b) and digest_of(a) != digest_of({"x": 2, "y": [1, 2]})


# -- the file --------------------------------------------------------------------

KNOWN_TOOLS = set(DEFAULT_TOOLS) | WRITE_TOOLS | DELETE_TOOLS | {"synology_logout"}


def file_document():
    document = base_document()
    for entry in document["clients"].values():
        entry["expires"] = future_expiry()
    return document


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "broker-policy.json"
    path.write_text(json.dumps(file_document()), encoding="utf-8")
    return PolicyStore(path, known_nas=BASE_URLS, known_tools=KNOWN_TOOLS)


class TestPolicyStore:
    def test_it_reads_the_file_as_written(self, store):
        assert store.read() == file_document()

    def test_a_missing_or_broken_file_is_a_policy_error_that_names_no_value(self, tmp_path):
        missing = PolicyStore(tmp_path / "nope.json", known_nas=BASE_URLS, known_tools=KNOWN_TOOLS)
        with pytest.raises(PolicyError, match="does not exist"):
            missing.read()
        broken = tmp_path / "broken.json"
        broken.write_text('{"token": "TOP-SECRET-VALUE"', encoding="utf-8")
        with pytest.raises(PolicyError) as error:
            PolicyStore(broken, known_nas=BASE_URLS, known_tools=KNOWN_TOOLS).read()
        assert "TOP-SECRET-VALUE" not in str(error.value)
        array = tmp_path / "array.json"
        array.write_text("[]", encoding="utf-8")
        with pytest.raises(PolicyError):
            PolicyStore(array, known_nas=BASE_URLS, known_tools=KNOWN_TOOLS).read()

    def test_a_valid_change_is_written_and_returned_as_a_policy(self, store):
        document = file_document()
        document["clients"]["alice"]["folders"] = {"nas1": ["/photos"]}
        policy = store.save(document)
        assert policy.clients["alice"].folders["nas1"] == ("/photos",)
        assert store.read()["clients"]["alice"]["folders"] == {"nas1": ["/photos"]}

    def test_the_old_file_is_kept_beside_it(self, store):
        before = store.path.read_text(encoding="utf-8")
        document = file_document()
        document["session"] = {"idle_seconds": 600}
        store.save(document)
        previous = store.path.with_name(store.path.name + ".previous")
        assert previous.read_text(encoding="utf-8") == before

    def test_an_invalid_change_writes_nothing(self, store):
        before = store.path.read_bytes()
        document = file_document()
        document["clients"]["alice"]["tools"] = ["not_a_tool"]
        with pytest.raises(PolicyError):
            store.save(document)
        assert store.path.read_bytes() == before
        assert [p.name for p in store.path.parent.iterdir()] == [store.path.name]

    def test_a_save_leaves_no_temporary_file(self, store):
        store.save(file_document())
        names = sorted(p.name for p in store.path.parent.iterdir())
        assert names == [store.path.name, store.path.name + ".previous"]

    def test_a_file_changed_since_the_change_was_prepared_is_not_overwritten(self, store):
        based_on = store.read()
        edited = file_document()
        edited["session"] = {"idle_seconds": 100}
        store.path.write_text(json.dumps(edited), encoding="utf-8")
        with pytest.raises(PolicyError, match="changed on disk"):
            store.save(file_document(), based_on=based_on)
        assert json.loads(store.path.read_text(encoding="utf-8"))["session"] == {
            "idle_seconds": 100
        }

    def test_what_the_page_does_not_edit_is_carried_over(self, store):
        document = store.read()
        document["deny_paths"] = ["/secret"]
        store.path.write_text(json.dumps(document), encoding="utf-8")
        changed = apply_proposal(
            store.read(), {"clients": {"alice": {"write": True}}}, restricted_allows=allows
        )
        store.save(changed)
        saved = store.read()
        assert saved["deny_paths"] == ["/secret"]
        assert saved["clients"]["alice"]["token_sha256"] == DIGEST
        assert saved["clients"]["alice"]["expires"] == document["clients"]["alice"]["expires"]

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
    def test_the_file_stays_private_to_the_broker(self, store):
        store.save(file_document())
        assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600

    def test_a_missing_file_is_not_writable(self, tmp_path):
        absent = PolicyStore(tmp_path / "x.json", known_nas=BASE_URLS, known_tools=KNOWN_TOOLS)
        assert absent.writable() is False

    def test_an_ordinary_file_is_writable(self, store):
        assert store.writable() is True


# -- the service -----------------------------------------------------------------

CLIENTS = {
    "alice": {"token": "alice-token-value", "nas": ["nas1"], "folders": {"nas1": ["/docs"]}},
    "bob": {"token": "bob-token-value", "nas": ["nas1", "nas2"], "tools": ["list_shares"]},
}


@pytest.fixture
def broker(monkeypatch):
    return Broker(
        monkeypatch,
        CLIENTS,
        session={"idle_seconds": 100, "absolute_seconds": 1000, "pending_seconds": 50},
    )


@pytest.fixture
def service(broker, tmp_path):
    from mcp_server import SynologyMCPServer

    path = tmp_path / "broker-policy.json"
    path.write_text(json.dumps(broker.document), encoding="utf-8")
    registry = SynologyMCPServer()
    store = PolicyStore(path, known_nas=BASE_URLS, known_tools=set(registry._tool_registry))
    broker.restricted_calls = []
    broker.runtime._set_restricted_mode = broker.restricted_calls.append
    service = SettingsService(store, broker.runtime, registry._is_tool_allowed, clock=broker.clock)
    service.store = store
    return service


def commit(service, proposal):
    prepared = service.prepare(proposal)
    assert prepared.digest, "the proposal should have changed something"
    return service.commit(prepared.digest)


class TestServiceView:
    def test_it_shows_the_live_policy(self, service):
        view = service.view()
        assert view["idle_minutes"] == pytest.approx(100 / 60)
        assert view["absolute_hours"] == pytest.approx(1000 / 3600)
        assert view["owner_idle_minutes"] == 10 and view["owner_absolute_hours"] == 1
        alice = next(c for c in view["clients"] if c["name"] == "alice")
        assert alice["write"] is False and alice["nas"] == [{"alias": "nas1", "roots": ["/docs"]}]
        bob = next(c for c in view["clients"] if c["name"] == "bob")
        assert [n["alias"] for n in bob["nas"]] == ["nas1", "nas2"]


class TestPrepare:
    def test_a_proposal_that_changes_nothing_holds_nothing(self, service):
        prepared = service.prepare({"clients": {"alice": {"folders": {"nas1": ["/docs"]}}}})
        assert prepared.digest == "" and prepared.changes == []
        assert service._pending == {}

    def test_it_says_what_would_change_and_writes_nothing(self, service):
        before = service.store.path.read_bytes()
        prepared = service.prepare({"clients": {"alice": {"write": True}}})
        assert "alice: write access ON" in prepared.changes
        assert len(prepared.digest) == 64
        assert service.store.path.read_bytes() == before

    def test_a_result_the_policy_would_refuse_is_refused_here_with_the_policys_words(self, service):
        with pytest.raises(SettingsError, match="may not exceed"):
            service.prepare({"session": {"idle_minutes": 600}})  # more than the 1000 s total
        with pytest.raises(SettingsError):
            service.prepare({"clients": {"alice": {"folders": {"nas1": ["/"]}}}})

    def test_a_read_only_policy_is_said_to_be_read_only(self, service, monkeypatch):
        monkeypatch.setattr(service.store, "writable", lambda: False)
        with pytest.raises(SettingsError, match="read-only"):
            service.prepare({"clients": {"alice": {"write": True}}})

    def test_a_broken_policy_file_is_reported_and_not_replaced(self, service):
        service.store.path.write_text("not json", encoding="utf-8")
        with pytest.raises(SettingsError, match="JSON"):
            service.prepare({"clients": {"alice": {"write": True}}})
        assert service.store.path.read_text(encoding="utf-8") == "not json"


class TestCommit:
    def test_the_file_and_the_running_broker_both_change(self, service, broker):
        old_policy = broker.runtime.policy
        changes = commit(
            service,
            {"clients": {"alice": {"write": True, "folders": {"nas1": ["/docs", "/photos"]}}}},
        )
        assert "alice: write access ON" in changes
        assert broker.runtime.policy is not old_policy
        alice = broker.runtime.policy.clients["alice"]
        assert WRITE_TOOLS <= alice.tools and alice.folders["nas1"] == ("/docs", "/photos")
        saved = json.loads(service.store.path.read_text(encoding="utf-8"))
        assert saved["clients"]["alice"]["folders"] == {"nas1": ["/docs", "/photos"]}
        assert saved["restricted_mode"] is False

    def test_the_broker_leaves_restricted_mode_when_a_client_gets_write_tools(
        self, service, broker
    ):
        commit(service, {"clients": {"alice": {"write": True}}})
        assert broker.restricted_calls == [False]

    def test_nothing_that_identifies_a_client_changes(self, service, broker):
        digests = {n: c.token_sha256 for n, c in broker.runtime.policy.clients.items()}
        expiries = {n: c.expires_at for n, c in broker.runtime.policy.clients.items()}
        commit(service, {"clients": {"alice": {"write": True}}, "session": {"idle_minutes": 1}})
        after = broker.runtime.policy.clients
        assert {n: c.token_sha256 for n, c in after.items()} == digests
        assert {n: c.expires_at for n, c in after.items()} == expiries

    def test_a_client_is_served_by_a_new_executor_with_the_new_tools(self, service, broker):
        before = broker.runtime.executor_for("alice")
        assert "create_file" not in before._allowed_tools
        commit(service, {"clients": {"alice": {"write": True}}})
        after = broker.runtime.executor_for("alice")
        assert after is not before and "create_file" in after._allowed_tools

    @pytest.mark.asyncio
    async def test_giving_one_client_write_access_leaves_another_clients_tools_alone(
        self, service, broker
    ):
        """Restricted mode is one switch for the whole broker, so granting write to one
        client turns it off for all; each client's own tool list is what still decides."""
        config = sys.modules["mcp_server"].config
        broker.runtime._set_restricted_mode = lambda value: setattr(
            config, "restricted_mode", value
        )
        alice_before = {t.name for t in await broker.runtime.list_tools("alice")}

        commit(service, {"clients": {"bob": {"write": True}}})

        assert config.restricted_mode is False  # the switch really did flip
        alice_after = {t.name for t in await broker.runtime.list_tools("alice")}
        bob_after = {t.name for t in await broker.runtime.list_tools("bob")}
        assert alice_after == alice_before and not alice_after & WRITE_TOOLS
        assert WRITE_TOOLS <= bob_after
        # ...and the tool is refused for a client whose list does not name it.
        result = await broker.runtime.call_tool("alice", "create_file", {"path": "/docs/x"})
        assert result.is_error and "not permitted" in result.content[0].text

    def test_signed_in_sessions_are_kept(self, service, broker):
        broker.sign_in("alice", "nas1")
        commit(service, {"clients": {"alice": {"folders": {"nas1": ["/photos"]}}}})
        assert broker.sessions.get("alice", "nas1", touch=False) is not None

    def test_a_shorter_session_limit_applies_to_sessions_already_open(self, service, broker):
        broker.sign_in("alice", "nas1")
        broker.clock.advance(70)  # inside the old 100 s limit
        commit(service, {"session": {"idle_minutes": 1, "absolute_hours": 0.25}})  # 60 s
        assert broker.sessions.get("alice", "nas1", touch=False) is None
        broker.runtime.reap_expired()
        assert broker.logged_out.wait(2)

    def test_a_change_can_be_confirmed_only_once(self, service):
        prepared = service.prepare({"clients": {"alice": {"write": True}}})
        service.commit(prepared.digest)
        with pytest.raises(SettingsError, match="expired"):
            service.commit(prepared.digest)

    def test_the_expiry_message_mentions_another_open_page_replacing_it(self, service):
        with pytest.raises(SettingsError, match="another open Settings page"):
            service.commit("0" * 64)

    def test_a_digest_that_was_never_prepared_is_refused(self, service, broker):
        before = broker.runtime.policy
        with pytest.raises(SettingsError):
            service.commit("0" * 64)
        assert broker.runtime.policy is before

    def test_a_change_that_waits_too_long_expires(self, service, broker):
        prepared = service.prepare({"clients": {"alice": {"write": True}}})
        broker.clock.advance(SettingsService.PENDING_SECONDS + 1)
        with pytest.raises(SettingsError, match="expired"):
            service.commit(prepared.digest)
        assert "restricted_mode" not in json.loads(service.store.path.read_text(encoding="utf-8"))

    def test_a_file_edited_after_the_change_was_prepared_is_not_overwritten(self, service, broker):
        prepared = service.prepare({"clients": {"alice": {"write": True}}})
        document = json.loads(service.store.path.read_text(encoding="utf-8"))
        document["deny_paths"] = ["/edited-by-hand"]
        service.store.path.write_text(json.dumps(document), encoding="utf-8")
        before = broker.runtime.policy
        with pytest.raises(SettingsError, match="changed on disk"):
            service.commit(prepared.digest)
        assert broker.runtime.policy is before
        assert json.loads(service.store.path.read_text(encoding="utf-8"))["deny_paths"] == [
            "/edited-by-hand"
        ]

    def test_only_a_bounded_number_of_changes_are_held(self, service):
        for minutes in range(1, SettingsService.MAX_PENDING + 5):
            service.prepare({"session": {"owner_idle_minutes": minutes}})
        assert len(service._pending) <= SettingsService.MAX_PENDING

    def test_a_write_failure_is_reported_and_the_broker_keeps_its_policy(
        self, service, broker, monkeypatch
    ):
        def fail(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(service.store, "save", fail)
        prepared = service.prepare({"clients": {"alice": {"write": True}}})
        before = broker.runtime.policy
        with pytest.raises(SettingsError, match="could not be written"):
            service.commit(prepared.digest)
        assert broker.runtime.policy is before
