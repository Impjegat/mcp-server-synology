"""The broker policy: strict parsing, hashed tokens, and a default tool set that
cannot widen by accident. Everything uses dummy values."""

import datetime
import json

import pytest

from broker.policy import (
    DEFAULT_TOOLS,
    NEVER_TOOLS,
    PolicyError,
    PolicyTokenVerifier,
    generate_token,
    hash_token,
    load_policy,
    parse_policy,
)
from tests.broker_support import future_expiry

DIGEST = hash_token("token-one")
OTHER_DIGEST = hash_token("token-two")
NAS = {"nas1", "nas2"}


@pytest.fixture(scope="module")
def known_tools():
    from mcp_server import SynologyMCPServer

    return set(SynologyMCPServer()._tool_registry)


def _parse(document, known_tools):
    return parse_policy(document, known_nas=NAS, known_tools=known_tools)


def _minimal(**client):
    entry = {"token_sha256": DIGEST, "nas": ["nas1"], "expires": future_expiry(), **client}
    return {"clients": {"alice": entry}}


class TestParsing:
    def test_a_minimal_policy_gets_the_default_scope(self, known_tools):
        policy = _parse(_minimal(), known_tools)
        client = policy.clients["alice"]

        assert client.tools == DEFAULT_TOOLS
        assert client.nas == {"nas1"}
        assert client.folders == {}
        assert "synology_logout" in client.allowed_tools()
        assert policy.session.idle_seconds == 900
        assert policy.session.absolute_seconds == 28800

    def test_disconnect_can_be_withheld(self, known_tools):
        client = _parse(_minimal(disconnect=False), known_tools).clients["alice"]
        assert "synology_logout" not in client.allowed_tools()

    def test_an_explicit_tool_list_replaces_the_default(self, known_tools):
        client = _parse(_minimal(tools=["list_shares"]), known_tools).clients["alice"]
        assert client.tools == {"list_shares"}

    def test_listing_logout_among_the_tools_does_not_bypass_the_disconnect_switch(
        self, known_tools
    ):
        client = _parse(
            _minimal(tools=["list_shares", "synology_logout"], disconnect=False), known_tools
        ).clients["alice"]
        assert "synology_logout" not in client.allowed_tools()

    def test_folders_and_session_settings_are_read(self, known_tools):
        document = _minimal(folders={"nas1": ["/docs", "/photos/2026"]})
        document["session"] = {"idle_seconds": 60, "absolute_seconds": 600}
        document["deny_paths"] = ["/docs/private"]
        policy = _parse(document, known_tools)

        assert policy.clients["alice"].folders == {"nas1": ("/docs", "/photos/2026")}
        assert policy.session.idle_seconds == 60
        assert policy.deny_paths == ("/docs/private",)
        folders = policy.folder_policy_for(policy.clients["alice"])
        assert folders.allows("nas1", "/docs/a.txt")
        assert not folders.allows("nas1", "/docs/private/a.txt")

    @pytest.mark.parametrize(
        "document,message",
        [
            ([], "JSON object"),
            ({}, "at least one client"),
            ({"clients": {}}, "at least one client"),
            ({"clients": {"a": {}}, "extra": 1}, "unknown setting 'extra'"),
            (_minimal(unexpected=1), "unknown setting 'unexpected'"),
            (_minimal(nas=[]), "at least one NAS"),
            (_minimal(nas=["elsewhere"]), "not a configured NAS"),
            (_minimal(tools=["no_such_tool"]), "not a known tool"),
            (_minimal(tools=["synology_login"]), "may not be granted"),
            (_minimal(folders={"nas2": ["/docs"]}), "not one of this client's NAS units"),
            (_minimal(folders={"nas1": ["/"]}), "share path"),
            (_minimal(folders={"nas1": ["docs"]}), "share path"),
            (_minimal(disconnect="yes"), "true or false"),
            ({**_minimal(), "session": {"idle_seconds": 0}}, "positive whole number"),
            ({**_minimal(), "session": {"idle_seconds": True}}, "positive whole number"),
            (
                {**_minimal(), "session": {"idle_seconds": 90, "absolute_seconds": 60}},
                "may not exceed",
            ),
            ({**_minimal(), "session": {"absolute_seconds": 30 * 24 * 3600}}, "seven days"),
            ({**_minimal(), "session": {"surprise": 5}}, "unknown setting 'surprise'"),
        ],
    )
    def test_a_bad_policy_is_refused(self, known_tools, document, message):
        with pytest.raises(PolicyError, match=message):
            _parse(document, known_tools)

    def test_a_client_name_must_be_plain(self, known_tools):
        entry = {"token_sha256": DIGEST, "nas": ["nas1"], "expires": future_expiry()}
        document = {"clients": {"bad name!": entry}}
        with pytest.raises(PolicyError, match="invalid client name"):
            _parse(document, known_tools)

    @pytest.mark.parametrize("digest", ["short", "G" * 64, DIGEST.upper(), "x" * 80, None, 5])
    def test_a_token_digest_must_be_lowercase_sha256_hex(self, known_tools, digest):
        entry = {"token_sha256": digest, "nas": ["nas1"], "expires": future_expiry()}
        document = {"clients": {"alice": entry}}
        with pytest.raises(PolicyError, match="token_sha256") as error:
            _parse(document, known_tools)
        if isinstance(digest, str):
            assert digest not in str(error.value)

    def test_two_clients_cannot_share_a_token(self, known_tools):
        entry = {"token_sha256": DIGEST, "nas": ["nas1"], "expires": future_expiry()}
        document = {"clients": {"alice": dict(entry), "bob": dict(entry)}}
        with pytest.raises(PolicyError, match="already used by 'alice'"):
            _parse(document, known_tools)

    @pytest.mark.parametrize("key", ["token", "password", "api_secret", "session_id", "otp_code"])
    def test_a_secret_where_a_digest_belongs_is_called_out_without_being_echoed(
        self, known_tools, key
    ):
        value = "Dummy-Secret-Value-123"
        document = _minimal(**{key: value})
        with pytest.raises(PolicyError, match="never belongs in this file") as error:
            _parse(document, known_tools)
        assert value not in str(error.value)


NOW = datetime.datetime(2026, 10, 11, 12, 0, tzinfo=datetime.timezone.utc).timestamp()
DAY = 86400


def _at(days=0.0, seconds=0):
    """An ISO datetime with a time zone, `days` after NOW."""
    moment = datetime.datetime.fromtimestamp(NOW + days * DAY + seconds, datetime.timezone.utc)
    return moment.isoformat()


def _graded(known_tools, expires, now=NOW):
    return parse_policy(_minimal(expires=expires), known_nas=NAS, known_tools=known_tools, now=now)


class TestGrantExpiry:
    """A client token is a grant that can call the broker's tools. It must say when
    it ends, and the broker must stop honouring it then (implementation review
    R12). Session deadlines are a different thing: they end a DSM session."""

    def test_r12_a_grant_without_an_expiry_is_refused(self, known_tools):
        document = _minimal()
        del document["clients"]["alice"]["expires"]
        with pytest.raises(PolicyError, match=r"clients\.alice\.expires: required"):
            parse_policy(document, known_nas=NAS, known_tools=known_tools, now=NOW)

    def test_the_message_says_how_to_fix_it(self, known_tools):
        document = _minimal()
        del document["clients"]["alice"]["expires"]
        with pytest.raises(PolicyError) as error:
            parse_policy(document, known_nas=NAS, known_tools=known_tools, now=NOW)
        assert "at most a year" in str(error.value) and "2027-" in str(error.value)

    def test_a_date_lasts_through_the_whole_of_that_day_in_utc(self, known_tools):
        client = _graded(known_tools, "2027-06-30").clients["alice"]
        start_of_next_day = datetime.datetime(2027, 7, 1, tzinfo=datetime.timezone.utc).timestamp()
        assert client.expires_at == start_of_next_day

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("2027-06-30T12:00:00Z", (2027, 6, 30, 12, 0)),
            ("2027-06-30T12:00:00+00:00", (2027, 6, 30, 12, 0)),
            ("2027-06-30T12:00:00+02:00", (2027, 6, 30, 10, 0)),
            ("2027-06-30T12:00:00-05:00", (2027, 6, 30, 17, 0)),
        ],
    )
    def test_a_datetime_with_a_time_zone_is_that_moment(self, known_tools, text, expected):
        want = datetime.datetime(*expected, tzinfo=datetime.timezone.utc).timestamp()
        assert _graded(known_tools, text).clients["alice"].expires_at == want

    @pytest.mark.parametrize(
        "value",
        [
            "tomorrow",
            "",
            "2027-13-40",
            "30/06/2027",
            "2027-06-30T12:00:00",  # no time zone: ambiguous
            "2027-06-30 12:00:00",
            5,
            1.5,
            True,
            None,
            ["2027-06-30"],
            {"date": "2027-06-30"},
            "Dummy-Secret-Value-123",
        ],
    )
    def test_r12_an_expiry_that_is_not_a_date_is_refused_without_being_echoed(
        self, known_tools, value
    ):
        document = _minimal(expires=value)
        with pytest.raises(PolicyError, match=r"clients\.alice\.expires") as error:
            parse_policy(document, known_nas=NAS, known_tools=known_tools, now=NOW)
        if isinstance(value, str) and value:
            assert value not in str(error.value)

    def test_r12_a_year_ahead_is_the_limit(self, known_tools):
        assert _graded(known_tools, _at(days=366)).clients["alice"].expires_at == NOW + 366 * DAY
        with pytest.raises(PolicyError, match="more than a year"):
            _graded(known_tools, _at(days=366, seconds=1))
        with pytest.raises(PolicyError, match="more than a year"):
            _graded(known_tools, "2030-01-01")

    def test_the_limit_is_judged_from_the_time_the_policy_is_loaded(self, known_tools):
        later = NOW + 100 * DAY
        _graded(known_tools, _at(days=450), now=later)  # 350 days from `later`
        with pytest.raises(PolicyError, match="more than a year"):
            _graded(known_tools, _at(days=450), now=NOW)

    def test_a_grant_that_has_already_ended_does_not_stop_the_broker_loading(self, known_tools):
        policy = _graded(known_tools, _at(days=-3))
        assert policy.clients["alice"].expires_at < NOW

    def test_every_client_needs_its_own_expiry(self, known_tools):
        document = {
            "clients": {
                "alice": {"token_sha256": DIGEST, "nas": ["nas1"], "expires": _at(days=30)},
                "bob": {"token_sha256": OTHER_DIGEST, "nas": ["nas1"]},
            }
        }
        with pytest.raises(PolicyError, match=r"clients\.bob\.expires: required"):
            parse_policy(document, known_nas=NAS, known_tools=known_tools, now=NOW)

    # -- what the broker says at start-up ------------------------------------

    def test_an_ended_grant_is_named_in_the_start_up_warnings(self, known_tools):
        warnings = _graded(known_tools, _at(days=-3)).grant_warnings(NOW)
        assert len(warnings) == 1
        assert "alice" in warnings[0] and "ended" in warnings[0]

    def test_a_grant_that_ends_soon_is_named_in_the_start_up_warnings(self, known_tools):
        warnings = _graded(known_tools, _at(days=13)).grant_warnings(NOW)
        assert len(warnings) == 1
        assert "alice" in warnings[0] and "13" in warnings[0]

    def test_a_grant_with_time_left_gives_no_warning(self, known_tools):
        assert _graded(known_tools, _at(days=15)).grant_warnings(NOW) == []

    def test_the_two_week_and_the_ended_boundaries(self, known_tools):
        """Fourteen days out is the first day worth a word; a grant ending at this
        very moment has ended, as the verifier (which refuses at that moment) agrees."""
        assert "ends in 14 day(s)" in _graded(known_tools, _at(days=14)).grant_warnings(NOW)[0]
        assert _graded(known_tools, _at(days=14, seconds=1)).grant_warnings(NOW) == []
        now_exactly = _graded(known_tools, _at(days=0)).grant_warnings(NOW)
        assert len(now_exactly) == 1 and "ended on" in now_exactly[0]

    def test_the_warnings_name_the_client_and_never_the_token_or_its_digest(self, known_tools):
        for days in (-3, 5):
            for line in _graded(known_tools, _at(days=days)).grant_warnings(NOW):
                assert DIGEST not in line and "token-one" not in line

    # -- the verifier --------------------------------------------------------

    @pytest.mark.asyncio
    async def test_r12_a_grant_works_until_it_ends_and_not_after(self, known_tools):
        policy = _graded(known_tools, _at(days=10))
        now = [NOW]
        verifier = PolicyTokenVerifier(policy, clock=lambda: now[0])

        access = await verifier.verify_token("token-one")
        assert access is not None and access.client_id == "alice"
        assert access.expires_at == int(NOW + 10 * DAY)

        now[0] = NOW + 10 * DAY - 1
        assert await verifier.verify_token("token-one") is not None
        now[0] = NOW + 10 * DAY  # the moment it ends
        assert await verifier.verify_token("token-one") is None
        now[0] = NOW + 11 * DAY
        assert await verifier.verify_token("token-one") is None

    @pytest.mark.asyncio
    async def test_r12_a_grant_that_had_ended_before_the_broker_started_is_refused(
        self, known_tools
    ):
        policy = _graded(known_tools, _at(days=-1))
        verifier = PolicyTokenVerifier(policy, clock=lambda: NOW)
        assert await verifier.verify_token("token-one") is None

    @pytest.mark.asyncio
    async def test_an_ended_grant_does_not_end_anyone_elses(self, known_tools):
        document = {
            "clients": {
                "alice": {
                    "token_sha256": hash_token("token-one"),
                    "nas": ["nas1"],
                    "expires": _at(days=-1),
                },
                "bob": {
                    "token_sha256": hash_token("token-two"),
                    "nas": ["nas1"],
                    "expires": _at(days=30),
                },
            }
        }
        policy = parse_policy(document, known_nas=NAS, known_tools=known_tools, now=NOW)
        verifier = PolicyTokenVerifier(policy, clock=lambda: NOW)
        assert await verifier.verify_token("token-one") is None
        assert (await verifier.verify_token("token-two")).client_id == "bob"

    @pytest.mark.asyncio
    async def test_a_grant_with_no_expiry_at_all_is_refused_rather_than_trusted(self):
        """Only the policy parser makes grants, and it requires one; but a verifier
        handed a client without one fails closed."""
        from broker.policy import ClientPolicy, Policy

        client = ClientPolicy("alice", hash_token("token-one"), frozenset({"nas1"}), DEFAULT_TOOLS)
        verifier = PolicyTokenVerifier(Policy(clients={"alice": client}), clock=lambda: NOW)
        assert await verifier.verify_token("token-one") is None

    @pytest.mark.asyncio
    async def test_the_rest_of_the_answer_is_unchanged(self, known_tools):
        policy = _graded(known_tools, _at(days=10))
        access = await PolicyTokenVerifier(policy, clock=lambda: NOW).verify_token("token-one")
        assert access.scopes == [] and access.token.startswith("sha256:")
        assert "token-one" not in access.token


class TestDefaultScope:
    def test_every_default_tool_exists(self, known_tools):
        assert DEFAULT_TOOLS <= known_tools

    def test_the_default_scope_is_read_only(self):
        from mcp_server import _READ_ONLY_TOOLS

        assert DEFAULT_TOOLS <= _READ_ONLY_TOOLS

    def test_account_enumeration_is_not_in_the_default_scope(self):
        from mcp_server import _ACCOUNT_ENUMERATION_TOOLS

        assert not DEFAULT_TOOLS & _ACCOUNT_ENUMERATION_TOOLS

    @pytest.mark.parametrize(
        "tool",
        [
            "synology_container_get",
            "synology_container_project_get",
            "synology_container_image_get",
            "synology_container_logs",
            "synology_system_log",
            "ds_list_tasks",
            "ds_list_downloaded_files",
            "ds_get_info",
            "ds_get_statistics",
        ],
    )
    def test_secret_bearing_or_unfiltered_tools_are_left_out(self, tool):
        assert tool not in DEFAULT_TOOLS

    def test_no_tool_that_changes_anything_is_in_the_default_scope(self, known_tools):
        from mcp_server import _READ_ONLY_TOOLS

        assert not (DEFAULT_TOOLS & (known_tools - _READ_ONLY_TOOLS))

    def test_the_password_login_is_never_grantable(self):
        assert "synology_login" in NEVER_TOOLS
        assert "synology_login" not in DEFAULT_TOOLS


class TestLoading:
    def test_a_policy_file_is_read(self, tmp_path, known_tools):
        path = tmp_path / "policy.json"
        path.write_text(json.dumps(_minimal()))
        policy = load_policy(path, known_nas=NAS, known_tools=known_tools)
        assert list(policy.clients) == ["alice"]

    def test_a_missing_file_is_named(self, tmp_path, known_tools):
        with pytest.raises(PolicyError, match="does not exist"):
            load_policy(tmp_path / "absent.json", known_nas=NAS, known_tools=known_tools)

    def test_broken_json_does_not_echo_the_file(self, tmp_path, known_tools):
        path = tmp_path / "policy.json"
        path.write_text('{"clients": SECRET-LOOKING-CONTENT')
        with pytest.raises(PolicyError, match="cannot be read as JSON") as error:
            load_policy(path, known_nas=NAS, known_tools=known_tools)
        assert "SECRET-LOOKING-CONTENT" not in str(error.value)


class TestTokens:
    def test_a_generated_token_matches_its_digest(self):
        token, digest = generate_token()
        assert digest == hash_token(token)
        assert len(token) >= 40
        assert generate_token()[0] != token

    @pytest.mark.asyncio
    async def test_a_valid_token_identifies_its_client_without_being_kept(self, known_tools):
        policy = _parse(
            {
                "clients": {
                    "alice": {
                        "token_sha256": hash_token("token-one"),
                        "nas": ["nas1"],
                        "expires": future_expiry(),
                    },
                    "bob": {
                        "token_sha256": hash_token("token-two"),
                        "nas": ["nas2"],
                        "expires": future_expiry(),
                    },
                }
            },
            known_tools,
        )
        verifier = PolicyTokenVerifier(policy)

        alice = await verifier.verify_token("token-one")
        bob = await verifier.verify_token("token-two")

        assert (alice.client_id, bob.client_id) == ("alice", "bob")
        assert "token-one" not in alice.token
        assert alice.token.startswith("sha256:")
        assert alice.scopes == []
        # The moment the grant ends, so the SDK's own bearer check refuses it then too.
        assert isinstance(alice.expires_at, int) and alice.expires_at > 0

    @pytest.mark.asyncio
    @pytest.mark.parametrize("token", ["wrong", "", "token-one ", "TOKEN-ONE", DIGEST])
    async def test_anything_else_is_refused(self, known_tools, token):
        policy = _parse(_minimal(), known_tools)  # the real token is "token-one"
        # Including the digest itself, which must not work as a token.
        assert await PolicyTokenVerifier(policy).verify_token(token) is None
