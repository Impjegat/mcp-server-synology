"""The broker policy: strict parsing, hashed tokens, and a default tool set that
cannot widen by accident. Everything uses dummy values."""

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
    entry = {"token_sha256": DIGEST, "nas": ["nas1"], **client}
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
        document = {"clients": {"bad name!": {"token_sha256": DIGEST, "nas": ["nas1"]}}}
        with pytest.raises(PolicyError, match="invalid client name"):
            _parse(document, known_tools)

    @pytest.mark.parametrize("digest", ["short", "G" * 64, DIGEST.upper(), "x" * 80, None, 5])
    def test_a_token_digest_must_be_lowercase_sha256_hex(self, known_tools, digest):
        document = {"clients": {"alice": {"token_sha256": digest, "nas": ["nas1"]}}}
        with pytest.raises(PolicyError, match="token_sha256") as error:
            _parse(document, known_tools)
        if isinstance(digest, str):
            assert digest not in str(error.value)

    def test_two_clients_cannot_share_a_token(self, known_tools):
        document = {
            "clients": {
                "alice": {"token_sha256": DIGEST, "nas": ["nas1"]},
                "bob": {"token_sha256": DIGEST, "nas": ["nas1"]},
            }
        }
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
                    "alice": {"token_sha256": hash_token("token-one"), "nas": ["nas1"]},
                    "bob": {"token_sha256": hash_token("token-two"), "nas": ["nas2"]},
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
        assert alice.scopes == [] and alice.expires_at is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("token", ["wrong", "", "token-one ", "TOKEN-ONE", DIGEST])
    async def test_anything_else_is_refused(self, known_tools, token):
        policy = _parse(_minimal(), known_tools)  # the real token is "token-one"
        # Including the digest itself, which must not work as a token.
        assert await PolicyTokenVerifier(policy).verify_token(token) is None
