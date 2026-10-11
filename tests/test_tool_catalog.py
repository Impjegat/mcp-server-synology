"""The tool catalog: plain-language titles, categories and examples.

The catalog is presentation only. These tests hold it to that: it must describe
exactly the tools the server registers, it must not change what any tool may do,
and what `docs/TOOL_CATALOG.md` says (what is on by default, what needs a
sign-in, what changes things) must be what the server actually does. All with
fake endpoints and dummy values.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from mcp.client import Client

import tool_catalog
from adapter.server import looks_like_credential
from broker.policy import DEFAULT_TOOLS, NEVER_TOOLS, parse_policy
from tool_catalog import CATALOG, CATEGORIES, NO_SIGN_IN_NEEDED, render_current, render_markdown

DOC = Path(__file__).resolve().parent.parent / "docs" / "TOOL_CATALOG.md"
BASE_URL = "https://nas.example.test:5001"


def _module():
    return sys.modules["mcp_server"]


def _server(**kwargs):
    import mcp_server

    return mcp_server.SynologyMCPServer(**kwargs)


def _definitions(server):
    return [*server._get_tool_definitions(), *server._all_session_tool_definitions()]


def _names(server):
    return {tool.name for tool in _definitions(server)}


@pytest.fixture
def broker_mode(monkeypatch):
    """Broker mode with one NAS configured, restricted mode on (the default)."""
    import auth.synology_auth  # noqa: F401
    import mcp_server  # noqa: F401
    import utils.synology_api  # noqa: F401

    for target in ("mcp_server", "utils.synology_api", "auth.synology_auth"):
        monkeypatch.setattr(sys.modules[target].config, "auth_mode", "broker")
    config = sys.modules["mcp_server"].config
    monkeypatch.setattr(config, "auto_login", False)
    monkeypatch.setattr(config, "restricted_mode", True)
    monkeypatch.setattr(
        config,
        "nas_configs",
        {"nas1": {"base_url": BASE_URL, "username": "reader", "verify_ssl": True, "note": ""}},
    )
    return config


@pytest.fixture
def legacy_mode(monkeypatch):
    import mcp_server  # noqa: F401

    config = sys.modules["mcp_server"].config
    monkeypatch.setattr(config, "auth_mode", "legacy")
    monkeypatch.setattr(config, "auto_login", False)
    monkeypatch.setattr(config, "restricted_mode", False)
    return config


def _text(result):
    assert len(result.content) == 1
    return result.content[0].text


# ------------------------------------------------------------------ the table


class TestTheCatalogDescribesTheRegistry:
    def test_every_registered_tool_has_an_entry_and_every_entry_a_tool(self, legacy_mode):
        server = _server()
        registered = set(server._tool_registry)
        assert registered == _names(server)  # the registry and the definitions agree
        assert set(CATALOG) == registered

    def test_in_broker_mode_the_catalog_still_covers_what_is_registered(self, broker_mode):
        server = _server()
        assert set(server._tool_registry) <= set(CATALOG)
        assert "synology_login" not in server._tool_registry and "synology_login" in CATALOG

    def test_every_entry_has_a_valid_category_a_sentence_and_a_distinct_title(self):
        categories = {key for key, _ in CATEGORIES}
        titles = [found.title for found in CATALOG.values()]
        assert len(set(titles)) == len(titles), "two tools share a title"
        for name, found in CATALOG.items():
            assert found.category in categories, name
            assert 3 <= len(found.title) <= 40 and found.title != name, name
            assert found.summary.endswith("."), name
            assert "\n" not in found.title and "|" not in found.title + found.summary, name

    def test_every_category_is_used(self):
        used = {found.category for found in CATALOG.values()}
        assert used == {key for key, _ in CATEGORIES}

    def test_the_headline_titles_from_the_plan_are_there(self):
        assert CATALOG["synology_health_summary"].title == "NAS health summary"
        assert CATALOG["list_shares"].title == "Browse shared folders"
        assert CATALOG["search_files"].title == "Search files"


# ------------------------------------------------------------ what is served


class TestTitlesAreServed:
    def test_every_listed_tool_carries_its_title_and_keeps_its_name(self, legacy_mode):
        server = _server()
        for tool in [*server._get_tool_definitions(), *server._session_tool_definitions()]:
            assert tool.name in CATALOG
            assert tool.title == CATALOG[tool.name].title
            assert tool.annotations.title == tool.title

    @pytest.mark.asyncio
    async def test_titles_travel_over_the_protocol(self, legacy_mode):
        server = _server()
        async with Client(server.server) as client:
            tools = (await client.list_tools()).tools
        assert tools and {tool.name for tool in tools} <= set(CATALOG)
        for tool in tools:
            assert tool.title == CATALOG[tool.name].title, tool.name
            wire = tool.model_dump(by_alias=True, exclude_none=True)
            assert wire["title"] == tool.title and wire["name"] == tool.name

    def test_the_read_only_and_destructive_hints_are_unchanged(self, legacy_mode):
        server = _server()
        by_name = {tool.name: tool for tool in _definitions(server)}
        module = _module()
        for name, tool in by_name.items():
            assert tool.annotations.read_only_hint == (name in module._READ_ONLY_TOOLS), name
            assert tool.annotations.destructive_hint == (name in module._DESTRUCTIVE_TOOLS), name

    def test_annotating_twice_does_not_repeat_a_note(self, legacy_mode):
        server = _server()
        tool = next(t for t in _definitions(server) if t.name == "get_file_content")
        once = tool.description
        server._annotate_tool(tool)
        assert tool.description == once and once.count(tool_catalog.CONTENT_NOTE) == 1


class TestNotesForTheModel:
    CONTENT_TOOLS = (
        "get_file_content",
        "synology_system_log",
        "synology_container_logs",
        "synology_container_get",
        "synology_container_project_get",
    )

    def test_tools_that_return_free_text_say_it_goes_to_the_ai_provider(self, legacy_mode):
        by_name = {tool.name: tool for tool in _definitions(_server())}
        flagged = {name for name, found in CATALOG.items() if found.sends_content}
        assert flagged == set(self.CONTENT_TOOLS)
        for name in flagged:
            assert "AI provider" in by_name[name].description, name
        for name in set(by_name) - flagged:
            assert "AI provider" not in by_name[name].description, name

    def test_status_tells_a_model_the_user_signs_in_privately_in_manual_mode(self, broker_mode):
        tool = next(t for t in _definitions(_server()) if t.name == "synology_status")
        assert "never ask for, or accept, a NAS password" in tool.description
        others = [t for t in _definitions(_server()) if t.name != "synology_status"]
        assert not any("never ask for" in (t.description or "") for t in others)

    def test_in_legacy_mode_that_note_is_not_there_because_a_login_tool_is(self, legacy_mode):
        tool = next(t for t in _definitions(_server()) if t.name == "synology_status")
        assert "never ask for" not in tool.description

    def test_the_original_descriptions_are_kept(self, legacy_mode):
        tool = next(t for t in _definitions(_server()) if t.name == "list_shares")
        assert tool.description == "List all available shares on the Synology NAS"


# ----------------------------------------- the catalog does not decide access


class TestTheCatalogIsNotAnAuthorization:
    @staticmethod
    async def _listed(server):
        return sorted(tool.name for tool in await server._list_tools())

    @pytest.mark.asyncio
    async def test_scrambling_the_catalog_changes_no_tool_that_is_offered(
        self, broker_mode, monkeypatch
    ):
        server = _server()
        before = await self._listed(server)
        allowed_before = {name: server._is_tool_allowed(name) for name in CATALOG}

        names = sorted(CATALOG)
        scrambled = {
            name: tool_catalog.ToolEntry(
                title=f"Harmless thing {index}",
                category="health",
                summary="Nothing to see.",
                example={},
                sends_content=False,
            )
            for index, name in enumerate(names)
        }
        monkeypatch.setattr(tool_catalog, "CATALOG", scrambled)

        assert await self._listed(_server()) == before
        assert {name: server._is_tool_allowed(name) for name in names} == allowed_before

    @pytest.mark.asyncio
    async def test_a_friendly_title_does_not_let_a_tool_through_restricted_mode(
        self, broker_mode, monkeypatch
    ):
        monkeypatch.setitem(
            CATALOG,
            "delete",
            tool_catalog.ToolEntry("Read a harmless note", "files", "Reads a note.", {}),
        )
        server = _server()
        result = await server._call_tool("delete", {"nas_name": "nas1", "path": "/Shared/x"})
        assert result.is_error is True
        assert "restricted" in _text(result).lower()

    def test_an_entry_that_calls_a_tool_safe_does_not_change_its_classification(
        self, legacy_mode, monkeypatch
    ):
        monkeypatch.setitem(
            CATALOG,
            "delete",
            tool_catalog.ToolEntry("Read a harmless note", "files", "Reads a note.", {}),
        )
        tool = next(t for t in _definitions(_server()) if t.name == "delete")
        assert (
            tool.annotations.read_only_hint is False and tool.annotations.destructive_hint is True
        )

    def test_the_module_holds_no_list_of_allowed_tools(self):
        source = Path(tool_catalog.__file__).read_text(encoding="utf-8")
        for forbidden in ("_READ_ONLY_TOOLS =", "_DESTRUCTIVE_TOOLS =", "DEFAULT_TOOLS ="):
            assert forbidden not in source
        # and it imports nothing from the server at import time
        head = source.split("def render_current")[0]
        assert "import mcp_server" not in head and "from broker" not in head


# ---------------------------------------------------------------- examples


class TestExamples:
    @staticmethod
    def _on_by_default(server):
        names = set(DEFAULT_TOOLS)
        names |= {name for name in CATALOG if server._is_tool_allowed(name)}
        return names - NEVER_TOOLS

    def test_every_tool_that_is_on_by_default_has_a_safe_example(self, legacy_mode):
        server = _server()
        for name in self._on_by_default(server):
            assert CATALOG[name].example is not None, name

    def test_each_example_is_valid_for_its_tool(self, legacy_mode):
        server = _server()
        for name, found in CATALOG.items():
            if found.example is None:
                continue
            errors = list(server._input_validators[name].iter_errors(dict(found.example)))
            assert errors == [], (name, [e.message for e in errors])

    def test_no_example_carries_a_credential_or_a_real_looking_address(self):
        for name, found in CATALOG.items():
            if found.example is None:
                continue
            text = json.dumps(found.example)
            assert not any(looks_like_credential(key) for key in found.example), name
            assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text), name
            assert "@" not in text, name
            assert all(isinstance(v, (str, int, bool)) for v in found.example.values()), name

    def test_every_example_is_for_a_tool_that_is_not_destructive(self, legacy_mode):
        module = _module()
        for name, found in CATALOG.items():
            if found.example is not None:
                assert name not in module._DESTRUCTIVE_TOOLS, name


# ---------------------------------------- the document says what is true


def _rows(markdown):
    """tool id -> (title, effect, sign-in needed, on by default) from the tables."""
    rows = {}
    for line in markdown.splitlines():
        match = re.match(
            r"^\| (?P<title>.+?) \| `(?P<id>[a-z_]+)` \| .* \| (?P<tail>[^|]+) \|$", line
        )
        if not match:
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        rows[match["id"]] = (cells[0], cells[3], cells[4], cells[5])
    return rows


class TestTheDocumentIsCurrentAndTrue:
    def test_the_file_is_what_the_generator_writes(self):
        expected = render_current()
        actual = DOC.read_text(encoding="utf-8").replace("\r\n", "\n")
        assert (
            actual == expected
        ), "docs/TOOL_CATALOG.md is out of date. Run: python scripts/generate_tool_catalog.py"

    def test_it_lists_every_registered_tool_once(self, legacy_mode):
        rows = _rows(DOC.read_text(encoding="utf-8"))
        assert set(rows) == set(_server()._tool_registry)
        text = DOC.read_text(encoding="utf-8")
        for name in rows:
            assert text.count(f"| `{name}` |") == 1, name

    def test_titles_and_effects_match_what_the_server_serves(self, legacy_mode):
        module = _module()
        rows = _rows(DOC.read_text(encoding="utf-8"))
        for name, (title, effect, _sign_in, _default) in rows.items():
            assert title == CATALOG[name].title
            if name in module._DESTRUCTIVE_TOOLS:
                assert effect == "Deletes data", name
            elif name in module._READ_ONLY_TOOLS:
                assert effect == "Reads only", name
            else:
                assert effect == "Changes things", name

    @pytest.mark.asyncio
    async def test_on_by_default_matches_restricted_mode_and_the_brokers_default_grant(
        self, broker_mode
    ):
        rows = _rows(DOC.read_text(encoding="utf-8"))
        server = _server()
        # what a default installation offers, from the server's own decision
        offered = {tool.name for tool in await server._list_tools()}
        said_offered = {n for n, row in rows.items() if row[3] in ("Yes", "Restricted mode only")}
        assert said_offered - {"synology_login"} == offered

        # what a broker client with no `tools` entry is granted, from the policy parser
        policy = parse_policy(
            {"clients": {"c": {"token_sha256": "a" * 64, "nas": ["nas1"]}}},
            known_nas={"nas1"},
            known_tools=set(CATALOG) - NEVER_TOOLS,
        )
        granted = policy.clients["c"].allowed_tools()
        said_granted = {n for n, row in rows.items() if row[3] == "Yes"}
        assert said_granted == granted
        assert {n for n, row in rows.items() if row[3] == "Legacy mode only"} == NEVER_TOOLS

    def test_the_brokers_default_grant_is_all_inside_restricted_mode(self, broker_mode):
        server = _server()
        assert all(server._is_tool_allowed(name) for name in DEFAULT_TOOLS)

    @pytest.mark.asyncio
    async def test_sign_in_needed_is_what_the_server_does(self, broker_mode):
        """With nobody signed in, a tool the document says needs a sign-in answers
        AUTHENTICATION_REQUIRED, and one it says does not, does not."""
        rows = _rows(DOC.read_text(encoding="utf-8"))
        server = _server()
        checked = set()
        for name, found in CATALOG.items():
            if found.example is None or name not in server._tool_registry:
                continue
            result = await server._call_tool(name, dict(found.example))
            asks_for_sign_in = result.is_error is True and _text(result).startswith(
                "AUTHENTICATION_REQUIRED"
            )
            says = rows[name][2]
            assert says == ("No" if name in NO_SIGN_IN_NEEDED else "Yes"), name
            assert asks_for_sign_in == (says == "Yes"), (name, _text(result)[:120])
            checked.add(name)
        # not a vacuous pass: every tool a default installation offers was tried,
        # on both sides of the line
        offered = {name for name in server._tool_registry if server._is_tool_allowed(name)}
        assert offered <= checked
        assert checked & NO_SIGN_IN_NEEDED and checked - NO_SIGN_IN_NEEDED

    def test_every_tool_that_is_on_by_default_has_its_example_in_the_document(self, legacy_mode):
        text = DOC.read_text(encoding="utf-8")
        server = _server()
        for name in TestExamples._on_by_default(server):
            example = json.dumps(CATALOG[name].example, separators=(", ", ": "))
            assert f"- `{name}`: `{example}`" in text, name

    def test_a_tool_that_is_off_by_default_has_no_example_in_the_document(self, legacy_mode):
        text = DOC.read_text(encoding="utf-8")
        for name in ("delete", "synology_create_user", "ds_create_task", "synology_login"):
            assert f"- `{name}`:" not in text, name

    def test_it_says_where_the_adapter_cannot_help(self):
        text = DOC.read_text(encoding="utf-8")
        create_user = next(line for line in text.splitlines() if "`synology_create_user`" in line)
        assert "Cannot be used through the adapter" in create_user
        set_user = next(line for line in text.splitlines() if "`synology_set_user`" in line)
        assert "leave out" in set_user

    def test_it_says_nothing_that_looks_like_a_secret(self):
        text = DOC.read_text(encoding="utf-8")
        assert not re.search(r"[0-9a-f]{40,}", text)
        assert "BEGIN " not in text


class TestRenderingRefusesADrift:
    def _inputs(self, names):
        schema = {"type": "object", "properties": {}, "required": []}
        return {
            "definitions": {name: schema for name in names},
            "read_only": set(names),
            "destructive": set(),
            "account_enumeration": set(),
            "session_tools": set(),
            "broker_default": set(),
            "never_granted": set(),
        }

    def test_a_registered_tool_without_an_entry_is_an_error(self):
        with pytest.raises(ValueError, match="no entry for \\['brand_new_tool'\\]"):
            render_markdown(**self._inputs([*CATALOG, "brand_new_tool"]))

    def test_an_entry_for_a_tool_that_is_not_registered_is_an_error(self):
        names = [name for name in CATALOG if name != "list_shares"]
        with pytest.raises(ValueError, match="list_shares"):
            render_markdown(**self._inputs(names))

    def test_the_same_inputs_give_the_same_text(self):
        inputs = self._inputs(list(CATALOG))
        assert render_markdown(**inputs) == render_markdown(**inputs)


class TestTheGeneratorScript:
    def _run(self, *args):
        script = Path(__file__).resolve().parent.parent / "scripts" / "generate_tool_catalog.py"
        return subprocess.run(
            [sys.executable, str(script), *args],
            capture_output=True,
            text=True,
            timeout=120,
            env={k: v for k, v in os.environ.items() if not k.startswith("SYNOLOGY")},
        )

    def test_check_passes_when_the_file_is_current(self):
        done = self._run("--check")
        assert done.returncode == 0, done.stderr
        assert "up to date" in done.stdout
