"""Restricted-mode tool registry tests (PR 2: unified deny-by-default
dispatch, tool classification, and the restricted synology_login check)."""

from unittest.mock import patch

import mcp.types as types
import pytest
from mcp.shared.exceptions import MCPError


def _server():
    from mcp_server import SynologyMCPServer

    return SynologyMCPServer()


def test_call_tool_direct_and_get_tools_list_are_gone():
    """The dead second dispatch path (leftover from the removed Xiaozhi
    bridge) must not exist — it had already drifted out of sync with the
    live dispatch before being deleted."""
    server = _server()
    assert not hasattr(server, "call_tool_direct")
    assert not hasattr(server, "get_tools_list")


def test_every_tool_definition_has_a_registry_entry_and_vice_versa():
    """`_get_tool_definitions()` (discovery) and `_tool_registry`
    (dispatch) must describe exactly the same set of tools — that's the
    whole point of having one registry instead of two independently
    maintained dispatch paths."""
    server = _server()
    definition_names = {t.name for t in server._get_tool_definitions()}
    registry_names = set(server._tool_registry.keys())

    # synology_login/synology_logout are added to the *discovery* list
    # separately (only when relevant), but are always in the registry.
    assert definition_names - registry_names == set()
    assert registry_names - definition_names - {"synology_login", "synology_logout"} == set()


@pytest.mark.parametrize(
    "name",
    [
        "list_directory",
        "get_file_info",
        "search_files",
        "get_file_content",
        "synology_system_info",
        "synology_disk_health",
        "synology_container_list",
        "synology_container_logs",
    ],
)
def test_read_only_tools_are_classified_allowed(name):
    server = _server()
    assert server._is_tool_allowed(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "delete",
        "rename_file",
        "move_file",
        "create_file",
        "create_directory",
        "ds_create_task",
        "ds_delete_tasks",
        "synology_create_user",
        "synology_delete_user",
        "synology_set_user_permissions",
        "synology_nfs_enable",
        "synology_create_share",
        "synology_container_start",
        "synology_container_delete",
        "synology_container_image_pull",
    ],
)
def test_modifying_tools_are_classified_disallowed(name):
    server = _server()
    assert server._is_tool_allowed(name) is False


@pytest.mark.parametrize(
    "name",
    [
        "synology_list_users",
        "synology_get_user",
        "synology_list_groups",
        "synology_list_group_members",
        "synology_get_user_permissions",
    ],
)
def test_account_enumeration_tools_are_read_only_but_disallowed(name):
    """These perform no writes (readOnlyHint stays True — the annotation is
    a separate question from restricted-mode eligibility), but full account/
    group/permission enumeration is a different trust tier than file
    browsing or NAS monitoring, so restricted mode's default install
    excludes them too."""
    server = _server()
    assert server._is_tool_allowed(name) is False
    definitions = {t.name: t for t in server._get_tool_definitions()}
    assert definitions[name].annotations.read_only_hint is True


@pytest.mark.asyncio
async def test_restricted_mode_hides_modifying_tools_from_discovery():
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        fake_config.auto_login = True
        fake_config.has_synology_credentials.return_value = True
        tools = await server._list_tools()

    names = {t.name for t in tools}
    assert "get_file_content" in names
    assert "delete" not in names
    assert "synology_create_user" not in names
    # Read-only, but a different trust tier — hidden by default too.
    assert "synology_list_users" not in names


@pytest.mark.asyncio
async def test_unrestricted_mode_exposes_every_tool():
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = False
        fake_config.auto_login = True
        fake_config.has_synology_credentials.return_value = True
        tools = await server._list_tools()

    names = {t.name for t in tools}
    assert "delete" in names
    assert "synology_create_user" in names


@pytest.mark.asyncio
async def test_restricted_mode_rejects_modifying_tool_before_any_network_call():
    """A modifying tool call must be refused before its handler runs — not
    merely hidden from discovery. Calling `delete` with no active session
    would normally raise "No active session"; in restricted mode it must
    never get that far."""
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        result = await server._call_tool("delete", {"path": "/share/x"})

    # A refusal is a failed call (isError), not a successful one.
    assert result.is_error is True
    assert len(result.content) == 1
    assert "restricted mode" in result.content[0].text
    assert "no active session" not in result.content[0].text.lower()


@pytest.mark.asyncio
async def test_restricted_mode_still_allows_read_only_tool_dispatch():
    """A read-only tool must still reach its handler in restricted mode —
    confirmed here by letting it fail on "no active session" rather than
    being blocked by the restricted-mode check."""
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        result = await server._call_tool("list_directory", {"path": "/share"})

    assert len(result.content) == 1
    assert "restricted mode" not in result.content[0].text
    # It reached its handler, which failed for want of a session.
    assert "no active sessions" in result.content[0].text
    assert result.is_error is True


@pytest.mark.asyncio
async def test_unknown_tool_name_is_rejected_even_when_restriction_would_also_apply():
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        # An unknown name is a protocol error (a JSON-RPC error response),
        # not a tool result — and that holds in restricted mode too.
        with pytest.raises(MCPError) as excinfo:
            await server._call_tool("not_a_real_tool", {})

    assert excinfo.value.code == types.INVALID_PARAMS
    assert "Unknown tool" in excinfo.value.message


# ---------------------------------------------------------------------------
# Restricted synology_login: base_url must match a configured NAS
# ---------------------------------------------------------------------------


def test_restricted_login_allows_configured_base_url():
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        fake_config.nas_configs = {"nas1": {"base_url": "https://nas.example.test:5001"}}
        fake_config.synology_url = None
        error = server._restricted_login_error("https://nas.example.test:5001")
    assert error is None


def test_restricted_login_blocks_unconfigured_base_url():
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        fake_config.nas_configs = {"nas1": {"base_url": "https://nas.example.test:5001"}}
        fake_config.synology_url = None
        error = server._restricted_login_error("https://attacker.example:5001")
    assert error is not None
    assert "attacker.example" in error


def test_restricted_login_unrestricted_when_no_nas_configured_yet():
    """Nothing to check against on a fresh install — leave login alone."""
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        fake_config.nas_configs = {}
        fake_config.synology_url = None
        error = server._restricted_login_error("https://anything.example:5001")
    assert error is None


def test_restricted_login_no_op_when_restricted_mode_off():
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = False
        fake_config.nas_configs = {"nas1": {"base_url": "https://nas.example.test:5001"}}
        fake_config.synology_url = None
        error = server._restricted_login_error("https://attacker.example:5001")
    assert error is None


def test_restricted_login_allows_legacy_env_configured_base_url():
    """The legacy single-NAS .env path (SYNOLOGY_URL) never populates
    nas_configs — it must still pin synology_login, not silently no-op."""
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        fake_config.nas_configs = {}
        fake_config.synology_url = "https://nas.example.test:5001"
        error = server._restricted_login_error("https://nas.example.test:5001")
    assert error is None


def test_restricted_login_blocks_unconfigured_base_url_with_legacy_env_only():
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        fake_config.nas_configs = {}
        fake_config.synology_url = "https://nas.example.test:5001"
        error = server._restricted_login_error("https://attacker.example:5001")
    assert error is not None
    assert "attacker.example" in error
