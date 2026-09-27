"""Restricted-mode tool registry tests (PR 2: unified deny-by-default
dispatch, tool classification, and the restricted synology_login check)."""

from unittest.mock import patch

import pytest


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
        "synology_list_users",
        "synology_get_user_permissions",
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
        result = await server._dispatch_tool_call("delete", {"path": "/share/x"})

    assert len(result) == 1
    assert "restricted mode" in result[0].text
    assert "No active session" not in result[0].text


@pytest.mark.asyncio
async def test_restricted_mode_still_allows_read_only_tool_dispatch():
    """A read-only tool must still reach its handler in restricted mode —
    confirmed here by letting it fail on "no active session" rather than
    being blocked by the restricted-mode check."""
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        result = await server._dispatch_tool_call("list_directory", {"path": "/share"})

    assert len(result) == 1
    assert "restricted mode" not in result[0].text


@pytest.mark.asyncio
async def test_unknown_tool_name_is_rejected_even_when_restriction_would_also_apply():
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        result = await server._dispatch_tool_call("not_a_real_tool", {})

    assert "Unknown tool" in result[0].text


# ---------------------------------------------------------------------------
# Restricted synology_login: base_url must match a configured NAS
# ---------------------------------------------------------------------------


def test_restricted_login_allows_configured_base_url():
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        fake_config.nas_configs = {"nas1": {"base_url": "https://nas.example.test:5001"}}
        error = server._restricted_login_error("https://nas.example.test:5001")
    assert error is None


def test_restricted_login_blocks_unconfigured_base_url():
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        fake_config.nas_configs = {"nas1": {"base_url": "https://nas.example.test:5001"}}
        error = server._restricted_login_error("https://attacker.example:5001")
    assert error is not None
    assert "attacker.example" in error


def test_restricted_login_unrestricted_when_no_nas_configured_yet():
    """Nothing to check against on a fresh install — leave login alone."""
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = True
        fake_config.nas_configs = {}
        error = server._restricted_login_error("https://anything.example:5001")
    assert error is None


def test_restricted_login_no_op_when_restricted_mode_off():
    server = _server()
    with patch("mcp_server.config") as fake_config:
        fake_config.restricted_mode = False
        fake_config.nas_configs = {"nas1": {"base_url": "https://nas.example.test:5001"}}
        error = server._restricted_login_error("https://attacker.example:5001")
    assert error is None
