# src/mcp_server.py - MCP Server for Synology NAS operations

import asyncio
import json
import logging
import traceback
from typing import Any, Callable, Dict, Optional

import urllib3

logger = logging.getLogger(__name__)

import mcp.server.stdio
import mcp.types as types
from jsonschema.exceptions import ValidationError, best_match
from jsonschema.validators import validator_for
from mcp.server import NotificationOptions, Server, ServerRequestContext
from mcp.shared.exceptions import MCPError

from auth import SynologyAuth, iter_all_secrets, request_secrets
from config import config
from container import SynologyContainer
from downloadstation import SynologyDownloadStation
from filestation import SynologyFileStation
from health import SynologyHealth
from nfs import SynologyNFS
from usermanagement import SynologyUserManager
from utils.redact import redact

# Container Manager tool suffixes (paired with the "synology_container_"
# prefix) that are read-only/monitoring-shaped: listing, inspecting, logs,
# resource usage. Every other suffix changes state.
_CONTAINER_READ_ONLY_SUFFIXES = frozenset(
    {
        "list",
        "get",
        "logs",
        "resource",
        "project_list",
        "project_get",
        "image_list",
        "image_get",
        "registry_list",
        "registry_search",
        "registry_tags",
        "network_list",
        "network_get",
    }
)

# Every container-tool suffix, used to populate the tool registry.
_CONTAINER_ALL_SUFFIXES = (
    "list",
    "get",
    "start",
    "stop",
    "restart",
    "delete",
    "logs",
    "resource",
    "project_list",
    "project_get",
    "project_create",
    "project_update",
    "project_start",
    "project_stop",
    "project_restart",
    "project_build",
    "project_clean",
    "project_delete",
    "image_list",
    "image_get",
    "image_delete",
    "image_pull",
    "registry_list",
    "registry_search",
    "registry_tags",
    "registry_download",
    "network_list",
    "network_get",
    "network_create",
    "network_delete",
)

# Tools that browse files/shares or read NAS/container monitoring data — the
# initial installation target plans/shipped/2026-09-27-remediation-roadmap/
# PLAN.md describes ("file browsing and NAS monitoring"). This is the
# semantic truth used for the MCP
# `readOnlyHint` annotation (metadata only — see _annotate_tool): every tool
# here genuinely performs no writes. It is NOT by itself the restricted-mode
# allowlist; see _ACCOUNT_ENUMERATION_TOOLS and _is_tool_allowed below for
# the one carve-out.
_READ_ONLY_TOOLS = frozenset(
    {
        "synology_status",
        "synology_list_nas",
        "list_shares",
        "list_directory",
        "get_file_info",
        "search_files",
        "get_file_content",
        "ds_get_info",
        "ds_list_tasks",
        "ds_get_statistics",
        "ds_list_downloaded_files",
        "synology_system_info",
        "synology_utilization",
        "synology_disk_health",
        "synology_disk_smart",
        "synology_volume_status",
        "synology_storage_pool",
        "synology_network",
        "synology_ups",
        "synology_services",
        "synology_system_log",
        "synology_health_summary",
        "synology_nfs_status",
        "synology_nfs_list_shares",
        "synology_list_users",
        "synology_get_user",
        "synology_list_groups",
        "synology_list_group_members",
        "synology_get_user_permissions",
    }
    | {f"synology_container_{suffix}" for suffix in _CONTAINER_READ_ONLY_SUFFIXES}
)

# These perform no writes (they stay in _READ_ONLY_TOOLS for the MCP
# annotation), but full enumeration of every local account, its group
# memberships, and its per-share permissions is a different trust tier than
# file browsing or NAS health monitoring — the kind of read DSM itself
# normally access-controls. Restricted mode's default install therefore
# excludes them too, alongside genuinely modifying tools; see
# _is_tool_allowed.
_ACCOUNT_ENUMERATION_TOOLS = frozenset(
    {
        "synology_list_users",
        "synology_get_user",
        "synology_list_groups",
        "synology_list_group_members",
        "synology_get_user_permissions",
    }
)

# Session-management tools: always reachable regardless of restricted mode
# (otherwise nothing else could ever be used). synology_login carries an
# additional restriction of its own in restricted mode — see
# SynologyMCPServer._restricted_login_error.
_SESSION_TOOLS = frozenset({"synology_login", "synology_logout"})

# Modifying tools whose effect is irreversible or destroys data outright,
# for the MCP `destructiveHint` annotation (metadata for clients — not
# itself an access control; enforcement is _is_tool_allowed above).
_DESTRUCTIVE_TOOLS = frozenset(
    {
        "delete",
        "ds_delete_tasks",
        "synology_delete_user",
        "synology_container_delete",
        "synology_container_project_delete",
        "synology_container_image_delete",
        "synology_container_network_delete",
    }
)


# Suppress InsecureRequestWarning when verify_ssl is explicitly disabled.
# VERIFY_SSL now defaults to true; this only fires if the user opted out.
if not config.verify_ssl:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logger.warning(
        "SSL certificate verification is DISABLED (VERIFY_SSL=false). The "
        "connection is still HTTPS-encrypted, but the server's certificate is "
        "not being validated, which makes it vulnerable to MITM attacks. "
        "Remove VERIFY_SSL=false unless you have a specific reason to keep it."
    )


# Argument names whose values are registered as secrets for the duration of the
# call that carries them (at any depth) — see SynologyMCPServer._call_tool.
# `otp_code` is deliberately absent, as it is from
# `config.iter_configured_secrets`: a 6-digit code masked as a substring
# corrupts unrelated output, and it is one-shot. Its echo vector here, a
# validation message, is closed at the source instead — such a message never
# quotes a submitted value (`_describe_validation_error`).
_CREDENTIAL_ARGUMENTS = frozenset({"password", "device_id"})

# A value shorter than this is not registered. Masking is by substring, so a
# one- or two-character "password" would blank out those characters wherever
# they appear in the call's output and logs — the same corruption that keeps
# `otp_code` out. The trade-off is accepted: there is little secrecy in a value
# that short, and a validation message never quotes a value whatever its
# length — but other text (a NAS's own error message, say) could still quote a
# short credential, and nothing will mask it.
_MIN_CREDENTIAL_LENGTH = 4


def _credential_strings(value: Any, *, under_credential_key: bool = False) -> list[str]:
    """Every string of at least `_MIN_CREDENTIAL_LENGTH` characters supplied
    under a `_CREDENTIAL_ARGUMENTS` key, however deeply nested (a malformed
    call may put a list or object there).

    Collected *before* the arguments are validated, because a wrong-typed
    credential is exactly what fails validation, and its value must already
    be known to the redactor by then.
    """
    if isinstance(value, str):
        return [value] if under_credential_key and len(value) >= _MIN_CREDENTIAL_LENGTH else []
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            found += _credential_strings(
                item, under_credential_key=under_credential_key or key in _CREDENTIAL_ARGUMENTS
            )
    elif isinstance(value, (list, tuple)):
        for item in value:
            found += _credential_strings(item, under_credential_key=under_credential_key)
    return found


def _describe_validation_error(error: ValidationError) -> str:
    """A description of a schema violation that never contains a submitted value.

    jsonschema's own `error.message` quotes the offending value
    (`['hunter2'] is not of type 'string'`), which for a mistyped password,
    device token or OTP code would echo the credential back to the client and
    into the logs. This builds the text from the schema alone: the field is
    named from the schema path (`properties` keys, which the server defines),
    and the constraint from `error.validator_value` (also the server's). The
    submitted value is never read. (A missing required property is the one
    case where jsonschema's own message is kept: it names a property from
    the schema's `required` list, which the caller did not supply.)
    """
    field = ""
    path = list(error.absolute_schema_path)[:-1]  # the last element is the keyword itself
    position = 0
    while position < len(path):
        if path[position] == "properties" and position + 1 < len(path):
            field += ("." if field else "") + str(path[position + 1])
            position += 2
        elif path[position] == "items":
            field += "[]"
            position += 1
        else:
            position += 1
    if error.validator == "required":
        return f"{field}: {error.message}" if field else error.message
    subject = field or "arguments"
    constraint = error.validator_value
    if error.validator == "type":
        types_ = constraint if isinstance(constraint, list) else [constraint]
        return f"{subject} must be of type {' or '.join(repr(t) for t in types_)}"
    if error.validator == "enum":
        return f"{subject} must be one of: {', '.join(repr(v) for v in constraint)}"
    if error.validator in ("minimum", "maximum"):
        bound = ">=" if error.validator == "minimum" else "<="
        return f"{subject} must be {bound} {constraint}"
    return f"{subject} does not satisfy the {error.validator!r} constraint"


class ToolExecutionError(Exception):
    """A tool ran and failed, and the caller should see it as a failure.

    Handlers raise this wherever they detect a failure — a failed login, a
    DSM result reporting `success: false`, a missing session — instead of
    returning failure text. `_call_tool` turns it into a result with
    `isError: true`, so the error flag is set explicitly by the code that
    knows a failure happened and never inferred from what a message says.
    `str(error)` is the text shown to the client; it is redacted like every
    other response before it leaves the process.
    """


class SynologyMCPServer:
    """MCP Server for Synology NAS operations."""

    def __init__(self):
        self.server = Server(
            config.server_name,
            version=config.server_version,
            on_list_tools=self._on_list_tools,
            on_call_tool=self._on_call_tool,
        )
        self.auth_instances: Dict[str, SynologyAuth] = {}
        self.sessions: Dict[str, str] = {}  # base_url -> session_id
        self.syno_tokens: Dict[str, str] = {}  # base_url -> SynoToken (CSRF, DSM 7.3.2+)
        self.filestation_instances: Dict[str, SynologyFileStation] = {}
        self.downloadstation_instances: Dict[str, SynologyDownloadStation] = {}
        self.health_instances: Dict[str, SynologyHealth] = {}
        self.container_instances: Dict[str, SynologyContainer] = {}
        self.nfs_instances: Dict[str, SynologyNFS] = {}
        self.usermgr_instances: Dict[str, SynologyUserManager] = {}
        self.nas_name_map: Dict[str, str] = {}  # nas_name -> base_url
        # Single source of truth for tool dispatch — see _build_tool_registry.
        self._tool_registry: Dict[str, Callable] = self._build_tool_registry()
        # One compiled JSON-Schema validator per tool, built from the same
        # definitions discovery serves — see _compile_input_validators.
        self._input_validators = self._compile_input_validators()

    def _build_tool_registry(self) -> Dict[str, Callable]:
        """Single source of truth: tool name -> async handler.

        Both tool discovery (`_list_tools`, via `_is_tool_allowed`) and tool
        dispatch (`_call_tool`) read from this one registry — replacing the
        previous if/elif chain and the separate, already-drifted
        `call_tool_direct` dispatch dict (deleted: it was dead code left
        over from the removed Xiaozhi bridge, and had already missed two
        tool names that the live if/elif chain had gained since).
        """
        registry: Dict[str, Callable] = {
            "synology_login": self._handle_login,
            "synology_logout": self._handle_logout,
            "synology_status": self._handle_status,
            "synology_list_nas": self._handle_list_nas,
            "list_shares": self._handle_list_shares,
            "list_directory": self._handle_list_directory,
            "get_file_info": self._handle_get_file_info,
            "search_files": self._handle_search_files,
            "get_file_content": self._handle_get_file_content,
            "rename_file": self._handle_rename_file,
            "move_file": self._handle_move_file,
            "create_file": self._handle_create_file,
            "create_directory": self._handle_create_directory,
            "delete": self._handle_delete,
            "ds_get_info": self._handle_ds_get_info,
            "ds_list_tasks": self._handle_ds_list_tasks,
            "ds_create_task": self._handle_ds_create_task,
            "ds_pause_tasks": self._handle_ds_pause_tasks,
            "ds_resume_tasks": self._handle_ds_resume_tasks,
            "ds_delete_tasks": self._handle_ds_delete_tasks,
            "ds_get_statistics": self._handle_ds_get_statistics,
            "ds_list_downloaded_files": self._handle_ds_list_downloaded_files,
            "synology_system_info": lambda a: self._handle_health_call(a, "system_info"),
            "synology_utilization": lambda a: self._handle_health_call(a, "utilization"),
            "synology_disk_health": lambda a: self._handle_health_call(a, "disk_list"),
            "synology_disk_smart": self._handle_disk_smart,
            "synology_volume_status": lambda a: self._handle_health_call(a, "volume_list"),
            "synology_storage_pool": lambda a: self._handle_health_call(a, "storage_pool_list"),
            "synology_network": lambda a: self._handle_health_call(a, "network_info"),
            "synology_ups": lambda a: self._handle_health_call(a, "ups_info"),
            "synology_services": lambda a: self._handle_health_call(a, "package_list"),
            "synology_system_log": self._handle_system_log,
            "synology_health_summary": lambda a: self._handle_health_call(a, "health_summary"),
            "synology_nfs_status": lambda a: self._handle_nfs_call(a, "nfs_status"),
            "synology_nfs_enable": self._handle_nfs_enable,
            "synology_nfs_list_shares": lambda a: self._handle_nfs_call(a, "list_shares"),
            "synology_nfs_set_permission": self._handle_nfs_set_permission,
            "synology_create_share": self._handle_create_share,
            "synology_list_users": lambda a: self._handle_usermgr_call(a, "list_users"),
            "synology_get_user": self._handle_usermgr_get_user,
            "synology_create_user": self._handle_usermgr_create_user,
            "synology_set_user": self._handle_usermgr_set_user,
            "synology_delete_user": self._handle_usermgr_delete_user,
            "synology_list_groups": lambda a: self._handle_usermgr_call(a, "list_groups"),
            "synology_list_group_members": self._handle_usermgr_list_group_members,
            "synology_add_user_to_group": self._handle_usermgr_add_to_group,
            "synology_remove_user_from_group": self._handle_usermgr_remove_from_group,
            "synology_get_user_permissions": self._handle_usermgr_get_permissions,
            "synology_set_user_permissions": self._handle_usermgr_set_permissions,
        }
        for suffix in _CONTAINER_ALL_SUFFIXES:
            registry[f"synology_container_{suffix}"] = (
                lambda arguments, _suffix=suffix: self._handle_container_call(arguments, _suffix)
            )
        return registry

    def _is_tool_allowed(self, name: str) -> bool:
        """Whether `name` may run under restricted mode (browsing and
        monitoring only — plus session tools, since otherwise nothing else
        could ever be used). Account/permission enumeration is carved out
        even though it's read-only: see _ACCOUNT_ENUMERATION_TOOLS. Irrelevant
        when config.restricted_mode is False — every registered tool is
        allowed then."""
        if name in _ACCOUNT_ENUMERATION_TOOLS:
            return False
        return name in _SESSION_TOOLS or name in _READ_ONLY_TOOLS

    @staticmethod
    def _annotate_tool(tool: "types.Tool") -> "types.Tool":
        """Attach MCP readOnlyHint/destructiveHint annotations. This is
        purely descriptive metadata for MCP clients about whether a tool
        performs writes — not an access control, and not the same question
        as "is this tool allowed under restricted mode" (that's
        _is_tool_allowed; the two diverge for _ACCOUNT_ENUMERATION_TOOLS,
        which are read-only but excluded from restricted mode's default set
        on trust-tier grounds)."""
        read_only = tool.name in _READ_ONLY_TOOLS
        tool.annotations = types.ToolAnnotations(
            read_only_hint=read_only,
            destructive_hint=tool.name in _DESTRUCTIVE_TOOLS,
        )
        return tool

    def _get_filestation(self, base_url: str) -> SynologyFileStation:
        """Get or create FileStation instance for a base URL."""
        if base_url not in self.sessions:
            raise Exception(f"No active session for {base_url}. Please login first.")

        if base_url not in self.filestation_instances:
            session_id = self.sessions[base_url]
            self.filestation_instances[base_url] = SynologyFileStation(
                base_url,
                session_id,
                verify_ssl=config.verify_ssl,
                syno_token=self.syno_tokens.get(base_url),
                max_file_content_size=config.max_file_content_size,
            )

        return self.filestation_instances[base_url]

    def _get_downloadstation(self, base_url: str) -> SynologyDownloadStation:
        """Get or create DownloadStation instance for a base URL."""
        if base_url not in self.sessions:
            raise Exception(f"No active session for {base_url}. Please login first.")

        if base_url not in self.downloadstation_instances:
            session_id = self.sessions[base_url]
            self.downloadstation_instances[base_url] = SynologyDownloadStation(
                base_url,
                session_id,
                verify_ssl=config.verify_ssl,
                syno_token=self.syno_tokens.get(base_url),
            )

        return self.downloadstation_instances[base_url]

    def _get_health(self, base_url: str) -> SynologyHealth:
        """Get or create Health instance for a base URL."""
        if base_url not in self.sessions:
            raise Exception(f"No active session for {base_url}. Please login first.")

        if base_url not in self.health_instances:
            session_id = self.sessions[base_url]
            self.health_instances[base_url] = SynologyHealth(
                base_url,
                session_id,
                verify_ssl=config.verify_ssl,
                syno_token=self.syno_tokens.get(base_url),
            )

        return self.health_instances[base_url]

    def _get_container(self, base_url: str) -> SynologyContainer:
        """Get or create Container Manager instance for a base URL."""
        if base_url not in self.sessions:
            raise Exception(f"No active session for {base_url}. Please login first.")

        if base_url not in self.container_instances:
            session_id = self.sessions[base_url]
            self.container_instances[base_url] = SynologyContainer(
                base_url,
                session_id,
                verify_ssl=config.verify_ssl,
                syno_token=self.syno_tokens.get(base_url),
            )

        return self.container_instances[base_url]

    def _get_nfs(self, base_url: str) -> SynologyNFS:
        """Get or create NFS instance for a base URL."""
        if base_url not in self.sessions:
            raise Exception(f"No active session for {base_url}. Please login first.")

        if base_url not in self.nfs_instances:
            session_id = self.sessions[base_url]
            self.nfs_instances[base_url] = SynologyNFS(
                base_url,
                session_id,
                verify_ssl=config.verify_ssl,
                syno_token=self.syno_tokens.get(base_url),
            )

        return self.nfs_instances[base_url]

    def _get_usermgr(self, base_url: str) -> SynologyUserManager:
        """Get or create UserManager instance for a base URL."""
        if base_url not in self.sessions:
            raise Exception(f"No active session for {base_url}. Please login first.")

        if base_url not in self.usermgr_instances:
            session_id = self.sessions[base_url]
            self.usermgr_instances[base_url] = SynologyUserManager(
                base_url,
                session_id,
                verify_ssl=config.verify_ssl,
                syno_token=self.syno_tokens.get(base_url),
            )

        return self.usermgr_instances[base_url]

    async def _auto_login_if_configured(self):
        """Automatically login to all configured NAS units."""
        logger.debug(f"Config: {config}")

        if not config.auto_login:
            logger.info("Auto-login disabled")
            return
        if not config.has_synology_credentials():
            logger.warning("No Synology credentials configured")
            return

        nas_names = config.get_nas_names()
        if not nas_names:
            # Legacy single-NAS from .env
            nas_names = [None]

        success_count = 0
        for nas_name in nas_names:
            try:
                nas_cfg = config.get_synology_config(nas_name)
                base_url = nas_cfg["base_url"]
                label = nas_name or "default"

                logger.info(f"Auto-login: {label} ({base_url})...")

                if base_url not in self.auth_instances:
                    self.auth_instances[base_url] = SynologyAuth(
                        base_url, verify_ssl=config.verify_ssl
                    )

                auth = self.auth_instances[base_url]
                auth.on_relogin = self._resync_session_after_relogin
                # Pass optional 2FA material from settings.json (or legacy .env
                # for otp_code). device_id wins over otp_code; both None means
                # the DSM account has 2FA off (existing behavior).
                result = auth.login(
                    nas_cfg["username"],
                    nas_cfg["password"],
                    otp_code=nas_cfg.get("otp_code"),
                    device_id=nas_cfg.get("device_id"),
                )

                if result.get("success"):
                    session_id = result["data"]["sid"]
                    self.sessions[base_url] = session_id
                    syno_token = result["data"].get("synotoken")
                    if syno_token:
                        self.syno_tokens[base_url] = syno_token
                    else:
                        self.syno_tokens.pop(base_url, None)
                    # Store the name->url mapping for tool resolution
                    self.nas_name_map[label] = base_url
                    if nas_name is None:
                        self.nas_name_map[base_url] = base_url
                    # DSM issues a device token (`did`) only on the first-time
                    # OTP login (the steady-state `device_id` path doesn't echo
                    # it back). Persist it straight into settings.json so 2FA
                    # accounts don't need OTP on the next start — never log or
                    # return the token itself, including truncated, per the
                    # credential-handling policy this server follows.
                    did = result["data"].get("did")
                    if did and nas_name is not None:
                        if config.save_device_id(nas_name, did):
                            logger.info(
                                f"{label}: 2FA device token saved to settings.json "
                                "— OTP won't be required on the next start"
                            )
                        else:
                            logger.warning(
                                f"{label}: 2FA succeeded but the device token could not be "
                                "saved automatically; OTP will be required again next start"
                            )
                    elif did:
                        # Legacy .env single-NAS path has no per-NAS settings.json
                        # entry to persist into.
                        logger.warning(
                            f"{label}: 2FA succeeded, but persistent device-token reuse "
                            "requires migrating to settings.json (see README) — OTP will "
                            "be required again next start"
                        )
                    logger.info(f"{label}: session established")

                    for inst_dict in self._service_instance_dicts():
                        inst_dict.pop(base_url, None)
                    success_count += 1
                else:
                    error_code = result.get("error", {}).get("code", "?")
                    logger.warning(f"{label}: login failed (code {error_code})")

            except Exception as e:
                logger.warning(f"{nas_name or 'default'}: {e}")
                if config.debug:
                    logger.debug("Traceback:", exc_info=True)

        if success_count == 0:
            raise Exception("Auto-login failed for all configured NAS units — stopping server.")
        logger.info(f"Connected to {success_count}/{len(nas_names)} NAS unit(s)")

    # ------------------------------------------------------------------
    # MCP SDK wiring. The SDK calls these two handlers (registered in
    # __init__); each is a thin wrapper around a plain method
    # (`_list_tools`, `_call_tool`), so the real logic stays directly
    # testable without going through the SDK.
    # ------------------------------------------------------------------

    async def _on_list_tools(
        self, ctx: ServerRequestContext, params: Optional[types.PaginatedRequestParams]
    ) -> types.ListToolsResult:
        """SDK handler for `tools/list`."""
        try:
            return types.ListToolsResult(tools=await self._list_tools())
        except Exception as e:
            # Never let an unexpected exception's text reach the client: the
            # SDK would send str(e) as the JSON-RPC error message.
            logger.error(f"Failed to list tools: {self._redact_text(str(e))}")
            self._log_traceback()
            raise MCPError(types.INTERNAL_ERROR, "Failed to list tools") from None

    async def _on_call_tool(
        self, ctx: ServerRequestContext, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        """SDK handler for `tools/call`."""
        return await self._call_tool(params.name, params.arguments or {})

    async def _list_tools(self) -> list[types.Tool]:
        """List available Synology tools."""
        tools = self._get_tool_definitions()
        if config.restricted_mode:
            # Deny-by-default: hide every tool not explicitly classified
            # read-only from discovery. See _is_tool_allowed.
            tools = [t for t in tools if self._is_tool_allowed(t.name)]

        # Add login/logout tools only if not using auto-login or no credentials configured
        if not config.auto_login or not config.has_synology_credentials():
            tools.extend(self._session_tool_definitions())

        return tools

    def _session_tool_definitions(self) -> list[types.Tool]:
        """The synology_login / synology_logout definitions. They are kept
        apart from `_get_tool_definitions()` because discovery only lists them
        when auto-login isn't in use, but they are always registered — so
        argument validation (`_compile_input_validators`) needs their schemas
        whether or not they are listed."""
        return [
            self._annotate_tool(t)
            for t in [
                types.Tool(
                    name="synology_login",
                    description=(
                        "Authenticate with Synology NAS and establish session.\n\n"
                        "2FA/OTP accounts: pass `otp_code` on the first login only. "
                        "DSM issues a device token on success, but this tool never "
                        "returns or logs it (credential-handling policy) — there is "
                        "no way to retrieve it from this call, so do not retry "
                        "expecting one. To get a persistent trusted-device token, "
                        "configure this NAS with `otp_code` in settings.json and "
                        "enable auto-login instead; the server saves the token to "
                        "settings.json itself on the first successful auto-login. If "
                        "you already have a `device_id`, pass it instead of `otp_code` "
                        "— DSM treats trusted devices as already authenticated."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "base_url": {
                                "type": "string",
                                "description": "Synology NAS base URL (e.g., https://192.168.1.100:5001)",
                            },
                            "username": {
                                "type": "string",
                                "description": "Username for authentication",
                            },
                            "password": {
                                "type": "string",
                                "description": "Password for authentication",
                            },
                            "otp_code": {
                                "type": "string",
                                "description": (
                                    "One-time 6-digit code from the user's authenticator. "
                                    "Required only on the first 2FA login for a new device. "
                                    "Ignored when `device_id` is also given."
                                ),
                            },
                            "device_id": {
                                "type": "string",
                                "description": (
                                    "Long-lived trusted-device token previously issued by DSM "
                                    "(returned as `did` in a successful 2FA login). When "
                                    "supplied, DSM skips the OTP step. Preferred over "
                                    "`otp_code` for repeated logins."
                                ),
                            },
                        },
                        "required": ["base_url", "username", "password"],
                    },
                ),
                types.Tool(
                    name="synology_logout",
                    description="Logout from Synology NAS session",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "base_url": {
                                "type": "string",
                                "description": "Synology NAS base URL",
                            }
                        },
                        "required": ["base_url"],
                    },
                ),
            ]
        ]

    def _compile_input_validators(self) -> Dict[str, Any]:
        """One JSON-Schema validator per tool, compiled once from the same
        `inputSchema` definitions that discovery serves.

        The MCP SDK validated tool arguments against each tool's inputSchema
        before calling the handler (through 1.x); 2.x no longer does, so
        `_call_tool` has to. Compiling here also fails fast, at startup, on a
        schema that isn't itself valid, and on a registered tool that has no
        definition (and so nothing to validate its arguments against) —
        rather than on the first call to it.
        """
        validators: Dict[str, Any] = {}
        for tool in [*self._get_tool_definitions(), *self._session_tool_definitions()]:
            schema_class = validator_for(tool.input_schema)
            schema_class.check_schema(tool.input_schema)
            validators[tool.name] = schema_class(tool.input_schema)

        undefined = set(self._tool_registry) - set(validators)
        if undefined:
            raise RuntimeError(f"Registered tool(s) without an input schema: {sorted(undefined)}")
        return validators

    def _validate_arguments(self, name: str, arguments: dict) -> Optional[str]:
        """The message describing why `arguments` don't match tool `name`'s
        input schema, or None if they do."""
        error = best_match(self._input_validators[name].iter_errors(arguments))
        return None if error is None else _describe_validation_error(error)

    def _redact_text(self, text: str) -> str:
        """`text` with every known/likely secret masked (see utils.redact)."""
        return redact(text, live_secrets=list(iter_all_secrets()))

    def _log_traceback(self) -> None:
        """Log the traceback of the exception being handled at DEBUG,
        already redacted: an exception's text can carry a session id (a
        `requests` error embeds the full request URL), so the raw traceback
        is never handed to the logging module."""
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Traceback:\n%s", self._redact_text(traceback.format_exc()))

    def _error_result(self, message: str) -> types.CallToolResult:
        """A tool result flagged `isError: true`, carrying `message`.

        Every code path that reports a tool failure comes through here, and
        the flag is set by that path because it knows a failure happened —
        it is never inferred afterwards from what the text says. The message
        is redacted like every other response."""
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=self._redact_text(message))],
            is_error=True,
        )

    async def _call_tool(self, name: str, arguments: dict) -> types.CallToolResult:
        """Look up and invoke `name` in `self._tool_registry` — the single
        place a tool name maps to a handler. A second, independent dispatch
        path (the old `call_tool_direct`) used to exist for a
        since-removed bridge and had already drifted out of sync with this
        one (missing tool names the live path had gained); it's gone, so
        there is exactly one path to audit or extend.

        How each outcome is reported:
        - An unknown tool name is a protocol error (`MCPError`, INVALID_PARAMS
          → a JSON-RPC error response), not a tool result.
        - A tool that exists but can't run is a result with `isError: true`:
          a restricted-mode refusal, arguments that don't match the tool's
          input schema, a `ToolExecutionError` from the handler, or any other
          exception the handler raises.
        - Otherwise a normal result (`isError: false`).

        The first three checks — unknown name, restricted mode, argument
        validation — all happen before the handler runs, and therefore
        before any NAS request is made. Restricted mode is deny-by-default: a
        direct call by exact name is covered the same way as discovery
        (`_list_tools`), since both consult `_is_tool_allowed` against the
        same classification. Every message that leaves here is redacted —
        including any `password` or `device_id`
        submitted in this very call, which is registered with the redactor
        before anything else runs, and the validation messages themselves
        never quote a submitted value (see `_describe_validation_error`).
        """
        handler = self._tool_registry.get(name)
        if handler is None:
            raise MCPError(types.INVALID_PARAMS, self._redact_text(f"Unknown tool: {name}"))

        # Credentials in this request count as secrets for all of it — the
        # refusal and validation messages included, which run before any login
        # could have taught the redactor a newly submitted password.
        with request_secrets(_credential_strings(arguments)):
            return await self._run_tool(name, handler, arguments)

    async def _run_tool(
        self, name: str, handler: Callable, arguments: dict
    ) -> types.CallToolResult:
        """The part of `_call_tool` that runs once the tool is known to exist:
        restricted-mode check, argument validation, then the handler."""
        if config.restricted_mode and not self._is_tool_allowed(name):
            return self._error_result(
                f"Tool '{name}' is not available: the server is running in "
                "restricted mode (browsing and monitoring only). Set "
                "restricted_mode to false in settings.json to enable it."
            )

        invalid = self._validate_arguments(name, arguments)
        if invalid is not None:
            message = self._redact_text(f"Invalid arguments for {name}: {invalid}")
            logger.debug(message)
            return self._error_result(message)

        # Nothing but the unknown-tool MCPError above may escape past here: the
        # SDK would send an unexpected exception's text to the client as-is.
        # Building the result is inside the try for the same reason.
        try:
            logger.debug(f"Executing tool: {name}")
            result = await handler(arguments)
            return types.CallToolResult(content=self._redact_tool_result(result), is_error=False)
        except ToolExecutionError as e:
            message = self._redact_text(str(e))
            logger.warning(f"Tool {name} failed: {message}")
            return self._error_result(message)
        except Exception as e:
            message = self._redact_text(f"Error executing {name}: {e}")
            logger.warning(message)
            self._log_traceback()
            return self._error_result(message)

    def _redact_tool_result(self, result: list[types.TextContent]) -> list[types.TextContent]:
        """Redact known/likely secrets from a tool response before it leaves the process.

        This is the single point every successful tool response passes through
        (see `_call_tool`; failures go through `_error_result`), so a leak
        anywhere in a handler or the service layer it calls (a raw DSM
        payload, a network-error message that embedded a `_sid=`-bearing URL,
        ...) is caught here rather than needing a fix at every individual
        call site.
        """
        live_secrets = list(iter_all_secrets())
        return [
            (
                types.TextContent(type="text", text=redact(item.text, live_secrets=live_secrets))
                if isinstance(item, types.TextContent)
                else item
            )
            for item in result
        ]

    @staticmethod
    def _dsm_result(result: Any, prefix: str = "") -> list[types.TextContent]:
        """Format a service-layer result as tool output, raising
        `ToolExecutionError` if the result reports a failure.

        The API client behind the health, NFS, user-management and container
        services reports failure as a *returned* dict —
        `{"success": False, "error": {...}}`, the shape DSM itself uses and
        the one network errors are mapped to — rather than by raising.
        Returning that as ordinary output would present a failed call as a
        successful one, so it becomes a failure here, decided from the
        structured `success` field and never from the text. A result with no
        `success` field at all is output as before, and a failure's message
        is the same JSON a success would have shown.
        """
        text = f"{prefix}{json.dumps(result, indent=2)}"
        if isinstance(result, dict) and result.get("success") is False:
            raise ToolExecutionError(text)
        return [types.TextContent(type="text", text=text)]

    def _service_instance_dicts(self):
        """Canonical set of per-domain instance caches keyed by base_url.

        Returned as one tuple so session login/relogin/logout/cleanup all evict
        the same set; adding a new service means updating this one place.
        """
        return (
            self.filestation_instances,
            self.downloadstation_instances,
            self.health_instances,
            self.container_instances,
            self.nfs_instances,
            self.usermgr_instances,
        )

    def _get_base_url(self, arguments: dict) -> str:
        """Get base URL from arguments or config.

        Accepts either:
          - base_url: a full URL like https://10.0.0.51:5001
          - nas_name: a key from settings.json like 'nas1', 'nas2'
        Falls back to the first connected NAS if neither is provided.
        """
        # Try nas_name first
        nas_name = arguments.get("nas_name")
        if nas_name:
            base_url = self.nas_name_map.get(nas_name)
            if base_url:
                return base_url
            raise Exception(
                f"NAS '{nas_name}' not found. Available: {list(self.nas_name_map.keys())}"
            )

        # Try explicit base_url
        base_url = arguments.get("base_url")
        if base_url:
            return base_url

        # Fall back to first connected session
        if self.sessions:
            return next(iter(self.sessions))

        raise Exception("No nas_name or base_url provided and no active sessions.")

    def _validate_url(self, url: str) -> bool:
        """Validate URL format and scheme.

        HTTPS-only: plain http:// is rejected so credentials and session
        tokens are never sent unencrypted.

        Args:
            url: URL to validate

        Returns:
            True if URL is valid, False otherwise
        """
        from urllib.parse import urlparse

        try:
            result = urlparse(url)
            return bool(result.scheme == "https" and result.netloc)
        except Exception:
            return False

    def _resync_session_after_relogin(
        self, base_url: str, session_id: Optional[str], syno_token: Optional[str]
    ) -> None:
        """Resync cached session state after a transparent relogin (DSM 119 recovery).

        SynologyAuth invokes this once it re-authenticates an expired session.
        Without it, self.sessions / self.syno_tokens keep the dead SID — so logout
        would target the expired session (leaking the new one) and lazily-created
        subsystems would start with a stale SID. Mirrors the post-login bookkeeping.
        """
        if not session_id:
            return
        self.sessions[base_url] = session_id
        if syno_token:
            self.syno_tokens[base_url] = syno_token
        else:
            self.syno_tokens.pop(base_url, None)
        # Drop cached service instances so they rebuild with the refreshed session.
        for inst_dict in self._service_instance_dicts():
            inst_dict.pop(base_url, None)

    def _restricted_login_error(self, base_url: str) -> Optional[str]:
        """In restricted mode, only allow login to a NAS already configured
        in settings.json or the legacy single-NAS .env vars — otherwise the
        model could point admin credentials at an arbitrary host of its
        choosing. Returns an error message, or None if the login may
        proceed.

        When no NAS is configured yet (a fresh install using synology_login
        directly rather than settings.json/.env), there is nothing to check
        against, so login is left unrestricted — restricted mode's tool
        classification still governs everything else.
        """
        if not config.restricted_mode:
            return None
        configured_urls = {cfg["base_url"] for cfg in config.nas_configs.values()}
        if config.synology_url:
            configured_urls.add(config.synology_url)
        if not configured_urls:
            return None
        if base_url not in configured_urls:
            return (
                f"Restricted mode: '{base_url}' is not one of the NAS units already "
                "configured in settings.json or SYNOLOGY_URL. Add it there first, or "
                "set restricted_mode to false to allow logging in to an arbitrary host."
            )
        return None

    async def _handle_login(self, arguments: dict) -> list[types.TextContent]:
        """Handle Synology login."""
        base_url = arguments["base_url"]
        username = arguments["username"]
        password = arguments["password"]
        # Both 2FA fields are optional. When both are supplied, `device_id`
        # wins (DSM won't ask for OTP on a trusted device). When neither is
        # supplied, behavior matches pre-2FA support.
        otp_code = arguments.get("otp_code")
        device_id = arguments.get("device_id")

        # Validate base_url format
        if not self._validate_url(base_url):
            raise ToolExecutionError(
                f"Invalid base_url format: {base_url}\n"
                "URL must start with https:// and include a hostname "
                "(e.g., https://192.168.1.100:5001). Plain http:// is not "
                "supported — enable HTTPS in DSM Control Panel > Security > "
                "Certificate."
            )

        restriction_error = self._restricted_login_error(base_url)
        if restriction_error:
            raise ToolExecutionError(restriction_error)

        # Create or get auth instance
        if base_url not in self.auth_instances:
            self.auth_instances[base_url] = SynologyAuth(base_url, verify_ssl=config.verify_ssl)

        auth = self.auth_instances[base_url]
        auth.on_relogin = self._resync_session_after_relogin

        # Perform login
        result = auth.login(username, password, otp_code=otp_code, device_id=device_id)

        # Store session if successful
        if result.get("success"):
            session_id = result["data"]["sid"]
            self.sessions[base_url] = session_id
            syno_token = result["data"].get("synotoken")
            if syno_token:
                self.syno_tokens[base_url] = syno_token
            else:
                self.syno_tokens.pop(base_url, None)

            # Drop cached service instances so they pick up the new session/token
            for inst_dict in self._service_instance_dicts():
                inst_dict.pop(base_url, None)

            # Curated status only — never echo the raw DSM response (it
            # carries the session id, SynoToken, and device token) back to
            # the MCP client or into logs.
            status_fields = [
                f"Successfully authenticated with {base_url}",
                "Session established: yes",
            ]
            if syno_token:
                status_fields.append("CSRF token issued: yes")
            if result["data"].get("did"):
                status_fields.append(
                    "2FA device token issued: yes (see settings.json if configured to persist it)"
                )
            return [types.TextContent(type="text", text="\n".join(status_fields))]
        else:
            error_info = result.get("error", {})
            error_code = error_info.get("code", "unknown")
            error_message = error_info.get("message", "Unknown error")
            raise ToolExecutionError(f"Authentication failed: {error_code} - {error_message}")

    async def _handle_logout(self, arguments: dict) -> list[types.TextContent]:
        """Handle Synology logout."""
        base_url = self._get_base_url(arguments)

        if base_url not in self.sessions:
            raise ToolExecutionError(f"No active session found for {base_url}")

        session_id = self.sessions[base_url]
        auth = self.auth_instances[base_url]

        # Use the improved logout method
        result = auth.logout(session_id)

        # Handle the result and provide detailed feedback
        if result.get("success"):
            # Remove session and all cached service instances on successful logout
            del self.sessions[base_url]
            self.syno_tokens.pop(base_url, None)
            for inst_dict in self._service_instance_dicts():
                inst_dict.pop(base_url, None)

            return [
                types.TextContent(
                    type="text",
                    text=f"✅ Successfully logged out from {base_url}\n"
                    "Session has been terminated",
                )
            ]
        else:
            error_info = result.get("error", {})
            error_code = error_info.get("code", "unknown")
            error_msg = error_info.get("message", "Unknown error")

            # Handle expected session expiration gracefully
            if str(error_code) in {"105", "106", "no_session"}:
                # Still clean up local session data
                del self.sessions[base_url]
                self.syno_tokens.pop(base_url, None)
                for inst_dict in self._service_instance_dicts():
                    inst_dict.pop(base_url, None)

                return [
                    types.TextContent(
                        type="text",
                        text=f"⚠️ Session for {base_url} was already expired or invalid\n"
                        f"Local session data has been cleaned up\n"
                        f"Details: {error_code} - {error_msg}",
                    )
                ]
            else:
                raise ToolExecutionError(
                    f"❌ Logout failed for {base_url}\n"
                    f"Error: {error_code} - {error_msg}\n"
                    f"Full response: {json.dumps(result, indent=2)}"
                )

    async def _handle_status(self, arguments: dict) -> list[types.TextContent]:
        """Handle status check."""
        status_info = []

        # Show configuration status
        nas_names = config.get_nas_names()
        if nas_names:
            status_info.append(f"✓ Configured NAS units: {', '.join(nas_names)}")
        elif config.has_synology_credentials():
            status_info.append(f"✓ Configuration: {config.synology_url}")
        else:
            status_info.append("⚠ No Synology credentials configured")
        status_info.append(f"✓ Auto-login: {'enabled' if config.auto_login else 'disabled'}")

        # Show active sessions with NAS names
        if self.sessions:
            # Build reverse map: base_url -> nas_name
            url_to_name = {v: k for k, v in self.nas_name_map.items()}
            status_info.append(f"\nActive sessions ({len(self.sessions)}):")
            for base_url in self.sessions:
                name = url_to_name.get(base_url, "?")
                status_info.append(f"• {name} ({base_url}): connected")

            # Show service instances
            if self.filestation_instances:
                status_info.append(f"\nFileStation instances: {len(self.filestation_instances)}")
            if self.downloadstation_instances:
                status_info.append(
                    f"DownloadStation instances: {len(self.downloadstation_instances)}"
                )
        else:
            status_info.append("\nNo active Synology sessions")

        return [types.TextContent(type="text", text="\n".join(status_info))]

    async def _handle_list_nas(self, arguments: dict) -> list[types.TextContent]:
        """Handle listing configured NAS units from settings.json."""
        nas_list = []

        # Get NAS names from config
        nas_names = config.get_nas_names()

        if not nas_names:
            # Fall back to .env if no settings.json
            if config.synology_url:
                nas_list.append(
                    {
                        "nas_name": "default",
                        "base_url": config.synology_url,
                        "username": config.synology_username,
                        "note": "From .env (single NAS)",
                    }
                )
                nas_list.append(
                    {
                        "message": "No multi-NAS configured. Add credentials to ~/.config/synology-mcp/settings.json for multi-NAS support."
                    }
                )
            else:
                nas_list.append(
                    {
                        "message": "No NAS configured. Set up credentials in .env or ~/.config/synology-mcp/settings.json"
                    }
                )
        else:
            # List each NAS from settings.json
            for nas_name in nas_names:
                nas_cfg = config.get_synology_config(nas_name)
                url = nas_cfg.get("base_url", "unknown")
                username = nas_cfg.get("username", "unknown")
                note = nas_cfg.get("note", "")

                # Check if connected
                connected = url in self.sessions

                nas_info = {
                    "nas_name": nas_name,
                    "base_url": url,
                    "username": username,
                    "connected": connected,
                }
                if note:
                    nas_info["note"] = note
                nas_list.append(nas_info)

        return [types.TextContent(type="text", text=json.dumps(nas_list, indent=2))]

    async def _handle_list_shares(self, arguments: dict) -> list[types.TextContent]:
        """Handle listing shares."""
        base_url = self._get_base_url(arguments)
        filestation = self._get_filestation(base_url)

        shares = filestation.list_shares()

        return [types.TextContent(type="text", text=json.dumps(shares, indent=2))]

    async def _handle_list_directory(self, arguments: dict) -> list[types.TextContent]:
        """Handle listing directory contents."""
        base_url = self._get_base_url(arguments)
        path = arguments["path"]

        filestation = self._get_filestation(base_url)
        files = filestation.list_directory(path)

        return [types.TextContent(type="text", text=json.dumps(files, indent=2))]

    async def _handle_get_file_info(self, arguments: dict) -> list[types.TextContent]:
        """Handle getting file information."""
        base_url = self._get_base_url(arguments)
        path = arguments["path"]

        filestation = self._get_filestation(base_url)
        info = filestation.get_file_info(path)

        return [types.TextContent(type="text", text=json.dumps(info, indent=2))]

    async def _handle_search_files(self, arguments: dict) -> list[types.TextContent]:
        """Handle searching files."""
        base_url = self._get_base_url(arguments)
        path = arguments["path"]
        pattern = arguments["pattern"]

        filestation = self._get_filestation(base_url)
        results = filestation.search_files(path, pattern)

        return [types.TextContent(type="text", text=json.dumps(results, indent=2))]

    async def _handle_get_file_content(self, arguments: dict) -> list[types.TextContent]:
        """Handle getting file content."""
        base_url = self._get_base_url(arguments)
        path = arguments["path"]

        filestation = self._get_filestation(base_url)
        content = filestation.get_file_content(path)

        return [types.TextContent(type="text", text=content)]

    async def _handle_rename_file(self, arguments: dict) -> list[types.TextContent]:
        """Handle renaming a file or directory."""
        base_url = self._get_base_url(arguments)
        path = arguments["path"]
        new_name = arguments["new_name"]

        filestation = self._get_filestation(base_url)
        result = filestation.rename_file(path, new_name)

        return [
            types.TextContent(type="text", text=f"Rename result: {json.dumps(result, indent=2)}")
        ]

    async def _handle_move_file(self, arguments: dict) -> list[types.TextContent]:
        """Handle moving a file or directory."""
        base_url = self._get_base_url(arguments)
        source_path = arguments["source_path"]
        destination_path = arguments["destination_path"]
        overwrite = arguments.get("overwrite", False)  # Default to False if not provided

        filestation = self._get_filestation(base_url)
        result = filestation.move_file(source_path, destination_path, overwrite)

        return [types.TextContent(type="text", text=f"Move result: {json.dumps(result, indent=2)}")]

    async def _handle_create_file(self, arguments: dict) -> list[types.TextContent]:
        """Handle creating a new file with specified content on the Synology NAS."""
        base_url = self._get_base_url(arguments)
        path = arguments["path"]
        content = arguments.get("content", "")
        overwrite = arguments.get("overwrite", False)

        filestation = self._get_filestation(base_url)
        result = filestation.create_file(path, content, overwrite)

        return [
            types.TextContent(
                type="text", text=f"Create file result: {json.dumps(result, indent=2)}"
            )
        ]

    async def _handle_create_directory(self, arguments: dict) -> list[types.TextContent]:
        """Handle creating a new directory on the Synology NAS."""
        base_url = self._get_base_url(arguments)
        folder_path = arguments["folder_path"]
        name = arguments["name"]
        force_parent = arguments.get("force_parent", False)

        filestation = self._get_filestation(base_url)
        result = filestation.create_directory(folder_path, name, force_parent)

        return [
            types.TextContent(
                type="text", text=f"Create directory result: {json.dumps(result, indent=2)}"
            )
        ]

    async def _handle_delete(self, arguments: dict) -> list[types.TextContent]:
        """Handle deleting a file or directory on the Synology NAS."""
        base_url = self._get_base_url(arguments)
        path = arguments["path"]

        filestation = self._get_filestation(base_url)
        result = filestation.delete(path)

        return [
            types.TextContent(type="text", text=f"Delete result: {json.dumps(result, indent=2)}")
        ]

    async def _handle_ds_get_info(self, arguments: dict) -> list[types.TextContent]:
        """Handle getting Download Station information and settings."""
        base_url = self._get_base_url(arguments)
        downloadstation = self._get_downloadstation(base_url)

        info = downloadstation.get_info()

        return [types.TextContent(type="text", text=json.dumps(info, indent=2))]

    async def _handle_ds_list_tasks(self, arguments: dict) -> list[types.TextContent]:
        """Handle listing all download tasks in Download Station."""
        base_url = self._get_base_url(arguments)
        downloadstation = self._get_downloadstation(base_url)

        tasks = downloadstation.list_tasks()

        return [types.TextContent(type="text", text=json.dumps(tasks, indent=2))]

    async def _handle_ds_create_task(self, arguments: dict) -> list[types.TextContent]:
        """Handle creating a new download task from URL or magnet link."""
        base_url = self._get_base_url(arguments)
        uri = arguments["uri"]
        destination = arguments.get("destination")
        username = arguments.get("username")
        password = arguments.get("password")

        downloadstation = self._get_downloadstation(base_url)
        result = downloadstation.create_task(uri, destination, username, password)

        return self._dsm_result(result, prefix="Create task result: ")

    async def _handle_ds_pause_tasks(self, arguments: dict) -> list[types.TextContent]:
        """Handle pausing one or more download tasks."""
        base_url = self._get_base_url(arguments)
        task_ids = arguments["task_ids"]

        downloadstation = self._get_downloadstation(base_url)
        result = downloadstation.pause_tasks(task_ids)

        return self._dsm_result(result, prefix="Pause tasks result: ")

    async def _handle_ds_resume_tasks(self, arguments: dict) -> list[types.TextContent]:
        """Handle resuming one or more paused download tasks."""
        base_url = self._get_base_url(arguments)
        task_ids = arguments["task_ids"]

        downloadstation = self._get_downloadstation(base_url)
        result = downloadstation.resume_tasks(task_ids)

        return self._dsm_result(result, prefix="Resume tasks result: ")

    async def _handle_ds_delete_tasks(self, arguments: dict) -> list[types.TextContent]:
        """Handle deleting one or more download tasks."""
        base_url = self._get_base_url(arguments)
        task_ids = arguments["task_ids"]
        force_complete = arguments.get("force_complete", False)

        downloadstation = self._get_downloadstation(base_url)
        result = downloadstation.delete_tasks(task_ids, force_complete)

        return self._dsm_result(result, prefix="Delete tasks result: ")

    async def _handle_ds_get_statistics(self, arguments: dict) -> list[types.TextContent]:
        """Handle getting Download Station download/upload statistics."""
        base_url = self._get_base_url(arguments)
        downloadstation = self._get_downloadstation(base_url)

        statistics = downloadstation.get_statistics()

        return [types.TextContent(type="text", text=json.dumps(statistics, indent=2))]

    async def _handle_ds_list_downloaded_files(self, arguments: dict) -> list[types.TextContent]:
        """Handle listing files in the download destination."""
        base_url = self._get_base_url(arguments)
        destination = arguments.get("destination")
        downloadstation = self._get_downloadstation(base_url)

        files = downloadstation.list_downloaded_files(destination)

        return [types.TextContent(type="text", text=json.dumps(files, indent=2))]

    # ------------------------------------------------------------------
    # Health monitoring handlers
    # ------------------------------------------------------------------

    async def _handle_health_call(
        self, arguments: dict, method_name: str
    ) -> list[types.TextContent]:
        """Generic handler for health monitoring calls."""
        base_url = self._get_base_url(arguments)
        health = self._get_health(base_url)
        result = getattr(health, method_name)()
        return self._dsm_result(result)

    async def _handle_disk_smart(self, arguments: dict) -> list[types.TextContent]:
        """Handle getting SMART info for a specific disk."""
        base_url = self._get_base_url(arguments)
        disk_id = arguments["disk_id"]
        health = self._get_health(base_url)
        result = health.disk_smart_info(disk_id)
        return self._dsm_result(result)

    async def _handle_system_log(self, arguments: dict) -> list[types.TextContent]:
        """Handle getting system log entries."""
        base_url = self._get_base_url(arguments)
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 50)
        health = self._get_health(base_url)
        result = health.system_log(offset=offset, limit=limit)
        return self._dsm_result(result)

    # ------------------------------------------------------------------
    # NFS management handlers
    # ------------------------------------------------------------------

    async def _handle_nfs_call(self, arguments: dict, method_name: str) -> list[types.TextContent]:
        """Generic handler for NFS calls."""
        base_url = self._get_base_url(arguments)
        nfs = self._get_nfs(base_url)
        result = getattr(nfs, method_name)()
        return self._dsm_result(result)

    async def _handle_nfs_enable(self, arguments: dict) -> list[types.TextContent]:
        """Handle enabling/disabling NFS service."""
        base_url = self._get_base_url(arguments)
        enable = arguments.get("enable", True)
        nfs_v4 = arguments.get("nfs_v4", False)
        nfs = self._get_nfs(base_url)
        result = nfs.nfs_enable(enable=enable, nfs_v4=nfs_v4)
        return self._dsm_result(result)

    async def _handle_nfs_set_permission(self, arguments: dict) -> list[types.TextContent]:
        """Handle setting NFS permissions on a share."""
        base_url = self._get_base_url(arguments)
        nfs = self._get_nfs(base_url)
        result = nfs.set_nfs_permission(
            share_name=arguments["share_name"],
            client_ip=arguments["client_ip"],
            privilege=arguments.get("privilege", "readwrite"),
            squash=arguments.get("squash", "root_squash"),
            security=arguments.get("security", "sys"),
        )
        return self._dsm_result(result)

    async def _handle_create_share(self, arguments: dict) -> list[types.TextContent]:
        """Handle creating a new shared folder."""
        base_url = self._get_base_url(arguments)
        nfs = self._get_nfs(base_url)
        result = nfs.create_share(
            name=arguments["share_name"],
            vol_path=arguments["vol_path"],
            desc=arguments.get("description", ""),
            enable_recycle_bin=arguments.get("enable_recycle_bin", True),
            recycle_bin_admin_only=arguments.get("recycle_bin_admin_only", True),
        )
        return self._dsm_result(result)

    # ------------------------------------------------------------------
    # Container Manager handlers
    # ------------------------------------------------------------------

    async def _handle_container_call(
        self, arguments: dict, method_name: str
    ) -> list[types.TextContent]:
        """Handle Container Manager container operations."""
        base_url = self._get_base_url(arguments)
        container = self._get_container(base_url)

        if method_name == "list":
            result = container.list_containers(
                offset=arguments.get("offset", 0),
                limit=arguments.get("limit", -1),
                container_type=arguments.get("container_type", "all"),
            )
        elif method_name == "project_list":
            result = container.list_projects()
        elif method_name == "project_create":
            result = container.create_project(
                name=arguments["name"],
                share_path=arguments["share_path"],
                content=arguments["content"],
                enable_service_portal=arguments.get("enable_service_portal", False),
                service_portal_name=arguments.get("service_portal_name"),
                service_portal_port=arguments.get("service_portal_port"),
                service_portal_protocol=arguments.get("service_portal_protocol", "http"),
            )
        elif method_name == "project_update":
            result = container.update_project(
                name=arguments["name"],
                content=arguments["content"],
                enable_service_portal=arguments.get("enable_service_portal"),
                service_portal_name=arguments.get("service_portal_name"),
                service_portal_port=arguments.get("service_portal_port"),
                service_portal_protocol=arguments.get("service_portal_protocol"),
            )
        elif method_name == "project_delete":
            result = container.delete_project(arguments["name"])
        elif method_name == "image_list":
            result = container.list_images(
                offset=arguments.get("offset", 0),
                limit=arguments.get("limit", -1),
                show_dsm=arguments.get("show_dsm", False),
            )
        elif method_name in {"image_get", "image_delete"}:
            image_method = {
                "image_get": container.get_image,
                "image_delete": container.delete_image,
            }[method_name]
            result = image_method(arguments["name"], tag=arguments.get("tag", "latest"))
        elif method_name in {"image_pull", "registry_download"}:
            result = container.pull_image(
                arguments["repository"],
                tag=arguments.get("tag", "latest"),
            )
        elif method_name == "registry_list":
            result = container.list_registries()
        elif method_name == "registry_search":
            result = container.search_registry(
                arguments["query"],
                offset=arguments.get("offset", 0),
                limit=arguments.get("limit", 50),
            )
        elif method_name == "registry_tags":
            result = container.list_registry_tags(
                arguments["repository"],
                offset=arguments.get("offset", 0),
                limit=arguments.get("limit", 50),
            )
        elif method_name == "network_list":
            result = container.list_networks()
        elif method_name == "network_get":
            result = container.get_network(arguments["name"])
        elif method_name == "network_create":
            result = container.create_network(
                arguments["name"],
                driver=arguments.get("driver", "bridge"),
                subnet=arguments.get("subnet"),
                gateway=arguments.get("gateway"),
                ip_range=arguments.get("ip_range"),
                enable_ipv6=arguments.get("enable_ipv6", False),
            )
        elif method_name == "network_delete":
            result = container.delete_network(arguments["name"])
        elif method_name == "delete":
            result = container.delete_container(
                arguments["name"],
                force=arguments.get("force", False),
                preserve_profile=arguments.get("preserve_profile", True),
            )
        elif method_name == "logs":
            result = container.get_container_logs(
                arguments["name"],
                since=arguments.get("since"),
                offset=arguments.get("offset", 0),
                limit=arguments.get("limit", 1000),
            )
        elif method_name in {
            "project_get",
            "project_start",
            "project_stop",
            "project_restart",
            "project_build",
            "project_clean",
        }:
            project_method = {
                "project_get": container.get_project,
                "project_start": container.start_project,
                "project_stop": container.stop_project,
                "project_restart": container.restart_project,
                "project_build": container.build_project,
                "project_clean": container.clean_project,
            }[method_name]
            result = project_method(arguments["name"])
        elif method_name in {"get", "start", "stop", "restart", "resource"}:
            container_method = {
                "get": container.get_container,
                "start": container.start_container,
                "stop": container.stop_container,
                "restart": container.restart_container,
                "resource": container.get_container_resource,
            }[method_name]
            result = container_method(arguments["name"])
        else:
            raise ValueError(f"Unknown container method: {method_name}")

        return self._dsm_result(result)

    # ------------------------------------------------------------------
    # User management handlers
    # ------------------------------------------------------------------

    async def _handle_usermgr_call(
        self, arguments: dict, method_name: str
    ) -> list[types.TextContent]:
        """Generic handler for simple user management calls."""
        base_url = self._get_base_url(arguments)
        usermgr = self._get_usermgr(base_url)
        result = getattr(usermgr, method_name)()
        return self._dsm_result(result)

    async def _handle_usermgr_get_user(self, arguments: dict) -> list[types.TextContent]:
        base_url = self._get_base_url(arguments)
        usermgr = self._get_usermgr(base_url)
        result = usermgr.get_user(arguments["name"])
        return self._dsm_result(result)

    async def _handle_usermgr_create_user(self, arguments: dict) -> list[types.TextContent]:
        base_url = self._get_base_url(arguments)
        usermgr = self._get_usermgr(base_url)
        result = usermgr.create_user(
            name=arguments["name"],
            password=arguments["password"],
            description=arguments.get("description", ""),
            email=arguments.get("email", ""),
            cannot_chg_passwd=arguments.get("cannot_chg_passwd", False),
            passwd_never_expire=arguments.get("passwd_never_expire", True),
        )
        return self._dsm_result(result)

    async def _handle_usermgr_set_user(self, arguments: dict) -> list[types.TextContent]:
        base_url = self._get_base_url(arguments)
        usermgr = self._get_usermgr(base_url)
        result = usermgr.set_user(
            name=arguments["name"],
            new_name=arguments.get("new_name"),
            password=arguments.get("password"),
            description=arguments.get("description"),
            email=arguments.get("email"),
            expired=arguments.get("expired"),
        )
        return self._dsm_result(result)

    async def _handle_usermgr_delete_user(self, arguments: dict) -> list[types.TextContent]:
        base_url = self._get_base_url(arguments)
        usermgr = self._get_usermgr(base_url)
        result = usermgr.delete_user(arguments["name"])
        return self._dsm_result(result)

    async def _handle_usermgr_list_group_members(self, arguments: dict) -> list[types.TextContent]:
        base_url = self._get_base_url(arguments)
        usermgr = self._get_usermgr(base_url)
        result = usermgr.list_group_members(arguments["group"])
        return self._dsm_result(result)

    async def _handle_usermgr_add_to_group(self, arguments: dict) -> list[types.TextContent]:
        base_url = self._get_base_url(arguments)
        usermgr = self._get_usermgr(base_url)
        result = usermgr.add_user_to_group(arguments["username"], arguments["groups"])
        return self._dsm_result(result)

    async def _handle_usermgr_remove_from_group(self, arguments: dict) -> list[types.TextContent]:
        base_url = self._get_base_url(arguments)
        usermgr = self._get_usermgr(base_url)
        result = usermgr.remove_user_from_group(arguments["username"], arguments["groups"])
        return self._dsm_result(result)

    async def _handle_usermgr_get_permissions(self, arguments: dict) -> list[types.TextContent]:
        base_url = self._get_base_url(arguments)
        usermgr = self._get_usermgr(base_url)
        result = usermgr.get_user_permissions(arguments["name"])
        return self._dsm_result(result)

    async def _handle_usermgr_set_permissions(self, arguments: dict) -> list[types.TextContent]:
        base_url = self._get_base_url(arguments)
        usermgr = self._get_usermgr(base_url)
        result = usermgr.set_user_permissions(arguments["name"], arguments["permissions"])
        return self._dsm_result(result)

    def _get_container_tool_definitions(self):
        """Get Container Manager container tool definitions."""
        target = {
            "nas_name": {
                "type": "string",
                "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
            },
            "base_url": {
                "type": "string",
                "description": "Synology NAS base URL (alternative to nas_name)",
            },
        }
        name = {"type": "string", "description": "Container name (e.g. 'watchtower')"}
        project_name = {"type": "string", "description": "Project name (e.g. 'watchtower')"}

        def tool(tool_name: str, description: str, properties: dict, required: list[str]):
            return types.Tool(
                name=tool_name,
                description=description,
                inputSchema={
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            )

        name_properties = {**target, "name": name}
        project_name_properties = {**target, "name": project_name}
        image_properties = {
            **target,
            "name": {"type": "string", "description": "Image repository name (e.g. 'nginx')"},
            "tag": {"type": "string", "description": "Image tag (default: latest)"},
        }
        repository_properties = {
            **target,
            "repository": {
                "type": "string",
                "description": "Image repository name (e.g. 'nginx')",
            },
            "tag": {"type": "string", "description": "Image tag (default: latest)"},
        }
        network_properties = {
            **target,
            "name": {"type": "string", "description": "Network name"},
        }
        project_content_properties = {
            **project_name_properties,
            "content": {
                "type": "string",
                "description": "Docker Compose YAML content",
            },
            "enable_service_portal": {
                "type": "boolean",
                "description": "Enable Synology service portal (default: false)",
            },
            "service_portal_name": {
                "type": "string",
                "description": "Optional service portal name",
            },
            "service_portal_port": {
                "type": "integer",
                "description": "Optional service portal port",
            },
            "service_portal_protocol": {
                "type": "string",
                "description": "Service portal protocol (default: http)",
            },
        }
        return [
            tool(
                "synology_container_list",
                "List Container Manager containers",
                {
                    **target,
                    "offset": {"type": "integer", "description": "Pagination offset"},
                    "limit": {"type": "integer", "description": "Maximum containers to return"},
                    "container_type": {
                        "type": "string",
                        "description": "Container filter (default: all)",
                    },
                },
                [],
            ),
            tool(
                "synology_container_get",
                "Get a Container Manager container",
                name_properties,
                ["name"],
            ),
            tool(
                "synology_container_start",
                "Start a Container Manager container",
                name_properties,
                ["name"],
            ),
            tool(
                "synology_container_stop",
                "Stop a Container Manager container",
                name_properties,
                ["name"],
            ),
            tool(
                "synology_container_restart",
                "Restart a Container Manager container",
                name_properties,
                ["name"],
            ),
            tool(
                "synology_container_delete",
                "Delete a Container Manager container",
                {
                    **name_properties,
                    "force": {"type": "boolean", "description": "Force deletion (default: false)"},
                    "preserve_profile": {
                        "type": "boolean",
                        "description": "Preserve Synology container profile (default: true)",
                    },
                },
                ["name"],
            ),
            tool(
                "synology_container_logs",
                "Get Container Manager container logs",
                {
                    **name_properties,
                    "since": {"type": "string", "description": "Optional log start time/filter"},
                    "offset": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Pagination offset (default: 0)",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Maximum log lines to return (default: 1000)",
                    },
                },
                ["name"],
            ),
            tool(
                "synology_container_resource",
                "Get real-time resource usage for a Container Manager container",
                name_properties,
                ["name"],
            ),
            tool(
                "synology_container_project_list",
                "List Container Manager projects",
                target,
                [],
            ),
            tool(
                "synology_container_project_get",
                "Get a Container Manager project",
                project_name_properties,
                ["name"],
            ),
            tool(
                "synology_container_project_create",
                "Create a Container Manager project",
                {
                    **project_content_properties,
                    "share_path": {
                        "type": "string",
                        "description": "Project folder path on the NAS",
                    },
                },
                ["name", "share_path", "content"],
            ),
            tool(
                "synology_container_project_update",
                "Update a Container Manager project",
                project_content_properties,
                ["name", "content"],
            ),
            tool(
                "synology_container_project_start",
                "Start a Container Manager project",
                project_name_properties,
                ["name"],
            ),
            tool(
                "synology_container_project_stop",
                "Stop a Container Manager project",
                project_name_properties,
                ["name"],
            ),
            tool(
                "synology_container_project_restart",
                "Restart a Container Manager project",
                project_name_properties,
                ["name"],
            ),
            tool(
                "synology_container_project_build",
                "Build a Container Manager project",
                project_name_properties,
                ["name"],
            ),
            tool(
                "synology_container_project_clean",
                "Clean a Container Manager project",
                project_name_properties,
                ["name"],
            ),
            tool(
                "synology_container_project_delete",
                "Delete a Container Manager project by name",
                project_name_properties,
                ["name"],
            ),
            tool(
                "synology_container_image_list",
                "List Container Manager images",
                {
                    **target,
                    "offset": {"type": "integer", "description": "Pagination offset"},
                    "limit": {"type": "integer", "description": "Maximum images to return"},
                    "show_dsm": {
                        "type": "boolean",
                        "description": "Include DSM images (default: false)",
                    },
                },
                [],
            ),
            tool(
                "synology_container_image_get",
                "Get a Container Manager image",
                image_properties,
                ["name"],
            ),
            tool(
                "synology_container_image_delete",
                "Delete a Container Manager image",
                image_properties,
                ["name"],
            ),
            tool(
                "synology_container_image_pull",
                "Pull a Container Manager image",
                repository_properties,
                ["repository"],
            ),
            tool(
                "synology_container_registry_list",
                "List Container Manager registries",
                target,
                [],
            ),
            tool(
                "synology_container_registry_search",
                "Search Container Manager registries",
                {
                    **target,
                    "query": {"type": "string", "description": "Image search query"},
                    "offset": {"type": "integer", "description": "Pagination offset"},
                    "limit": {"type": "integer", "description": "Maximum results to return"},
                },
                ["query"],
            ),
            tool(
                "synology_container_registry_tags",
                "List tags for a registry image",
                {
                    **target,
                    "repository": {
                        "type": "string",
                        "description": "Image repository name (e.g. 'nginx')",
                    },
                    "offset": {"type": "integer", "description": "Pagination offset"},
                    "limit": {"type": "integer", "description": "Maximum tags to return"},
                },
                ["repository"],
            ),
            tool(
                "synology_container_registry_download",
                "Download a registry image",
                repository_properties,
                ["repository"],
            ),
            tool(
                "synology_container_network_list",
                "List Container Manager networks",
                target,
                [],
            ),
            tool(
                "synology_container_network_get",
                "Get a Container Manager network",
                network_properties,
                ["name"],
            ),
            tool(
                "synology_container_network_create",
                "Create a Container Manager network",
                {
                    **network_properties,
                    "driver": {
                        "type": "string",
                        "description": "Network driver (default: bridge)",
                    },
                    "subnet": {
                        "type": "string",
                        "description": "Subnet CIDR (e.g. 172.28.0.0/16)",
                    },
                    "gateway": {"type": "string", "description": "Gateway IP"},
                    "ip_range": {"type": "string", "description": "Allocatable IP range CIDR"},
                    "enable_ipv6": {
                        "type": "boolean",
                        "description": "Enable IPv6 (default: false)",
                    },
                },
                ["name"],
            ),
            tool(
                "synology_container_network_delete",
                "Delete a Container Manager network",
                network_properties,
                ["name"],
            ),
        ]

    def _get_tool_definitions(self):
        """Build every non-container tool definition, plus the spliced-in
        container tool definitions, each annotated read-only/destructive
        from this server's own restricted-mode classification (see
        `_annotate_tool`) so the two can never silently drift apart."""
        tools = [
            types.Tool(
                name="synology_status",
                description="Check authentication status for Synology NAS instances",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name="synology_list_nas",
                description="List all configured NAS units from settings.json. Returns NAS names, URLs, and connection status.",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name="list_shares",
                description="List all available shares on the Synology NAS",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="list_directory",
                description="List contents of a directory on the Synology NAS. Returns detailed information about files and folders including name, type, size, and timestamps.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "path": {
                            "type": "string",
                            "description": "Directory path to list (must start with /)",
                        },
                    },
                    "required": ["path"],
                },
            ),
            types.Tool(
                name="get_file_info",
                description="Get detailed information about a specific file or directory",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "path": {
                            "type": "string",
                            "description": "File or directory path (must start with /)",
                        },
                    },
                    "required": ["path"],
                },
            ),
            types.Tool(
                name="search_files",
                description="Search for files and directories matching a pattern",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "path": {
                            "type": "string",
                            "description": "Directory path to search in (must start with /)",
                        },
                        "pattern": {
                            "type": "string",
                            "description": "Search pattern (supports wildcards like *.txt)",
                        },
                    },
                    "required": ["path", "pattern"],
                },
            ),
            types.Tool(
                name="get_file_content",
                description="Get the content of a file",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "path": {"type": "string", "description": "File path (must start with /)"},
                    },
                    "required": ["path"],
                },
            ),
            types.Tool(
                name="rename_file",
                description="Rename a file or directory on the Synology NAS",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "path": {
                            "type": "string",
                            "description": "Full path to the file/directory to rename (must start with /)",
                        },
                        "new_name": {
                            "type": "string",
                            "description": "New name for the file/directory (just the name, not full path)",
                        },
                    },
                    "required": ["path", "new_name"],
                },
            ),
            types.Tool(
                name="move_file",
                description="Move a file or directory to a new location on the Synology NAS",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "source_path": {
                            "type": "string",
                            "description": "Full path to the file/directory to move (must start with /)",
                        },
                        "destination_path": {
                            "type": "string",
                            "description": "Destination path - can be a directory or full path with new name (must start with /)",
                        },
                        "overwrite": {
                            "type": "boolean",
                            "description": "Whether to overwrite existing files at destination (default: false)",
                        },
                    },
                    "required": ["source_path", "destination_path"],
                },
            ),
            types.Tool(
                name="create_file",
                description="Create a new file with specified content on the Synology NAS",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "path": {
                            "type": "string",
                            "description": "Full path where the file should be created (must start with /)",
                        },
                        "content": {
                            "type": "string",
                            "description": "Content to write to the file (default: empty string)",
                        },
                        "overwrite": {
                            "type": "boolean",
                            "description": "Whether to overwrite existing file (default: false)",
                        },
                    },
                    "required": ["path"],
                },
            ),
            types.Tool(
                name="create_directory",
                description="Create a new directory on the Synology NAS",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "folder_path": {
                            "type": "string",
                            "description": "Parent directory path where the new folder should be created (must start with /)",
                        },
                        "name": {
                            "type": "string",
                            "description": "Name of the new directory to create",
                        },
                        "force_parent": {
                            "type": "boolean",
                            "description": "Whether to create parent directories if they don't exist (default: false)",
                        },
                    },
                    "required": ["folder_path", "name"],
                },
            ),
            types.Tool(
                name="delete",
                description="Delete a file or directory on the Synology NAS (auto-detects type)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "path": {
                            "type": "string",
                            "description": "Full path to the file/directory to delete (must start with /)",
                        },
                    },
                    "required": ["path"],
                },
            ),
            # Download Station Tools
            types.Tool(
                name="ds_get_info",
                description="Get Download Station information and settings",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="ds_list_tasks",
                description="List all download tasks in Download Station",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "offset": {
                            "type": "integer",
                            "description": "Starting offset for pagination (default: 0)",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of tasks to return (default: -1 for all)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="ds_create_task",
                description="Create a new download task from URL or magnet link",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "uri": {"type": "string", "description": "Download URL or magnet link"},
                        "destination": {
                            "type": "string",
                            "description": "Destination folder path (optional)",
                        },
                        "username": {
                            "type": "string",
                            "description": "Username for protected downloads (optional)",
                        },
                        "password": {
                            "type": "string",
                            "description": "Password for protected downloads (optional)",
                        },
                    },
                    "required": ["uri"],
                },
            ),
            types.Tool(
                name="ds_pause_tasks",
                description="Pause one or more download tasks",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "task_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of task IDs to pause",
                        },
                    },
                    "required": ["task_ids"],
                },
            ),
            types.Tool(
                name="ds_resume_tasks",
                description="Resume one or more paused download tasks",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "task_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of task IDs to resume",
                        },
                    },
                    "required": ["task_ids"],
                },
            ),
            types.Tool(
                name="ds_delete_tasks",
                description="Delete one or more download tasks",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "task_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of task IDs to delete",
                        },
                        "force_complete": {
                            "type": "boolean",
                            "description": "Force delete completed tasks (default: false)",
                        },
                    },
                    "required": ["task_ids"],
                },
            ),
            types.Tool(
                name="ds_get_statistics",
                description="Get Download Station download/upload statistics",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="ds_list_downloaded_files",
                description="List files in the Download Station destination folder",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "destination": {
                            "type": "string",
                            "description": "Destination folder to list (optional, defaults to download station's default)",
                        },
                    },
                    "required": [],
                },
            ),
            # ============================================================
            # Health Monitoring Tools
            # ============================================================
            types.Tool(
                name="synology_system_info",
                description="Get Synology NAS system information: model, serial, DSM version, uptime, temperature",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_utilization",
                description="Get real-time CPU, memory, swap, and disk I/O utilization",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_disk_health",
                description="List all physical disks with SMART health status, model, temperature, and capacity",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_disk_smart",
                description="Get detailed S.M.A.R.T. attributes for a specific physical disk",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "disk_id": {
                            "type": "string",
                            "description": "Disk identifier (e.g. 'sda', 'sdb') from synology_disk_health output",
                        },
                    },
                    "required": ["disk_id"],
                },
            ),
            types.Tool(
                name="synology_volume_status",
                description="List all volumes/filesystems with status, total size, used space, and RAID info",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_storage_pool",
                description="List RAID/storage pools with RAID level, status, and member disks",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_network",
                description="Get network interface status and transfer rates",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_ups",
                description="Get UPS (uninterruptible power supply) status, battery level, and power info",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_services",
                description="List installed packages/services and their running status",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_system_log",
                description="Get recent system log entries for diagnosing issues",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "offset": {
                            "type": "integer",
                            "description": "Starting offset (default: 0)",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max entries to return (default: 50)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_health_summary",
                description=(
                    "Get a combined health overview: system info, CPU/memory utilization, "
                    "disk health, volume status, storage pools, network, and UPS — all in "
                    "one call.\n\n"
                    "Check `status` in the result. `complete` means every check ran. "
                    "`partial` means some checks could not be completed (listed in "
                    "`failed_checks`) and `data` holds only the rest — a partial result is "
                    "NOT confirmation that the NAS is healthy, so report the failed checks "
                    "rather than treating the missing sections as fine. A check the NAS "
                    "does not offer at all (a UPS that is not attached) is listed in "
                    "`unavailable_checks` and does not make the result partial. If every "
                    "check fails the tool returns an error."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            # ============================================================
            # Container Manager Tools
            # ============================================================
            *self._get_container_tool_definitions(),
            # ============================================================
            # NFS Management Tools
            # ============================================================
            types.Tool(
                name="synology_nfs_status",
                description="Get NFS service status and configuration (enabled/disabled, NFSv4 settings)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_nfs_enable",
                description="Enable or disable the NFS file service on the Synology NAS",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "enable": {
                            "type": "boolean",
                            "description": "True to enable NFS, false to disable (default: true)",
                        },
                        "nfs_v4": {
                            "type": "boolean",
                            "description": "Enable NFSv4 support (default: false)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_nfs_list_shares",
                description="List all shared folders with their NFS access permissions",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_nfs_set_permission",
                description="Set NFS client access permissions on a shared folder (IP/subnet, read/write, squash options)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "share_name": {
                            "type": "string",
                            "description": "Name of the shared folder (e.g. 'media', 'backups')",
                        },
                        "client_ip": {
                            "type": "string",
                            "description": "Client IP or subnet (e.g. '192.168.1.0/24', '10.0.0.5')",
                        },
                        "privilege": {
                            "type": "string",
                            "enum": ["readonly", "readwrite"],
                            "description": "Access level (default: readwrite)",
                        },
                        "squash": {
                            "type": "string",
                            "enum": ["root_squash", "no_root_squash", "all_squash"],
                            "description": "Squash option for root user mapping (default: root_squash)",
                        },
                        "security": {
                            "type": "string",
                            "enum": ["sys", "krb5", "krb5i", "krb5p"],
                            "description": "Security mode (default: sys/AUTH_SYS)",
                        },
                    },
                    "required": ["share_name", "client_ip"],
                },
            ),
            types.Tool(
                name="synology_create_share",
                description="Create a new shared folder on a Synology NAS volume",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "share_name": {
                            "type": "string",
                            "description": "Name of the shared folder to create (e.g. 'rag-corpus')",
                        },
                        "vol_path": {
                            "type": "string",
                            "description": "Volume path where the share will be created (e.g. '/volume1', '/volume2')",
                        },
                        "description": {
                            "type": "string",
                            "description": "Optional description for the shared folder",
                        },
                        "enable_recycle_bin": {
                            "type": "boolean",
                            "description": "Enable recycle bin for deleted files (default: true)",
                        },
                        "recycle_bin_admin_only": {
                            "type": "boolean",
                            "description": "Restrict recycle bin access to administrators only (default: true)",
                        },
                    },
                    "required": ["share_name", "vol_path"],
                },
            ),
            # ============================================================
            # User Management Tools
            # ============================================================
            types.Tool(
                name="synology_list_users",
                description="List all local users on the Synology NAS",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_get_user",
                description="Get detailed information about a specific user",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "name": {"type": "string", "description": "Username to look up"},
                    },
                    "required": ["name"],
                },
            ),
            types.Tool(
                name="synology_create_user",
                description="Create a new local user on the Synology NAS",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "name": {"type": "string", "description": "Username for the new account"},
                        "password": {
                            "type": "string",
                            "description": "Password for the new account",
                        },
                        "description": {
                            "type": "string",
                            "description": "User description (optional)",
                        },
                        "email": {"type": "string", "description": "User email address (optional)"},
                        "cannot_chg_passwd": {
                            "type": "boolean",
                            "description": "Prevent user from changing password (default: false)",
                        },
                        "passwd_never_expire": {
                            "type": "boolean",
                            "description": "Password never expires (default: true)",
                        },
                    },
                    "required": ["name", "password"],
                },
            ),
            types.Tool(
                name="synology_set_user",
                description="Modify an existing user (rename, change password, enable/disable)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "name": {"type": "string", "description": "Target username to modify"},
                        "new_name": {"type": "string", "description": "Rename the user (optional)"},
                        "password": {"type": "string", "description": "New password (optional)"},
                        "description": {
                            "type": "string",
                            "description": "New description (optional)",
                        },
                        "email": {"type": "string", "description": "New email (optional)"},
                        "expired": {
                            "type": "string",
                            "enum": ["normal", "now"],
                            "description": "'normal' = active, 'now' = disabled",
                        },
                    },
                    "required": ["name"],
                },
            ),
            types.Tool(
                name="synology_delete_user",
                description="Delete a local user from the Synology NAS",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "name": {"type": "string", "description": "Username to delete"},
                    },
                    "required": ["name"],
                },
            ),
            types.Tool(
                name="synology_list_groups",
                description="List all local groups on the Synology NAS",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="synology_list_group_members",
                description="List members of a specific group",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "group": {"type": "string", "description": "Group name to list members of"},
                    },
                    "required": ["group"],
                },
            ),
            types.Tool(
                name="synology_add_user_to_group",
                description="Add a user to one or more groups",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "username": {"type": "string", "description": "Username to add to groups"},
                        "groups": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of group names to join",
                        },
                    },
                    "required": ["username", "groups"],
                },
            ),
            types.Tool(
                name="synology_remove_user_from_group",
                description="Remove a user from one or more groups",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "username": {
                            "type": "string",
                            "description": "Username to remove from groups",
                        },
                        "groups": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of group names to leave",
                        },
                    },
                    "required": ["username", "groups"],
                },
            ),
            types.Tool(
                name="synology_get_user_permissions",
                description="Get shared folder permissions for a user",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "name": {
                            "type": "string",
                            "description": "Username to check permissions for",
                        },
                    },
                    "required": ["name"],
                },
            ),
            types.Tool(
                name="synology_set_user_permissions",
                description="Set shared folder permissions for a user (read/write/deny per folder)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "nas_name": {
                            "type": "string",
                            "description": "NAS identifier from settings.json (e.g. 'nas1', 'nas2')",
                        },
                        "base_url": {
                            "type": "string",
                            "description": "Synology NAS base URL (alternative to nas_name)",
                        },
                        "name": {
                            "type": "string",
                            "description": "Username to set permissions for",
                        },
                        "permissions": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string", "description": "Shared folder name"},
                                    "is_writable": {
                                        "type": "boolean",
                                        "description": "Grant write access",
                                    },
                                    "is_deny": {
                                        "type": "boolean",
                                        "description": "Deny access entirely",
                                    },
                                },
                                "required": ["name"],
                            },
                            "description": "List of folder permission objects",
                        },
                    },
                    "required": ["name", "permissions"],
                },
            ),
        ]
        return [self._annotate_tool(t) for t in tools]

    async def run(self):
        """Run the MCP server."""
        # Validate configuration first
        config_errors = config.validate_config()
        if config_errors and config.auto_login:
            error_msg = f"Configuration errors: {', '.join(config_errors)}"
            logger.error(error_msg)
            raise Exception(f"Invalid configuration - stopping server. {error_msg}")
        elif config.debug:
            logger.debug(f"Configuration loaded: {config}")

        # Attempt auto-login if configured (this will raise exception on failure and stop server)
        logger.info("Attempting auto-login...")
        await self._auto_login_if_configured()

        # Only start server if auto-login succeeded (or wasn't required)
        try:
            logger.info("Starting MCP server on stdio...")
            async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
                await self.server.run(
                    read_stream,
                    write_stream,
                    self.server.create_initialization_options(NotificationOptions()),
                )
        except KeyboardInterrupt:
            logger.info("Received shutdown signal, cleaning up sessions...")
        except Exception as e:
            logger.error(f"Server runtime error: {e}")
            if config.debug:
                logger.debug("Traceback:", exc_info=True)
            raise
        finally:
            # Always attempt session cleanup on shutdown
            if self.sessions:
                logger.info("Cleaning up active sessions...")
                cleanup_results = await self.cleanup_sessions()

                if cleanup_results:
                    logger.info("Session cleanup summary:")
                    for result in cleanup_results:
                        logger.info(f"  {result}")

                logger.info("Session cleanup completed")
            else:
                logger.info("No active sessions to clean up")

    async def cleanup_sessions(self):
        """Clean up all active sessions during shutdown."""
        cleanup_results = []

        for base_url, session_id in list(self.sessions.items()):
            try:
                auth = self.auth_instances.get(base_url)
                if auth:
                    logger.info(f"Cleaning up session for {base_url}...")
                    result = auth.logout(session_id)

                    if result.get("success"):
                        logger.info(f"Session for {base_url} logged out successfully")
                        cleanup_results.append(f"{base_url}: Logged out successfully")
                    else:
                        error_info = result.get("error", {})
                        error_code = error_info.get("code", "unknown")

                        if str(error_code) in {"105", "106", "no_session"}:
                            logger.info(f"Session for {base_url} was already expired")
                            cleanup_results.append(f"{base_url}: Session already expired")
                        else:
                            logger.error(f"Failed to logout session for {base_url}: {error_code}")
                            cleanup_results.append(f"{base_url}: Logout failed - {error_code}")

                # Always clear local data
                del self.sessions[base_url]
                self.syno_tokens.pop(base_url, None)
                for inst_dict in self._service_instance_dicts():
                    inst_dict.pop(base_url, None)

            except Exception as e:
                logger.error(f"Exception during cleanup for {base_url}: {e}")
                cleanup_results.append(f"{base_url}: Exception - {str(e)}")

        return cleanup_results


async def main():
    """Main entry point."""
    server = SynologyMCPServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
