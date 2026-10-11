"""How the tools are presented: a plain-language title, a category, a one-line
summary and a safe example for each.

This is presentation only. It decides what a person (or a client's tool picker)
sees; it never decides what may run. Which tools exist is the server's
registry. Which are read-only, destructive or restricted is classified in
`mcp_server.py` (`_READ_ONLY_TOOLS`, `_DESTRUCTIVE_TOOLS`,
`_ACCOUNT_ENUMERATION_TOOLS`, `_is_tool_allowed`), and which a broker client
gets is its policy (`broker/policy.py`, `DEFAULT_TOOLS`). This module holds no
list of allowed tools, so there is no second allowlist to drift from those.
A title or a category can be wrong without widening anything; a test checks that
every registered tool has an entry and no entry names a tool that is not
registered.

The tool IDs are the stable names and never change here. `docs/TOOL_CATALOG.md`
is generated from this table plus the registry and the broker's default policy
(`python scripts/generate_tool_catalog.py`), and a test fails when it is stale.

Importing this module has no side effects and imports nothing from the server.
"""

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

# In the order the catalog shows them.
CATEGORIES: Tuple[Tuple[str, str], ...] = (
    ("connection", "Connection"),
    ("health", "Health and monitoring"),
    ("files", "Files"),
    ("downloads", "Downloads"),
    ("containers", "Containers"),
    ("sharing", "Sharing and NFS"),
    ("accounts", "Users and groups"),
)
CATEGORY_TITLES: Dict[str, str] = dict(CATEGORIES)

# Tools that work with nobody signed in: they only describe configuration, or
# end a session. Everything else needs the user to have signed in.
NO_SIGN_IN_NEEDED = frozenset(
    {"synology_status", "synology_list_nas", "synology_login", "synology_logout"}
)

# Said once, to the model, in the description of the tool it calls first, and
# only when the user signs in privately: otherwise a model that finds no session
# may ask the user for the NAS password in chat, which is the one thing that
# must not happen.
SIGN_IN_NOTE = (
    " When a NAS is not signed in, the user signs in themselves on a private page;"
    " never ask for, or accept, a NAS password or one-time code in the chat."
)

# Said in the description of every tool that returns text from the NAS that the
# user may not have read: it goes to the AI application and on to its provider.
CONTENT_NOTE = (
    " What this returns is sent to the AI application and its AI provider, so ask"
    " for only what is needed."
)


@dataclass(frozen=True)
class ToolEntry:
    title: str
    category: str
    summary: str
    # Arguments of one safe call, shown in the catalog for the tools that are
    # on by default. Never a real name, path or credential.
    example: Optional[Mapping[str, Any]] = None
    # The tool returns free text or file content that goes to the AI provider.
    sends_content: bool = False


def _e(
    title: str,
    category: str,
    summary: str,
    example: Optional[Mapping[str, Any]] = None,
    sends_content: bool = False,
) -> ToolEntry:
    return ToolEntry(title, category, summary, example, sends_content)


_NAS = {"nas_name": "nas1"}
_DOCS = "/Shared/Documents"

CATALOG: Dict[str, ToolEntry] = {
    # ------------------------------------------------------------ connection
    "synology_status": _e(
        "Connection status",
        "connection",
        "Shows which configured NAS units are signed in. It never signs anyone in.",
        {},
    ),
    "synology_list_nas": _e(
        "Configured NAS units",
        "connection",
        "Lists the NAS units this server knows about, with their addresses and whether each is signed in.",
        {},
    ),
    "synology_login": _e(
        "Sign in (legacy mode only)",
        "connection",
        "Signs in with a username and password given in the call. It exists only in legacy mode: "
        "with manual authentication it is not offered at all, because a password must never pass "
        "through an AI application. The user signs in on the private page instead.",
    ),
    "synology_logout": _e(
        "Sign out",
        "connection",
        "Ends the session with a NAS. Signing in again is done by the user.",
        {"base_url": "https://nas.example:5001"},
    ),
    # ---------------------------------------------------------------- health
    "synology_health_summary": _e(
        "NAS health summary",
        "health",
        "One overview of system, CPU and memory, disks, volumes, storage pools, network and UPS, "
        "and which checks could not be completed.",
        _NAS,
    ),
    "synology_system_info": _e(
        "System information",
        "health",
        "Model, serial number, DSM version, uptime and temperature.",
        _NAS,
    ),
    "synology_utilization": _e(
        "CPU and memory use",
        "health",
        "Current CPU, memory, swap and disk activity.",
        _NAS,
    ),
    "synology_disk_health": _e(
        "Disk health",
        "health",
        "Every physical disk with its S.M.A.R.T. status, model, temperature and capacity.",
        _NAS,
    ),
    "synology_disk_smart": _e(
        "Disk S.M.A.R.T. details",
        "health",
        "The detailed S.M.A.R.T. attributes of one disk.",
        {**_NAS, "disk_id": "sata1"},
    ),
    "synology_volume_status": _e(
        "Volume status",
        "health",
        "Every volume with its status, size, space used and RAID type.",
        _NAS,
    ),
    "synology_storage_pool": _e(
        "Storage pools",
        "health",
        "Every storage pool with its RAID level, status and member disks.",
        _NAS,
    ),
    "synology_network": _e(
        "Network status",
        "health",
        "Network interfaces with their status and current transfer rates.",
        _NAS,
    ),
    "synology_ups": _e(
        "UPS status",
        "health",
        "The uninterruptible power supply: status, battery level and power.",
        _NAS,
    ),
    "synology_services": _e(
        "Installed packages",
        "health",
        "The installed packages and whether each is running.",
        _NAS,
    ),
    "synology_system_log": _e(
        "System log",
        "health",
        "Recent system log entries. They can contain user names and file names.",
        _NAS,
        sends_content=True,
    ),
    # ----------------------------------------------------------------- files
    "list_shares": _e(
        "Browse shared folders",
        "files",
        "Lists the shared folders on a NAS. With manual authentication, only the shares this client "
        "may reach are shown.",
        _NAS,
    ),
    "list_directory": _e(
        "List a folder",
        "files",
        "Lists what is inside a folder, with type, size and dates.",
        {**_NAS, "path": _DOCS},
    ),
    "get_file_info": _e(
        "File details",
        "files",
        "Size, dates and type of one file or folder. Says plainly when it does not exist.",
        {**_NAS, "path": f"{_DOCS}/report.txt"},
    ),
    "search_files": _e(
        "Search files",
        "files",
        "Finds files and folders whose names match a pattern, inside one folder. A search of a large "
        "folder can take a while and is stopped at its time limit.",
        {**_NAS, "path": _DOCS, "pattern": "*.pdf"},
    ),
    "get_file_content": _e(
        "Read a file",
        "files",
        "The text of one file. The content goes to the AI application and its provider. Files over "
        "the size limit (1,000,000 bytes unless MAX_FILE_CONTENT_SIZE says otherwise) are refused.",
        {**_NAS, "path": f"{_DOCS}/notes.txt"},
        sends_content=True,
    ),
    "rename_file": _e(
        "Rename a file or folder",
        "files",
        "Gives one file or folder a new name, in the same place.",
    ),
    "move_file": _e(
        "Move a file or folder",
        "files",
        "Moves a file or folder to another folder.",
    ),
    "create_file": _e(
        "Create a file",
        "files",
        "Creates a new file with the text it is given.",
    ),
    "create_directory": _e(
        "Create a folder",
        "files",
        "Creates a new folder inside an existing one.",
    ),
    "delete": _e(
        "Delete a file or folder",
        "files",
        "Deletes a file, or a folder and everything in it. This server cannot undo it.",
    ),
    # ------------------------------------------------------------- downloads
    "ds_get_info": _e(
        "Download Station settings",
        "downloads",
        "Download Station's version and settings.",
        _NAS,
    ),
    "ds_list_tasks": _e(
        "List downloads",
        "downloads",
        "Every download in Download Station with its status.",
        _NAS,
    ),
    "ds_create_task": _e(
        "Start a download",
        "downloads",
        "Adds a download from a web address or a magnet link.",
    ),
    "ds_pause_tasks": _e("Pause downloads", "downloads", "Pauses one or more downloads."),
    "ds_resume_tasks": _e("Resume downloads", "downloads", "Resumes one or more paused downloads."),
    "ds_delete_tasks": _e(
        "Remove downloads", "downloads", "Removes one or more downloads from Download Station."
    ),
    "ds_get_statistics": _e(
        "Download speeds",
        "downloads",
        "Current download and upload speeds.",
        _NAS,
    ),
    "ds_list_downloaded_files": _e(
        "List downloaded files",
        "downloads",
        "The files in Download Station's destination folder.",
        _NAS,
    ),
    # ------------------------------------------------------------ containers
    "synology_container_list": _e(
        "List containers", "containers", "Every Container Manager container with its status.", _NAS
    ),
    "synology_container_get": _e(
        "Container details",
        "containers",
        "Everything known about one container. This can include environment variables and mounts, "
        "which sometimes hold secrets.",
        {**_NAS, "name": "watchtower"},
        sends_content=True,
    ),
    "synology_container_start": _e("Start a container", "containers", "Starts a container."),
    "synology_container_stop": _e("Stop a container", "containers", "Stops a running container."),
    "synology_container_restart": _e("Restart a container", "containers", "Restarts a container."),
    "synology_container_delete": _e("Delete a container", "containers", "Deletes a container."),
    "synology_container_logs": _e(
        "Container logs",
        "containers",
        "Recent log lines of one container. Free text that may hold anything.",
        {**_NAS, "name": "watchtower"},
        sends_content=True,
    ),
    "synology_container_resource": _e(
        "Container resource use",
        "containers",
        "Current CPU and memory use of one container.",
        {**_NAS, "name": "watchtower"},
    ),
    "synology_container_project_list": _e(
        "List projects", "containers", "Every Container Manager project with its status.", _NAS
    ),
    "synology_container_project_get": _e(
        "Project details",
        "containers",
        "One project, including its compose file, which can hold environment variables and secrets.",
        {**_NAS, "name": "watchtower"},
        sends_content=True,
    ),
    "synology_container_project_create": _e(
        "Create a project", "containers", "Creates a project from a compose file."
    ),
    "synology_container_project_update": _e(
        "Update a project", "containers", "Replaces a project's compose file."
    ),
    "synology_container_project_start": _e("Start a project", "containers", "Starts a project."),
    "synology_container_project_stop": _e("Stop a project", "containers", "Stops a project."),
    "synology_container_project_restart": _e(
        "Restart a project", "containers", "Restarts a project."
    ),
    "synology_container_project_build": _e("Build a project", "containers", "Builds a project."),
    "synology_container_project_clean": _e(
        "Clean a project", "containers", "Cleans up a project's containers and images."
    ),
    "synology_container_project_delete": _e("Delete a project", "containers", "Deletes a project."),
    "synology_container_image_list": _e(
        "List images", "containers", "Every container image on the NAS.", _NAS
    ),
    "synology_container_image_get": _e(
        "Image details",
        "containers",
        "One image, including how it was built.",
        {**_NAS, "name": "nginx"},
    ),
    "synology_container_image_delete": _e("Delete an image", "containers", "Deletes an image."),
    "synology_container_image_pull": _e(
        "Pull an image", "containers", "Downloads an image from a registry to the NAS."
    ),
    "synology_container_registry_list": _e(
        "List image registries",
        "containers",
        "The registries Container Manager can pull from.",
        _NAS,
    ),
    "synology_container_registry_search": _e(
        "Search image registries",
        "containers",
        "Searches the registries for an image.",
        {**_NAS, "query": "nginx"},
    ),
    "synology_container_registry_tags": _e(
        "List image tags",
        "containers",
        "The tags available for one registry image.",
        {**_NAS, "repository": "nginx"},
    ),
    "synology_container_registry_download": _e(
        "Download a registry image",
        "containers",
        "Downloads an image from a registry to the NAS.",
    ),
    "synology_container_network_list": _e(
        "List container networks", "containers", "Every container network.", _NAS
    ),
    "synology_container_network_get": _e(
        "Network details",
        "containers",
        "One container network.",
        {**_NAS, "name": "bridge"},
    ),
    "synology_container_network_create": _e(
        "Create a container network", "containers", "Creates a container network."
    ),
    "synology_container_network_delete": _e(
        "Delete a container network", "containers", "Deletes a container network."
    ),
    # --------------------------------------------------------------- sharing
    "synology_nfs_status": _e(
        "NFS status",
        "sharing",
        "Whether the NFS file service is on, and its settings.",
        _NAS,
    ),
    "synology_nfs_enable": _e(
        "Turn NFS on or off", "sharing", "Turns the NFS file service on or off."
    ),
    "synology_nfs_list_shares": _e(
        "NFS access by folder",
        "sharing",
        "Every shared folder with the NFS access it allows.",
        _NAS,
    ),
    "synology_nfs_set_permission": _e(
        "Set NFS access",
        "sharing",
        "Sets which client addresses may use a shared folder over NFS, and how.",
    ),
    "synology_create_share": _e(
        "Create a shared folder", "sharing", "Creates a new shared folder on a volume."
    ),
    # -------------------------------------------------------------- accounts
    "synology_list_users": _e("List users", "accounts", "Every local user."),
    "synology_get_user": _e("User details", "accounts", "Details of one local user."),
    "synology_create_user": _e(
        "Create a user",
        "accounts",
        "Creates a local user. It takes a password for the new account.",
    ),
    "synology_set_user": _e(
        "Change a user",
        "accounts",
        "Renames a user, changes a password, or enables or disables the account.",
    ),
    "synology_delete_user": _e("Delete a user", "accounts", "Deletes a local user."),
    "synology_list_groups": _e("List groups", "accounts", "Every local group."),
    "synology_list_group_members": _e("Group members", "accounts", "The members of one group."),
    "synology_add_user_to_group": _e(
        "Add a user to groups", "accounts", "Adds a user to one or more groups."
    ),
    "synology_remove_user_from_group": _e(
        "Remove a user from groups", "accounts", "Removes a user from one or more groups."
    ),
    "synology_get_user_permissions": _e(
        "User folder permissions", "accounts", "Which shared folders a user may read or write."
    ),
    "synology_set_user_permissions": _e(
        "Set user folder permissions",
        "accounts",
        "Sets, per shared folder, whether a user may read, write or is denied.",
    ),
}


def title_for(name: str) -> Optional[str]:
    found = CATALOG.get(name)
    return found.title if found else None


def described(name: str, description: Optional[str], *, manual_authentication: bool) -> str:
    """The description to serve for `name`: what the tool's definition says, plus
    the notes that matter to a model. Safe to apply twice."""
    text = description or ""
    found = CATALOG.get(name)
    notes: List[str] = []
    if name == "synology_status" and manual_authentication:
        notes.append(SIGN_IN_NOTE)
    if found is not None and found.sends_content:
        notes.append(CONTENT_NOTE)
    for note in notes:
        if note not in text:
            text += note
    return text


# ----------------------------------------------------------------- the catalog


def _effect(name: str, read_only: Iterable[str], destructive: Iterable[str]) -> str:
    if name in set(destructive):
        return "Deletes data"
    if name in set(read_only):
        return "Reads only"
    return "Changes things"


def _credential_fields(schema: Mapping[str, Any]) -> List[str]:
    from adapter.server import credential_fields

    return credential_fields(dict.fromkeys(schema.get("properties", {}), 1))


def render_markdown(
    *,
    definitions: Mapping[str, Mapping[str, Any]],
    read_only: Iterable[str],
    destructive: Iterable[str],
    account_enumeration: Iterable[str],
    session_tools: Iterable[str],
    broker_default: Iterable[str],
    never_granted: Iterable[str],
) -> str:
    """The catalog as Markdown. Pure: every input is passed in, so the same text
    comes out wherever it is run. `definitions` maps a tool ID to its input
    schema."""
    read_only = frozenset(read_only)
    destructive = frozenset(destructive)
    enumeration = frozenset(account_enumeration)
    session = frozenset(session_tools)
    broker = frozenset(broker_default)
    never = frozenset(never_granted)

    def restricted_ok(name: str) -> bool:
        return name not in enumeration and (name in session or name in read_only)

    lines: List[str] = [
        "# Tool catalog",
        "",
        "<!-- Generated by `python scripts/generate_tool_catalog.py`. Do not edit by hand: "
        "a test fails when this file is out of date. -->",
        "",
        "Every tool the server can offer, in plain language. The **Tool ID** is the stable name "
        "that applications and policies use; the **title** is only what a person sees. A title, a "
        "category or a read-only label is information for the application, not permission: what a "
        "tool may do is decided by the server, and for a broker client by its policy.",
        "",
        "## How to read it",
        "",
        "- **Effect:** *Reads only* tools change nothing on the NAS. *Changes things* tools write. "
        "*Deletes data* tools remove something this server cannot bring back.",
        "- **Sign-in needed:** with manual authentication, you sign in yourself on the private "
        "page. A tool that needs it answers `AUTHENTICATION_REQUIRED` until you have. The AI "
        "application never receives your NAS password or one-time code.",
        "- **On by default:** *Yes* means a default installation (restricted mode) offers the "
        "tool **and** a broker client has it in its default grant. *Restricted mode only* means a "
        "default installation offers it but a broker client has to be given it in its policy. "
        "*No* means it has to be turned on, as described below.",
        "- **Contents go to the AI provider:** anything a tool returns is seen by the AI "
        "application and its provider. Tools marked this way return free text or file content "
        "you may not have read, so ask for only what is needed.",
        "",
        "### Turning a tool on",
        "",
        "- **Restricted mode** is on by default and offers only browsing and monitoring tools, "
        "plus sign-in and sign-out. Setting `RESTRICTED_MODE=false` makes every registered tool "
        "available: the tools that change things, and also the account and permission tools. Those "
        "only read, but a list of every account is a different level of trust from a list of files, "
        "so they are off in restricted mode.",
        "- **A broker client** gets the tools in its policy entry (`tools`), or the default set "
        "marked below if it has none. A tool must be allowed by *both* the policy and the "
        "broker's restricted mode: to give a client a tool that changes things, the broker needs "
        "`RESTRICTED_MODE=false` as well as the tool in that client's entry. `synology_login` "
        "can never be granted.",
        "",
    ]

    # A catalog that has drifted from the registry is an error, not a quietly
    # shorter document.
    missing = sorted(set(definitions) - set(CATALOG))
    extra = sorted(set(CATALOG) - set(definitions))
    if missing or extra:
        raise ValueError(
            f"the tool catalog and the registry disagree: no entry for {missing}; "
            f"entries for tools that are not registered: {extra}"
        )

    by_category: Dict[str, List[str]] = {key: [] for key, _ in CATEGORIES}
    for name in definitions:
        by_category[CATALOG[name].category].append(name)

    for key, heading in CATEGORIES:
        names = by_category[key]
        if not names:
            continue
        lines += [f"## {heading}", ""]
        lines += [
            "| Title | Tool ID | What it does | Effect | Sign-in needed | On by default |",
            "|---|---|---|---|---|---|",
        ]
        for name in names:
            found = CATALOG[name]
            schema = definitions[name]
            required = [f"`{field}`" for field in schema.get("required", [])]
            notes: List[str] = []
            if required:
                notes.append("Needs " + ", ".join(required) + ".")
            if found.sends_content:
                notes.append("Contents go to the AI provider.")
            blocked = _credential_fields(schema)
            if blocked and name not in never:
                fields = ", ".join(f"`{field}`" for field in blocked)
                if any(field in schema.get("required", []) for field in blocked):
                    notes.append(
                        f"Cannot be used through the adapter: it needs {fields}, and the adapter "
                        "refuses a call that carries a field named like a credential."
                    )
                else:
                    notes.append(
                        f"Through the adapter, leave out {fields}: the adapter refuses a call "
                        "that carries a field named like a credential."
                    )
            if name == "synology_login":
                notes.append("Legacy mode only.")
            what = " ".join([found.summary, *notes])
            if name in never:
                default = "Legacy mode only"
            elif name in broker and restricted_ok(name):
                default = "Yes"
            elif restricted_ok(name):
                default = "Restricted mode only"
            else:
                default = "No"
            sign_in = "No" if name in NO_SIGN_IN_NEEDED else "Yes"
            effect = _effect(name, read_only, destructive)
            lines.append(
                f"| {found.title} | `{name}` | {what} | {effect} | {sign_in} | {default} |"
            )
        lines.append("")

        examples = [
            (name, CATALOG[name].example)
            for name in names
            if CATALOG[name].example is not None and (name in broker or restricted_ok(name))
        ]
        if examples:
            lines += ["Safe examples (the arguments of one call):", ""]
            for name, example in examples:
                lines.append(f"- `{name}`: `{_compact(example)}`")
            lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"


def _compact(value: Mapping[str, Any]) -> str:
    import json

    return json.dumps(value, separators=(", ", ": "), sort_keys=False)


def render_current() -> str:
    """The catalog for this checkout: the registry, the classification sets in
    `mcp_server.py` and the broker's default policy. Imports the server, so it
    is not called at import time."""
    import mcp_server
    from broker.policy import DEFAULT_TOOLS, NEVER_TOOLS, ClientPolicy

    # A client with no `tools` entry gets DEFAULT_TOOLS, plus disconnect, which
    # the policy adds by its own rule; ask it rather than repeat the rule.
    default_client = ClientPolicy(
        name="default", token_sha256="0" * 64, nas=frozenset(), tools=DEFAULT_TOOLS
    )
    server = mcp_server.SynologyMCPServer()
    definitions = {
        tool.name: tool.input_schema
        for tool in [*server._get_tool_definitions(), *server._all_session_tool_definitions()]
    }
    return render_markdown(
        definitions=definitions,
        read_only=mcp_server._READ_ONLY_TOOLS,
        destructive=mcp_server._DESTRUCTIVE_TOOLS,
        account_enumeration=mcp_server._ACCOUNT_ENUMERATION_TOOLS,
        session_tools=mcp_server._SESSION_TOOLS,
        broker_default=default_client.allowed_tools(),
        never_granted=NEVER_TOOLS,
    )
