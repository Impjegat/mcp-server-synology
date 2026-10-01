# 💾 Synology MCP Server

![Synology MCP Server](assets/banner.png)

A Model Context Protocol (MCP) server for Synology NAS devices. Enables AI assistants to manage files and downloads through secure authentication and session management.

> **About this fork:** this is a security-hardened fork of [atom2ueki/mcp-server-synology](https://github.com/atom2ueki/mcp-server-synology). Compared with upstream it connects over HTTPS only, starts in a read-only restricted mode by default, masks secrets in logs and responses, reports tool failures as MCP errors, and runs on the MCP Python SDK 2.x. See [Differences from upstream](#differences-from-upstream) and the [CHANGELOG](CHANGELOG.md).

## 🚀 Quick Start with Docker

**Requirements:** Docker with Compose v2.24 or later, **or** Python 3.10 or later for a local install (the MCP SDK 2.x this server uses does not support older Pythons).

### 1️⃣ Setup Environment
```bash
# Clone repository
git clone https://github.com/Impjegat/mcp-server-synology.git
cd mcp-server-synology

# Create environment file
cp env.example .env
```

### 2️⃣ Configure .env File

> **🔒 HTTPS-only:** This server requires an encrypted connection to your NAS.
> `SYNOLOGY_URL` (and any `settings.json` host) must resolve to `https://`.
> Enable HTTPS in DSM (**Control Panel → Login Portal → Advanced → enable
> HTTPS**, or **Control Panel → Security → Certificate**) and use port
> `5001`. Plain `http://` URLs are rejected at startup.

**Configuration:**
```bash
# Required: Synology NAS connection (HTTPS only)
SYNOLOGY_URL=https://192.168.1.100:5001
SYNOLOGY_USERNAME=your_username
SYNOLOGY_PASSWORD=your_password

# Optional: Auto-login on startup
AUTO_LOGIN=true
VERIFY_SSL=true
```

> **🔒 Restricted mode is on by default.** The server starts exposing only browsing and monitoring tools; every tool that changes anything on the NAS (creating, deleting or moving files, managing downloads, containers, shares or users, …) is hidden and refused. Set `RESTRICTED_MODE=false` once you deliberately want them. The **Available MCP Tools** section below lists which tools each mode offers, and **Security Recommendations** has the details.

**How Docker reads `.env`:** `docker-compose.yml` hands `.env` to the container when it starts (an optional `env_file`). It is never copied into the image, so editing it needs no rebuild. This needs Docker Compose v2.24 or later — check with `docker compose version`. Compose expands `$` in `.env` values, so if a password contains `$`, wrap the value in single quotes (`SYNOLOGY_PASSWORD='pa$word'`) or it will be silently altered. If you'd rather not keep credentials in `.env`, configure the server through `settings.json` instead (see below).

### 3️⃣ Build the Image

```bash
docker-compose build
```

There's nothing to start or leave running here: this is a per-session stdio process, not a background service. Your MCP client launches it itself via `docker-compose run --rm` — see the "Client Setup" section below for the exact config each client uses.

### 4️⃣ Alternative: Local Python

Needs Python 3.10 or later.

```bash
# Install dependencies
pip install -r requirements.txt

# Run with environment control
python main.py
```

## 🪟 Windows Installation

Docker Desktop (with the WSL2 backend) is the easiest path on Windows — the `docker-compose.yml` config works the same as on macOS/Linux, and Docker Desktop's own installer handles WSL2 for you. Local Python works too, without WSL:

```powershell
# Clone repository
git clone https://github.com/Impjegat/mcp-server-synology.git
cd mcp-server-synology

# Create environment file
copy env.example .env

# Create a virtual environment and install dependencies
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Run
python main.py
```

Edit `.env` with a text editor the same way as on macOS/Linux — the file format doesn't change.

**Where settings.json lives:** `~/.config/synology-mcp/settings.json` resolves to `%USERPROFILE%\.config\synology-mcp\settings.json` (e.g. `C:\Users\<you>\.config\synology-mcp\settings.json`) by default — Python's `Path.home()` maps to `%USERPROFILE%` on Windows, and the server uses a literal `.config` subdirectory there rather than a Windows-native location like `%APPDATA%`, so tooling and instructions stay identical across platforms. Set the `XDG_CONFIG_HOME` environment variable (System Properties → Environment Variables, or `setx XDG_CONFIG_HOME "C:\path\you\want"` in a new shell) to store it elsewhere.

**File permissions:** Windows has no POSIX file-mode bits, so the server can't `chmod 600` `settings.json` the way it does on macOS/Linux. It instead shells out to `icacls` to strip inherited permissions and grant only the current user full control, best-effort (a failure to do so is logged as a warning, not a startup error — restrict access to the file yourself if that warning appears).

**Docker Desktop note:** the `docker-compose.yml` volume mount (`${XDG_CONFIG_HOME:-$HOME/.config}/synology-mcp:...`) is expanded by Docker Compose itself, not your shell, so it resolves the same way whether you run `docker-compose` from PowerShell, cmd, or WSL2 — as long as `HOME` or `XDG_CONFIG_HOME` is set in the environment Compose sees (WSL2 sets `HOME` automatically; from native PowerShell/cmd, set `XDG_CONFIG_HOME` explicitly first).

## 🔌 Client Setup

### 🤖 Claude Desktop

Add to your Claude Desktop configuration file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "synology": {
      "command": "docker-compose",
      "args": [
        "-f", "/path/to/your/mcp-server-synology/docker-compose.yml",
        "run", "--rm", "synology-mcp"
      ],
      "cwd": "/path/to/your/mcp-server-synology"
    }
  }
}
```

### ↗️ Cursor

Add to your Cursor MCP settings:

```json
{
  "mcpServers": {
    "synology": {
      "command": "docker-compose",
      "args": [
        "-f", "/path/to/your/mcp-server-synology/docker-compose.yml",
        "run", "--rm", "synology-mcp"
      ],
      "cwd": "/path/to/your/mcp-server-synology"
    }
  }
}
```

### 🔄 Continue (VS Code Extension)

Add to your Continue configuration (`.continue/config.json`):

```json
{
  "mcpServers": {
    "synology": {
      "command": "docker-compose",
      "args": [
        "-f", "/path/to/your/mcp-server-synology/docker-compose.yml",
        "run", "--rm", "synology-mcp"
      ],
      "cwd": "/path/to/your/mcp-server-synology"
    }
  }
}
```

### 💻 Codeium

For Codeium's MCP support:

```json
{
  "mcpServers": {
    "synology": {
      "command": "docker-compose",
      "args": [
        "-f", "/path/to/your/mcp-server-synology/docker-compose.yml",
        "run", "--rm", "synology-mcp"
      ],
      "cwd": "/path/to/your/mcp-server-synology"
    }
  }
}
```

### 🐍 Alternative: Direct Python Execution

If you prefer not to use Docker:

```json
{
  "mcpServers": {
    "synology": {
      "command": "python",
      "args": ["main.py"],
      "cwd": "/path/to/your/mcp-server-synology",
      "env": {
        "SYNOLOGY_URL": "https://192.168.1.100:5001",
        "SYNOLOGY_USERNAME": "your_username",
        "SYNOLOGY_PASSWORD": "your_password",
        "AUTO_LOGIN": "true"
      }
    }
  }
}
```

## 🛠️ Available MCP Tools

**Restricted mode** (the default) offers only the tools in the middle column below; the rest are hidden from tool discovery and refused if called by name. Set `RESTRICTED_MODE=false` to enable them all.

| Domain | Available in restricted mode | Hidden until `RESTRICTED_MODE=false` |
|---|---|---|
| Authentication | all four (once a NAS is configured, `synology_login` only works for a NAS already in your configuration) | — |
| File System | `list_shares`, `list_directory`, `get_file_info`, `search_files`, `get_file_content` | `create_file`, `create_directory`, `delete`, `rename_file`, `move_file` |
| Download Station | `ds_get_info`, `ds_list_tasks`, `ds_get_statistics`, `ds_list_downloaded_files` | `ds_create_task`, `ds_pause_tasks`, `ds_resume_tasks`, `ds_delete_tasks` |
| Health Monitoring | all | — |
| Container Manager | listing and inspection: containers (`list`, `get`, `logs`, `resource`), projects (`list`, `get`), images (`list`, `get`), registries (`list`, `search`, `tags`), networks (`list`, `get`) | starting, stopping, restarting and deleting containers; creating, updating, running and deleting projects; deleting and pulling images; registry download; creating and deleting networks |
| NFS and shared folders | `synology_nfs_status`, `synology_nfs_list_shares` | `synology_nfs_enable`, `synology_nfs_set_permission`, `synology_create_share` |
| User & Group Management | none | all of them, including the read-only listings (enumerating accounts and permissions is treated as a separate trust level) |

### 🔐 Authentication
- **`synology_status`** - Check authentication status and active sessions
- **`synology_list_nas`** - List all configured NAS units from settings.json
- **`synology_login`** - Authenticate with Synology NAS *(conditional)*
- **`synology_logout`** - Logout from session *(conditional)*

### 📁 File System Operations
- **`list_shares`** - List all available NAS shares
- **`list_directory`** - List directory contents with metadata
  - `path` (required): Directory path starting with `/`
- **`get_file_info`** - Get detailed file/directory information
  - `path` (required): File path starting with `/`
- **`search_files`** - Search files matching pattern (waiting for the search is limited to 2 minutes, so the call takes at most 140 s in all — see [Time limits](#time-limits))
  - `path` (required): Search directory
  - `pattern` (required): Search pattern (e.g., `*.pdf`)
- **`get_file_content`** - Read a text file's contents (sent to the MCP client's AI provider)
  - `path` (required): File path starting with `/`
  - Refuses files larger than `MAX_FILE_CONTENT_SIZE` (default 1,000,000 bytes), checked via file metadata before downloading
- **`create_file`** - Create new files with content
  - `path` (required): Full file path starting with `/`
  - `content` (optional): File content (default: empty string)
  - `overwrite` (optional): Overwrite existing files (default: false)
- **`create_directory`** - Create new directories
  - `folder_path` (required): Parent directory path starting with `/`
  - `name` (required): New directory name
  - `force_parent` (optional): Create parent directories if needed (default: false)
- **`delete`** - Delete files or directories (auto-detects type; limited to 2 minutes, at most 125 s in all — see [Time limits](#time-limits))
  - `path` (required): File/directory path starting with `/`
- **`rename_file`** - Rename files or directories
  - `path` (required): Current file path
  - `new_name` (required): New filename
- **`move_file`** - Move files to new location (limited to 1 minute, at most 65 s in all — see [Time limits](#time-limits))
  - `source_path` (required): Source file path
  - `destination_path` (required): Destination path
  - `overwrite` (optional): Overwrite existing files

#### Time limits

`search_files`, `delete` and `move_file` start a task on the NAS and wait for it to finish. Each has a time limit that covers starting the task and waiting for it; every request made during that wait is cut off at whatever time is left, so a slow NAS cannot stretch the limit. If the limit is reached the call returns an error ("… timed out after N seconds") and the task is asked to stop.

| Tool | Limit | Also allowed | Longest a call can take |
|---|---|---|---|
| `search_files` | 120 s | up to 15 s to fetch the results of a search that finished, then up to 5 s to stop the task | 140 s |
| `delete` | 120 s (includes the initial lookup of the path) | up to 5 s to stop the task after a failure | 125 s |
| `move_file` | 60 s | up to 5 s to stop the task after a failure | 65 s |

A timed-out call does not prove the operation did not happen: DSM may still finish a `delete` or `move_file` whose status request ran out of time. If the request that *starts* a delete or move is itself given up on, the error says so ("The NAS may have started it anyway — check … before retrying"), because no task id ever came back to stop. `delete` looks the path up for at most 15 s, so that lookup can never use up the time the start request needs. Check the NAS before retrying.

### 📥 Download Station Management
- **`ds_get_info`** - Get Download Station information
- **`ds_list_tasks`** - List all download tasks with status
  - `offset` (optional): Pagination offset
  - `limit` (optional): Max tasks to return
- **`ds_create_task`** - Create new download task
  - `uri` (required): Download URL or magnet link
  - `destination` (optional): Download folder path
- **`ds_pause_tasks`** - Pause download tasks
  - `task_ids` (required): Array of task IDs
- **`ds_resume_tasks`** - Resume paused tasks
  - `task_ids` (required): Array of task IDs  
- **`ds_delete_tasks`** - Delete download tasks
  - `task_ids` (required): Array of task IDs
  - `force_complete` (optional): Force delete completed
- **`ds_get_statistics`** - Get download/upload statistics
- **`ds_list_downloaded_files`** - List files in the Download Station destination folder
  - `destination` (optional): Folder to list (defaults to Download Station's default)

### 🏥 Health Monitoring
- **`synology_system_info`** - Get system model, serial, DSM version, uptime, temperature
- **`synology_utilization`** - Get real-time CPU, memory, swap, and disk I/O utilization
- **`synology_disk_health`** - List all physical disks with SMART status, model, temp, size
- **`synology_disk_smart`** - Get detailed SMART attributes for a specific disk
- **`synology_volume_status`** - List all volumes with status, size, usage, filesystem type
- **`synology_storage_pool`** - List RAID/storage pools with level, status, member disks
- **`synology_network`** - Get network interface status and transfer rates
- **`synology_ups`** - Get UPS status, battery level, power readings
- **`synology_services`** - List installed packages and their running status
- **`synology_system_log`** - Get recent system log entries
- **`synology_health_summary`** - Aggregate system info, utilization, disk health, volume status, storage pools, network, and UPS. The result carries a `status`: `complete`, or `partial` with a message and `failed_checks` naming each check that could not be completed (the gathered `data` is still returned, but a partial result does not show the NAS is healthy). A UPS check that DSM reports as not available on this NAS is listed under `unavailable_checks` and does not make the result partial. If every check fails it is reported as an error.

### 🐳 Container Manager
- **`synology_container_list`** - List Container Manager containers
  - `offset` (optional): Pagination offset
  - `limit` (optional): Maximum containers to return
  - `container_type` (optional): Container filter (default: `all`)
- **`synology_container_get`** - Get a Container Manager container
  - `name` (required): Container name
- **`synology_container_start`** - Start a Container Manager container
  - `name` (required): Container name
- **`synology_container_stop`** - Stop a Container Manager container
  - `name` (required): Container name
- **`synology_container_restart`** - Restart a Container Manager container
  - `name` (required): Container name
- **`synology_container_delete`** - Delete a Container Manager container
  - `name` (required): Container name
  - `force` (optional): Force deletion (default: false)
  - `preserve_profile` (optional): Preserve Synology container profile (default: true)
- **`synology_container_logs`** - Get Container Manager container logs
  - `name` (required): Container name
  - `since` (optional): Log start time/filter
  - `offset` (optional): Pagination offset (default: 0)
  - `limit` (optional): Maximum log lines to return (default: 1000)
- **`synology_container_resource`** - Get real-time resource usage for a Container Manager container
  - `name` (required): Container name
- **`synology_container_project_list`** - List Container Manager projects
- **`synology_container_project_get`** - Get a Container Manager project
  - `name` (required): Project name
- **`synology_container_project_create`** - Create a Container Manager project
  - `name` (required): Project name
  - `share_path` (required): Project folder path on the NAS
  - `content` (required): Docker Compose YAML content
  - `enable_service_portal` (optional): Enable Synology service portal (default: false)
  - `service_portal_name` (optional): Service portal name
  - `service_portal_port` (optional): Service portal port
  - `service_portal_protocol` (optional): Service portal protocol (default: `http`)
- **`synology_container_project_update`** - Update a Container Manager project
  - `name` (required): Project name
  - `content` (required): Docker Compose YAML content
  - `enable_service_portal` (optional): Enable Synology service portal
  - `service_portal_name` (optional): Service portal name
  - `service_portal_port` (optional): Service portal port
  - `service_portal_protocol` (optional): Service portal protocol
- **`synology_container_project_start`** - Start a Container Manager project
  - `name` (required): Project name
- **`synology_container_project_stop`** - Stop a Container Manager project
  - `name` (required): Project name
- **`synology_container_project_restart`** - Restart a Container Manager project
  - `name` (required): Project name
- **`synology_container_project_build`** - Build a Container Manager project
  - `name` (required): Project name
- **`synology_container_project_clean`** - Clean a Container Manager project
  - `name` (required): Project name
- **`synology_container_project_delete`** - Delete a Container Manager project
  - `name` (required): Project name
- **`synology_container_image_list`** - List Container Manager images
  - `offset` (optional): Pagination offset
  - `limit` (optional): Maximum images to return
  - `show_dsm` (optional): Include DSM images (default: false)
- **`synology_container_image_get`** - Get a Container Manager image
  - `name` (required): Image repository name
  - `tag` (optional): Image tag (default: `latest`)
- **`synology_container_image_delete`** - Delete a Container Manager image
  - `name` (required): Image repository name
  - `tag` (optional): Image tag (default: `latest`)
- **`synology_container_image_pull`** - Pull a Container Manager image
  - `repository` (required): Image repository name
  - `tag` (optional): Image tag (default: `latest`)
- **`synology_container_registry_list`** - List Container Manager registries
- **`synology_container_registry_search`** - Search Container Manager registries
  - `query` (required): Image search query
  - `offset` (optional): Pagination offset
  - `limit` (optional): Maximum results to return
- **`synology_container_registry_tags`** - List tags for a registry image
  - `repository` (required): Image repository name
  - `offset` (optional): Pagination offset
  - `limit` (optional): Maximum tags to return
- **`synology_container_registry_download`** - Download a registry image
  - `repository` (required): Image repository name
  - `tag` (optional): Image tag (default: `latest`)
- **`synology_container_network_list`** - List Container Manager networks
- **`synology_container_network_get`** - Get a Container Manager network
  - `name` (required): Network name
- **`synology_container_network_create`** - Create a Container Manager network
  - `name` (required): Network name
  - `driver` (optional): Network driver (default: `bridge`)
  - `subnet` (optional): Subnet CIDR
  - `gateway` (optional): Gateway IP
  - `ip_range` (optional): Allocatable IP range CIDR
  - `enable_ipv6` (optional): Enable IPv6 (default: false)
- **`synology_container_network_delete`** - Delete a Container Manager network
  - `name` (required): Network name

### 📦 NFS Management
- **`synology_nfs_status`** - Get NFS service status and configuration
- **`synology_nfs_enable`** - Enable or disable the NFS service
- **`synology_nfs_list_shares`** - List all shared folders with their NFS permissions
- **`synology_nfs_set_permission`** - Set NFS client access permissions on a shared folder
- **`synology_create_share`** - Create a new shared folder on a volume
  - `share_name` (required): Name of the shared folder
  - `vol_path` (required): Volume path, e.g. `/volume1`
  - `description` (optional): Description of the folder
  - `enable_recycle_bin` (optional): Enable the recycle bin (default: true)
  - `recycle_bin_admin_only` (optional): Restrict recycle bin access to administrators (default: true)

### 👥 User & Group Management

These need an administrator account and are all hidden in restricted mode.

- **`synology_list_users`** - List all local users
- **`synology_get_user`** - Get details of one user
  - `name` (required): Username
- **`synology_create_user`** - Create a local user
  - `name` (required): Username
  - `password` (required): Password
  - `description`, `email` (optional)
  - `cannot_chg_passwd` (optional): Prevent the user changing their password (default: false)
  - `passwd_never_expire` (optional): Password never expires (default: true)
- **`synology_set_user`** - Modify a user (rename, change password, enable/disable)
  - `name` (required): User to modify
  - `new_name`, `password`, `description`, `email` (optional)
  - `expired` (optional): `normal` to enable, `now` to disable
- **`synology_delete_user`** - Delete a local user
  - `name` (required): Username
- **`synology_list_groups`** - List all local groups
- **`synology_list_group_members`** - List the members of a group
  - `group` (required): Group name
- **`synology_add_user_to_group`** / **`synology_remove_user_from_group`** - Change a user's group membership
  - `username` (required): Username
  - `groups` (required): Array of group names
- **`synology_get_user_permissions`** - Get a user's shared-folder permissions
  - `name` (required): Username
- **`synology_set_user_permissions`** - Set a user's shared-folder permissions (read/write/deny per folder)
  - `name` (required): Username
  - `permissions` (required): Array of `{name, is_writable, is_deny}` objects

## 🧠 Claude Code / Claude.ai Skill

For Claude Code, Claude Desktop, and claude.ai users, this repo ships an Anthropic Agent Skill that teaches Claude how to use the MCP tools effectively — picking the right tool, targeting the right NAS in multi-NAS setups, preferring aggregate health checks over fan-out calls, and using correct path conventions.

The skill lives at [`skills/synology-nas/`](skills/synology-nas/) and uses progressive disclosure across seven domains (auth, files, downloads, health, containers, shares/NFS, user management).

**Install:**

- **Claude Code**: copy or symlink the folder into `~/.claude/skills/synology-nas/`
- **Claude.ai / Claude Desktop**: upload the `synology-nas/` folder via the Skills settings page

The skill is purely additive — it works alongside the MCP and only triggers on Synology/NAS-related prompts.

## ⚙️ Configuration Options

> **⚠️ Security Warning: Use a Dedicated Account**
>
> For this MCP server, create a dedicated Synology user account (not your personal one). This account should:
> - Have only the permissions you need. Note that DSM's monitoring APIs generally require an administrator, so if you want monitoring to work, see **Restricted Mode** under Security Recommendations below for how to scope a dedicated admin account
> - Be used exclusively for MCP server automation
> - **2FA is now supported** — if your DSM account has 2FA enabled, see the
>   **2FA / OTP Accounts** section below to supply
>   an `otp_code` (one-shot) or `device_id` (persistent) field. Older guidance
>   of "no 2FA" is no longer required.

### Environment variables (`.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SYNOLOGY_URL` | Yes* | - | NAS base URL, **must be HTTPS** (e.g., `https://192.168.1.100:5001`) |
| `SYNOLOGY_USERNAME` | Yes* | - | Username for authentication |
| `SYNOLOGY_PASSWORD` | Yes* | - | Password for authentication |
| `SYNOLOGY_OTP_CODE` | No | - | One-shot 2FA code for the first login (see **2FA / OTP Accounts** below) |
| `AUTO_LOGIN` | No | `true` | Auto-login on server start |
| `VERIFY_SSL` | No | `true` | Verify SSL certificates; `false` disables verification (avoid), or set to a CA bundle file path to trust a private CA/self-signed cert |
| `RESTRICTED_MODE` | No | `true` | Expose only browsing and monitoring tools; `false` enables every tool. Any value other than an explicit false (`false`/`0`/`no`/`off`) keeps it on |
| `MAX_FILE_CONTENT_SIZE` | No | `1000000` | `get_file_content` refuses files larger than this (bytes) |
| `SESSION_TIMEOUT` | No | `3600` | Session timeout in seconds (minimum 60) |
| `LOG_LEVEL` | No | `INFO` | Log level (`DEBUG`, `INFO`, `WARNING`, ...) |
| `DEBUG` | No | `false` | Enable debug logging |

*Required for auto-login and default operations

Every option except the credentials can also be set under `"server"` in `settings.json` (see below, e.g. `"restricted_mode": false`). Both can be used together; `settings.json` takes priority.

### Using settings.json (Recommended, Multi-NAS Support)

For managing multiple Synology NAS devices, use the XDG standard config directory (`~/.config/synology-mcp/settings.json`):

```bash
mkdir -p ~/.config/synology-mcp
touch ~/.config/synology-mcp/settings.json
chmod 600 ~/.config/synology-mcp/settings.json  # Important: secure permissions!
```

**Note:** This follows the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html) - `~/.config/` is the standard location for user configuration files on Linux/macOS. You can customize the location by setting the `XDG_CONFIG_HOME` environment variable.

**With Docker:**
The docker-compose.yml automatically mounts your `~/.config/synology-mcp` directory into the container at `/home/mcpuser/.config/synology-mcp`, so multi-NAS works out of the box with Docker as well.

**settings.json format:**
```json
{
  "synology": {
    "nas1": {
      "host": "192.168.1.100",
      "port": 5001,
      "username": "admin",
      "password": "your_password",
      "note": "Primary NAS at home"
    },
    "nas2": {
      "host": "192.168.1.200",
      "port": 5001,
      "username": "admin",
      "password": "your_password",
      "note": "Backup NAS"
    }
  },
  "server": {
    "auto_login": true,
    "verify_ssl": true,
    "session_timeout": 3600,
    "debug": false,
    "log_level": "INFO",
    "restricted_mode": true,
    "max_file_content_size": 1000000
  }
}
```

**Configuration fields:**
| Field | Required | Description |
|-------|----------|-------------|
| `host` | Yes | NAS hostname or IP address |
| `port` | No | HTTPS API port on your NAS (default: `5001`) |
| `username` | Yes | NAS username |
| `password` | Yes | NAS password |
| `otp_code` | No | One-shot 6-digit 2FA code (first login only, then remove) |
| `device_id` | No | Long-lived trusted-device token from DSM (`did`); skip OTP on all future logins |
| `note` | No | Optional description for your reference |

**Notes:**
- HTTPS-only: the server always connects as `https://<host>:<port>` — plain HTTP is not supported. Make sure `port` is your DSM's HTTPS port (`5001` by default) and that HTTPS is enabled in DSM.
- File permissions: `chmod 600 ~/.config/synology-mcp/settings.json` is required for security
- The server will refuse to load settings if permissions are too open
- Both .env and settings.json can be used together (settings.json takes priority)

### ⚠️ Security Recommendations

**Restricted Mode (RESTRICTED_MODE):**
- Default is `true` — the server exposes only browsing and monitoring tools (file listing/reading, download/container/health status, and similar read-only operations). Every modifying tool (file writes/deletes, user and container management, share creation, ...) is hidden from tool discovery *and* rejected before any request reaches the NAS, even if a client somehow calls it by name.
- Set `RESTRICTED_MODE=false` in `.env`, or `"restricted_mode": false` under the `"server"` key in `settings.json`, only once you deliberately want the full tool set available.
- While restricted, `synology_login`'s `base_url` is also pinned to a NAS already configured in `settings.json` or `SYNOLOGY_URL` — a client can't point your credentials at an arbitrary host. This check is skipped only when no NAS is configured yet (nothing to pin against on a fresh install).
- Local user/group listing and permission-lookup tools are hidden too, even though they don't write anything — enumerating every account, its group memberships, and its per-share permissions is a different trust tier than file browsing or NAS health monitoring.
- Because DSM's monitoring APIs (`SYNO.Core.*`, `SYNO.Storage.CGI.*`) generally require an administrator account, a non-admin account will see most monitoring tools fail even though they're read-only. If you want monitoring to work, use a **dedicated admin account created for this server** (not your personal one): enable 2FA with the device-token flow described below, and deny it any DSM application privilege the server doesn't need (Download Station, Container Manager, file-sharing protocols, etc.) wherever DSM's privilege controls allow it. With an admin account, restricted mode and your MCP client's own tool allowlist are the only barriers to writes — DSM per-share permissions can't make an administrator read-only.

**Secret redaction:**
- Session IDs, SynoTokens, device tokens and configured passwords are masked (`***REDACTED***`) in log output, tool results and error messages, including exception tracebacks, so a failing request can't leak them.
- Any `password` or `device_id` you pass to a tool is masked for the duration of that call, even before a login has happened.
- Values shorter than 4 characters are not masked (masking by substring would blank those characters out of everything the call prints), and a one-shot `otp_code` is not masked by value. Text such as a NAS's own error message could therefore still quote a very short credential.
- Argument-validation errors never quote what you submitted — see **Tool results and errors** below.

**SSL Certificate Verification (VERIFY_SSL):**
- Default is `true` — certificates are verified against the system trust store
- Setting `VERIFY_SSL=false` disables certificate verification and makes your connection vulnerable to man-in-the-middle (MITM) attacks; only do this if your NAS uses a self-signed certificate you can't add to your trust store
- **Prefer a CA bundle path instead of disabling verification**: if your NAS uses a self-signed certificate or a private/internal CA, set `VERIFY_SSL` to that CA's bundle file path (e.g. `VERIFY_SSL=/etc/ssl/certs/my-ca.pem`, or `"verify_ssl": "/etc/ssl/certs/my-ca.pem"` under `"server"` in `settings.json`) instead of `false` — this keeps verification on while trusting your specific CA. `REQUESTS_CA_BUNDLE` also works as a global override for the whole process.
- On Windows, `requests` uses its own bundled CA store rather than the OS trust store, so a private CA must be supplied explicitly via one of the options above — adding it to Windows' certificate store alone is not enough.
- Never disable SSL verification on untrusted networks
- Note this is separate from the HTTPS-only transport requirement above — HTTPS is always required; `VERIFY_SSL` only controls whether the server's certificate is validated

**Auto-Login (AUTO_LOGIN):**
- Default is `true` for convenience with settings.json
- Credentials are stored securely in `~/.config/synology-mcp/settings.json` with 0600 permissions
- If you prefer manual login, set `AUTO_LOGIN=false` and use the `synology_login` tool

**2FA / OTP Accounts (optional):**

The MCP server supports DSM accounts with 2FA enabled. There are two ways to use it:

1. **One-shot OTP via `synology_login` tool** (interactive):
   ```json
   { "base_url": "https://nas.lan:5001", "username": "alice", "password": "…", "otp_code": "123456" }
   ```
   DSM issues a device token on success, but this tool never returns, logs, or persists it (credential-handling policy) — there's no way to retrieve it from this call. Every future interactive login needs a fresh OTP code. For a token that's actually persisted to skip OTP, use the auto-login workflow below instead.

2. **Persistent trusted-device token** (recommended for `AUTO_LOGIN=true`):

   Add `otp_code` (one-shot, **first login only**) and/or `device_id` (long-lived, ongoing) fields per-NAS in `settings.json`:

   ```json
   {
     "synology": {
       "nas1": {
         "host": "192.168.1.100", "port": 5001,
         "username": "alice", "password": "…",
         "otp_code": "123456",
         "note": "primary — 2FA enabled"
       }
     }
   }
   ```

   **Workflow:**
   1. Set `otp_code` to a fresh 6-digit code from your authenticator and start the server.
   2. On the first successful auto-login, the server saves the device token straight into `settings.json` for you (no manual copy step — the token itself is never logged or printed, per the credential-handling policy) and logs a confirmation once it's done.
   3. `otp_code` is now redundant; you may delete it from `settings.json`.
   4. From now on, DSM treats this process as a trusted device — restarts, relogins after DSM error 119, and container-manager sessions all skip OTP.

   When `device_id` is present, it takes precedence over `otp_code` (trusted-device path). Legacy `.env` users can set the one-shot `SYNOLOGY_OTP_CODE` env var; for persistent `device_id`, migrate to `settings.json` (long opaque token doesn't fit an env var cleanly).

   **On Windows**, saving the device token also requires restricting `settings.json`'s permissions via `icacls` (see the Windows Installation section's "File permissions" note above) — if that fails, the token isn't saved at all (a warning is logged; nothing is left half-written) and you'll be prompted for `otp_code` again on the next start.

## Tool results and errors

- **Success:** an ordinary result (`isError: false`).
- **Failure:** a result with `isError: true` and a text message. This covers a failed login or logout, a DSM call that reports `success: false`, a missing session or path, a restricted-mode refusal, and any exception inside a tool. Clients and scripts should check `isError`, not the message text.
- **Invalid arguments** (a missing field, a wrong type) are refused before any request reaches the NAS, with a message such as `Invalid arguments for synology_login: password must be of type 'string'`. The message names the field but never quotes the value you submitted.
- **Protocol errors:** an unknown tool name, or a malformed `tools/call` request, returns a standard JSON-RPC `-32602` error instead of a tool result.
- **Health summary:** `synology_health_summary` reports `status: "partial"` when some checks failed and an error when all of them did; see its entry above.
- **Timeouts:** see [Time limits](#time-limits).

## 📖 Usage Examples

### 📁 File Operations

#### ✅ Creating Files and Directories
![File Creation](assets/add.png)

```json
// List directory
{
  "path": "/volume1/homes"
}

// Search for PDFs
{
  "path": "/volume1/documents", 
  "pattern": "*.pdf"
}

// Create new file
{
  "path": "/volume1/documents/notes.txt",
  "content": "My important notes\nLine 2 of notes",
  "overwrite": false
}
```

#### 🗑️ Deleting Files and Directories
![File Deletion](assets/delete.png)

```json
// Delete file or directory (auto-detects type)
{
  "path": "/volume1/temp/old-file.txt"
}

// Move file
{
  "source_path": "/volume1/temp/file.txt",
  "destination_path": "/volume1/archive/file.txt"
}
```

### ⬇️ Download Management

#### 🛠️ Creating a Download Task
![Download Sample](assets/download_sample.png)

```json
// Create download task
{
  "uri": "https://example.com/file.zip",
  "destination": "/volume1/downloads"
}

// Pause tasks
{
  "task_ids": ["dbid_123", "dbid_456"]
}
```

#### 🦦 Download Results
![Download Result](assets/download_result.png)

## ✨ Features

- ✅ **Secure Authentication** - HTTPS-only NAS connections with certificate verification enabled by default
- ✅ **Restricted Mode** - Read-only browsing and monitoring tools by default; modifying tools stay hidden until you opt in
- ✅ **Secret Redaction** - Passwords, session IDs and tokens are masked in logs, results and errors
- ✅ **Session Management** - Persistent sessions across multiple NAS devices, with 2FA support
- ✅ **File Operations** - Create, delete, list, search, rename, move and read files, with bounded read size and time limits
- ✅ **Download Station** - Complete torrent and download management
- ✅ **Health Monitoring** - System, disk, volume, storage pool, network and UPS status
- ✅ **Container Manager** - Containers, Compose projects, images, registries and networks
- ✅ **NFS and Shared Folders** - NFS permissions and shared-folder creation
- ✅ **User & Group Management** - Local users, groups and shared-folder permissions
- ✅ **Docker Support** - Containerized deployment with credentials supplied at runtime, never baked into the image
- ✅ **Clear Error Reporting** - Failures are returned as MCP errors (`isError`), never as successful-looking text

## Differences from upstream

This fork changes some defaults and behaviours of [atom2ueki/mcp-server-synology](https://github.com/atom2ueki/mcp-server-synology). If you are moving over from upstream, or from an older checkout of this fork, check these first (the [CHANGELOG](CHANGELOG.md) has the full list):

- **HTTPS only.** `http://` URLs are rejected at startup; upstream built `http://` URLs for `settings.json` hosts on any port other than `5001`. The default `port` is now `5001`.
- **`VERIFY_SSL` defaults to `true`**, and also accepts a CA bundle path for a private CA.
- **`RESTRICTED_MODE` defaults to `true`.** Modifying tools, and the user/group tools, are hidden until you set it to `false`.
- **Tool failures are `isError` results**, and unknown tools or malformed requests are JSON-RPC errors, instead of successful-looking text.
- **MCP Python SDK 2.x and Python 3.10+.** Docker users need to rebuild the image (`docker-compose build`).
- **Credentials are handled differently:** `.env` is passed to the container at start instead of being copied into the image, `settings.json` must have restricted permissions, and secrets are redacted from logs and responses.
- **Removed:** the Xiaozhi WebSocket bridge and the HTTP/SSE remote-deployment path (`docker-compose.http.yml`).
- **Bounded operations:** `search_files`, `delete` and `move_file` have enforced [time limits](#time-limits), and `get_file_content` refuses files over `MAX_FILE_CONTENT_SIZE`.

## 🏗️ Architecture

### File Structure
```
mcp-server-synology/
├── main.py                    # 🎯 Entry point (stdio server, log redaction)
├── src/
│   ├── mcp_server.py         # MCP server: tool registry, restricted mode, argument validation
│   ├── config.py             # .env and settings.json loading
│   ├── auth/                 # Login, sessions, 2FA
│   ├── filestation/          # File operations
│   ├── downloadstation/      # Download management
│   ├── health/               # Health monitoring
│   ├── container/            # Container Manager
│   ├── nfs/                  # NFS and shared folders
│   ├── usermanagement/       # Users, groups, permissions
│   └── utils/                # DSM API client, secret redaction
├── tests/                    # Unit and end-to-end tests (see tests/README.md)
├── skills/synology-nas/      # Claude Agent Skill
├── plans/                    # Design notes for shipped changes
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── env.example               # Configuration template (copy to .env)
```
