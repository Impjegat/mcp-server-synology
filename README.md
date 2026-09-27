# 💾 Synology MCP Server

![Synology MCP Server](assets/banner.png)

A Model Context Protocol (MCP) server for Synology NAS devices. Enables AI assistants to manage files and downloads through secure authentication and session management.

## 🚀 Quick Start with Docker

### 1️⃣ Setup Environment
```bash
# Clone repository
git clone https://github.com/atom2ueki/mcp-server-synology.git
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

### 3️⃣ Run with Docker

```bash
docker-compose up -d

# Build and run
docker-compose up -d --build
```

### 4️⃣ Alternative: Local Python

```bash
# Install dependencies
pip install -r requirements.txt

# Run with environment control
python main.py
```

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
- **`search_files`** - Search files matching pattern (times out after 2 minutes rather than polling indefinitely)
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
- **`delete`** - Delete files or directories (auto-detects type)
  - `path` (required): File/directory path starting with `/`
- **`rename_file`** - Rename files or directories
  - `path` (required): Current file path
  - `new_name` (required): New filename
- **`move_file`** - Move files to new location
  - `source_path` (required): Source file path
  - `destination_path` (required): Destination path
  - `overwrite` (optional): Overwrite existing files

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
- **`synology_health_summary`** - Aggregate system info, utilization, disk health, and volume status

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
> For this MCP server, create a dedicated Synology user account with appropriate permissions. This account should:
> - Have minimal required permissions only (not admin!)
> - Be used exclusively for MCP server automation
> - **2FA is now supported** — if your DSM account has 2FA enabled, see the
>   [2FA / OTP Accounts](#2fa--otp-accounts-optional) section below to supply
>   an `otp_code` (one-shot) or `device_id` (persistent) field. Older guidance
>   of "no 2FA" is no longer required.

### Using settings.json (Recommended)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SYNOLOGY_URL` | Yes* | - | NAS base URL, **must be HTTPS** (e.g., `https://192.168.1.100:5001`) |
| `SYNOLOGY_USERNAME` | Yes* | - | Username for authentication |
| `SYNOLOGY_PASSWORD` | Yes* | - | Password for authentication |
| `AUTO_LOGIN` | No | `true` | Auto-login on server start |
| `VERIFY_SSL` | No | `true` | Verify SSL certificates; `false` disables verification (avoid), or set to a CA bundle file path to trust a private CA/self-signed cert |
| `MAX_FILE_CONTENT_SIZE` | No | `1000000` | `get_file_content` refuses files larger than this (bytes) |
| `DEBUG` | No | `false` | Enable debug logging |

*Required for auto-login and default operations

### Using settings.json (Multi-NAS Support)

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
    "log_level": "INFO"
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
   DSM will return a `did` (device token) in the response — copy that value into `settings.json` (below) to skip OTP on future process restarts.

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
   2. On the first successful login, the server logs a warning line like:
      `nas1: 2FA bootstrap — copy this device_id into settings.json to skip OTP on future starts: <did>`
      Copy the `<did>` value.
   3. Paste it into `device_id` and delete `otp_code`.
   4. From now on, DSM treats this process as a trusted device — restarts, relogins after DSM error 119, and container-manager sessions all skip OTP.

   When `device_id` is present, it takes precedence over `otp_code` (trusted-device path). Legacy `.env` users can set the one-shot `SYNOLOGY_OTP_CODE` env var; for persistent `device_id`, migrate to `settings.json` (long opaque token doesn't fit an env var cleanly).

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
- ✅ **Session Management** - Persistent sessions across multiple NAS devices  
- ✅ **Complete File Operations** - Create, delete, list, search, rename, move files with detailed metadata
- ✅ **Directory Management** - Recursive directory operations with safety checks
- ✅ **Download Station** - Complete torrent and download management
- ✅ **Docker Support** - Easy containerized deployment
- ✅ **Backward Compatible** - Existing configurations work unchanged
- ✅ **Error Handling** - Comprehensive error reporting and recovery

## 🏗️ Architecture

### File Structure
```
mcp-server-synology/
├── main.py                    # 🎯 Entry point
├── src/
│   ├── mcp_server.py         # MCP server (stdio)
│   ├── auth/                 # Authentication modules
│   ├── filestation/          # File operations
│   └── downloadstation/      # Download management
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env                      # Configuration
```
