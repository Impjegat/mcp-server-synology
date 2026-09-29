# src/config.py - Configuration management
# Loads all settings from XDG standard config directory (~/.config/synology-mcp/settings.json).
# Supports multiple NAS and server settings.

import json
import logging
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

# Setup logger
logger = logging.getLogger("synology-mcp")


class InsecureURLError(ValueError):
    """Raised at startup when a configured NAS URL does not use HTTPS."""


# Before CA-bundle-path support, VERIFY_SSL's parsing was
# `.lower() == "true"`, so any other value — including these common
# boolean aliases — silently meant "disabled". Recognizing them here keeps
# that working rather than turning a working (if insecure) upgrade into a
# hard failure the first time DSM is contacted, while any other string is
# now treated as a CA-bundle path instead of silently disabling
# verification.
_VERIFY_SSL_TRUTHY = {"true", "1", "yes", "on"}
_VERIFY_SSL_FALSY = {"false", "0", "no", "off"}


def _parse_verify_ssl(value: str) -> Any:
    """Parse VERIFY_SSL's env-var string form into what `requests`' own
    `verify=` parameter accepts: True, False, or a path to a CA bundle file
    (e.g. for a private CA or self-signed certificate, without disabling
    verification outright). `REQUESTS_CA_BUNDLE` already works as a global
    override today; this is the equivalent per-server setting."""
    lowered = value.strip().lower()
    if lowered in _VERIFY_SSL_TRUTHY:
        return True
    if lowered in _VERIFY_SSL_FALSY:
        return False
    return value.strip()


def _parse_restricted_mode(value: Any) -> bool:
    """Parse RESTRICTED_MODE's env-var or settings.json string form.

    Unlike VERIFY_SSL, there's no non-boolean meaning to fall back to here,
    so this fails closed rather than open: restricted mode is the only
    barrier against write actions from the (necessarily administrator)
    account this server runs as, so a value we don't recognize must never
    silently disable it the way a plain `.lower() == "true"` comparison
    would (e.g. `RESTRICTED_MODE=1` previously left restricted mode off).
    Only an explicit falsy value turns it off; everything else — including
    an unrecognized string — leaves it on and logs a warning.
    """
    if isinstance(value, bool):
        return value
    lowered = str(value).strip().lower()
    if lowered in _VERIFY_SSL_FALSY:
        return False
    if lowered not in _VERIFY_SSL_TRUTHY:
        logger.warning(
            f"RESTRICTED_MODE value {value!r} is not a recognized true/false value "
            "— leaving restricted mode ON. Use one of "
            f"{sorted(_VERIFY_SSL_TRUTHY | _VERIFY_SSL_FALSY)} to be explicit."
        )
    return True


# XDG Base Directory Specification: ~/.config/synology-mcp/
XDG_CONFIG_HOME: Path = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
CONFIG_DIR = XDG_CONFIG_HOME / "synology-mcp"
SETTINGS_FILE = CONFIG_DIR / "settings.json"

# Example settings.json structure for documentation
SETTINGS_JSON_EXAMPLE = """
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
"""


class SynologyConfig:
    """Configuration manager for Synology MCP Server."""

    def __init__(self, env_file: Optional[str] = None):
        """Initialize configuration from settings.json."""
        # Legacy .env support (deprecated - use settings.json instead)
        if env_file:
            load_dotenv(env_file)
        elif os.path.exists(".env"):
            load_dotenv(".env")

        self._load_env_settings()
        self._load_settings()

    def _load_env_settings(self):
        """Load non-sensitive settings from environment / .env."""
        self.server_name = os.getenv("MCP_SERVER_NAME", "synology-mcp-server")
        self.server_version = os.getenv("MCP_SERVER_VERSION", "1.0.0")
        self.default_session_timeout = int(os.getenv("SESSION_TIMEOUT", "3600"))
        self.auto_login = os.getenv("AUTO_LOGIN", "true").lower() == "true"
        self.verify_ssl = _parse_verify_ssl(os.getenv("VERIFY_SSL", "true"))
        # Restricted mode: the server exposes only browsing and monitoring
        # tools by default (plans/shipped/2026-09-27-remediation-roadmap/
        # PLAN.md's stated objective for the initial installation).
        # Modifying tools (file writes/deletes, user
        # and container management, ...) are hidden from discovery and
        # rejected before any NAS request is made. Set to false deliberately
        # to enable the full tool set.
        self.restricted_mode = _parse_restricted_mode(os.getenv("RESTRICTED_MODE", "true"))
        self.debug = os.getenv("DEBUG", "false").lower() == "true"
        self.log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        # get_file_content refuses to download a file larger than this (checked
        # via file metadata before any download request is made) — file
        # contents are sent to the MCP client's AI provider, and this tool is
        # exposed even in restricted mode.
        self.max_file_content_size = int(os.getenv("MAX_FILE_CONTENT_SIZE", str(1_000_000)))

        # Legacy single-NAS env vars (still supported as fallback)
        self.synology_url = os.getenv("SYNOLOGY_URL")
        if self.synology_url and not self.synology_url.lower().startswith("https://"):
            raise InsecureURLError(
                f"SYNOLOGY_URL must use HTTPS, got: {self.synology_url!r}. "
                "Set SYNOLOGY_URL to https://<your-nas>:5001 and ensure DSM has a "
                "valid TLS certificate (DSM Control Panel > Security > Certificate)."
            )
        self.synology_username = os.getenv("SYNOLOGY_USERNAME")
        self.synology_password = os.getenv("SYNOLOGY_PASSWORD")
        # One-shot 2FA code for legacy .env single-NAS users on first login.
        # Settings.json users store `device_id` per-NAS for ongoing reuse and
        # don't need this. Read-only here; auto-login consumes it but does
        # not clear it (auto-login only runs once per process start today).
        self.synology_otp_code = os.getenv("SYNOLOGY_OTP_CODE")

    def _check_file_permissions(self, path: Path) -> bool:
        """Check if secrets file has safe permissions (0600 or stricter).

        Returns True if permissions are safe, False otherwise.
        Prints warning if permissions are too open.

        POSIX only: os.getuid() and the group/other mode bits this check
        relies on don't exist on Windows (NTFS uses ACLs, not POSIX mode
        bits), so on platforms without os.getuid() the check is skipped
        with a warning instead of raising.
        """
        if not hasattr(os, "getuid"):
            logger.warning(
                f"Skipping file-permission check for {path}: not supported on "
                "this platform. Restrict access to this file yourself (it "
                "contains NAS credentials) via your OS's file permissions."
            )
            return True

        try:
            file_stat = path.stat()
            mode = file_stat.st_mode

            # Check if file is owned by current user
            if os.getuid() != file_stat.st_uid:
                logger.warning(f"{path} is owned by a different user (uid={file_stat.st_uid})")
                return False

            # Check for group/other read/write permissions
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                logger.warning(f"{path} has overly permissive permissions (mode={oct(mode)})")
                logger.warning(f"Recommended: chmod 600 {path}")
                return False

            return True
        except OSError as e:
            logger.warning(f"Could not check permissions for {path}: {e}")
            return False

    def _restrict_file_permissions(self, path: Path) -> bool:
        """Attempt to restrict `path` to the current user only, and report
        whether that attempt is known to have succeeded.

        POSIX: chmod 0600. Windows: shell out to `icacls` to strip
        inherited permissions and grant the current user Full Control,
        since Windows has no POSIX mode bits (NTFS uses ACLs) and Python's
        standard library has no built-in ACL API.

        Returns True if the restriction is known to have succeeded (or
        wasn't attempted because this platform is neither of the two
        handled above — matches this method's original silent-success
        behavior there), False if it's known to have failed. A caller about
        to write secret-bearing content to `path` should treat False as a
        reason not to write yet: reporting success regardless (the previous
        behavior here) can leave secrets sitting in a file other local
        users can read, especially on Windows, where a freshly-created file
        otherwise inherits its containing directory's ACLs rather than
        being unreadable-by-default the way a POSIX 0600 file is.
        """
        try:
            if hasattr(os, "getuid"):
                os.chmod(path, 0o600)
            elif sys.platform == "win32":
                user = os.environ.get("USERNAME") or os.getlogin()
                subprocess.run(
                    [
                        "icacls",
                        str(path),
                        "/inheritance:r",
                        "/grant:r",
                        f"{user}:F",
                    ],
                    capture_output=True,
                    check=True,
                    timeout=10,
                )
            return True
        except Exception as e:
            logger.warning(
                f"Could not restrict permissions on {path}: {e}. "
                "It contains NAS credentials — restrict access to it yourself."
            )
            return False

    def _atomic_write_settings(self, data: Dict[str, Any]) -> bool:
        """Atomically overwrite SETTINGS_FILE with `data`.

        Writes to a uniquely-named temp file in the same directory (so the
        final `os.replace` is on the same filesystem and therefore atomic;
        a unique name — rather than the previous fixed `settings.json.tmp`
        — avoids two concurrent writers colliding on the same temp file).

        Permissions are restricted on the temp file *before* any
        secret-bearing content is written to it, and writing only proceeds
        if that restriction is confirmed to have succeeded. On POSIX this
        makes no practical difference (`tempfile.mkstemp` already creates
        the file at mode 0600, ignoring umask, so `_restrict_file_permissions`
        just reconfirms it), but on Windows — where restriction means
        shelling out to `icacls`, and a freshly-created file otherwise
        inherits the containing directory's ACLs — restricting only after
        writing left every configured NAS's password briefly world/group
        readable, and left it that way indefinitely whenever the `icacls`
        call itself failed, since this method previously reported success
        regardless of that failure.

        Returns True on success, False on any failure (logged, and the temp
        file is always cleaned up on any exit path — never raised, since a
        failed settings write must never crash the server or fall back to
        printing what it was trying to save, and must never leave a
        half-written or insecurely-permissioned temp file behind).
        """
        tmp_path: Optional[Path] = None
        try:
            settings_dir = SETTINGS_FILE.parent
            settings_dir.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(
                dir=settings_dir, prefix="settings.", suffix=".json.tmp"
            )
            tmp_path = Path(tmp_name)
            os.close(fd)

            if not self._restrict_file_permissions(tmp_path):
                logger.warning(
                    f"Refusing to write {SETTINGS_FILE}: could not restrict "
                    f"permissions on the temp file at {tmp_path}. The "
                    "existing settings file, if any, was left unchanged."
                )
                return False

            tmp_path.write_text(json.dumps(data, indent=2))
            os.replace(tmp_path, SETTINGS_FILE)
            tmp_path = None  # moved into place — nothing left to clean up
            return True
        except Exception as e:
            logger.warning(f"Failed to save {SETTINGS_FILE}: {e}")
            return False
        finally:
            if tmp_path is not None:
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def save_device_id(self, nas_name: str, device_id: str) -> bool:
        """Persist a freshly-issued DSM trusted-device token for `nas_name`.

        Reads the settings file fresh from disk (not from the parsed
        `self.nas_configs`, which only carries the fields this class knows
        about) so any other keys — other NAS entries, the `server` section,
        anything a future version added — survive untouched. Updates the
        in-memory config on success so the running process sees the new
        token immediately, without needing a restart.

        Returns True on success, False otherwise. Callers must not fall
        back to logging or printing `device_id` when this returns False —
        that would defeat the point of storing it out of logs in the first
        place; instead, the next login simply falls back to OTP again.
        """
        if not SETTINGS_FILE.exists():
            logger.warning(
                f"Cannot save device token for '{nas_name}': {SETTINGS_FILE} does not exist "
                "(legacy .env configuration does not support persistent device tokens — "
                "migrate to settings.json)."
            )
            return False

        try:
            data = json.loads(SETTINGS_FILE.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Cannot save device token for '{nas_name}': {e}")
            return False

        synology_section = data.get("synology", {})
        if nas_name not in synology_section or not isinstance(synology_section[nas_name], dict):
            logger.warning(f"Cannot save device token: '{nas_name}' not found in {SETTINGS_FILE}")
            return False

        synology_section[nas_name]["device_id"] = device_id
        if not self._atomic_write_settings(data):
            return False

        if nas_name in self.nas_configs:
            self.nas_configs[nas_name]["device_id"] = device_id
        return True

    def _load_settings(self):
        """Load all settings from XDG config directory (~/.config/synology-mcp/settings.json)."""
        self.nas_configs: Dict[str, Dict[str, Any]] = {}

        if SETTINGS_FILE.exists():
            # Check file permissions - refuse to load if insecure
            if not self._check_file_permissions(SETTINGS_FILE):
                logger.error("Refusing to load settings with insecure permissions")
                return

            try:
                data = json.loads(SETTINGS_FILE.read_text())

                # Load Synology NAS credentials
                synology_section = data.get("synology", {})

                if not synology_section:
                    logger.warning(f"No 'synology' section found in {SETTINGS_FILE}")

                for nas_name, nas_info in synology_section.items():
                    if not isinstance(nas_info, dict):
                        logger.warning(
                            f"Invalid entry for NAS '{nas_name}' - expected object, got {type(nas_info)}"
                        )
                        continue

                    host = nas_info.get("host", "")
                    # 5001 is DSM's default HTTPS port; 5000 is HTTP-only and
                    # would fail outright given the HTTPS-only base_url below.
                    port = nas_info.get("port", 5001)
                    username = nas_info.get("username", "")
                    password = nas_info.get("password", "")
                    # Optional 2FA/OTP support (DSM Login Web API Guide):
                    #   - `otp_code`: one-shot code from authenticator. Needed
                    #     only on the FIRST login after enabling 2FA on the
                    #     DSM account. After that first login, DSM issues a
                    #     device token (`did`); paste it as `device_id` and
                    #     remove `otp_code`.
                    #   - `device_id`: long-lived trusted-device token. When
                    #     present, DSM skips OTP for this login and for the
                    #     silent re-auth path (DSM error 119 recovery).
                    otp_code = nas_info.get("otp_code") or None
                    device_id = nas_info.get("device_id") or None

                    if not host:
                        logger.warning(f"Missing 'host' for NAS '{nas_name}' in {SETTINGS_FILE}")
                        continue
                    if not username:
                        logger.warning(
                            f"Missing 'username' for NAS '{nas_name}' in {SETTINGS_FILE}"
                        )
                        continue
                    if not password:
                        logger.warning(
                            f"Missing 'password' for NAS '{nas_name}' in {SETTINGS_FILE}"
                        )
                        continue

                    # HTTPS-only: never fall back to plain http:// based on port
                    # number. If DSM isn't serving HTTPS on this port, the
                    # connection will simply fail rather than transmit in the
                    # clear.
                    base_url = f"https://{host}:{port}"

                    self.nas_configs[nas_name] = {
                        "base_url": base_url,
                        "username": username,
                        "password": password,
                        "verify_ssl": self.verify_ssl,
                        "note": nas_info.get("note", ""),
                        "otp_code": otp_code,
                        "device_id": device_id,
                    }

                # Load server settings (override env vars if present)
                server_section = data.get("server", {})
                if server_section:
                    if "auto_login" in server_section:
                        self.auto_login = server_section["auto_login"]
                    if "verify_ssl" in server_section:
                        value = server_section["verify_ssl"]
                        self.verify_ssl = (
                            _parse_verify_ssl(value) if isinstance(value, str) else value
                        )
                    if "session_timeout" in server_section:
                        self.default_session_timeout = server_section["session_timeout"]
                    if "debug" in server_section:
                        self.debug = server_section["debug"]
                    if "log_level" in server_section:
                        self.log_level = server_section["log_level"].upper()
                    if "restricted_mode" in server_section:
                        self.restricted_mode = _parse_restricted_mode(
                            server_section["restricted_mode"]
                        )
                    if "max_file_content_size" in server_section:
                        self.max_file_content_size = int(server_section["max_file_content_size"])

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse {SETTINGS_FILE}: {e}")
            except OSError as e:
                logger.error(f"Failed to read {SETTINGS_FILE}: {e}")
        else:
            # No settings file
            logger.info(f"No {SETTINGS_FILE} found")

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @staticmethod
    def get_config_dir() -> Path:
        """Return the XDG config directory path."""
        return CONFIG_DIR

    @staticmethod
    def get_settings_file() -> Path:
        """Return the settings file path."""
        return SETTINGS_FILE

    def get_nas_names(self) -> List[str]:
        """Return the list of configured NAS names."""
        return list(self.nas_configs.keys())

    def has_synology_credentials(self) -> bool:
        """Check if at least one NAS has credentials."""
        return bool(self.nas_configs) or bool(
            self.synology_url and self.synology_username and self.synology_password
        )

    def iter_configured_secrets(self):
        """Yield every configured (not necessarily yet-live) secret value
        that's safe to blanket-mask as a verbatim substring wherever it
        appears in logs or tool output.

        Covers passwords and trusted-device tokens from settings.json's
        per-NAS entries, plus the legacy `.env` single-NAS password —
        across both, whether or not a session has ever been established.
        Used to redact these even before login makes them "live" (see
        `auth.iter_live_secrets`, which covers session IDs/SynoTokens/
        device IDs that only exist post-login).

        Deliberately excludes `otp_code`: DSM's 2FA code is always exactly
        6 digits, and blanket-masking a short, purely-numeric value as a
        substring risks corrupting unrelated legitimate output that
        happens to contain the same digits (a file size, a port number, a
        timestamp fragment, ...) rather than protecting anything — it's
        one-shot and typically stale by the time anything would need
        redacting, and its actual leak vector (a login request's URL/body)
        is already covered unconditionally by redact()'s own `otp_code=`
        key=value pattern, independent of this list.

        Always yields `str`: settings.json is user-edited JSON, and nothing
        stops `password`/`device_id` from being written as a bare JSON
        number rather than a quoted string — valid JSON, but redact()'s
        `str.replace()` would raise on a non-string value, which would
        surface as an unhandled exception from inside an error handler
        wherever this feeds `redact()` (see `_dispatch_tool_call`'s except
        clause).
        """
        for nas_cfg in self.nas_configs.values():
            for key in ("password", "device_id"):
                value = nas_cfg.get(key)
                if value:
                    yield str(value)
        if self.synology_password:
            yield self.synology_password

    def get_synology_config(self, nas_name: Optional[str] = None) -> Dict[str, Any]:
        """Get connection config for a specific NAS (or the first/legacy one).

        Args:
            nas_name: Key from secrets.json (e.g. 'nas1'). If None, returns
                      the first configured NAS or falls back to .env values.
        """
        if nas_name and nas_name in self.nas_configs:
            return self.nas_configs[nas_name]

        # Return first available from secrets.json
        if self.nas_configs:
            first = next(iter(self.nas_configs.values()))
            return first

        # Legacy .env fallback
        return {
            "base_url": self.synology_url,
            "username": self.synology_username,
            "password": self.synology_password,
            "verify_ssl": self.verify_ssl,
            "otp_code": self.synology_otp_code,
            "device_id": None,
        }

    def resolve_base_url(self, nas_name: str) -> Optional[str]:
        """Get the base_url for a NAS name, or None if not found."""
        cfg = self.nas_configs.get(nas_name)
        return cfg["base_url"] if cfg else None

    def validate_config(self) -> list[str]:
        """Validate configuration and return list of errors."""
        errors = []
        if not self.has_synology_credentials():
            errors.append("No Synology credentials found in secrets.json or .env")
        if self.default_session_timeout < 60:
            errors.append("SESSION_TIMEOUT must be at least 60 seconds")
        return errors

    def __str__(self) -> str:
        nas_names = ", ".join(self.nas_configs.keys()) if self.nas_configs else "none"
        return (
            f"SynologyConfig(nas=[{nas_names}], auto_login={self.auto_login}, "
            f"restricted_mode={self.restricted_mode})"
        )


# Global config instance
config = SynologyConfig()
