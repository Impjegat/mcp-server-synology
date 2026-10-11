# Download Station module for DSM 7.0+ using modern APIs

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from broker.errors import AuthenticationRequired, RedirectRefused, SessionRenewedNotRepeated
from broker.file_policy import FolderGuard
from utils.redact import redact
from utils.synology_api import (
    raise_if_authentication_required,
    raise_unless_read_only,
    recover_session,
    refuse_redirect,
)

logger = logging.getLogger(__name__)

# Errors that must reach the caller as they are. The fallbacks below turn an
# ordinary failure into a default answer; these say something a default would
# hide: the session is gone, the NAS tried to send the request on, or a lost
# session was renewed but the change that found it lost was not repeated.
_PASS_THROUGH = (AuthenticationRequired, RedirectRefused, SessionRenewedNotRepeated)

# DSM's answers that say the API, the method or the version asked for is not
# there (102, 103, 104). The NAS did nothing in answer to a request it could not
# understand, so asking again in an older form cannot do anything twice. Any other
# answer is not a reason to ask again.
_UNSUPPORTED_CODES = frozenset({"102", "103", "104"})

_UNCERTAIN = (
    "It is unclear whether the download was created; check the task list before trying again."
)


class DownloadStationAPIError(Exception):
    """DSM answered a request, and said no. `code` is its error code, as text.
    The message is what it has always been."""

    def __init__(self, code: Any, message: str):
        super().__init__(message)
        self.code = str(code)


class DownloadStationNetworkError(Exception):
    """A request may or may not have reached the NAS: a timeout, a lost connection,
    an HTTP error from something in between, or an answer that was cut off or is not
    DSM's. Nobody knows whether the NAS acted, so nothing that creates may be sent
    again on the strength of one."""


class SynologyDownloadStation:
    """Handles Synology Download Station API operations using DSM 7.0+ modern APIs."""

    def __init__(
        self,
        base_url: str,
        session_id: str,
        verify_ssl: bool = True,
        syno_token: Optional[str] = None,
        folder_guard: Optional[FolderGuard] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.session_id = session_id
        self.verify_ssl = verify_ssl
        self.syno_token = syno_token
        # Broker mode: downloads may only be placed in, and listed from, the
        # folders the client's policy allows.
        self.folder_guard = folder_guard

        # DSM 7.0+ modern API endpoints (the only ones that work)
        self.api_url = f"{self.base_url}/webapi/entry.cgi"
        self.task_api = "SYNO.DownloadStation2.Task"
        self.task_version = "2"
        self.info_api = "SYNO.DownloadStation.Info"
        self.info_version = "2"
        self.stat_api = "SYNO.DownloadStation.Statistic"
        self.stat_version = "1"

        # Default destination preference
        self.preferred_default_destination = "downloads"

    def _check_destination(self, destination: str) -> None:
        """Broker mode: refuse a destination folder outside the allowed roots."""
        if self.folder_guard is not None:
            self.folder_guard.check("/" + destination.lstrip("/"))

    def _validate_uri(self, uri: str) -> bool:
        """Validate URI for SSRF protection.

        Args:
            uri: URI to validate

        Returns:
            True if URI is valid, False otherwise
        """
        from urllib.parse import urlparse

        try:
            result = urlparse(uri)
            # Must be http or https
            if result.scheme not in ("http", "https"):
                return False
            # Block internal/private networks
            host = result.hostname
            if not host:
                return False
            if host in ("localhost", "127.0.0.1"):
                return False
            # Block private IP ranges
            if host.startswith(("10.", "192.168.", "172.", "169.254.")):
                return False
            # Block link-local and multicast
            if host == "0.0.0.0" or host.startswith("224."):
                return False
            return True
        except Exception:
            return False

    def _make_request(
        self, api: str, version: str, method: str, *, _retry: bool = True, **params
    ) -> Dict[str, Any]:
        """Make a request to Synology Download Station API.

        A lost session (DSM 106/107/119) is handled by `utils.synology_api`:
        manual mode raises `AuthenticationRequired`; legacy mode renews the
        session from its cached login once and repeats a read (`_retry` stops it
        looping). A change (a create, a delete, a pause, a resume) is never
        repeated: it raises `SessionRenewedNotRepeated` with the session already
        renewed.

        A failure is a `DownloadStationAPIError` when DSM answered (with its code),
        and a `DownloadStationNetworkError` when it is not known whether the
        request arrived.
        """
        request_params = {
            "api": api,
            "version": version,
            "method": method,
            "_sid": self.session_id,
            **params,
        }

        # Use entry.cgi for modern APIs, specific paths for legacy info/stats
        if api.startswith("SYNO.DownloadStation2"):
            endpoint_url = self.api_url
        elif api == "SYNO.DownloadStation.Info":
            endpoint_url = f"{self.base_url}/webapi/DownloadStation/info.cgi"
        elif api == "SYNO.DownloadStation.Statistic":
            endpoint_url = f"{self.base_url}/webapi/DownloadStation/statistic.cgi"
        else:
            endpoint_url = self.api_url

        # DSM 7.3.2+ enforces CSRF on mutating endpoints via X-SYNO-TOKEN.
        # Harmless on reads and on older DSM (header is ignored there).
        headers = {"X-SYNO-TOKEN": self.syno_token} if self.syno_token else None

        try:
            # Use POST for create operations, GET for others
            if method == "create":
                response = requests.post(
                    endpoint_url,
                    data=request_params,
                    headers=headers,
                    verify=self.verify_ssl,
                    timeout=15,
                    allow_redirects=False,
                )
            else:
                response = requests.get(
                    endpoint_url,
                    params=request_params,
                    headers=headers,
                    verify=self.verify_ssl,
                    timeout=15,
                    allow_redirects=False,
                )

            refuse_redirect(response)
            response.raise_for_status()
            data = response.json()

            if not data.get("success"):
                error_code = data.get("error", {}).get("code", "unknown")
                raise_if_authentication_required(error_code)
                if _retry:
                    recovered = recover_session(self.base_url, self.session_id, error_code)
                    if recovered:
                        self.session_id, self.syno_token = recovered
                        # A read is asked again; a change stops here, with the
                        # session already renewed for the caller's next try.
                        raise_unless_read_only(method)
                        return self._make_request(api, version, method, _retry=False, **params)
                error_msg = self._get_error_message(error_code)
                raise DownloadStationAPIError(
                    error_code, f"Download Station API error {error_code}: {error_msg}"
                )

            return data.get("data", {})

        except requests.exceptions.RequestException as e:
            # `str(e)` commonly embeds the full request URL, which carries
            # `_sid=<session_id>` on every GET call — redact before it
            # propagates to a caller. Backstop; the tool-response boundary
            # in mcp_server.py also redacts.
            raise DownloadStationNetworkError(self._redact(f"Network error: {e}"))

    def _redact(self, message: str) -> str:
        """Redact this instance's live secrets from an error message."""
        return redact(message, live_secrets=[self.session_id, self.syno_token])

    def _get_error_message(self, error_code: str) -> str:
        """Get human-readable error message for error codes."""
        error_messages = {
            "100": "Unknown error",
            "101": "Invalid parameter",
            "102": "The requested API does not exist",
            "103": "The requested method does not exist",
            "104": "The requested version does not support the functionality",
            "105": "The logged in session does not have permission",
            "106": "Session timeout",
            "107": "Session interrupted by duplicate login",
            "120": "Invalid task id or task not found",
            "400": "File upload failed",
            "401": "Max number of tasks reached",
            "402": "Destination denied",
            "403": "Destination does not exist",
            "404": "Invalid task id",
            "405": "Invalid task action",
            "406": "No default destination",
            "407": "Set destination failed",
            "408": "File does not exist",
            "409": "Task already exists",
            "410": "Task already finished",
        }
        return error_messages.get(str(error_code), f"Unknown error: {error_code}")

    def get_info(self) -> Dict[str, Any]:
        """Get Download Station information."""
        try:
            data = self._make_request(self.info_api, self.info_version, "getinfo")
            return {
                "version": data.get("version"),
                "version_string": data.get("version_string"),
                "is_manager": data.get("is_manager", False),
                "hostname": data.get("hostname", "Synology NAS"),
            }
        except _PASS_THROUGH:
            raise
        except Exception as e:
            # Fallback response if API fails
            return {
                "version": "Unknown",
                "version_string": "Download Station Available",
                "is_manager": True,
                "hostname": "Synology NAS",
                "note": self._redact(f"Limited info: {str(e)}"),
            }

    def list_tasks(
        self, offset: int = 0, limit: int = -1, additional: Optional[str] = None
    ) -> Dict[str, Any]:
        """List download tasks using modern Download Station API."""
        params: Dict[str, Any] = {"offset": offset, "limit": limit if limit > 0 else 100}

        # Use additional parameters for detailed task info.
        # DSM 7.3.2 silently drops the comma-string form; expects a JSON array.
        if additional:
            # If caller passed a comma-string, normalize to JSON array.
            if additional.startswith("["):
                params["additional"] = additional
            else:
                params["additional"] = json.dumps(
                    [s.strip() for s in additional.split(",") if s.strip()]
                )
        else:
            params["additional"] = json.dumps(["detail", "transfer"])

        try:
            data = self._make_request(self.task_api, self.task_version, "list", **params)
        except _PASS_THROUGH:
            raise
        except DownloadStationAPIError as e:
            # Only DSM saying the API, method or version is not there is a reason
            # to try the older form. This used to be a search of the error text for
            # "102" or "104", so a network error naming an address such as
            # 10.0.0.102 started one.
            if e.code not in _UNSUPPORTED_CODES:
                raise
            logger.warning(f"{self.task_api} v{self.task_version} failed, trying v1")
            try:
                basic_params = {"offset": offset, "limit": params["limit"]}
                data = self._make_request(self.task_api, "1", "list", **basic_params)
            except _PASS_THROUGH:
                # Not "no task API here": there is no session, or the NAS redirected.
                raise
            except DownloadStationAPIError as e2:
                if e2.code not in _UNSUPPORTED_CODES:
                    raise
                # Neither form exists on this NAS, so there is no task list to show.
                logger.warning(f"No task APIs available: {e2}")
                return {"total": 0, "offset": offset, "tasks": []}

        tasks = []
        for task in data.get("tasks", []):
            task_info = {
                "id": task.get("id"),
                "type": task.get("type"),
                "username": task.get("username"),
                "title": task.get("title"),
                "size": task.get("size"),
                "status": task.get("status"),
                "status_extra": task.get("status_extra", {}),
                "create_time": task.get("create_time"),
                "started_time": task.get("started_time"),
                "completed_time": task.get("completed_time"),
            }

            # Parse additional info if available
            if "additional" in task:
                additional_info = task["additional"]

                if "detail" in additional_info:
                    detail = additional_info["detail"]
                    task_info.update(
                        {
                            "destination": detail.get("destination"),
                            "uri": detail.get("uri"),
                            "priority": detail.get("priority"),
                            "total_peers": detail.get("total_peers"),
                            "connected_seeders": detail.get("connected_seeders"),
                            "connected_leechers": detail.get("connected_leechers"),
                        }
                    )

                if "transfer" in additional_info:
                    transfer = additional_info["transfer"]
                    task_info.update(
                        {
                            "size_downloaded": transfer.get("size_downloaded"),
                            "size_uploaded": transfer.get("size_uploaded"),
                            "speed_download": transfer.get("speed_download"),
                            "speed_upload": transfer.get("speed_upload"),
                        }
                    )

            tasks.append(task_info)

        return {
            "total": data.get("total", len(tasks)),
            "offset": data.get("offset", offset),
            "tasks": tasks,
        }

    def get_config(self) -> Dict[str, Any]:
        """Get Download Station configuration."""
        try:
            data = self._make_request(self.info_api, "1", "getconfig")
            return data
        except _PASS_THROUGH:
            raise
        except Exception:
            return {
                "default_destination": "",
                "emule_enabled": False,
                "bt_max_download": 0,
                "bt_max_upload": 0,
            }

    def create_task(
        self,
        uri: str,
        destination: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new download task using modern Download Station API.

        Note: The destination folder MUST already exist on the NAS.
        If no destination is provided, will use 'downloads' as default.
        """

        # Validate URI for SSRF protection
        if not self._validate_uri(uri):
            raise Exception(
                f"Invalid or blocked URI: {uri}\n"
                "Only http/https URLs are allowed. "
                "Internal/private network addresses are not permitted."
            )

        # Get valid destination if not provided
        if not destination:
            destination = self.get_default_destination()
        self._check_destination(destination)

        # ✅ VALIDATE DESTINATION EXISTS BEFORE CREATING TASK
        logger.info(f"Validating destination folder exists: {destination}")
        if not self._check_destination_exists(destination):
            # Get suggestions for existing folders
            common_destinations = self.get_common_destinations()
            available_suggestions = []
            for common_dest in common_destinations:
                if self._check_destination_exists(common_dest):
                    available_suggestions.append(common_dest)

            error_msg = f"Destination folder '{destination}' does not exist on the NAS."
            if available_suggestions:
                error_msg += f" Available folders: {', '.join(available_suggestions)}"
            else:
                error_msg += " Please create the 'downloads' folder first in File Station."

            raise Exception(error_msg)

        logger.info(f"Destination '{destination}' exists, proceeding with task creation")

        # Use the exact format captured from real NAS operation
        params = {
            "type": "url",
            "destination": destination,
            "create_list": "true",
            "url": json.dumps([uri]),  # URL as JSON array
        }

        # Add optional authentication parameters if provided
        if username:
            params["username"] = username
        if password:
            params["password"] = password

        try:
            logger.debug("Creating task with real NAS format")
            logger.debug(f"URI: {uri}")
            logger.debug(f"Destination: {destination}")

            data = self._make_request(self.task_api, self.task_version, "create", **params)

            logger.info("Task created successfully!")
            logger.debug(f"Task IDs: {data.get('task_id', [])}")
            logger.debug(f"List IDs: {data.get('list_id', [])}")

            return data

        except _PASS_THROUGH:
            raise
        except DownloadStationNetworkError as e:
            # The request may have reached the NAS and been acted on. Asking again,
            # in this form or an older one, could create the download twice.
            logger.warning(self._redact(f"Create task failed: {e}"))
            raise Exception(self._redact(f"Task creation failed: {e}. {_UNCERTAIN}"))
        except DownloadStationAPIError as e:
            logger.warning(self._redact(f"Create task failed: {e}"))
            # Only an answer that says the API, method or version is not there is a
            # reason to ask again in an older form: the NAS did nothing in answer to
            # a request it could not understand. Any other refusal is final.
            if e.code in _UNSUPPORTED_CODES and self.task_version != "1":
                return self._create_task_older_form(uri, destination, username, password, e)
            raise Exception(
                self._redact(
                    f"Task creation failed: {e}. Make sure the URL is valid and you have "
                    "permission to create downloads."
                )
            )

    def _create_task_older_form(
        self,
        uri: str,
        destination: str,
        username: Optional[str],
        password: Optional[str],
        first: Exception,
    ) -> Dict[str, Any]:
        """The one repeat of a create: in the older form, after DSM said the newer one
        is not supported. It is never repeated again, whatever happens to it."""
        logger.info("Trying with DownloadStation2.Task v1")
        fallback_params = {"uri": uri, "destination": destination}
        if username:
            fallback_params["username"] = username
        if password:
            fallback_params["password"] = password
        try:
            data = self._make_request(self.task_api, "1", "create", **fallback_params)
        except _PASS_THROUGH:
            raise
        except DownloadStationNetworkError as e:
            logger.warning(self._redact(f"v1 also failed: {e}"))
            raise Exception(self._redact(f"Task creation failed: {e}. {_UNCERTAIN}"))
        except Exception as e:
            logger.warning(self._redact(f"v1 also failed: {e}"))
            raise Exception(
                self._redact(
                    f"Task creation failed: {first}; the older form failed too: {e}. "
                    "Make sure the URL is valid and you have permission to create downloads."
                )
            )
        logger.info("Create successful with v1")
        return data

    def delete_tasks(self, task_ids: List[str], force_complete: bool = False) -> Dict[str, Any]:
        """Delete download tasks."""
        params = {"id": ",".join(task_ids), "force_complete": force_complete}
        return self._make_request(self.task_api, self.task_version, "delete", **params)

    def pause_tasks(self, task_ids: List[str]) -> Dict[str, Any]:
        """Pause download tasks."""
        params = {"id": ",".join(task_ids)}
        return self._make_request(self.task_api, self.task_version, "pause", **params)

    def resume_tasks(self, task_ids: List[str]) -> Dict[str, Any]:
        """Resume download tasks."""
        params = {"id": ",".join(task_ids)}
        return self._make_request(self.task_api, self.task_version, "resume", **params)

    def get_statistics(self) -> Dict[str, Any]:
        """Get Download Station statistics."""
        try:
            data = self._make_request(self.stat_api, self.stat_version, "getinfo")
            return {
                "speed_download": data.get("speed_download", 0),
                "speed_upload": data.get("speed_upload", 0),
                "emule_speed_download": data.get("emule_speed_download", 0),
                "emule_speed_upload": data.get("emule_speed_upload", 0),
            }
        except _PASS_THROUGH:
            raise
        except Exception:
            # Fallback: calculate from task list
            try:
                tasks_data = self.list_tasks(limit=100)
                total_down_speed = sum(
                    task.get("speed_download", 0) for task in tasks_data.get("tasks", [])
                )
                total_up_speed = sum(
                    task.get("speed_upload", 0) for task in tasks_data.get("tasks", [])
                )

                return {
                    "speed_download": total_down_speed,
                    "speed_upload": total_up_speed,
                    "note": "Calculated from active tasks",
                }
            except _PASS_THROUGH:
                # Zeroes are an answer about the NAS; a lost session or a redirect is
                # not, and must not be reported as "no downloads running".
                raise
            except Exception:
                return {"speed_download": 0, "speed_upload": 0, "error": "Statistics not available"}

    def _check_destination_exists(self, destination: str) -> bool:
        """Check if destination folder exists using FileStation API."""
        if self.folder_guard is not None and not self.folder_guard.allows(
            "/" + destination.lstrip("/")
        ):
            return False
        try:
            # Use FileStation API to check if folder exists
            request_params = {
                "api": "SYNO.FileStation.List",
                "version": "2",
                "method": "getinfo",
                "path": f"/{destination}",
                "_sid": self.session_id,
            }

            headers = {"X-SYNO-TOKEN": self.syno_token} if self.syno_token else None
            response = requests.get(
                self.api_url,
                params=request_params,
                headers=headers,
                verify=self.verify_ssl,
                timeout=15,
                allow_redirects=False,
            )
            refuse_redirect(response)
            response.raise_for_status()
            data = response.json()

            if not data.get("success"):
                raise_if_authentication_required(data.get("error", {}).get("code"))

            # Check if the request was successful and returned file info
            if data.get("success") and data.get("data", {}).get("files"):
                files = data["data"]["files"]
                if files and files[0].get("isdir"):
                    return True

            return False

        except _PASS_THROUGH:
            raise
        except Exception:
            # If we can't check, assume it doesn't exist
            return False

    def get_common_destinations(self) -> List[str]:
        """Get a list of commonly used destination folders.

        Returns common folder names that typically exist on Synology NAS.
        Note: Actual availability depends on your NAS configuration.
        """
        return [
            self.preferred_default_destination,  # Always try preferred first
            "video",  # Common for video content
            "music",  # Common for audio content
            "software",  # Common for applications/software
            "documents",  # Common for document files
            "photos",  # Common for image files
            "backup",  # Common for backup files
        ]

    def get_default_destination(self) -> str:
        """Get the best available default destination.

        Returns the preferred default destination if it exists,
        otherwise returns the first available common destination.
        """
        # First, try our preferred default
        if self._check_destination_exists(self.preferred_default_destination):
            return self.preferred_default_destination

        # Try other common destinations
        for dest in self.get_common_destinations()[1:]:  # Skip first since it's preferred
            if self._check_destination_exists(dest):
                logger.warning(
                    f"Preferred destination '{self.preferred_default_destination}' not found, using '{dest}'"
                )
                return dest

        # If nothing exists, return preferred anyway (will cause validation error later)
        logger.warning(
            f"No common destinations found, defaulting to '{self.preferred_default_destination}'"
        )
        return self.preferred_default_destination

    def set_default_destination(self, destination: str) -> bool:
        """Set the preferred default destination.

        Args:
            destination: The folder name to use as default

        Returns:
            True if the destination exists, False otherwise
        """
        exists = self._check_destination_exists(destination)

        if exists:
            self.preferred_default_destination = destination
            logger.info(f"Default destination set to '{destination}'")
        else:
            logger.warning(f"Destination '{destination}' does not exist, not setting as default")

        return exists

    def ensure_downloads_folder(self) -> bool:
        """Ensure the 'downloads' folder exists and is set as default.

        Returns:
            True if downloads folder exists or was created successfully
        """
        if self._check_destination_exists("downloads"):
            self.preferred_default_destination = "downloads"
            logger.info("'downloads' folder exists and is set as default")
            return True
        else:
            logger.warning("'downloads' folder does not exist. Please create it in File Station.")
            logger.info("Typical path: Control Panel > Shared Folder > Create > Name: 'downloads'")
            return False

    def list_downloaded_files(self, destination: Optional[str] = None) -> Dict[str, Any]:
        if not destination:
            destination = self.get_default_destination()
        self._check_destination(destination)

        logger.info(f"Listing downloaded files in: {destination}")

        try:
            request_params = {
                "api": "SYNO.FileStation.List",
                "version": "2",
                "method": "list",
                "folder_path": f"/{destination}",
                "_sid": self.session_id,
            }

            headers = {"X-SYNO-TOKEN": self.syno_token} if self.syno_token else None
            response = requests.get(
                self.api_url,
                params=request_params,
                headers=headers,
                verify=self.verify_ssl,
                timeout=15,
                allow_redirects=False,
            )
            refuse_redirect(response)
            response.raise_for_status()
            data = response.json()

            if data.get("success"):
                return data.get("data", {})
            else:
                error_code = data.get("error", {}).get("code", "unknown")
                raise_if_authentication_required(error_code)
                error_msg = self._get_error_message(error_code)
                raise Exception(f"FileStation API error {error_code}: {error_msg}")

        except _PASS_THROUGH:
            raise
        except Exception as e:
            # This request's URL carries `_sid=<session_id>` directly (it's
            # built by hand, not through `_make_request`), so a
            # RequestException's str() can embed it — redact before re-raising.
            raise Exception(self._redact(f"Could not list downloaded files: {e}"))
