# src/synology_filestation.py - Synology FileStation API utilities

import contextvars
import json
import os
import posixpath
import re
import tempfile
import threading
import time
import unicodedata
from typing import Any, Dict, List, Optional

import requests

from utils.redact import redact

# Paths no path-taking method below may touch, read or write. See
# _check_critical_path.
#
# Volume roots and /homes are blocked only as exact matches: they're raw
# volume mounts and the aggregate home-directories share, not places real
# files live directly — but /volume2/photo or /homes/alice are ordinary
# user shares/subfolders and must stay reachable, so these are NOT
# prefix-matched. Synology NAS units commonly expose more than one storage
# volume (/volume1, /volume2, ...), so this is a pattern, not a fixed name.
_VOLUME_ROOT_RE = re.compile(r"/volume\d+")
_CRITICAL_PATHS_EXACT = ("/homes",)
# True OS-level directories have no legitimate DSM share overlap at all, so
# every path under them is blocked too (e.g. /etc/passwd, not just /etc).
_CRITICAL_PATHS_PREFIX = ("/var", "/etc", "/usr", "/bin", "/sbin")

# Time limits for the operations that start a DSM task and poll it (search,
# delete, move). Each limit is one wall-clock budget that covers the request
# that starts the task and the polling that follows; every request made inside
# it is cut off at whatever time is left (see _make_request's `deadline`).
# Fetching a finished search's results, and stopping the task during cleanup,
# are not inside that budget: each gets its own short allowance below, which
# is why the worst case is a little more than the stated limit —
#   search_files  _SEARCH_LIMIT + _RESULTS_TIMEOUT + _CLEANUP_TIMEOUT = 140 s
#   delete        _DELETE_LIMIT + _CLEANUP_TIMEOUT                    = 125 s
#   move_file     _MOVE_LIMIT + _CLEANUP_TIMEOUT                      =  65 s
_SEARCH_LIMIT = 120
_DELETE_LIMIT = 120
_MOVE_LIMIT = 60
_REQUEST_TIMEOUT = 15  # a single request, when no deadline is bounding it
_RESULTS_TIMEOUT = 15  # fetching a finished search's results
_CLEANUP_TIMEOUT = 5  # stopping a task that is abandoned or failed
_POLL_INTERVAL = 0.5


class _DeadlineError(Exception):
    """A time budget ran out. Raised by `_make_request` and `_wait_for_task`;
    each operation turns it into its own "timed out after N seconds" error."""


def _decode_downloaded_text(content: bytes, declared_encoding: Optional[str]) -> str:
    """Decode a downloaded file's bytes the way `requests.Response.text`
    would: use the declared encoding if the server sent one, otherwise
    auto-detect (mirroring `Response.apparent_encoding`) instead of
    assuming UTF-8. DSM's download endpoint doesn't send a charset, so the
    auto-detect path is the common case here, not an edge case.

    This can't just call `response.apparent_encoding` — that reads
    `response.content`, which raises once the body has already been
    consumed via `iter_content()` (needed here to enforce the size cap
    against the actual bytes read, not just pre-download metadata).
    """
    if declared_encoding:
        return content.decode(declared_encoding, errors="replace")
    try:
        import charset_normalizer

        detected = charset_normalizer.detect(content)["encoding"]
    except Exception:
        detected = None
    return content.decode(detected or "utf-8", errors="replace")


def _dsm_download_error_code(body: bytes) -> Optional[str]:
    """If `body` is a DSM error envelope, return its error code (or
    "unknown"); return None if it is anything else.

    DSM's download endpoint reports failures as a small JSON body,
    `{"success": false, "error": {"code": N}}`, served with a JSON
    Content-Type — but a real `.json` file downloads with that same
    Content-Type. So a JSON Content-Type alone can't tell the two apart; the
    body has to look like the error envelope: an object whose `success` is
    `false` and that carries an `error` key. Anything else — a list, a
    scalar, invalid JSON, an object without those two keys — is the file's
    own content.
    """
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        # ValueError covers both malformed JSON and a body that isn't valid
        # text in any JSON encoding; RecursionError is a deeply nested
        # (but size-capped) file blowing the parser's stack.
        return None
    if not isinstance(data, dict) or data.get("success") is not False or "error" not in data:
        return None
    error = data["error"]
    return str(error.get("code", "unknown")) if isinstance(error, dict) else "unknown"


class SynologyFileStation:
    """Handles Synology FileStation API operations."""

    def __init__(
        self,
        base_url: str,
        session_id: str,
        verify_ssl: bool = True,
        syno_token: Optional[str] = None,
        max_file_content_size: int = 1_000_000,
    ):
        self.base_url = base_url.rstrip("/")
        self.session_id = session_id
        self.verify_ssl = verify_ssl
        self.syno_token = syno_token
        self.api_url = f"{self.base_url}/webapi/entry.cgi"
        # get_file_content refuses to download a file larger than this,
        # checked via file metadata before any download request is made.
        self.max_file_content_size = max_file_content_size

    def _csrf_headers(self, *, post: bool) -> Dict[str, str]:
        """Build request headers, including X-SYNO-TOKEN for DSM 7.3.2+ CSRF.

        Always sets the UTF-8 charset on POSTs (preserves prior Unicode behavior).
        """
        headers: Dict[str, str] = {}
        if post:
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
        if self.syno_token:
            headers["X-SYNO-TOKEN"] = self.syno_token
        return headers

    def _redact(self, message: str) -> str:
        """Redact this instance's live secrets from an error message."""
        return redact(message, live_secrets=[self.session_id, self.syno_token])

    def _make_request(
        self,
        api: str,
        version: str,
        method: str,
        use_post: bool = False,
        *,
        deadline: Optional[float] = None,
        **params,
    ) -> Dict[str, Any]:
        """Make a request to Synology API.

        `deadline` is a `time.monotonic()` timestamp the request must not
        outlive. Without one the request is limited only by its own timeout
        (`_REQUEST_TIMEOUT`). With one, the request is given at most the time
        that is left: it is not sent at all if none is, its timeout is capped
        to what remains, and — because a `requests` timeout limits each
        connect and each read, not the whole exchange, so a server that keeps
        trickling bytes can outlast it — it is also abandoned outright when the
        time is up. Running out of time raises `_DeadlineError`.
        """
        request_params = {
            "api": api,
            "version": version,
            "method": method,
            "_sid": self.session_id,
            **params,
        }

        timeout: float = _REQUEST_TIMEOUT
        remaining: Optional[float] = None
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _DeadlineError()
            timeout = min(_REQUEST_TIMEOUT, remaining)

        def send() -> Any:
            if use_post:
                response = requests.post(
                    self.api_url,
                    data=request_params,
                    headers=self._csrf_headers(post=True),
                    verify=self.verify_ssl,
                    timeout=timeout,
                )
            else:
                response = requests.get(
                    self.api_url,
                    params=request_params,
                    headers=self._csrf_headers(post=False) or None,
                    verify=self.verify_ssl,
                    timeout=timeout,
                )
            response.raise_for_status()
            return response.json()

        try:
            data = send() if remaining is None else self._run_within(send, remaining)
        except requests.RequestException as e:
            if (
                isinstance(e, requests.Timeout)
                and remaining is not None
                and remaining < _REQUEST_TIMEOUT
            ):
                # The timeout that fired was the one cut down to the time left,
                # so it is the deadline arriving, not a slow NAS.
                raise _DeadlineError() from None
            # This GET request's URL carries `_sid=<session_id>` directly, and
            # `str(e)` on a RequestException commonly embeds the full URL —
            # redact before it propagates. Backstop; the tool-response
            # boundary in mcp_server.py also redacts.
            raise Exception(self._redact(f"Network error: {e}"))

        if not data.get("success"):
            error_code = data.get("error", {}).get("code", "unknown")
            error_info = data.get("error", {})

            # Include detailed error information if available
            error_message = f"Synology API error: {error_code}"

            # Check for detailed errors array as mentioned in documentation
            if "errors" in error_info and error_info["errors"]:
                detailed_errors = []
                for err in error_info["errors"]:
                    err_detail = f"Code {err.get('code', 'unknown')}"
                    if "path" in err:
                        err_detail += f" for path: {err['path']}"
                    detailed_errors.append(err_detail)
                error_message += f" - Details: {'; '.join(detailed_errors)}"

            raise Exception(error_message)

        return data.get("data", {})

    @staticmethod
    def _run_within(func, seconds: float) -> Any:
        """Call `func()` and return its result, or raise `_DeadlineError` if
        it has not finished within `seconds`.

        `func` runs in a daemon thread, so giving up on it cannot hold up the
        caller or the process's exit. An abandoned call is only ever a read —
        a task's status, a listing, a stop — and its result is discarded; the
        `requests` timeout inside it still ends it in the background. The
        caller's context (which carries the secrets being redacted from log
        output) is copied into the thread.
        """
        outcome: Dict[str, Any] = {}

        def target() -> None:
            try:
                outcome["value"] = func()
            except Exception as e:  # handed back to the caller's thread below
                outcome["error"] = e

        thread = threading.Thread(
            target=contextvars.copy_context().run, args=(target,), daemon=True
        )
        thread.start()
        thread.join(seconds)
        if thread.is_alive():
            raise _DeadlineError()
        if "error" in outcome:
            raise outcome["error"]
        return outcome["value"]

    def _wait_for_task(self, api: str, version: str, task_id: str, deadline: float) -> Dict:
        """Poll a DSM task's status until it reports `finished`, and return that
        status. Raises `_DeadlineError` once `deadline` (a `time.monotonic()`
        timestamp) passes: every status request is cut off at the time left,
        and the deadline is checked again after each response, so the poll
        loop never starts another round it has no time for."""
        while True:
            status_data = self._make_request(
                api, version, "status", taskid=task_id, deadline=deadline
            )
            if status_data.get("finished"):
                return status_data
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _DeadlineError()
            time.sleep(min(_POLL_INTERVAL, remaining))

    def _stop_task(self, api: str, version: str, task_id: str) -> None:
        """Ask DSM to stop a task that is being abandoned or has failed. Bounded
        by `_CLEANUP_TIMEOUT`, and any failure is ignored: this is cleanup, and
        must not replace the error that made it necessary."""
        try:
            self._make_request(
                api,
                version,
                "stop",
                taskid=task_id,
                deadline=time.monotonic() + _CLEANUP_TIMEOUT,
            )
        except Exception:
            pass

    def _make_upload_request(
        self, api: str, version: str, method: str, files: Dict[str, Any], **params
    ) -> Dict[str, Any]:
        """Make an upload request to Synology API."""
        request_params = {
            "api": api,
            "version": version,
            "method": method,
            "_sid": self.session_id,
            **params,
        }

        # Multipart upload — let requests set Content-Type with the boundary;
        # we only thread the X-SYNO-TOKEN header (no charset override here).
        # `_sid` and the other API params go in `data=` (regular multipart
        # form fields, sent alongside `files=`), not `params=` — `params=`
        # would put them in the URL query string even though this is a POST.
        upload_headers = {"X-SYNO-TOKEN": self.syno_token} if self.syno_token else None
        try:
            response = requests.post(
                self.api_url,
                data=request_params,
                files=files,
                headers=upload_headers,
                verify=self.verify_ssl,
                timeout=15,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            raise Exception(self._redact(f"Network error: {e}"))

        if not data.get("success"):
            error_code = data.get("error", {}).get("code", "unknown")
            raise Exception(f"Synology API error: {error_code}")

        return data.get("data", {})

    def _format_path(self, path: str) -> str:
        """Format path for Synology API."""
        # Collapse any run of leading slashes to exactly one *before*
        # normpath: posixpath.normpath has a POSIX quirk where it preserves
        # exactly two leading slashes verbatim (three or more collapse to
        # one), so "//etc/passwd" would otherwise survive unchanged and
        # bypass a "/etc" prefix check even though the filesystem treats
        # "//" the same as "/".
        path = "/" + path.lstrip("/")

        # Resolve "." / ".." segments (POSIX-style, regardless of the host
        # OS this process runs on) before anything downstream — otherwise
        # e.g. "/share/../etc/passwd" never matches _check_critical_path's
        # prefix check on the literal, unresolved string, even though it
        # names a critical path once resolved.
        path = posixpath.normpath(path)

        # Normalize Unicode characters to NFC form (most common for filesystems)
        path = unicodedata.normalize("NFC", path)
        return path

    def list_shares(self) -> List[Dict[str, Any]]:
        """List all available shares."""
        data = self._make_request("SYNO.FileStation.List", "2", "list_share")
        shares = data.get("shares", [])

        return [
            {
                "name": share.get("name"),
                "path": share.get("path"),
                "description": share.get("desc", ""),
                "is_writable": share.get("iswritable", False),
            }
            for share in shares
        ]

    def list_directory(self, path: str, additional_info: bool = True) -> List[Dict[str, Any]]:
        """List contents of a directory."""
        formatted_path = self._format_path(path)
        self._check_critical_path(formatted_path)

        params: Dict[str, Any] = {"folder_path": formatted_path}

        if additional_info:
            # DSM 7.3.2 silently drops the comma-string form; expects a JSON array.
            # Verified live: comma-string → no `additional` field in response;
            # JSON array → returns time/size/owner/perm as documented.
            params["additional"] = json.dumps(["time", "size", "owner", "perm"])

        data = self._make_request("SYNO.FileStation.List", "2", "list", **params)
        files = data.get("files", [])

        result = []
        for file_info in files:
            item = {
                "name": file_info.get("name"),
                "path": file_info.get("path"),
                "type": "directory" if file_info.get("isdir") else "file",
                "size": file_info.get("size", 0),
            }

            # Add additional info if available
            if "additional" in file_info:
                additional = file_info["additional"]

                # DSM returns the requested "size" additional field nested
                # here, same as time/owner/perm below — not at the file
                # object's top level, despite the fallback above.
                if "size" in additional:
                    item["size"] = additional["size"]

                if "time" in additional:
                    time_info = additional["time"]
                    item.update(
                        {
                            "created": time_info.get("crtime"),
                            "modified": time_info.get("mtime"),
                            "accessed": time_info.get("atime"),
                        }
                    )

                if "owner" in additional:
                    owner_info = additional["owner"]
                    item.update(
                        {
                            "owner": owner_info.get("user", "unknown"),
                            "group": owner_info.get("group", "unknown"),
                        }
                    )

                if "perm" in additional:
                    perm_info = additional["perm"]
                    item["permissions"] = perm_info.get("posix", "unknown")

            result.append(item)

        return result

    def get_file_info(self, path: str, *, deadline: Optional[float] = None) -> Dict[str, Any]:
        """Get detailed information about a file or directory. `deadline` is
        passed to the request (see `_make_request`); `delete` uses it so that
        looking the path up counts against its time limit."""
        formatted_path = self._format_path(path)
        self._check_critical_path(formatted_path)

        data = self._make_request(
            "SYNO.FileStation.List",
            "2",
            "getinfo",
            deadline=deadline,
            path=formatted_path,
            # DSM 7.3.2 requires JSON array; comma-string is silently ignored.
            additional=json.dumps(["time", "size", "owner", "perm"]),
        )

        files = data.get("files", [])
        if not files:
            raise Exception(f"File not found: {path}")

        file_info = files[0]

        # DSM reports a per-path failure (e.g. 408 for a missing path) inside
        # the entry itself, with the request as a whole still success:true.
        if "code" in file_info:
            if file_info["code"] == 408:
                raise Exception(f"File not found: {path}")
            raise Exception(f"Cannot get info for {path} (DSM error {file_info['code']})")

        result = {
            "name": file_info.get("name"),
            "path": file_info.get("path"),
            "type": "directory" if file_info.get("isdir") else "file",
            "size": file_info.get("size", 0),
        }

        # Add additional info
        if "additional" in file_info:
            additional = file_info["additional"]

            # DSM returns the requested "size" additional field nested
            # here, same as time/owner/perm below — not at the file
            # object's top level, despite the fallback above. Without this,
            # get_file_content's size cap (checked via this method's "size")
            # never fires against a real NAS.
            if "size" in additional:
                result["size"] = additional["size"]

            if "time" in additional:
                time_info = additional["time"]
                result.update(
                    {
                        "created": time_info.get("crtime"),
                        "modified": time_info.get("mtime"),
                        "accessed": time_info.get("atime"),
                    }
                )

            if "owner" in additional:
                owner_info = additional["owner"]
                result.update(
                    {
                        "owner": owner_info.get("user", "unknown"),
                        "group": owner_info.get("group", "unknown"),
                    }
                )

            if "perm" in additional:
                perm_info = additional["perm"]
                result["permissions"] = perm_info.get("posix", "unknown")

        return result

    def search_files(self, path: str, pattern: str) -> List[Dict[str, Any]]:
        """Search for files matching a pattern.

        Starting the search and waiting for it to finish share one
        `_SEARCH_LIMIT` (120 s) budget; every request inside it is cut off at
        the time left. Fetching the results (up to `_RESULTS_TIMEOUT`) and
        stopping the task afterwards (up to `_CLEANUP_TIMEOUT`) have their own
        allowances, so the call takes at most 140 s in all.
        """
        formatted_path = self._format_path(path)
        self._check_critical_path(formatted_path)

        # A wall-clock deadline, not a tally of time spent sleeping: each
        # request can itself take time a sleep counter never sees.
        deadline = time.monotonic() + _SEARCH_LIMIT
        timed_out = f"Search operation timed out after {_SEARCH_LIMIT} seconds"

        # Start search
        try:
            start_data = self._make_request(
                "SYNO.FileStation.Search",
                "2",
                "start",
                deadline=deadline,
                folder_path=formatted_path,
                pattern=pattern,
            )
        except _DeadlineError:
            # No task id came back, so there is nothing to stop.
            raise Exception(timed_out) from None

        task_id = start_data.get("taskid")
        if not task_id:
            raise Exception("Failed to start search task")

        try:
            # Wait for search to complete
            try:
                self._wait_for_task("SYNO.FileStation.Search", "2", task_id, deadline)
            except _DeadlineError:
                raise Exception(timed_out) from None

            # Get results — a fresh allowance, so a search that finishes just
            # inside its limit is not thrown away for want of time to read it.
            try:
                result_data = self._make_request(
                    "SYNO.FileStation.Search",
                    "2",
                    "list",
                    deadline=time.monotonic() + _RESULTS_TIMEOUT,
                    taskid=task_id,
                )
            except _DeadlineError:
                raise Exception(
                    f"Search finished, but fetching its results timed out after "
                    f"{_RESULTS_TIMEOUT} seconds"
                ) from None

            files = result_data.get("files", [])
            return [
                {
                    "name": file_info.get("name"),
                    "path": file_info.get("path"),
                    "type": "directory" if file_info.get("isdir") else "file",
                    "size": file_info.get("size", 0),
                }
                for file_info in files
            ]

        finally:
            # Clean up search task
            self._stop_task("SYNO.FileStation.Search", "2", task_id)

    def rename_file(self, path: str, new_name: str) -> Dict[str, Any]:
        """Rename a file or directory.

        Args:
            path: Full path to the file/directory to rename
            new_name: New name for the file/directory (just the name, not full path)

        Returns:
            Dict with operation result
        """
        formatted_path = self._format_path(path)

        # Check for critical paths
        self._check_critical_path(formatted_path)

        # Validate new name
        if not new_name or new_name.strip() == "":
            raise Exception("New name cannot be empty")

        # Remove any path separators from new name
        new_name = new_name.strip().replace("/", "").replace("\\", "")

        if not new_name:
            raise Exception("Invalid new name")

        # According to official Synology API docs, path and name must be JSON arrays even for single values
        # The parameters should be formatted as: path=["/path"] and name=["name"]
        # Let requests library handle URL encoding automatically

        # Create JSON arrays without manual URL encoding - let requests handle it
        path_array = json.dumps([formatted_path])
        name_array = json.dumps([new_name])

        # Use GET request as specified in official documentation
        self._make_request(
            "SYNO.FileStation.Rename",
            "2",
            "rename",
            use_post=False,  # Official docs specify GET
            path=path_array,
            name=name_array,
        )

        # Get the parent directory path
        parent_dir = os.path.dirname(formatted_path)
        new_path = os.path.join(parent_dir, new_name).replace("\\", "/")

        return {
            "success": True,
            "old_path": formatted_path,
            "new_path": new_path,
            "old_name": os.path.basename(formatted_path),
            "new_name": new_name,
            "message": f"Successfully renamed '{os.path.basename(formatted_path)}' to '{new_name}'",
        }

    def create_file(self, path: str, content: str = "", overwrite: bool = False) -> Dict[str, Any]:
        """Create a new file with specified content.

        Args:
            path: Full path where the file should be created (must start with /)
            content: Content to write to the file (default: empty string)
            overwrite: Whether to overwrite existing file (default: False)

        Returns:
            Dict with operation result
        """
        formatted_path = self._format_path(path)

        # Validate path
        if not formatted_path or formatted_path == "/":
            raise Exception("Invalid file path")

        self._check_critical_path(formatted_path)

        # Get directory and filename
        directory = os.path.dirname(formatted_path)
        filename = os.path.basename(formatted_path)

        if not filename:
            raise Exception("Invalid filename")

        # Create temporary file with content
        with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            # Use context manager for session to prevent resource leak
            with requests.Session() as session:
                with open(temp_file_path, "rb") as payload:
                    # `api`/`version`/`method`/`_sid` go in the multipart form
                    # body (data=), not the URL — putting `_sid` in the URL
                    # query string would leak the session id into any log or
                    # exception text that captures the request URL, even
                    # though this is a POST.
                    files = {"file": (filename, payload, "text/plain")}

                    data = {
                        "api": "SYNO.FileStation.Upload",
                        "version": "2",
                        "method": "upload",
                        "_sid": self.session_id,
                        "path": directory,
                        "create_parents": "true",
                        "overwrite": str(overwrite).lower(),
                    }

                    # Make the request — thread X-SYNO-TOKEN for DSM 7.3.2+ CSRF;
                    # let requests set Content-Type with the multipart boundary.
                    upload_headers = {"X-SYNO-TOKEN": self.syno_token} if self.syno_token else None
                    try:
                        response = session.post(
                            self.api_url,
                            files=files,
                            data=data,
                            headers=upload_headers,
                            verify=self.verify_ssl,
                            timeout=15,
                        )
                        response.raise_for_status()
                        result = response.json()
                    except requests.RequestException as e:
                        raise Exception(self._redact(f"Network error: {e}"))

                    if not result.get("success"):
                        error_code = result.get("error", {}).get("code", "unknown")
                        raise Exception(f"Upload failed with error: {error_code}")

            return {
                "success": True,
                "path": formatted_path,
                "filename": filename,
                "directory": directory,
                "size": len(content.encode("utf-8")),
                "message": f"Successfully created file '{filename}' at '{directory}'",
            }

        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file_path)
            except Exception:
                pass  # Ignore cleanup errors

    def create_directory(
        self, folder_path: str, name: str, force_parent: bool = False
    ) -> Dict[str, Any]:
        """Create a new directory.

        Args:
            folder_path: Parent directory path where the new folder should be created (must start with /)
            name: Name of the new directory to create
            force_parent: Whether to create parent directories if they don't exist (default: False)

        Returns:
            Dict with operation result
        """
        formatted_folder_path = self._format_path(folder_path)

        # Validate folder path
        if not formatted_folder_path:
            raise Exception("Invalid folder path")

        self._check_critical_path(formatted_folder_path)

        # Validate name
        if not name or name.strip() == "":
            raise Exception("Directory name cannot be empty")

        # Remove any path separators from name
        clean_name = name.strip().replace("/", "").replace("\\", "")

        if not clean_name:
            raise Exception("Invalid directory name")

        # Use the exact working pattern from the user's request
        data = self._make_request(
            "SYNO.FileStation.CreateFolder",
            "2",
            "create",
            folder_path=formatted_folder_path,
            name=clean_name,
            force_parent=force_parent,
        )

        folders = data.get("folders", [])
        if not folders:
            raise Exception("Failed to create directory - no folder data returned")

        created_folder = folders[0]
        full_path = created_folder.get("path", f"{formatted_folder_path}/{clean_name}")

        return {
            "success": True,
            "folder_path": formatted_folder_path,
            "name": clean_name,
            "full_path": full_path,
            "is_directory": created_folder.get("isdir", True),
            "force_parent": force_parent,
            "message": f"Successfully created directory '{clean_name}' at '{formatted_folder_path}'",
        }

    def delete(self, path: str) -> Dict[str, Any]:
        """Delete a file or directory (auto-detects type).

        Looking the path up, starting the delete and waiting for it to finish
        share one `_DELETE_LIMIT` (120 s) budget, and every request inside it
        is cut off at the time left. Stopping the task after a failure gets its
        own `_CLEANUP_TIMEOUT`, so the call takes at most 125 s.

        Args:
            path: Full path to the file/directory to delete (must start with /)

        Returns:
            Dict with operation result
        """
        formatted_path = self._format_path(path)

        # Validate path
        if not formatted_path or formatted_path == "/":
            raise Exception("Invalid path - cannot delete root")

        self._check_critical_path(formatted_path)

        deadline = time.monotonic() + _DELETE_LIMIT  # wall-clock, as in search_files
        timed_out = f"Delete operation timed out after {_DELETE_LIMIT} seconds"

        # Auto-detect if this is a file or directory
        try:
            file_info = self.get_file_info(formatted_path, deadline=deadline)
            recursive = file_info.get("type") == "directory"
        except _DeadlineError:
            # Out of time before anything was started: don't fall through to
            # deleting it as a file on a guess.
            raise Exception(timed_out) from None
        except Exception:
            recursive = False  # Default to file behavior if can't determine

        item_name = os.path.basename(formatted_path)
        item_type = "directory" if recursive else "file"

        # Use the correct API format according to documentation
        path_array = json.dumps([formatted_path])

        # Start the delete task (async operation)
        try:
            start_data = self._make_request(
                "SYNO.FileStation.Delete",
                "2",
                "start",
                deadline=deadline,
                path=path_array,
                accurate_progress="true",
                recursive=str(recursive).lower(),
            )
        except _DeadlineError:
            raise Exception(timed_out) from None

        task_id = start_data.get("taskid")
        if not task_id:
            raise Exception("Failed to start delete task")

        try:
            # Wait for delete to complete
            status_data = self._wait_for_task("SYNO.FileStation.Delete", "2", task_id, deadline)

            # Check if there were any errors
            if "error" in status_data:
                error_info = status_data["error"]
                raise Exception(f"Delete failed: {error_info}")

            return {
                "success": True,
                "path": formatted_path,
                "item_name": item_name,
                "item_type": item_type,
                "recursive": recursive,
                "task_id": task_id,
                "message": f"Successfully deleted {item_type} '{item_name}'",
            }

        except _DeadlineError:
            self._stop_task("SYNO.FileStation.Delete", "2", task_id)
            raise Exception(timed_out) from None
        except Exception:
            # Try to stop the task if it's still running
            self._stop_task("SYNO.FileStation.Delete", "2", task_id)
            raise

    def _check_critical_path(self, path: str) -> None:
        """Check if path is a critical system path, or inside one — raise if so.

        `_CRITICAL_PATHS_EXACT`/`_VOLUME_ROOT_RE` entries block only the
        literal path itself (a real share/subfolder underneath is
        unaffected); `_CRITICAL_PATHS_PREFIX` entries block the path and
        everything under it. This is the one denylist check every
        path-taking method below calls; it used to be exact-match-only here
        and separately duplicated with prefix-matching in `delete()` —
        consolidated so there is one definition of "critical path" instead
        of two that could drift apart.

        Args:
            path: Formatted path to check

        Raises:
            Exception: If path is or is inside a critical system path
        """
        if path in _CRITICAL_PATHS_EXACT or _VOLUME_ROOT_RE.fullmatch(path):
            raise Exception(f"Cannot access critical system path: {path}")
        for cp in _CRITICAL_PATHS_PREFIX:
            if path == cp or path.startswith(cp + "/"):
                raise Exception(f"Cannot access critical system path: {path}")

    def get_file_content(self, path: str) -> str:
        """Get the content of a file."""
        formatted_path = self._format_path(path)

        # Check for critical paths
        self._check_critical_path(formatted_path)

        # Enforce the size cap via file metadata, before any download
        # request is made — not after reading the whole file into memory.
        # File contents are sent to the MCP client's AI provider, and this
        # tool stays enabled even in restricted mode.
        info = self.get_file_info(formatted_path)
        size = info.get("size", 0)
        if size > self.max_file_content_size:
            raise Exception(
                f"File '{path}' is {size} bytes, which exceeds the configured "
                f"limit of {self.max_file_content_size} bytes (max_file_content_size)."
            )

        # Use the download API to get file content
        download_headers = {"X-SYNO-TOKEN": self.syno_token} if self.syno_token else None
        try:
            response = requests.get(
                f"{self.base_url}/webapi/entry.cgi",
                params={
                    "api": "SYNO.FileStation.Download",
                    "version": "2",
                    "method": "download",
                    "path": formatted_path,
                    "_sid": self.session_id,
                },
                headers=download_headers,
                verify=self.verify_ssl,
                stream=True,
                timeout=15,
            )
            # `with response:` closes the connection on every exit path —
            # the oversize abort, a DSM error, an exception mid-stream —
            # not only the one that used to call close() by hand.
            with response:
                response.raise_for_status()

                # Enforce the cap on the bytes actually read too, not just on
                # the get_file_info() pre-check above: that check can be stale
                # (the file can grow between the two requests) or silently
                # absent (info.get("size", 0) fails open to 0 if DSM's response
                # doesn't carry a size for some reason). Streaming (already
                # requested via stream=True) lets this abort mid-download
                # instead of buffering an oversized body into memory first.
                #
                # This read comes before any JSON handling on purpose:
                # response.json() would pull the entire body into memory
                # first, so a JSON response would bypass the cap.
                chunks = []
                total_bytes = 0
                for chunk in response.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    total_bytes += len(chunk)
                    if total_bytes > self.max_file_content_size:
                        raise Exception(
                            f"File '{path}' exceeds the configured limit of "
                            f"{self.max_file_content_size} bytes (max_file_content_size) "
                            "while downloading."
                        )
                    chunks.append(chunk)
                body = b"".join(chunks)

                # The download API is special: it reports failure as a JSON
                # body rather than an HTTP error status. See
                # _dsm_download_error_code for why a JSON Content-Type isn't
                # enough to call it an error.
                if "application/json" in response.headers.get("Content-Type", "").lower():
                    error_code = _dsm_download_error_code(body)
                    if error_code is not None:
                        raise Exception(f"Synology API error: {error_code}")

                # Assuming the content is text, decode it
                # For binary files, this would need to be handled differently
                return _decode_downloaded_text(body, response.encoding)
        except requests.RequestException as e:
            # This GET request's URL carries `_sid=<session_id>` directly —
            # redact before a RequestException's str() (which commonly
            # embeds the full URL) propagates to the caller.
            raise Exception(self._redact(f"Network error: {e}"))

    def move_file(
        self, source_path: str, destination_path: str, overwrite: bool = False
    ) -> Dict[str, Any]:
        """Move a file or directory to a new location.

        Starting the move and waiting for it to finish share one `_MOVE_LIMIT`
        (60 s) budget, and every request inside it is cut off at the time
        left. Stopping the task after a failure gets its own
        `_CLEANUP_TIMEOUT`, so the call takes at most 65 s.

        Args:
            source_path: Full path to the file/directory to move
            destination_path: Destination path (can be directory or full path with new name)
            overwrite: Whether to overwrite existing files at destination

        Returns:
            Dict with operation result
        """
        formatted_source = self._format_path(source_path)
        formatted_dest = self._format_path(destination_path)

        # Check for critical paths
        self._check_critical_path(formatted_source)
        self._check_critical_path(formatted_dest)

        # Validate paths
        if not formatted_source or formatted_source == "/":
            raise Exception("Invalid source path")

        if not formatted_dest or formatted_dest == "/":
            raise Exception("Invalid destination path")

        # Start the move operation
        deadline = time.monotonic() + _MOVE_LIMIT  # wall-clock, as in search_files
        timed_out = f"Move operation timed out after {_MOVE_LIMIT} seconds"
        try:
            start_data = self._make_request(
                "SYNO.FileStation.CopyMove",
                "3",
                "start",
                deadline=deadline,
                path=formatted_source,
                dest_folder_path=formatted_dest,
                overwrite=overwrite,
                remove_src=True,  # This makes it a move operation instead of copy
            )
        except _DeadlineError:
            raise Exception(timed_out) from None

        task_id = start_data.get("taskid")
        if not task_id:
            raise Exception("Failed to start move task")

        try:
            # Wait for move to complete
            status_data = self._wait_for_task("SYNO.FileStation.CopyMove", "3", task_id, deadline)

            # Check if there were any errors
            if "error" in status_data:
                error_info = status_data["error"]
                raise Exception(f"Move failed: {error_info}")

            # Determine the final destination path
            source_name = os.path.basename(formatted_source)
            if formatted_dest.endswith("/") or not os.path.splitext(formatted_dest)[1]:
                # Destination is a directory
                final_dest = os.path.join(formatted_dest, source_name).replace("\\", "/")
            else:
                # Destination includes the new filename
                final_dest = formatted_dest

            return {
                "success": True,
                "source_path": formatted_source,
                "destination_path": final_dest,
                "task_id": task_id,
                "message": f"Successfully moved '{formatted_source}' to '{final_dest}'",
            }

        except _DeadlineError:
            self._stop_task("SYNO.FileStation.CopyMove", "3", task_id)
            raise Exception(timed_out) from None
        except Exception:
            # Try to stop the task if it's still running
            self._stop_task("SYNO.FileStation.CopyMove", "3", task_id)
            raise
