# src/health/synology_health.py - Synology NAS health monitoring
# Supports both DSM 6 and DSM 7 APIs with automatic fallback.

from typing import Any, Dict, List, Optional

from utils.synology_api import SynologyAPIClient


class SynologyHealth:
    """Queries Synology DSM APIs for system health, storage, network, and UPS status."""

    def __init__(
        self,
        base_url: str,
        session_id: str,
        verify_ssl: bool = True,
        syno_token: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.session_id = session_id
        self.verify_ssl = verify_ssl
        self.syno_token = syno_token
        self._api = SynologyAPIClient(base_url, session_id, verify_ssl, syno_token=syno_token)

    def _api_call(
        self, api: str, method: str, version: int = 1, extra_params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make an authenticated call to /webapi/entry.cgi."""
        return self._api.get(api, method, version, extra_params)

    def _api_call_with_fallback(
        self,
        primary_api: str,
        primary_method: str,
        fallback_api: str,
        fallback_method: str,
        version: int = 1,
        extra_params: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Try the primary API, fall back to an alternative if it fails."""
        result = self._api_call(primary_api, primary_method, version, extra_params)
        if result.get("success"):
            return result
        return self._api_call(fallback_api, fallback_method, version, extra_params)

    # ------------------------------------------------------------------
    # System
    # ------------------------------------------------------------------

    def system_info(self) -> Dict[str, Any]:
        """Get system model, serial, DSM version, uptime, temperature."""
        result = self._api_call("SYNO.Core.System", "info")
        if result.get("success"):
            return result
        # SYNO.DSM.Info requires version 2 on DSM 7.x (minVersion=2, maxVersion=2)
        return self._api_call("SYNO.DSM.Info", "getinfo", 2)

    def utilization(self) -> Dict[str, Any]:
        """Get real-time CPU, memory, swap, and disk I/O utilization."""
        return self._api_call("SYNO.Core.System.Utilization", "get")

    # ------------------------------------------------------------------
    # Storage — uses SYNO.Storage.CGI.Storage on DSM 6 as fallback
    # ------------------------------------------------------------------

    def _storage_load_info(self) -> Dict[str, Any]:
        """DSM 6 fallback: loads all storage info in one call."""
        return self._api_call("SYNO.Storage.CGI.Storage", "load_info")

    def disk_list(self) -> Dict[str, Any]:
        """List all physical disks with SMART status, model, temp, size."""
        result = self._api_call("SYNO.Core.Storage.Disk", "list")
        if result.get("success"):
            return result
        # DSM 6 fallback
        storage = self._storage_load_info()
        if storage.get("success"):
            return {"success": True, "data": {"disks": storage["data"].get("disks", [])}}
        return storage

    def disk_smart_info(self, disk_id: str) -> Dict[str, Any]:
        """Get detailed SMART attributes for a specific disk."""
        result = self._api_call(
            "SYNO.Core.Storage.Disk", "get_smart_info", extra_params={"disk": disk_id}
        )
        if result.get("success"):
            return result
        # DSM 6 fallback
        return self._api_call("SYNO.Storage.CGI.Smart", "get")

    def volume_list(self) -> Dict[str, Any]:
        """List all volumes with status, size, usage, filesystem type."""
        result = self._api_call("SYNO.Core.Storage.Volume", "list")
        if result.get("success"):
            return result
        # DSM 6 fallback
        storage = self._storage_load_info()
        if storage.get("success"):
            return {"success": True, "data": {"volumes": storage["data"].get("volumes", [])}}
        return storage

    def storage_pool_list(self) -> Dict[str, Any]:
        """List RAID/storage pools with level, status, member disks."""
        result = self._api_call("SYNO.Core.Storage.Pool", "list")
        if result.get("success"):
            return result
        # DSM 6 fallback
        storage = self._storage_load_info()
        if storage.get("success"):
            return {"success": True, "data": {"pools": storage["data"].get("storagePools", [])}}
        return storage

    # ------------------------------------------------------------------
    # Network
    # ------------------------------------------------------------------

    def network_info(self) -> Dict[str, Any]:
        """Get network interface status and transfer rates."""
        return self._api_call("SYNO.Core.Network", "get")

    # ------------------------------------------------------------------
    # UPS
    # ------------------------------------------------------------------

    def ups_info(self) -> Dict[str, Any]:
        """Get UPS status, battery level, power readings."""
        return self._api_call("SYNO.Core.ExternalDevice.UPS", "get")

    # ------------------------------------------------------------------
    # Services / Packages
    # ------------------------------------------------------------------

    def package_list(self) -> Dict[str, Any]:
        """List installed packages and their running status."""
        return self._api_call("SYNO.Core.Package", "list")

    # ------------------------------------------------------------------
    # Logs
    # ------------------------------------------------------------------

    def system_log(self, offset: int = 0, limit: int = 50) -> Dict[str, Any]:
        """Get recent system log entries."""
        return self._api_call(
            "SYNO.Core.SyslogClient.Log",
            "list",
            extra_params={"offset": str(offset), "limit": str(limit)},
        )

    # ------------------------------------------------------------------
    # Combined summary
    # ------------------------------------------------------------------

    # (key in the summary, SynologyHealth method that produces it, optional).
    # An optional check covers something a NAS may simply not have — a UPS —
    # so DSM saying the API isn't available is not a gap in the summary.
    _SUMMARY_CHECKS = (
        ("system", "system_info", False),
        ("utilization", "utilization", False),
        ("disks", "disk_list", False),
        ("volumes", "volume_list", False),
        ("storage_pools", "storage_pool_list", False),
        ("network", "network_info", False),
        ("ups", "ups_info", True),
    )

    # DSM's documented "this NAS doesn't offer that" codes: the API (102), the
    # method (103) or the requested version (104) doesn't exist. Compared as
    # strings because the error code may arrive as an int or a string.
    _API_UNAVAILABLE_CODES = frozenset({"102", "103", "104"})

    def health_summary(self) -> Dict[str, Any]:
        """Aggregate system info, utilization, disk health, volume status,
        storage pools, network, and UPS into one result.

        The result says how complete it is, so a summary with holes is never
        mistaken for a clean bill of health:

        - every check succeeded: `success: True`, `status: "complete"`;
        - some failed: `success: True`, `status: "partial"`, a `message`, and
          `failed_checks` (each failed check and its error) next to the
          `data` that was gathered;
        - all failed: `success: False` with the same `failed_checks` in the
          error, which is what an unreachable NAS looks like.

        An optional check (the UPS) that DSM reports as not available on this
        NAS is neither a success nor a failure: it is listed under
        `unavailable_checks` and does not make the summary partial, so a NAS
        without that feature can still be `complete`. Any other error from it
        — a network failure, a permission error — is a failed check like any
        other.
        """
        summary: Dict[str, Any] = {}
        failed_checks: List[Dict[str, Any]] = []
        unavailable_checks: List[Dict[str, Any]] = []

        for key, method_name, optional in self._SUMMARY_CHECKS:
            result = getattr(self, method_name)()
            if result.get("success"):
                summary[key] = result.get("data", {})
                continue
            error = result.get("error", {})
            entry = {"check": key, "error": error}
            code = error.get("code") if isinstance(error, dict) else None
            if optional and str(code) in self._API_UNAVAILABLE_CODES:
                unavailable_checks.append(entry)
            else:
                failed_checks.append(entry)

        if not summary:
            return {
                "success": False,
                "error": {
                    "code": "health_checks_failed",
                    "message": "None of the health checks could be completed.",
                    "failed_checks": failed_checks,
                },
            }
        outcome: Dict[str, Any] = {"success": True}
        if failed_checks:
            outcome["status"] = "partial"
            outcome["message"] = "Some health checks could not be completed."
            outcome["failed_checks"] = failed_checks
        else:
            outcome["status"] = "complete"
        if unavailable_checks:
            outcome["unavailable_checks"] = unavailable_checks
        outcome["data"] = summary
        return outcome
