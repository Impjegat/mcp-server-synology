"""Health monitoring module tests."""

from unittest.mock import patch

import pytest


@pytest.mark.real_nas
class TestSynologyHealth:
    """Test Synology health monitoring operations."""

    def test_system_info(self, session_info):
        """Test getting system information."""
        from health.synology_health import SynologyHealth

        health = SynologyHealth(
            session_info["base_url"],
            session_info["session_id"],
            syno_token=session_info.get("syno_token"),
        )

        result = health.system_info()

        assert isinstance(result, dict)
        if result.get("success"):
            data = result.get("data", {})
            print("✅ System info retrieved")
            print(f"   Data keys: {list(data.keys())}")
        else:
            print(f"⚠️  System info failed: {result.get('error')}")

    def test_utilization(self, session_info):
        """Test getting system utilization."""
        from health.synology_health import SynologyHealth

        health = SynologyHealth(
            session_info["base_url"],
            session_info["session_id"],
            syno_token=session_info.get("syno_token"),
        )

        result = health.utilization()

        assert isinstance(result, dict)
        if result.get("success"):
            print("✅ Utilization data retrieved")
        else:
            print(f"⚠️  Utilization failed: {result.get('error')}")

    def test_disk_list(self, session_info):
        """Test listing physical disks."""
        from health.synology_health import SynologyHealth

        health = SynologyHealth(
            session_info["base_url"],
            session_info["session_id"],
            syno_token=session_info.get("syno_token"),
        )

        result = health.disk_list()

        assert isinstance(result, dict)
        if result.get("success"):
            disks = result.get("data", {}).get("disks", [])
            print(f"✅ Found {len(disks)} disk(s)")
            for disk in disks:
                print(f"   - {disk.get('disk', 'unknown')}: {disk.get('model', 'unknown')}")
        else:
            print(f"⚠️  Disk list failed: {result.get('error')}")

    def test_volume_list(self, session_info):
        """Test listing volumes."""
        from health.synology_health import SynologyHealth

        health = SynologyHealth(
            session_info["base_url"],
            session_info["session_id"],
            syno_token=session_info.get("syno_token"),
        )

        result = health.volume_list()

        assert isinstance(result, dict)
        if result.get("success"):
            volumes = result.get("data", {}).get("volumes", [])
            print(f"✅ Found {len(volumes)} volume(s)")
            for vol in volumes:
                print(f"   - {vol.get('volume_path', 'unknown')}: {vol.get('status', 'unknown')}")
        else:
            print(f"⚠️  Volume list failed: {result.get('error')}")

    def test_storage_pool_list(self, session_info):
        """Test listing storage pools."""
        from health.synology_health import SynologyHealth

        health = SynologyHealth(
            session_info["base_url"],
            session_info["session_id"],
            syno_token=session_info.get("syno_token"),
        )

        result = health.storage_pool_list()

        assert isinstance(result, dict)
        if result.get("success"):
            pools = result.get("data", {}).get("pools", [])
            print(f"✅ Found {len(pools)} storage pool(s)")
        else:
            print(f"⚠️  Storage pool list failed: {result.get('error')}")

    def test_network_info(self, session_info):
        """Test getting network information."""
        from health.synology_health import SynologyHealth

        health = SynologyHealth(
            session_info["base_url"],
            session_info["session_id"],
            syno_token=session_info.get("syno_token"),
        )

        result = health.network_info()

        assert isinstance(result, dict)
        if result.get("success"):
            print("✅ Network info retrieved")
        else:
            print(f"⚠️  Network info failed: {result.get('error')}")

    def test_ups_info(self, session_info):
        """Test getting UPS information."""
        from health.synology_health import SynologyHealth

        health = SynologyHealth(
            session_info["base_url"],
            session_info["session_id"],
            syno_token=session_info.get("syno_token"),
        )

        result = health.ups_info()

        assert isinstance(result, dict)
        # UPS might not be connected, so we just check response
        print(f"UPS info result: {result}")

    def test_package_list(self, session_info):
        """Test listing installed packages."""
        from health.synology_health import SynologyHealth

        health = SynologyHealth(
            session_info["base_url"],
            session_info["session_id"],
            syno_token=session_info.get("syno_token"),
        )

        result = health.package_list()

        assert isinstance(result, dict)
        if result.get("success"):
            packages = result.get("data", {}).get("packages", [])
            print(f"✅ Found {len(packages)} package(s)")
        else:
            print(f"⚠️  Package list failed: {result.get('error')}")

    def test_system_log(self, session_info):
        """Test getting system logs."""
        from health.synology_health import SynologyHealth

        health = SynologyHealth(
            session_info["base_url"],
            session_info["session_id"],
            syno_token=session_info.get("syno_token"),
        )

        result = health.system_log(offset=0, limit=10)

        assert isinstance(result, dict)
        if result.get("success"):
            print("✅ System logs retrieved")
        else:
            print(f"⚠️  System log failed: {result.get('error')}")

    def test_health_summary(self, session_info):
        """Test getting comprehensive health summary."""
        from health.synology_health import SynologyHealth

        health = SynologyHealth(
            session_info["base_url"],
            session_info["session_id"],
            syno_token=session_info.get("syno_token"),
        )

        result = health.health_summary()

        assert isinstance(result, dict)
        if result.get("success"):
            data = result.get("data", {})
            print("✅ Health summary retrieved")
            print(f"   Sections: {list(data.keys())}")
        else:
            print(f"⚠️  Health summary failed: {result.get('error')}")


class TestSystemInfoFallback:
    """Unit tests for system_info DSM 6/7 fallback behaviour (no live NAS required)."""

    def _make_health(self):
        from health.synology_health import SynologyHealth

        return SynologyHealth("http://nas:5000", "fake-sid", verify_ssl=False)

    def test_primary_success(self):
        """Uses SYNO.Core.System when it returns data."""
        health = self._make_health()
        expected = {"success": True, "data": {"model": "DS920+"}}
        with patch.object(health._api, "get", return_value=expected) as mock_get:
            result = health.system_info()
        assert result == expected
        mock_get.assert_called_once_with("SYNO.Core.System", "info", 1, None)

    def test_fallback_uses_version_2(self):
        """Falls back to SYNO.DSM.Info v2 when SYNO.Core.System fails."""
        health = self._make_health()
        dsm_info = {
            "success": True,
            "data": {"model": "DS1621+", "version_string": "DSM 7.3.2-86009"},
        }

        def side_effect(api, method, version=1, extra_params=None):
            if api == "SYNO.Core.System":
                return {"success": False, "error": {"code": 1006}}
            if api == "SYNO.DSM.Info" and version == 2:
                return dsm_info
            return {"success": False, "error": {"code": 999}}

        with patch.object(health._api, "get", side_effect=side_effect):
            result = health.system_info()
        assert result == dsm_info

    def test_both_fail(self):
        """Returns the fallback error when both APIs fail."""
        health = self._make_health()
        with patch.object(
            health._api, "get", return_value={"success": False, "error": {"code": 104}}
        ):
            result = health.system_info()
        assert not result.get("success")


def test_health_url_construction():
    """Test URL handling in health module."""
    from health.synology_health import SynologyHealth

    # Test URL trailing slash handling
    health1 = SynologyHealth("https://nas.example.com:5001/", "test_session")
    assert health1.base_url == "https://nas.example.com:5001"

    health2 = SynologyHealth("http://nas.example.com:5000", "test_session")
    assert health2.base_url == "http://nas.example.com:5000"

    print("✅ URL construction tests passed")


def test_health_verify_ssl_parameter():
    """Test verify_ssl parameter propagation."""
    from health.synology_health import SynologyHealth

    health1 = SynologyHealth("https://nas.example.com:5001", "test_session", verify_ssl=True)
    assert health1.verify_ssl is True

    health2 = SynologyHealth("https://nas.example.com:5001", "test_session", verify_ssl=False)
    assert health2.verify_ssl is False

    print("✅ verify_ssl parameter tests passed")


# Every DSM API the summary's seven checks call first, by the key they fill.
_UPS_API = "SYNO.Core.ExternalDevice.UPS"
_SUMMARY_KEYS = ["system", "utilization", "disks", "volumes", "storage_pools", "network", "ups"]


class TestHealthSummaryAggregation:
    """health_summary() must say how complete it is (no live NAS required)."""

    def _make_health(self):
        from health.synology_health import SynologyHealth

        return SynologyHealth("http://nas:5000", "fake-sid", verify_ssl=False)

    @staticmethod
    def _dsm(failing_apis):
        """A fake DSM: every API answers with data, except `failing_apis`."""
        calls = []

        def get(api, method, version=1, extra_params=None):
            calls.append(api)
            if api in failing_apis or failing_apis == "all":
                return {"success": False, "error": {"code": "network_error", "message": "down"}}
            return {"success": True, "data": {"from": api}}

        get.calls = calls
        return get

    def test_when_every_check_fails_the_summary_is_a_failure(self):
        """The P2 finding: an unreachable NAS used to come back as
        `{"success": True, "data": {}}`."""
        health = self._make_health()
        get = self._dsm("all")

        with patch.object(health._api, "get", side_effect=get):
            result = health.health_summary()

        assert result["success"] is False
        assert result["error"]["code"] == "health_checks_failed"
        assert "data" not in result
        failed = result["error"]["failed_checks"]
        assert [f["check"] for f in failed] == _SUMMARY_KEYS
        assert all(f["error"]["code"] == "network_error" for f in failed)
        assert len(get.calls) == 11  # each check, including the DSM 6 fallbacks

    def test_when_some_checks_fail_the_summary_says_it_is_partial(self):
        health = self._make_health()

        with patch.object(health._api, "get", side_effect=self._dsm({_UPS_API})):
            result = health.health_summary()

        assert result["success"] is True
        assert result["status"] == "partial"
        assert result["message"] == "Some health checks could not be completed."
        assert [f["check"] for f in result["failed_checks"]] == ["ups"]
        assert result["failed_checks"][0]["error"]["message"] == "down"
        assert list(result["data"]) == [k for k in _SUMMARY_KEYS if k != "ups"]
        # The warning is read before the data it qualifies.
        assert list(result)[:4] == ["success", "status", "message", "failed_checks"]

    def test_when_every_check_succeeds_the_summary_is_complete(self):
        health = self._make_health()

        with patch.object(health._api, "get", side_effect=self._dsm(set())):
            result = health.health_summary()

        assert result["success"] is True
        assert result["status"] == "complete"
        assert "failed_checks" not in result and "message" not in result
        assert list(result["data"]) == _SUMMARY_KEYS

    def test_a_check_whose_failure_carries_no_error_is_still_reported(self):
        health = self._make_health()

        def get(api, method, version=1, extra_params=None):
            return {"success": api != _UPS_API, "data": {}}  # failure with no "error" key

        with patch.object(health._api, "get", side_effect=get):
            result = health.health_summary()

        assert result["failed_checks"] == [{"check": "ups", "error": {}}]
