"""File Station functionality tests."""

from unittest.mock import MagicMock, patch

import pytest
import requests


@pytest.mark.real_nas
class TestSynologyFileStation:
    """Test Synology FileStation operations."""

    @pytest.fixture(scope="class")
    def file_station(self, session_info):
        """Get authenticated FileStation client."""
        from filestation.synology_filestation import SynologyFileStation

        fs = SynologyFileStation(
            session_info["base_url"],
            session_info["session_id"],
            syno_token=session_info.get("syno_token"),
        )

        print("✅ FileStation client ready")
        return fs

    def test_list_shares(self, file_station):
        """Test listing available shares."""
        shares = file_station.list_shares()

        assert isinstance(shares, list)
        assert len(shares) > 0, "No shares found - this is unexpected"

        print(f"📁 Found {len(shares)} shares:")
        for share in shares[:5]:  # Show first 5 shares
            name = share.get("name", "Unknown")
            path = share.get("path", "Unknown")
            writable = share.get("is_writable", False)
            description = share.get("description", "")

            write_status = "✏️" if writable else "👁️"
            print(f"  {write_status} {name} ({path}) - {description}")

    def test_list_root_directory(self, file_station):
        """Test listing root directory contents."""
        try:
            contents = file_station.list_directory("/")

            assert isinstance(contents, list)
            print(f"📂 Root directory has {len(contents)} items")

            # Show some directory contents
            for item in contents[:10]:  # Show first 10 items
                name = item.get("name", "Unknown")
                item_type = item.get("type", "unknown")
                size = item.get("size", 0)

                type_icon = "📁" if item_type == "directory" else "📄"

                if item_type == "file" and size > 0:
                    # Format file size
                    if size > 1024 * 1024 * 1024:
                        size_str = f"({size / (1024 * 1024 * 1024):.1f} GB)"
                    elif size > 1024 * 1024:
                        size_str = f"({size / (1024 * 1024):.1f} MB)"
                    elif size > 1024:
                        size_str = f"({size / 1024:.1f} KB)"
                    else:
                        size_str = f"({size} B)"
                else:
                    size_str = ""

                print(f"  {type_icon} {name} {size_str}")

        except Exception as e:
            # Root directory access might be restricted
            print(f"⚠️  Root directory access failed (may be expected): {e}")
            pytest.skip("Root directory access not permitted")

    def test_list_common_directories(self, file_station):
        """Test listing common directories that typically exist."""
        common_paths = ["/volume1", "/homes", "/home", "/shared"]

        accessible_dirs = []

        for path in common_paths:
            try:
                contents = file_station.list_directory(path)
                accessible_dirs.append(path)
                print(f"✅ {path}: {len(contents)} items")

                # Show a few items from each accessible directory
                for item in contents[:3]:
                    name = item.get("name", "Unknown")
                    item_type = item.get("type", "unknown")
                    type_icon = "📁" if item_type == "directory" else "📄"
                    print(f"    {type_icon} {name}")

            except Exception as e:
                print(f"⚠️  {path}: Not accessible ({str(e)[:50]}...)")

        if not accessible_dirs:
            pytest.skip("No common directories accessible")

        print(f"✅ Accessible directories: {', '.join(accessible_dirs)}")

    def test_get_file_info(self, file_station):
        """Test getting detailed file information."""
        # Try to get info for root first
        test_paths = ["/", "/volume1", "/homes"]

        for path in test_paths:
            try:
                info = file_station.get_file_info(path)

                assert isinstance(info, dict)
                assert "name" in info
                assert "type" in info

                name = info.get("name", "Unknown")
                file_type = info.get("type", "unknown")
                size = info.get("size", 0)
                owner = info.get("owner", "Unknown")
                permissions = info.get("permissions", "Unknown")

                print(f"📋 File info for {path}:")
                print(f"   Name: {name}")
                print(f"   Type: {file_type}")
                print(f"   Size: {size:,} bytes")
                print(f"   Owner: {owner}")
                print(f"   Permissions: {permissions}")

                # If we get here, test passed
                return

            except Exception as e:
                print(f"⚠️  {path}: {str(e)[:50]}...")
                continue

        pytest.skip("No test paths accessible for file info")

    @pytest.mark.slow
    def test_search_functionality(self, file_station):
        """Test file search functionality."""
        # Search in accessible directories
        search_locations = ["/", "/volume1", "/homes"]
        search_pattern = "*.txt"

        for location in search_locations:
            try:
                print(f"🔍 Searching for '{search_pattern}' in {location}...")
                results = file_station.search_files(location, search_pattern)

                assert isinstance(results, list)
                print(f"   Found {len(results)} files")

                # Show first few results
                for result in results[:5]:
                    name = result.get("name", "Unknown")
                    path = result.get("path", "Unknown")
                    size = result.get("size", 0)
                    print(f"   📄 {name} ({path}) - {size:,} bytes")

                # If search worked once, that's enough
                return

            except Exception as e:
                print(f"⚠️  Search in {location} failed: {str(e)[:50]}...")
                continue

        pytest.skip("Search functionality not accessible in any test locations")

    def test_path_formatting(self, file_station):
        """Test internal path formatting."""
        # Test the _format_path method
        test_cases = [
            ("home", "/home"),
            ("/home", "/home"),
            ("home/", "/home"),
            ("/home/", "/home"),
            ("/", "/"),
            ("", "/"),
            ("path/to/file", "/path/to/file"),
        ]

        for input_path, expected in test_cases:
            result = file_station._format_path(input_path)
            assert result == expected, (
                f"Path '{input_path}' should format to '{expected}', got '{result}'"
            )
            print(f"✅ '{input_path}' → '{result}'")

        print("✅ Path formatting tests passed")

    def test_api_accessibility(self, file_station):
        """Test that FileStation API endpoints are accessible."""
        # Verify the client is configured properly
        assert file_station.base_url is not None
        assert file_station.session_id is not None
        assert file_station.api_url is not None

        # Verify API URL format
        assert file_station.api_url.startswith("http")
        assert "webapi" in file_station.api_url.lower()

        print(f"✅ API URL: {file_station.api_url}")
        print(f"✅ Session: {file_station.session_id[:10]}...")

    def test_error_handling(self, file_station):
        """Test error handling for invalid operations."""
        # Test with clearly invalid path
        invalid_path = "/this/path/definitely/does/not/exist/12345"

        try:
            file_station.get_file_info(invalid_path)
            pytest.fail("Expected exception for invalid path")
        except Exception as e:
            print(f"✅ Invalid path correctly rejected: {str(e)[:50]}...")

        # Test with invalid search pattern
        try:
            # This might work or fail depending on implementation
            results = file_station.search_files("/", "")
            print(f"⚠️  Empty search pattern returned {len(results)} results")
        except Exception as e:
            print(f"✅ Empty search pattern correctly rejected: {str(e)[:50]}...")


# Quick connectivity test
def test_filestation_connectivity(session_info):
    """Quick test to verify FileStation is accessible."""
    from filestation.synology_filestation import SynologyFileStation

    try:
        fs = SynologyFileStation(
            session_info["base_url"],
            session_info["session_id"],
            syno_token=session_info.get("syno_token"),
        )

        # Try a simple operation
        shares = fs.list_shares()
        print(f"🔗 FileStation connected: {len(shares)} shares available")
        assert True  # If we get here, connection works

    except Exception as e:
        pytest.fail(f"FileStation connectivity failed: {e}")


def test_filestation_url_construction():
    """Test FileStation URL construction."""
    from filestation.synology_filestation import SynologyFileStation

    base_url = "https://192.168.1.100:5001"
    session_id = "test_session_123"

    fs = SynologyFileStation(base_url, session_id)

    expected_api_url = f"{base_url}/webapi/entry.cgi"
    assert fs.api_url == expected_api_url
    assert fs.base_url == base_url
    assert fs.session_id == session_id

    print(f"✅ URL construction: {fs.api_url}")
    print("✅ FileStation URL construction tests passed")


# ---------------------------------------------------------------------------
# Credential-and-session-leak hardening (PR 1) unit tests — no real NAS needed
# ---------------------------------------------------------------------------


def test_create_file_upload_does_not_put_session_id_in_url():
    """create_file()'s upload request must carry `_sid` in the multipart form
    body, not the URL — a `params=`/hand-built-URL bug would leak the
    session id into the query string even though the request is a POST."""
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "LIVE_SID_create")

    fake_response = MagicMock()
    fake_response.json.return_value = {"success": True}
    fake_response.raise_for_status = MagicMock()

    with patch("filestation.synology_filestation.requests.Session") as mock_session_cls:
        mock_session = MagicMock()
        mock_session.post.return_value = fake_response
        mock_session_cls.return_value.__enter__.return_value = mock_session

        fs.create_file("/share/test.txt", content="hello")

        assert mock_session.post.called
        call = mock_session.post.call_args
        url = call.args[0] if call.args else call.kwargs.get("url")
        assert "LIVE_SID_create" not in url
        assert "?" not in url
        assert call.kwargs["data"]["_sid"] == "LIVE_SID_create"


def test_make_request_redacts_session_id_from_network_error():
    """_make_request()'s GET path must not leak the session id through an
    uncaught RequestException — its str() commonly embeds the full URL,
    which carries `_sid=<session_id>`."""
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "LIVE_SID_req")
    fake_url = f"{fs.api_url}?api=X&_sid=LIVE_SID_req"

    with patch(
        "filestation.synology_filestation.requests.get",
        side_effect=requests.exceptions.ConnectionError(f"Failed to connect: {fake_url}"),
    ):
        with pytest.raises(Exception) as exc_info:
            fs._make_request("SYNO.FileStation.List", "2", "list", path="/share")

    assert "LIVE_SID_req" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# Critical-path check consolidation (PR 2): one helper, applied consistently
# across every path-taking method. True OS-level paths are prefix-matched
# (the path and everything under it is blocked); /volume1 and /homes are
# exact-matched only — they're the raw volume mount and the aggregate
# home-directories share, not places real files live directly, so a real
# share/subfolder underneath (e.g. /volume1/photo, /homes/alice) must stay
# reachable. An earlier version of this PR prefix-matched them too, which
# blocked browsing/reading almost everything on a real NAS — caught in
# review and fixed before merge.
# ---------------------------------------------------------------------------


def test_check_critical_path_blocks_exact_and_nested_paths():
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid")

    with pytest.raises(Exception, match="critical system path"):
        fs._check_critical_path("/etc")
    # Prefix-matched, not just exact — this was the gap between the two
    # previously-separate denylists (one exact-only, one prefix-matching).
    with pytest.raises(Exception, match="critical system path"):
        fs._check_critical_path("/etc/passwd")
    # A share that merely starts with the same characters must NOT match.
    fs._check_critical_path("/etchome")  # no exception


@pytest.mark.parametrize("root", ["/volume1", "/volume2", "/volume3", "/volume42", "/homes"])
def test_check_critical_path_blocks_volume_and_homes_root_only(root):
    """Any /volumeN root and /homes are raw volume mounts and the aggregate
    home-directories share — block the bare root, but a real share or
    subfolder underneath must stay reachable (unlike /etc, these are not
    prefix-matched). Synology NAS units commonly expose more than one
    storage volume, so this must not be hardcoded to /volume1 alone."""
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid")

    with pytest.raises(Exception, match="critical system path"):
        fs._check_critical_path(root)
    fs._check_critical_path(f"{root}/some-share-or-user")  # no exception


def test_check_critical_path_volume_regex_does_not_overmatch():
    """A share that merely starts with "volume" (not a bare /volumeN root)
    must not match — e.g. /volume1backup or /volumes."""
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid")

    fs._check_critical_path("/volume1backup")  # no exception
    fs._check_critical_path("/volumes")  # no exception


@pytest.mark.parametrize(
    "method_name,args",
    [
        ("list_directory", ("/etc",)),
        ("get_file_info", ("/etc",)),
        ("search_files", ("/etc", "*.conf")),
        ("create_directory", ("/etc", "newdir")),
    ],
)
def test_previously_unchecked_methods_now_reject_critical_paths(method_name, args):
    """Before PR 2, only rename_file/get_file_content/move_file/delete
    checked critical paths at all. list_directory, get_file_info,
    search_files, and create_directory had no check whatsoever."""
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid")

    with pytest.raises(Exception, match="critical system path"):
        getattr(fs, method_name)(*args)


def test_delete_uses_the_consolidated_helper_not_a_separate_denylist():
    """delete() used to carry its own independent, prefix-matching denylist;
    it must now go through the one shared `_check_critical_path` helper."""
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid")

    with pytest.raises(Exception, match="critical system path"):
        fs.delete("/var/log/nested/deep")


@pytest.mark.parametrize(
    "raw_path,expected_formatted",
    [
        ("/share/../etc/passwd", "/etc/passwd"),
        ("/homes/alice/../../etc/passwd", "/etc/passwd"),
        ("/volume1/photo/../../../etc", "/etc"),
        ("/homes/../etc", "/etc"),
        ("/a/./b/../c", "/a/c"),
        # Double (or more) leading slashes: posixpath.normpath alone
        # preserves exactly two leading slashes verbatim (a POSIX quirk),
        # which would otherwise let "//etc/passwd" survive unresolved even
        # though the filesystem treats "//" the same as "/".
        ("//etc/passwd", "/etc/passwd"),
        ("///etc/passwd", "/etc/passwd"),
        ("//homes/../../etc/shadow", "/etc/shadow"),
    ],
)
def test_format_path_resolves_dot_dot_before_any_check_runs(raw_path, expected_formatted):
    """`_format_path` must resolve `.`/`..` segments (and collapse repeated
    leading slashes) itself — a prefix-based critical-path check downstream
    only ever sees the literal string, so an unresolved
    `/share/../etc/passwd` or `//etc/passwd` would sail past a check for
    `/etc`."""
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid")
    assert fs._format_path(raw_path) == expected_formatted


@pytest.mark.parametrize(
    "method_name,args",
    [
        ("list_directory", ("/share/../etc",)),
        ("get_file_info", ("/homes/alice/../../etc/passwd",)),
        ("search_files", ("/volume1/../../etc", "*.conf")),
        ("create_directory", ("/homes/../etc", "newdir")),
        ("get_file_info", ("//etc/passwd",)),
        ("list_directory", ("///etc",)),
    ],
)
def test_dot_dot_traversal_cannot_bypass_the_critical_path_check(method_name, args):
    """A `..`-bearing or double-slash-prefixed path that resolves to a
    critical path must still be rejected — the denylist check must see the
    resolved path, not the raw string the caller supplied."""
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid")

    with pytest.raises(Exception, match="critical system path"):
        getattr(fs, method_name)(*args)


# ---------------------------------------------------------------------------
# Connection defaults and bounds (PR 3): search_files gets a polling
# deadline, get_file_content enforces a size cap checked via metadata.
# ---------------------------------------------------------------------------


def test_search_files_times_out_instead_of_polling_forever(monkeypatch):
    """search_files previously polled with `while True` and no deadline —
    an unresponsive NAS would hang this call indefinitely."""
    import time

    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid")

    def fake_make_request(api, version, method, use_post=False, **params):
        if method == "start":
            return {"taskid": "task123"}
        if method == "status":
            return {"finished": False}  # never finishes
        if method == "stop":
            return {}
        raise AssertionError(f"unexpected method {method}")

    monkeypatch.setattr(fs, "_make_request", fake_make_request)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)

    with pytest.raises(Exception, match="timed out"):
        fs.search_files("/share", "*.txt")


def test_search_files_still_returns_results_when_it_finishes_in_time(monkeypatch):
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid")

    calls = {"status_calls": 0}

    def fake_make_request(api, version, method, use_post=False, **params):
        if method == "start":
            return {"taskid": "task123"}
        if method == "status":
            calls["status_calls"] += 1
            return {"finished": calls["status_calls"] >= 2}
        if method == "list":
            return {"files": [{"name": "a.txt", "path": "/share/a.txt", "isdir": False, "size": 3}]}
        if method == "stop":
            return {}
        raise AssertionError(f"unexpected method {method}")

    monkeypatch.setattr(fs, "_make_request", fake_make_request)
    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    results = fs.search_files("/share", "*.txt")
    assert results == [{"name": "a.txt", "path": "/share/a.txt", "type": "file", "size": 3}]


def test_get_file_content_rejects_oversized_file_before_downloading(monkeypatch):
    """The size cap must be enforced via file metadata (get_file_info),
    before any download request is made — not after reading the whole file
    into memory."""
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid", max_file_content_size=100)

    monkeypatch.setattr(
        fs,
        "get_file_info",
        lambda path: {"name": "big.bin", "path": path, "type": "file", "size": 200},
    )

    def fail_if_called(*args, **kwargs):
        raise AssertionError("get_file_content must not download when the size cap is exceeded")

    monkeypatch.setattr("filestation.synology_filestation.requests.get", fail_if_called)

    with pytest.raises(Exception, match="exceeds the configured limit"):
        fs.get_file_content("/share/big.bin")


def _fake_download_response(content_bytes, encoding=None):
    fake_response = MagicMock()
    fake_response.raise_for_status = MagicMock()
    fake_response.headers = {}
    fake_response.encoding = encoding
    fake_response.iter_content = lambda chunk_size=None: iter([content_bytes])
    return fake_response


def test_get_file_content_allows_file_within_size_cap(monkeypatch):
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid", max_file_content_size=100)

    monkeypatch.setattr(
        fs,
        "get_file_info",
        lambda path: {"name": "small.txt", "path": path, "type": "file", "size": 10},
    )

    fake_response = _fake_download_response(b"hi there!!")
    monkeypatch.setattr(
        "filestation.synology_filestation.requests.get", lambda *a, **k: fake_response
    )

    assert fs.get_file_content("/share/small.txt") == "hi there!!"


def test_get_file_content_aborts_mid_download_if_actual_bytes_exceed_the_cap(monkeypatch):
    """The size cap must also be enforced against the bytes actually
    streamed back, not just the get_file_info() pre-check — that check can
    be stale (the file grows between the two requests) or silently absent
    (a response missing a size field fails open to 0). A response that
    claims to be small but streams back more than the cap must still be
    rejected, and before the oversized body is fully buffered."""
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid", max_file_content_size=10)

    monkeypatch.setattr(
        fs,
        "get_file_info",
        lambda path: {"name": "lied.txt", "path": path, "type": "file", "size": 1},
    )

    fake_response = _fake_download_response(b"this is way more than ten bytes")
    monkeypatch.setattr(
        "filestation.synology_filestation.requests.get", lambda *a, **k: fake_response
    )

    with pytest.raises(Exception, match="exceeds the configured limit"):
        fs.get_file_content("/share/lied.txt")


def test_get_file_content_honors_declared_response_encoding(monkeypatch):
    """A declared response.encoding (from a Content-Type charset, when DSM
    sends one) must be used as-is, not overridden by auto-detection."""
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid", max_file_content_size=1000)
    monkeypatch.setattr(
        fs, "get_file_info", lambda path: {"name": "f", "path": path, "type": "file", "size": 5}
    )

    fake_response = _fake_download_response("café".encode("latin-1"), encoding="latin-1")
    monkeypatch.setattr(
        "filestation.synology_filestation.requests.get", lambda *a, **k: fake_response
    )

    assert fs.get_file_content("/share/f") == "café"


def test_decode_downloaded_text_uses_declared_encoding_when_present():
    from filestation.synology_filestation import _decode_downloaded_text

    assert _decode_downloaded_text("café".encode("latin-1"), "latin-1") == "café"


def test_decode_downloaded_text_auto_detects_when_no_declared_encoding(monkeypatch):
    """response.encoding is None for DSM's download endpoint (it never
    sends a charset) — the common case here, not an edge case. This must
    auto-detect rather than blindly assume UTF-8, which would silently
    mangle non-UTF-8 text via errors="replace" — the regression this
    replaces."""
    import charset_normalizer

    from filestation.synology_filestation import _decode_downloaded_text

    monkeypatch.setattr(charset_normalizer, "detect", lambda _content: {"encoding": "latin-1"})

    assert _decode_downloaded_text("café".encode("latin-1"), None) == "café"


def test_decode_downloaded_text_falls_back_to_utf8_if_detection_fails(monkeypatch):
    import charset_normalizer

    from filestation.synology_filestation import _decode_downloaded_text

    def _boom(_content):
        raise RuntimeError("no detector available")

    monkeypatch.setattr(charset_normalizer, "detect", _boom)

    assert _decode_downloaded_text(b"hello", None) == "hello"


def _fake_files_response(size):
    """DSM's SYNO.FileStation.List response shape: "size" (like time/owner/
    perm) is nested under the file object's "additional" key, not at its
    top level."""
    return {
        "files": [
            {
                "name": "f",
                "path": "/share/f",
                "isdir": False,
                "additional": {"size": size},
            }
        ]
    }


def test_get_file_info_reads_size_from_additional_not_top_level(monkeypatch):
    """DSM nests the requested "size" additional field under
    file["additional"]["size"], same as time/owner/perm — not at the file
    object's top level. Without reading it from there, get_file_content's
    size cap never fires against a real NAS."""
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid")
    monkeypatch.setattr(fs, "_make_request", lambda *a, **k: _fake_files_response(5_000_000))

    assert fs.get_file_info("/share/f")["size"] == 5_000_000


def test_list_directory_reads_size_from_additional_not_top_level(monkeypatch):
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid")
    monkeypatch.setattr(fs, "_make_request", lambda *a, **k: _fake_files_response(42))

    assert fs.list_directory("/share")[0]["size"] == 42


def test_get_file_content_size_cap_fires_against_a_realistic_dsm_response(monkeypatch):
    """End-to-end version of the size-cap test that does NOT monkeypatch
    get_file_info directly — exercises the real _make_request →
    additional["size"] parsing path, which the earlier size-cap tests
    skipped by mocking get_file_info wholesale."""
    from filestation.synology_filestation import SynologyFileStation

    fs = SynologyFileStation("https://nas.example.test:5001", "sid", max_file_content_size=100)
    monkeypatch.setattr(fs, "_make_request", lambda *a, **k: _fake_files_response(5_000_000))

    def fail_if_called(*args, **kwargs):
        raise AssertionError("get_file_content must not download when the size cap is exceeded")

    monkeypatch.setattr("filestation.synology_filestation.requests.get", fail_if_called)

    with pytest.raises(Exception, match="exceeds the configured limit"):
        fs.get_file_content("/share/f")
