"""Which NAS folders a broker client may reach.

The folder policy is checked on the path as the NAS will see it, so these tests
cover traversal, lookalike names and Unicode; and again on where DSM says a path
really lives, so a symbolic link cannot lead out of a root. The File Station and
Download Station tests use a tiny fake DSM and fail if a request that should have
been refused reaches it.
"""

import unicodedata

import pytest

from broker.errors import AuthorizationDenied
from broker.file_policy import FolderPolicy, canonicalize
from tests.broker_support import FakeClock, FakeDSM

URL = "https://nas1.example.test:5001"


def _policy(roots=("/docs",), deny=(), **kwargs):
    return FolderPolicy({"nas1": list(roots)}, deny=list(deny), **kwargs)


class TestCanonicalize:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("/docs/a.txt", "/docs/a.txt"),
            ("docs/a.txt", "/docs/a.txt"),
            ("//docs///a.txt", "/docs/a.txt"),
            ("/docs/./a.txt", "/docs/a.txt"),
            ("/docs/sub/../a.txt", "/docs/a.txt"),
            ("/docs/../etc/passwd", "/etc/passwd"),
            ("/../../etc", "/etc"),
            ("/docs/", "/docs"),
            ("/", "/"),
        ],
    )
    def test_it_resolves_a_path_the_way_the_nas_will(self, raw, expected):
        assert canonicalize(raw) == expected

    def test_it_uses_nfc_unicode(self):
        decomposed = unicodedata.normalize("NFD", "/docs/caf\u00e9")
        assert decomposed != "/docs/caf\u00e9"
        assert canonicalize(decomposed) == "/docs/caf\u00e9"

    @pytest.mark.parametrize(
        "raw", ["/docs/a\\b", "/docs/a\x00b", "/docs/a\nb", "/docs/\x7f", "C:\\docs", None, 5]
    )
    def test_a_path_that_cannot_be_judged_is_refused(self, raw):
        with pytest.raises(AuthorizationDenied):
            canonicalize(raw)


class TestRoots:
    def test_a_root_and_everything_under_it_is_allowed(self):
        policy = _policy()
        assert policy.allows("nas1", "/docs")
        assert policy.allows("nas1", "/docs/a/b/c.txt")
        assert policy.allows("nas1", "docs//a")

    @pytest.mark.parametrize(
        "path",
        [
            "/",
            "/etc/passwd",
            "/docs2",
            "/docs2/a.txt",
            "/doc",
            "/documents",
            "/docs/../photos",
            "/docs/../../etc",
            "/photos/docs",
            "//photos//docs",
            "/Docs",
            "/DOCS/a.txt",
        ],
    )
    def test_everything_else_is_denied(self, path):
        assert not _policy().allows("nas1", path)

    def test_the_closest_root_is_reported(self):
        policy = _policy(roots=("/a", "/a/b"))
        assert policy.root_for("nas1", "/a/b/c") == "/a/b"
        assert policy.root_for("nas1", "/a/x") == "/a"
        assert policy.root_for("nas1", "/c") is None

    def test_a_nas_with_no_roots_allows_nothing(self):
        assert not _policy().allows("nas2", "/docs")
        assert not FolderPolicy({}).allows("nas1", "/docs")

    def test_a_root_of_slash_is_refused(self):
        with pytest.raises(ValueError, match="may not be"):
            FolderPolicy({"nas1": ["/"]})
        with pytest.raises(ValueError, match="may not be"):
            FolderPolicy({"nas1": ["/docs/.."]})

    def test_check_returns_the_canonical_path_or_refuses(self):
        policy = _policy()
        assert policy.check("nas1", "docs/./a.txt") == "/docs/a.txt"
        with pytest.raises(AuthorizationDenied, match="outside the folders"):
            policy.check("nas1", "/etc")

    def test_the_refusal_does_not_say_where_anything_is(self):
        with pytest.raises(AuthorizationDenied) as error:
            _policy().check("nas1", "/volume1/secret-place")
        assert "volume1" not in str(error.value)


class TestDeniedLocations:
    @pytest.mark.parametrize(
        "path",
        [
            "/docs/.env",
            "/docs/.ENV",
            "/docs/app/.env.local",
            "/docs/secrets.yaml",
            "/docs/Credentials.json",
            "/docs/secrets/a.txt",
            "/docs/Credentials/a.txt",
            "/docs/server.pem",
            "/docs/id.KEY",
            "/docs/vault.kdbx",
            "/docs/.ssh/id_rsa",
            "/docs/.aws/credentials",
            "/docs/synology-mcp/settings.json",
            "/docs/.htpasswd",
        ],
    )
    def test_secret_looking_names_are_denied_inside_an_allowed_root(self, path):
        assert not _policy().allows("nas1", path)

    @pytest.mark.parametrize(
        "path", ["/docs/environment.txt", "/docs/secretary.txt", "/docs/keys.txt"]
    )
    def test_ordinary_names_that_only_look_similar_are_allowed(self, path):
        assert _policy().allows("nas1", path)

    def test_an_administrator_can_deny_a_folder_inside_a_root(self):
        policy = _policy(deny=["/docs/Private"])
        assert policy.allows("nas1", "/docs/public/a.txt")
        assert not policy.allows("nas1", "/docs/private")
        assert not policy.allows("nas1", "/docs/PRIVATE/a.txt")
        assert policy.allows("nas1", "/docs/privateer")

    def test_a_root_that_is_itself_denied_allows_nothing(self):
        assert not _policy(roots=("/secrets",)).allows("nas1", "/secrets/a.txt")


class TestShareVisibility:
    def test_a_share_is_visible_if_it_holds_or_is_an_allowed_root(self):
        policy = _policy(roots=("/docs", "/photos/2026"))
        assert policy.share_visible("nas1", "/docs")
        assert policy.share_visible("nas1", "/photos")  # holds an allowed folder
        assert not policy.share_visible("nas1", "/music")
        assert not policy.share_visible("nas1", "/docs2")

    def test_a_denied_share_is_not_visible(self):
        assert not _policy(roots=("/docs",), deny=["/docs"]).share_visible("nas1", "/docs")

    def test_a_share_that_cannot_be_judged_is_not_visible(self):
        assert not _policy().share_visible("nas1", "/docs\\x")


class TestRealPaths:
    """`verify_real` judges where DSM says a path really is."""

    def _verify(self, policy, requested, real, root_real="/volume1/docs"):
        policy.guard("nas1").verify_real(requested, real, lambda root: root_real)

    def test_a_real_path_inside_the_real_root_is_allowed(self):
        self._verify(_policy(), "/docs/a.txt", "/volume1/docs/a.txt")
        self._verify(_policy(), "/docs", "/volume1/docs")

    @pytest.mark.parametrize(
        "real",
        [
            "/volume1/other/a.txt",  # a link leading elsewhere
            "/volume1/docs2/a.txt",  # a lookalike of the root
            "/volume1/docs/../other",  # climbs out after resolving
            "/volume1",
            "/",
            "/volume1/docs/.ssh/id_rsa",  # inside the root but a denied name
        ],
    )
    def test_a_real_path_outside_is_refused(self, real):
        with pytest.raises(AuthorizationDenied):
            self._verify(_policy(), "/docs/a.txt", real)

    @pytest.mark.parametrize(
        "real,root_real",
        [(None, "/volume1/docs"), ("/volume1/docs/a", None), ("", "/volume1/docs")],
    )
    def test_what_cannot_be_established_is_refused(self, real, root_real):
        with pytest.raises(AuthorizationDenied):
            self._verify(_policy(), "/docs/a.txt", real, root_real)

    def test_a_path_with_no_root_is_refused(self):
        with pytest.raises(AuthorizationDenied):
            self._verify(_policy(), "/photos/a.txt", "/volume1/docs/a.txt")

    def test_the_real_root_is_asked_for_once_and_remembered_briefly(self):
        clock = FakeClock()
        policy = _policy(clock=clock, real_root_ttl=60)
        asked = []

        def resolve(root):
            asked.append(root)
            return "/volume1/docs"

        guard = policy.guard("nas1")
        for _ in range(3):
            guard.verify_real("/docs/a.txt", "/volume1/docs/a.txt", resolve)
        assert asked == ["/docs"]

        clock.advance(61)
        guard.verify_real("/docs/a.txt", "/volume1/docs/a.txt", resolve)
        assert asked == ["/docs", "/docs"]


# ----------------------------------------------------------------------------
# File Station
# ----------------------------------------------------------------------------


@pytest.fixture
def station():
    """A File Station limited to /docs, whose DSM is `fake`."""
    from filestation import SynologyFileStation

    policy = _policy(roots=("/docs",))
    fs = SynologyFileStation(URL, "SID", folder_guard=policy.guard("nas1"))
    fs.fake = FakeDSM(
        real_paths={
            "/docs": "/volume1/docs",
            "/docs/a.txt": "/volume1/docs/a.txt",
            "/docs/link": "/volume1/elsewhere",
            "/docs/sub": "/volume1/docs/sub",
        }
    )
    fs._make_request = fs.fake
    return fs


def _without_a_guard():
    from filestation import SynologyFileStation

    return SynologyFileStation(URL, "SID")


class TestFileStationFolders:
    def test_a_folder_inside_a_root_is_listed(self, station):
        station.fake.listing = [{"name": "a.txt", "path": "/docs/a.txt", "isdir": False}]
        assert [e["name"] for e in station.list_directory("/docs")] == ["a.txt"]

    @pytest.mark.parametrize(
        "path", ["/", "/music", "/docs2", "/docs/../music", "//music", "/volume1/docs"]
    )
    def test_a_folder_outside_is_refused_before_any_request(self, station, path):
        with pytest.raises(Exception):
            station.list_directory(path)
        assert station.fake.calls == []

    def test_the_critical_path_check_still_comes_first(self, station):
        with pytest.raises(Exception, match="critical system path"):
            station.list_directory("/etc")
        assert station.fake.calls == []

    def test_a_link_leading_out_of_the_root_is_refused_and_never_listed(self, station):
        with pytest.raises(AuthorizationDenied):
            station.list_directory("/docs/link")
        assert ("SYNO.FileStation.List", "list") not in station.fake.methods()

    def test_a_path_that_exists_but_whose_real_location_dsm_omits_is_refused(self, station):
        """Not judged by its parent: a link whose target DSM will not name could
        otherwise pass as an ordinary folder inside the root."""
        original = station.fake.__call__

        def omit_real_path(api, version, method, use_post=False, **params):
            result = original(api, version, method, use_post, **params)
            if method == "getinfo" and params.get("path") == "/docs/sub":
                result["files"][0]["additional"].pop("real_path")
            return result

        station._make_request = omit_real_path
        with pytest.raises(AuthorizationDenied):
            station.list_directory("/docs/sub")
        assert ("SYNO.FileStation.List", "list") not in station.fake.methods()

    def test_a_path_that_does_not_exist_is_judged_by_its_nearest_parent(self, station):
        station.fake.listing = []
        assert station.list_directory("/docs/not/there/yet") == []

    def test_file_info_inside_is_returned_and_a_link_out_is_refused(self, station):
        assert station.get_file_info("/docs/a.txt")["path"] == "/docs/a.txt"
        with pytest.raises(AuthorizationDenied):
            station.get_file_info("/docs/link")

    def test_a_missing_file_is_not_reported_as_one_that_exists(self, station):
        # Not under any link either: its nearest existing parent is /docs.
        with pytest.raises(Exception, match="File not found"):
            station.get_file_info("/docs/missing.txt")

    def test_content_is_never_downloaded_for_a_path_outside(self, station, monkeypatch):
        def no_download(*args, **kwargs):
            raise AssertionError("a download request was made")

        monkeypatch.setattr("filestation.synology_filestation.requests.get", no_download)
        for path in ("/music/a.txt", "/docs/link"):
            with pytest.raises(Exception):
                station.get_file_content(path)

    def test_the_share_list_shows_only_shares_that_hold_an_allowed_folder(self, station):
        station.fake.shares = [
            {"name": "docs", "path": "/docs"},
            {"name": "music", "path": "/music"},
            {"name": "docs2", "path": "/docs2"},
            {"name": "nameless"},
        ]
        assert [s["name"] for s in station.list_shares()] == ["docs"]

    def test_without_a_policy_nothing_is_filtered(self):
        fs = _without_a_guard()
        fs._make_request = FakeDSM(shares=[{"name": "music", "path": "/music"}])
        assert [s["name"] for s in fs.list_shares()] == ["music"]
        assert fs._make_request.methods() == [("SYNO.FileStation.List", "list_share")]


class TestFileStationSearch:
    def test_hits_outside_the_root_or_leading_out_of_it_are_dropped(self, station):
        station.fake.real_paths["/docs/sub/x.txt"] = "/volume1/docs/sub/x.txt"
        station.fake.hits = [
            {
                "name": "x.txt",
                "path": "/docs/sub/x.txt",
                "additional": {"real_path": "/volume1/docs/sub/x.txt"},
            },
            {
                "name": "y.txt",
                "path": "/music/y.txt",
                "additional": {"real_path": "/volume1/music/y.txt"},
            },
            {
                "name": "l.txt",
                "path": "/docs/l.txt",
                "additional": {"real_path": "/volume1/elsewhere/l.txt"},
            },
            {"name": "n.txt", "path": "/docs/n.txt"},  # no real path reported
            {
                "name": ".env",
                "path": "/docs/.env",
                "additional": {"real_path": "/volume1/docs/.env"},
            },
        ]

        hits = station.search_files("/docs", "*.txt")

        assert [h["name"] for h in hits] == ["x.txt"]

    def test_the_search_asks_dsm_where_each_hit_really_is(self, station):
        station.search_files("/docs", "*.txt")
        list_call = next(
            c for c in station.fake.calls if c[:2] == ("SYNO.FileStation.Search", "list")
        )
        assert list_call[2]["additional"] == '["real_path"]'

    def test_a_search_outside_a_root_never_starts(self, station):
        with pytest.raises(AuthorizationDenied):
            station.search_files("/music", "*.mp3")
        assert ("SYNO.FileStation.Search", "start") not in station.fake.methods()

    def test_without_a_policy_the_search_is_unchanged(self):
        fs = _without_a_guard()
        fs._make_request = FakeDSM(hits=[{"name": "y", "path": "/music/y"}])
        assert [h["name"] for h in fs.search_files("/music", "y")] == ["y"]
        list_call = next(
            c for c in fs._make_request.calls if c[:2] == ("SYNO.FileStation.Search", "list")
        )
        assert "additional" not in list_call[2]


class TestFileStationWrites:
    """Changing tools are off by default; if an administrator turns them on, the
    same folders apply, and a refused change never reaches the NAS."""

    @pytest.mark.parametrize(
        "call",
        [
            lambda fs: fs.rename_file("/music/a.txt", "b.txt"),
            lambda fs: fs.rename_file("/docs/link", "b"),
            lambda fs: fs.create_file("/music/new.txt", "x"),
            lambda fs: fs.create_directory("/music", "new"),
            lambda fs: fs.delete("/music/a.txt"),
            lambda fs: fs.delete("/docs/link"),
            lambda fs: fs.move_file("/docs/a.txt", "/music/a.txt"),
            lambda fs: fs.move_file("/music/a.txt", "/docs/a.txt"),
            lambda fs: fs.move_file("/docs/link", "/docs/a2.txt"),
        ],
    )
    def test_a_refused_change_never_reaches_the_nas(self, station, call):
        with pytest.raises(Exception):
            call(station)
        assert not station.fake.changed_something()

    def test_a_new_file_is_judged_by_the_nearest_folder_that_exists(self, station):
        # /docs/new does not exist yet; /docs does, and is inside the root.
        station._verify_location("/docs/new/deeper/file.txt")

    def test_a_new_file_under_a_link_out_is_refused(self, station):
        with pytest.raises(AuthorizationDenied):
            station._verify_location("/docs/link/new.txt")

    def test_a_new_file_whose_nearest_folder_is_not_inside_a_root_is_refused(self, station):
        station.fake.real_paths["/music"] = "/volume1/music"
        with pytest.raises(AuthorizationDenied):
            station._verify_location("/music/new.txt")


# ----------------------------------------------------------------------------
# Download Station
# ----------------------------------------------------------------------------


@pytest.fixture
def downloads(monkeypatch):
    from downloadstation import SynologyDownloadStation

    guard = _policy(roots=("/downloads",)).guard("nas1")
    ds = SynologyDownloadStation(URL, "SID", folder_guard=guard)

    def no_request(*args, **kwargs):
        raise AssertionError("a request reached the NAS")

    monkeypatch.setattr("downloadstation.synology_downloadstation.requests.get", no_request)
    monkeypatch.setattr("downloadstation.synology_downloadstation.requests.post", no_request)
    return ds


class TestDownloadStationFolders:
    def test_a_destination_outside_the_root_is_refused_before_any_request(self, downloads):
        with pytest.raises(AuthorizationDenied):
            downloads.create_task("https://files.example.org/a.iso", destination="music")
        with pytest.raises(AuthorizationDenied):
            downloads.create_task("https://files.example.org/a.iso", destination="/docs/x")

    def test_the_default_destination_is_judged_too(self, downloads):
        # Policy allows /downloads but the default folder name is checked, not assumed.
        downloads.get_default_destination = lambda: "music"
        with pytest.raises(AuthorizationDenied):
            downloads.create_task("https://files.example.org/a.iso")

    def test_listing_a_folder_outside_is_refused(self, downloads):
        with pytest.raises(AuthorizationDenied):
            downloads.list_downloaded_files("music")

    def test_an_outside_folder_is_not_probed_even_to_suggest_it(self, downloads):
        assert downloads._check_destination_exists("music") is False
        assert downloads._check_destination_exists("../etc") is False
