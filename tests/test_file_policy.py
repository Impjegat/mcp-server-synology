"""Which NAS folders a broker client may reach.

The folder policy is checked on the path as the NAS will see it, so these tests
cover traversal, lookalike names and Unicode; and again on where DSM says a path
really lives, so a symbolic link cannot lead out of a root. The File Station and
Download Station tests use a tiny fake DSM and fail if a request that should have
been refused reaches it.
"""

import copy
import json
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

    def test_a_failed_lookup_is_never_remembered(self):
        """One transient error from the NAS must not block a root for the whole
        lifetime of the cache."""
        policy = _policy(real_root_ttl=300)
        answers = iter([None, None, "/volume1/docs"])
        asked = []

        def resolve(root):
            asked.append(root)
            return next(answers)

        guard = policy.guard("nas1")
        for _ in range(2):
            with pytest.raises(AuthorizationDenied):
                guard.verify_real("/docs/a.txt", "/volume1/docs/a.txt", resolve)
        guard.verify_real("/docs/a.txt", "/volume1/docs/a.txt", resolve)  # recovers at once
        guard.verify_real("/docs/a.txt", "/volume1/docs/a.txt", resolve)  # and now it is remembered

        assert asked == ["/docs", "/docs", "/docs"]


class TestDeniedFoldersInThePhysicalNamespace:
    """`deny_paths` are share paths (`/docs/private`); `verify_real` is handed where
    DSM says a target really lives (`/volume1/docs/private/x`). A denied folder has
    to be judged in the same namespace as the target, or a link into it passes
    (implementation review R02)."""

    @staticmethod
    def _dsm(locations):
        """A `lookup(path) -> (found, real)` over a dict; a path that is not in it
        does not exist. Records what was asked."""
        asked = []

        def lookup(path):
            asked.append(path)
            if path not in locations:
                return False, None
            return True, locations[path]

        lookup.asked = asked
        return lookup

    @staticmethod
    def _verify(policy, requested, real, lookup, root_real="/volume1/docs"):
        policy.guard("nas1").verify_real(requested, real, lambda root: root_real, lookup)

    def _denying(self, **kwargs):
        return _policy(deny=["/docs/private"], **kwargs)

    def test_r02_a_target_inside_the_real_location_of_a_denied_folder_is_refused(self):
        lookup = self._dsm({"/docs/private": "/volume1/docs/private"})
        for real in ("/volume1/docs/private", "/volume1/docs/private/secret.txt"):
            with pytest.raises(AuthorizationDenied):
                self._verify(self._denying(), "/docs/shortcut/secret.txt", real, lookup)

    def test_a_lookalike_of_the_denied_folder_is_allowed(self):
        lookup = self._dsm({"/docs/private": "/volume1/docs/private"})
        self._verify(self._denying(), "/docs/a.txt", "/volume1/docs/privateer/a.txt", lookup)
        self._verify(self._denying(), "/docs/a.txt", "/volume1/docs/public/a.txt", lookup)

    def test_r02_a_denied_folder_that_is_itself_a_link_is_followed(self):
        lookup = self._dsm({"/docs/private": "/volume1/docs/archive/vault"})
        with pytest.raises(AuthorizationDenied):
            self._verify(self._denying(), "/docs/alias/y", "/volume1/docs/archive/vault/y", lookup)
        # The link's own place, once it points elsewhere, is not what is denied.
        self._verify(self._denying(), "/docs/private2/y", "/volume1/docs/private/y", lookup)

    def test_r02_a_denied_folder_that_does_not_exist_is_judged_by_its_nearest_parent(self):
        """Nothing to protect today, but a link made to where it would be must not
        become a way in once it exists."""
        lookup = self._dsm({"/docs": "/volume1/docs"})
        with pytest.raises(AuthorizationDenied):
            self._verify(self._denying(), "/docs/shortcut", "/volume1/docs/private/x", lookup)
        self._verify(self._denying(), "/docs/a.txt", "/volume1/docs/a.txt", lookup)

    def test_a_denied_folder_whose_whole_path_is_missing_protects_nothing(self):
        self._verify(self._denying(), "/docs/a.txt", "/volume1/docs/a.txt", self._dsm({}))

    def test_a_missing_denied_folder_is_followed_up_to_sixteen_levels_and_no_further(self):
        """Nothing on a path that deep exists, and past sixteen levels the search for
        an existing parent stops: not finding one is not taken to mean it is safe."""
        shallow = _policy(deny=["/" + "/".join(["d"] * 16)])
        self._verify(shallow, "/docs/a.txt", "/volume1/docs/a.txt", self._dsm({}))
        deep = _policy(deny=["/" + "/".join(["d"] * 17)])
        with pytest.raises(AuthorizationDenied):
            self._verify(deep, "/docs/a.txt", "/volume1/docs/a.txt", self._dsm({}))

    def test_r02_the_comparison_ignores_case(self):
        """Judged by the denial alone: the root is wide enough that only the denied
        folder can refuse this target."""
        lookup = self._dsm({"/docs/private": "/volume1/docs/Private"})
        with pytest.raises(AuthorizationDenied):
            self._verify(
                self._denying(), "/docs/x", "/volume1/DOCS/private/x", lookup, root_real="/volume1"
            )
        # The same target one folder over is not refused, so it was the denial.
        self._verify(
            self._denying(), "/docs/x", "/volume1/DOCS/privateer/x", lookup, root_real="/volume1"
        )

    def test_r02_an_equivalent_path_through_another_share_is_refused(self):
        policy = _policy(roots=("/docs", "/archive"), deny=["/docs/private"])
        lookup = self._dsm({"/docs/private": "/volume1/docs/private"})
        with pytest.raises(AuthorizationDenied):
            self._verify(
                policy,
                "/archive/p/x.txt",
                "/volume1/docs/private/x.txt",
                lookup,
                root_real="/volume1/docs",  # /archive is another door onto the same volume path
            )

    def test_r02_a_denied_folder_that_exists_but_cannot_be_located_refuses_everything(self):
        for real in (None, ""):
            lookup = self._dsm({"/docs/private": real})
            with pytest.raises(AuthorizationDenied):
                self._verify(self._denying(), "/docs/a.txt", "/volume1/docs/a.txt", lookup)

    def test_r02_with_denials_and_no_way_to_resolve_them_nothing_is_allowed(self):
        with pytest.raises(AuthorizationDenied):
            self._denying().guard("nas1").verify_real(
                "/docs/a.txt", "/volume1/docs/a.txt", lambda root: "/volume1/docs"
            )

    def test_without_denials_no_lookup_is_needed_or_made(self):
        _policy().guard("nas1").verify_real(
            "/docs/a.txt", "/volume1/docs/a.txt", lambda root: "/volume1/docs"
        )

    def test_a_failed_lookup_is_not_swallowed_or_remembered(self):
        policy = self._denying(real_root_ttl=300)
        answers = iter([RuntimeError("the NAS did not answer"), (True, "/volume1/docs/private")])
        asked = []

        def lookup(path):
            asked.append(path)
            answer = next(answers)
            if isinstance(answer, Exception):
                raise answer
            return answer

        with pytest.raises(RuntimeError):
            self._verify(policy, "/docs/a.txt", "/volume1/docs/a.txt", lookup)
        self._verify(policy, "/docs/a.txt", "/volume1/docs/a.txt", lookup)  # recovers at once
        assert asked == ["/docs/private", "/docs/private"]

    def test_the_denied_locations_are_asked_for_once_and_remembered_briefly(self):
        clock = FakeClock()
        policy = self._denying(clock=clock, real_root_ttl=60)
        lookup = self._dsm({"/docs/private": "/volume1/docs/private"})
        for _ in range(3):
            self._verify(policy, "/docs/a.txt", "/volume1/docs/a.txt", lookup)
        assert lookup.asked == ["/docs/private"]

        clock.advance(61)
        self._verify(policy, "/docs/a.txt", "/volume1/docs/a.txt", lookup)
        assert lookup.asked == ["/docs/private", "/docs/private"]

    def test_a_folder_that_was_missing_is_asked_about_again_every_time(self):
        """Not remembered: it may be created, or replaced by a link, a moment later."""
        policy = self._denying(real_root_ttl=300)
        lookup = self._dsm({"/docs": "/volume1/docs"})
        for _ in range(2):
            self._verify(policy, "/docs/a.txt", "/volume1/docs/a.txt", lookup)
        assert lookup.asked == ["/docs/private", "/docs", "/docs/private", "/docs"]

    def test_every_denied_folder_is_checked(self):
        policy = _policy(deny=["/docs/private", "/docs/hr"])
        lookup = self._dsm({"/docs/private": "/volume1/docs/private", "/docs/hr": "/volume1/hr"})
        with pytest.raises(AuthorizationDenied):
            self._verify(policy, "/docs/x", "/volume1/hr/payroll.txt", lookup, root_real="/volume1")


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
        station.fake.listing = [
            {
                "name": "a.txt",
                "path": "/docs/a.txt",
                "isdir": False,
                "additional": {"real_path": "/volume1/docs/a.txt"},
            }
        ]
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


@pytest.fixture
def guarded_station():
    """A File Station limited to /docs, with /docs/private denied, and a link
    (`shortcut`) inside /docs that leads into the denied folder."""
    from filestation import SynologyFileStation

    policy = _policy(roots=("/docs",), deny=["/docs/private"])
    fs = SynologyFileStation(URL, "SID", folder_guard=policy.guard("nas1"))
    fs.fake = FakeDSM(
        real_paths={
            "/docs": "/volume1/docs",
            "/docs/private": "/volume1/docs/private",
            "/docs/private/secret.txt": "/volume1/docs/private/secret.txt",
            "/docs/public": "/volume1/docs/public",
            "/docs/readme.txt": "/volume1/docs/readme.txt",
            "/docs/shortcut": "/volume1/docs/private",
            "/docs/shortcut/secret.txt": "/volume1/docs/private/secret.txt",
        }
    )
    fs._make_request = fs.fake
    return fs


class TestALinkIntoADeniedFolder:
    """The reviewer's case: allowed `/docs`, denied `/docs/private`, and a
    permitted-looking link inside `/docs` that resolves into it (R02)."""

    def test_r02_the_content_behind_the_link_is_never_downloaded(
        self, guarded_station, monkeypatch
    ):
        def no_download(*args, **kwargs):
            raise AssertionError("a download request was made")

        monkeypatch.setattr("filestation.synology_filestation.requests.get", no_download)
        for path in ("/docs/shortcut/secret.txt", "/docs/shortcut"):
            with pytest.raises(AuthorizationDenied):
                guarded_station.get_file_content(path)

    def test_r02_the_link_cannot_be_inspected_or_listed(self, guarded_station):
        with pytest.raises(AuthorizationDenied):
            guarded_station.get_file_info("/docs/shortcut/secret.txt")
        with pytest.raises(AuthorizationDenied):
            guarded_station.list_directory("/docs/shortcut")
        assert ("SYNO.FileStation.List", "list") not in guarded_station.fake.methods()

    def test_r02_a_search_does_not_return_what_is_behind_the_link(self, guarded_station):
        guarded_station.fake.hits = [
            {
                "name": "secret.txt",
                "path": "/docs/shortcut/secret.txt",
                "additional": {"real_path": "/volume1/docs/private/secret.txt"},
            },
            {
                "name": "readme.txt",
                "path": "/docs/readme.txt",
                "additional": {"real_path": "/volume1/docs/readme.txt"},
            },
        ]
        hits = guarded_station.search_files("/docs", "*.txt")
        assert [h["name"] for h in hits] == ["readme.txt"]

    def test_the_denied_folder_itself_is_refused_directly_as_before(self, guarded_station):
        for path in ("/docs/private", "/docs/private/secret.txt"):
            with pytest.raises(AuthorizationDenied):
                guarded_station.get_file_info(path)

    def test_ordinary_files_and_folders_are_still_reachable(self, guarded_station):
        assert guarded_station.get_file_info("/docs/readme.txt")["path"] == "/docs/readme.txt"
        guarded_station.fake.listing = []
        assert guarded_station.list_directory("/docs/public") == []

    def test_r02_with_the_denied_folder_unlocatable_nothing_is_reachable(self, guarded_station):
        """DSM finds `/docs/private` but will not say where it is: the denial cannot
        be applied, so nothing is shown rather than assuming the target is safe."""
        original = guarded_station.fake.__call__

        def omit_real_path(api, version, method, use_post=False, **params):
            result = original(api, version, method, use_post, **params)
            if method == "getinfo" and params.get("path") == "/docs/private":
                result["files"][0]["additional"].pop("real_path")
            return result

        guarded_station._make_request = omit_real_path
        with pytest.raises(AuthorizationDenied):
            guarded_station.get_file_info("/docs/readme.txt")

    def test_a_link_made_to_where_a_missing_denied_folder_would_be_is_refused(
        self, guarded_station
    ):
        del guarded_station.fake.real_paths["/docs/private"]
        del guarded_station.fake.real_paths["/docs/private/secret.txt"]
        del guarded_station.fake.real_paths["/docs/shortcut/secret.txt"]
        with pytest.raises(AuthorizationDenied):
            guarded_station.get_file_info("/docs/shortcut")


def _child(name, real, **extra):
    entry = {
        "name": name,
        "path": f"/docs/{name}",
        "isdir": extra.pop("isdir", False),
        "additional": {"real_path": real, **extra.pop("additional", {})},
    }
    return {**entry, **extra}


class TestListingFiltersItsChildren:
    """Browsing checked the folder asked for and then returned every child,
    whatever it was or pointed at (implementation review R06)."""

    CHILDREN = [
        _child("a.txt", "/volume1/docs/a.txt", additional={"size": 5}),
        _child("sub", "/volume1/docs/sub", isdir=True, additional={"size": 0}),
        _child(".env", "/volume1/docs/.env"),
        _child("secrets", "/volume1/docs/secrets", isdir=True),
        _child("id.pem", "/volume1/docs/id.pem"),
        _child("out", "/volume1/elsewhere", isdir=True),  # a link leading out of the root
        {"name": "unknown", "path": "/docs/unknown", "additional": {}},  # no real path
        {"name": "bare", "path": "/docs/bare"},  # no `additional` at all
        {"name": "pathless", "additional": {"real_path": "/volume1/docs/pathless"}},
        "not-an-object",
    ]

    def test_r06_denied_names_outside_links_and_unresolved_children_are_omitted(self, station):
        station.fake.listing = copy.deepcopy(self.CHILDREN)
        names = [e["name"] for e in station.list_directory("/docs")]
        assert names == ["a.txt", "sub"]

    def test_r06_no_metadata_of_an_omitted_child_is_returned(self, station):
        station.fake.listing = copy.deepcopy(self.CHILDREN)
        text = str(station.list_directory("/docs"))
        for name in (
            ".env",
            "secrets",
            "id.pem",
            "elsewhere",
            "unknown",
            "bare",
            "pathless",
            "not-an-object",
        ):
            assert name not in text

    def test_r06_permitted_children_keep_their_metadata(self, station):
        station.fake.listing = copy.deepcopy(self.CHILDREN)
        first = station.list_directory("/docs")[0]
        assert (first["name"], first["path"], first["type"], first["size"]) == (
            "a.txt",
            "/docs/a.txt",
            "file",
            5,
        )

    def test_r06_dsm_is_asked_where_each_child_really_is(self, station):
        station.list_directory("/docs")
        call = next(c for c in station.fake.calls if c[:2] == ("SYNO.FileStation.List", "list"))
        assert "real_path" in json.loads(call[2]["additional"])

    def test_r06_it_is_asked_even_when_no_other_detail_is_wanted(self, station):
        station.list_directory("/docs", additional_info=False)
        call = next(c for c in station.fake.calls if c[:2] == ("SYNO.FileStation.List", "list"))
        assert json.loads(call[2]["additional"]) == ["real_path"]

    def test_r06_the_real_path_itself_is_not_passed_on(self, station):
        station.fake.listing = copy.deepcopy(self.CHILDREN)
        assert "/volume1" not in str(station.list_directory("/docs"))

    def test_r06_a_child_that_is_a_denied_folder_or_a_link_into_one_is_omitted(
        self, guarded_station
    ):
        guarded_station.fake.listing = [
            _child("public", "/volume1/docs/public", isdir=True),
            _child("private", "/volume1/docs/private", isdir=True),
            _child("shortcut", "/volume1/docs/private", isdir=True),
            _child("readme.txt", "/volume1/docs/readme.txt"),
        ]
        names = [e["name"] for e in guarded_station.list_directory("/docs")]
        assert names == ["public", "readme.txt"]

    def test_without_a_policy_every_child_is_returned_and_no_real_path_is_requested(self):
        fs = _without_a_guard()
        objects = [dict(c) for c in self.CHILDREN if isinstance(c, dict)]
        fs._make_request = FakeDSM(listing=objects)
        assert len(fs.list_directory("/anywhere")) == len(objects)
        call = next(c for c in fs._make_request.calls if c[:2] == ("SYNO.FileStation.List", "list"))
        assert "real_path" not in call[2]["additional"]


class TestManyEntriesDoNotMultiplyTheLookups:
    """A denied folder that does not exist is placed by walking up to its nearest
    existing parent, one request per level. That answer is not remembered (the
    folder may appear, or become a link, a moment later), so it must be worked out
    once for a listing or a search and not again for every entry in it."""

    # One deny entry three levels deep that does not exist, one whose whole path
    # (not even its share) is missing.
    DENIED = ["/docs/hidden/deep", "/nosuchshare/x"]

    def _station(self):
        from filestation import SynologyFileStation

        policy = _policy(roots=("/docs",), deny=self.DENIED)
        fs = SynologyFileStation(URL, "SID", folder_guard=policy.guard("nas1"))
        fs.fake = FakeDSM(real_paths={"/docs": "/volume1/docs"})
        fs._make_request = fs.fake
        return fs

    @staticmethod
    def _probes(fs, path):
        return [
            c
            for c in fs.fake.calls
            if c[:2] == ("SYNO.FileStation.List", "getinfo") and c[2].get("path") == path
        ]

    @pytest.mark.parametrize("path", DENIED)
    def test_a_listing_places_each_denied_folder_once_however_many_children_it_has(self, path):
        probed = {}
        for count in (5, 60):
            fs = self._station()
            fs.fake.listing = [_child(f"f{i}.txt", f"/volume1/docs/f{i}.txt") for i in range(count)]
            assert len(fs.list_directory("/docs")) == count
            probed[count] = len(self._probes(fs, path))
        assert probed == {5: 1, 60: 1}

    def test_the_whole_listing_costs_the_same_for_five_children_as_for_sixty(self):
        calls = {}
        for count in (5, 60):
            fs = self._station()
            fs.fake.listing = [_child(f"f{i}.txt", f"/volume1/docs/f{i}.txt") for i in range(count)]
            fs.list_directory("/docs")
            calls[count] = len(fs.fake.calls)
        assert calls[5] == calls[60]

    @pytest.mark.parametrize("path", DENIED)
    def test_a_search_places_each_denied_folder_once_however_many_hits_it_has(self, path):
        probed = {}
        for count in (5, 60):
            fs = self._station()
            fs.fake.hits = [
                {
                    "name": f"f{i}.txt",
                    "path": f"/docs/f{i}.txt",
                    "additional": {"real_path": f"/volume1/docs/f{i}.txt"},
                }
                for i in range(count)
            ]
            assert len(fs.search_files("/docs", "*.txt")) == count
            probed[count] = len(self._probes(fs, path))
        assert probed == {5: 1, 60: 1}

    def test_a_single_request_still_works_the_denied_folder_out_afresh_each_time(self):
        """Nothing is remembered between requests: the folder may be created."""
        fs = self._station()
        for _ in range(3):
            fs.get_file_info("/docs")
        assert len(self._probes(fs, "/docs/hidden/deep")) == 3

    def test_children_are_still_judged_against_the_denied_folder_found_for_the_listing(self):
        from filestation import SynologyFileStation

        policy = _policy(roots=("/docs",), deny=["/docs/private"])
        fs = SynologyFileStation(URL, "SID", folder_guard=policy.guard("nas1"))
        fs.fake = FakeDSM(
            real_paths={"/docs": "/volume1/docs", "/docs/private": "/volume1/docs/private"},
            listing=[
                _child("shortcut", "/volume1/docs/private", isdir=True),
                _child("readme.txt", "/volume1/docs/readme.txt"),
            ],
        )
        fs._make_request = fs.fake
        assert [e["name"] for e in fs.list_directory("/docs")] == ["readme.txt"]

    def test_denied_locations_resolved_once_can_be_handed_to_many_checks(self):
        lookup = TestDeniedFoldersInThePhysicalNamespace._dsm(
            {"/docs/private": "/volume1/docs/private"}
        )
        guard = _policy(deny=["/docs/private"]).guard("nas1")
        denied = guard.denied_locations(lookup)
        assert denied == ("/volume1/docs/private",)

        for _ in range(3):
            # No lookup at all: the answer already worked out is used.
            guard.verify_real(
                "/docs/a.txt", "/volume1/docs/a.txt", lambda root: "/volume1/docs", denied=denied
            )
        assert lookup.asked == ["/docs/private"]
        with pytest.raises(AuthorizationDenied):
            guard.verify_real(
                "/docs/x", "/volume1/docs/private/x", lambda root: "/volume1/docs", denied=denied
            )

    def test_an_empty_answer_means_nothing_is_denied_not_ask_again(self):
        lookup = TestDeniedFoldersInThePhysicalNamespace._dsm({})
        guard = _policy(deny=["/nosuchshare/x"]).guard("nas1")
        denied = guard.denied_locations(lookup)
        assert denied == ()
        asked = list(lookup.asked)
        guard.verify_real(
            "/docs/a.txt", "/volume1/docs/a.txt", lambda root: "/volume1/docs", denied=denied
        )
        assert lookup.asked == asked


class TestALeftOutChildIsCountedNotNamed:
    def test_a_listing_logs_how_many_children_it_left_out_and_nothing_about_them(
        self, station, caplog
    ):
        station.fake.listing = [
            _child("a.txt", "/volume1/docs/a.txt"),
            _child(".env", "/volume1/docs/.env"),
            _child("linkaway", "/volume1/elsewhere", isdir=True),
        ]
        with caplog.at_level("DEBUG", logger="filestation.synology_filestation"):
            station.list_directory("/docs")

        messages = [r.getMessage() for r in caplog.records if r.name.startswith("filestation")]
        assert any("2" in m and "left out" in m for m in messages)
        for message in messages:
            for name in (".env", "linkaway", "elsewhere", "a.txt", "/volume1"):
                assert name not in message

    def test_nothing_is_logged_when_nothing_was_left_out(self, station, caplog):
        station.fake.listing = [_child("a.txt", "/volume1/docs/a.txt")]
        with caplog.at_level("DEBUG", logger="filestation.synology_filestation"):
            station.list_directory("/docs")
        assert not [r for r in caplog.records if "left out" in r.getMessage()]


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
