"""What the File Station, Download Station and shared-client modules do when the
NAS fails or the session is gone (implementation review R09, R10 and R11).

R09  A download is created once. After a timeout or a lost connection nobody knows
     whether the NAS created it, so it is not created again.
R10  A lost session, and a redirect, reach the caller from every fallback, instead
     of becoming an empty list, zeroes or a generic error.
R11  After a session is renewed from a stored login (legacy mode), only a request
     that reads is repeated. What counts as one is decided by the operation, not by
     the HTTP verb: some changes are GETs and some reads are POSTs.

Every NAS answer is scripted on the real transport (`tests/network_support.py`);
nothing opens a socket.
"""

import pytest
import requests

from broker.errors import AuthenticationRequired, RedirectRefused, SessionRenewedNotRepeated
from tests.network_support import ScriptedNas, dsm_error, dsm_ok

NAS = "https://nas.example.test:5001"
URL = "https://files.example.test/a.iso"

CREATE = ("SYNO.DownloadStation2.Task", "create")
TASK_LIST = ("SYNO.DownloadStation2.Task", "list")
STATISTICS = ("SYNO.DownloadStation.Statistic", "getinfo")
GETINFO = ("SYNO.FileStation.List", "getinfo")
UPLOAD = ("SYNO.FileStation.Upload", "upload")

# `downloads` exists, so a create gets as far as asking the NAS to create it.
DESTINATION_EXISTS = {GETINFO: dsm_ok({"files": [{"isdir": True}]})}


def _ds():
    from downloadstation.synology_downloadstation import SynologyDownloadStation

    return SynologyDownloadStation(NAS, "OLD-SID", True, "OLD-TOKEN")


def _fs():
    from filestation.synology_filestation import SynologyFileStation

    return SynologyFileStation(NAS, "OLD-SID", True, "OLD-TOKEN")


@pytest.fixture
def manual_mode(monkeypatch):
    import utils.synology_api as api

    monkeypatch.setattr(api.config, "auth_mode", "broker")


@pytest.fixture
def renewals(monkeypatch):
    """Legacy mode, where a lost session is renewed from the stored login. Each
    renewal is recorded and gives the session `NEW-SID`."""
    import utils.synology_api as api

    monkeypatch.setattr(api.config, "auth_mode", "legacy")
    calls = []

    def relogin(base_url, stale_session_id=None):
        calls.append((base_url, stale_session_id))
        return ("NEW-SID", "NEW-TOKEN")

    monkeypatch.setattr(api, "_try_relogin", relogin)
    return calls


# ---------------------------------------------------------------------------
# R09: a download is created once
# ---------------------------------------------------------------------------


class TestACreateIsNeverRepeatedAfterAnUncertainOutcome:
    @pytest.mark.parametrize(
        "failure",
        [
            requests.exceptions.ReadTimeout("timed out"),
            requests.exceptions.ConnectionError("the connection was lost"),
            requests.exceptions.ChunkedEncodingError("cut off"),
            502,
            504,
            b"<html>bad gateway</html>",
        ],
        ids=["read-timeout", "lost-connection", "cut-off", "502", "504", "not-json"],
    )
    def test_r09_one_create_request_and_an_error_that_says_the_outcome_is_unknown(
        self, monkeypatch, failure
    ):
        nas = ScriptedNas({**DESTINATION_EXISTS, CREATE: failure}).install(monkeypatch)

        with pytest.raises(Exception) as error:
            _ds().create_task(URL, "downloads")

        assert nas.count(*CREATE) == 1
        message = str(error.value)
        assert "unclear whether the download was created" in message
        assert "task list" in message and "before trying again" in message

    @pytest.mark.parametrize("code", [120, 400, 401, 402, 403, 406, 408, 409])
    def test_a_definite_refusal_is_one_request_and_not_called_uncertain(self, monkeypatch, code):
        nas = ScriptedNas({**DESTINATION_EXISTS, CREATE: dsm_error(code)}).install(monkeypatch)

        with pytest.raises(Exception) as error:
            _ds().create_task(URL, "downloads")

        assert nas.count(*CREATE) == 1
        assert "unclear" not in str(error.value)
        assert "Task creation failed" in str(error.value)

    @pytest.mark.parametrize("code", [102, 103, 104])
    def test_an_unsupported_version_falls_back_once_to_the_older_form(self, monkeypatch, code):
        nas = ScriptedNas(
            {**DESTINATION_EXISTS, CREATE: [dsm_error(code), dsm_ok({"task_id": ["t1"]})]}
        ).install(monkeypatch)

        data = _ds().create_task(URL, "downloads")

        assert data == {"task_id": ["t1"]}
        first, second = nas.requests_for(*CREATE)
        assert first["fields"]["version"] == "2" and "url" in first["fields"]
        assert second["fields"]["version"] == "1" and second["fields"]["uri"] == URL

    def test_a_fallback_that_times_out_is_uncertain_and_is_not_repeated(self, monkeypatch):
        nas = ScriptedNas(
            {
                **DESTINATION_EXISTS,
                CREATE: [dsm_error(104), requests.exceptions.ReadTimeout("timed out")],
            }
        ).install(monkeypatch)

        with pytest.raises(Exception) as error:
            _ds().create_task(URL, "downloads")

        assert nas.count(*CREATE) == 2  # the version that was refused, then the old form once
        assert "unclear whether the download was created" in str(error.value)

    def test_a_fallback_that_is_refused_is_a_definite_failure(self, monkeypatch):
        nas = ScriptedNas({**DESTINATION_EXISTS, CREATE: [dsm_error(104), dsm_error(402)]}).install(
            monkeypatch
        )

        with pytest.raises(Exception) as error:
            _ds().create_task(URL, "downloads")

        assert nas.count(*CREATE) == 2
        assert "unclear" not in str(error.value) and "Task creation failed" in str(error.value)

    def test_there_is_no_older_form_to_fall_back_to_from_the_older_form(self, monkeypatch):
        nas = ScriptedNas({**DESTINATION_EXISTS, CREATE: dsm_error(104)}).install(monkeypatch)
        ds = _ds()
        ds.task_version = "1"

        with pytest.raises(Exception, match="Task creation failed"):
            ds.create_task(URL, "downloads")
        assert nas.count(*CREATE) == 1

    def test_a_create_that_works_is_one_request(self, monkeypatch):
        nas = ScriptedNas({**DESTINATION_EXISTS, CREATE: dsm_ok({"task_id": ["t1"]})}).install(
            monkeypatch
        )
        assert _ds().create_task(URL, "downloads") == {"task_id": ["t1"]}
        assert nas.count(*CREATE) == 1

    def test_the_error_does_not_carry_the_session(self, monkeypatch):
        failure = requests.exceptions.ConnectionError("failed: https://nas/?_sid=OLD-SID")
        ScriptedNas({**DESTINATION_EXISTS, CREATE: failure}).install(monkeypatch)
        with pytest.raises(Exception) as error:
            _ds().create_task(URL, "downloads")
        assert "OLD-SID" not in str(error.value)


class TestTheTaskListFallsBackOnTheCodeNotOnTheText:
    def test_an_unsupported_version_falls_back_once_to_the_older_form(self, monkeypatch):
        nas = ScriptedNas({TASK_LIST: [dsm_error(104), dsm_ok({"tasks": [], "total": 0})]}).install(
            monkeypatch
        )

        assert _ds().list_tasks()["total"] == 0
        assert [r["fields"]["version"] for r in nas.requests_for(*TASK_LIST)] == ["2", "1"]

    def test_r09_a_network_error_that_merely_mentions_102_does_not_start_a_fallback(
        self, monkeypatch
    ):
        """The old test was a substring search of the message, so an address such as
        10.0.0.102 in it was taken for DSM error 102."""
        failure = requests.exceptions.ConnectionError("Failed to connect to 10.0.0.102")
        nas = ScriptedNas({TASK_LIST: failure}).install(monkeypatch)

        with pytest.raises(Exception):
            _ds().list_tasks()
        assert nas.count(*TASK_LIST) == 1

    @pytest.mark.parametrize("code", [101, 105, 400, 120])
    def test_any_other_refusal_is_not_a_reason_to_try_the_older_form(self, monkeypatch, code):
        nas = ScriptedNas({TASK_LIST: dsm_error(code)}).install(monkeypatch)
        with pytest.raises(Exception):
            _ds().list_tasks()
        assert nas.count(*TASK_LIST) == 1


# ---------------------------------------------------------------------------
# R10: a lost session and a redirect survive every fallback
# ---------------------------------------------------------------------------


class TestAUploadThatLosesTheSession:
    @pytest.mark.parametrize("code", [106, 107, 119])
    def test_r10_it_is_authentication_required_not_a_generic_upload_error(
        self, manual_mode, monkeypatch, code
    ):
        nas = ScriptedNas({UPLOAD: dsm_error(code)}).install(monkeypatch)

        with pytest.raises(AuthenticationRequired):
            _fs().create_file("/docs/a.txt", "payload")
        assert nas.count(*UPLOAD) == 1

    def test_another_failure_is_still_a_plain_upload_error(self, manual_mode, monkeypatch):
        ScriptedNas({UPLOAD: dsm_error(414)}).install(monkeypatch)
        with pytest.raises(Exception, match="Upload failed with error: 414") as error:
            _fs().create_file("/docs/a.txt", "payload")
        assert not isinstance(error.value, AuthenticationRequired)

    def test_a_redirect_while_uploading_is_refused(self, manual_mode, monkeypatch):
        ScriptedNas({UPLOAD: 307}).install(monkeypatch)
        with pytest.raises(RedirectRefused):
            _fs().create_file("/docs/a.txt", "payload")

    def test_legacy_mode_reports_the_code_as_before(self, monkeypatch):
        import utils.synology_api as api

        monkeypatch.setattr(api.config, "auth_mode", "legacy")
        ScriptedNas({UPLOAD: dsm_error(119)}).install(monkeypatch)
        with pytest.raises(Exception, match="Upload failed with error: 119"):
            _fs().create_file("/docs/a.txt", "payload")


class TestNoFallbackHidesALostSessionOrARedirect:
    LOST = dsm_error(119)

    def test_r10_a_task_list_whose_older_form_loses_the_session_says_so(
        self, manual_mode, monkeypatch
    ):
        nas = ScriptedNas({TASK_LIST: [dsm_error(104), self.LOST]}).install(monkeypatch)
        with pytest.raises(AuthenticationRequired):
            _ds().list_tasks()  # not {"total": 0, "tasks": []}
        assert nas.count(*TASK_LIST) == 2

    def test_r10_the_same_for_a_redirect(self, manual_mode, monkeypatch):
        ScriptedNas({TASK_LIST: [dsm_error(104), 307]}).install(monkeypatch)
        with pytest.raises(RedirectRefused):
            _ds().list_tasks()

    def test_r10_statistics_that_fall_back_to_the_task_list_do_not_hide_a_lost_session(
        self, manual_mode, monkeypatch
    ):
        ScriptedNas({STATISTICS: dsm_error(101), TASK_LIST: self.LOST}).install(monkeypatch)
        with pytest.raises(AuthenticationRequired):
            _ds().get_statistics()  # not zeroes

    def test_r10_the_same_for_a_redirect_in_the_statistics_fallback(self, manual_mode, monkeypatch):
        ScriptedNas({STATISTICS: dsm_error(101), TASK_LIST: 307}).install(monkeypatch)
        with pytest.raises(RedirectRefused):
            _ds().get_statistics()

    def test_ordinary_failures_still_give_the_default_statistics(self, manual_mode, monkeypatch):
        ScriptedNas({STATISTICS: dsm_error(101), TASK_LIST: dsm_error(101)}).install(monkeypatch)
        assert _ds().get_statistics() == {
            "speed_download": 0,
            "speed_upload": 0,
            "error": "Statistics not available",
        }

    def test_r10_a_create_whose_older_form_loses_the_session_says_so(
        self, manual_mode, monkeypatch
    ):
        nas = ScriptedNas({**DESTINATION_EXISTS, CREATE: [dsm_error(104), self.LOST]}).install(
            monkeypatch
        )
        with pytest.raises(AuthenticationRequired):
            _ds().create_task(URL, "downloads")
        assert nas.count(*CREATE) == 2

    def test_r10_the_same_for_a_redirect_in_the_create_fallback(self, manual_mode, monkeypatch):
        ScriptedNas({**DESTINATION_EXISTS, CREATE: [dsm_error(104), 307]}).install(monkeypatch)
        with pytest.raises(RedirectRefused):
            _ds().create_task(URL, "downloads")

    def test_r10_a_redirect_while_classifying_a_delete_stops_it_before_it_starts(self, monkeypatch):
        nas = ScriptedNas({GETINFO: 307}).install(monkeypatch)
        with pytest.raises(RedirectRefused):
            _fs().delete("/docs/a.txt")
        assert nas.count("SYNO.FileStation.Delete", "start") == 0

    def test_a_delete_whose_lookup_merely_fails_still_treats_the_path_as_a_file(self, monkeypatch):
        """Unchanged: a lookup that fails for an ordinary reason is not a reason to
        refuse, and the delete goes ahead as for a file."""
        nas = ScriptedNas(
            {
                GETINFO: dsm_error(408),
                ("SYNO.FileStation.Delete", "start"): dsm_ok({"taskid": "t1"}),
                ("SYNO.FileStation.Delete", "status"): dsm_ok({"finished": True}),
            }
        ).install(monkeypatch)
        assert _fs().delete("/docs/a.txt")["item_type"] == "file"
        assert nas.count("SYNO.FileStation.Delete", "start") == 1


class TestThroughTheBroker:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool", ["ds_list_tasks", "ds_get_statistics"])
    async def test_r10_the_broker_drops_the_session_and_asks_for_a_new_sign_in(
        self, monkeypatch, tool
    ):
        from tests.broker_support import Broker

        broker = Broker(monkeypatch, {"alice": {"nas": ["nas1"], "tools": [tool]}})
        broker.sign_in("alice")
        ScriptedNas(
            {
                TASK_LIST: [dsm_error(104), dsm_error(119)],
                STATISTICS: dsm_error(101),
            }
        ).install(monkeypatch)

        result = await broker.runtime.call_tool("alice", tool, {"nas_name": "nas1"})

        assert result.is_error is True
        assert result.content[0].text.startswith("AUTHENTICATION_REQUIRED")
        # The session is gone at once...
        assert broker.sessions.get("alice", "nas1", touch=False) is None
        # ...and the next call that needs one leaves a sign-in request for the owner.
        again = await broker.runtime.call_tool("alice", tool, {"nas_name": "nas1"})
        assert again.content[0].text.startswith("AUTHENTICATION_REQUIRED")
        assert broker.sessions.pending("alice", "nas1") is not None


# ---------------------------------------------------------------------------
# R11: only a read is repeated after a session is renewed
# ---------------------------------------------------------------------------

_A_FILE = dsm_ok(
    {"files": [{"name": "a.txt", "path": "/docs/a.txt", "isdir": False, "additional": {"size": 1}}]}
)


class TestFileStationRepeatsReadsOnly:
    @pytest.mark.parametrize(
        "call,key",
        [
            (
                lambda fs: fs.rename_file("/docs/a.txt", "b.txt"),
                ("SYNO.FileStation.Rename", "rename"),
            ),
            (lambda fs: fs.delete("/docs/a.txt"), ("SYNO.FileStation.Delete", "start")),
            (
                lambda fs: fs.move_file("/docs/a.txt", "/docs/sub"),
                ("SYNO.FileStation.CopyMove", "start"),
            ),
            (
                lambda fs: fs.create_directory("/docs", "new"),
                ("SYNO.FileStation.CreateFolder", "create"),
            ),
        ],
        ids=["rename", "delete", "move", "create-folder"],
    )
    def test_r11_a_change_is_sent_once_the_session_is_renewed_and_the_caller_told(
        self, renewals, monkeypatch, call, key
    ):
        nas = ScriptedNas({key: dsm_error(119), GETINFO: _A_FILE}).install(monkeypatch)
        fs = _fs()

        with pytest.raises(Exception) as error:
            call(fs)

        assert nas.count(*key) == 1  # not repeated, whatever the HTTP verb
        assert "run it again" in str(error.value) and "renewed" in str(error.value)
        assert len(renewals) == 1 and fs.session_id == "NEW-SID"  # the next call works

    def test_a_listing_is_repeated_once_with_the_renewed_session(self, renewals, monkeypatch):
        nas = ScriptedNas(
            {("SYNO.FileStation.List", "list_share"): [dsm_error(119), dsm_ok({"shares": []})]}
        ).install(monkeypatch)

        assert _fs().list_shares() == []

        first, second = nas.requests_for("SYNO.FileStation.List", "list_share")
        assert first["fields"]["_sid"] == "OLD-SID" and second["fields"]["_sid"] == "NEW-SID"
        assert len(renewals) == 1

    def test_a_read_is_repeated_at_most_once(self, renewals, monkeypatch):
        nas = ScriptedNas({("SYNO.FileStation.List", "list_share"): dsm_error(119)}).install(
            monkeypatch
        )
        with pytest.raises(Exception):
            _fs().list_shares()
        assert nas.count("SYNO.FileStation.List", "list_share") == 2
        assert len(renewals) == 1

    def test_the_polling_of_a_task_is_a_read(self, renewals, monkeypatch):
        key = ("SYNO.FileStation.Delete", "status")
        nas = ScriptedNas({key: [dsm_error(119), dsm_ok({"finished": True})]}).install(monkeypatch)
        _fs()._make_request("SYNO.FileStation.Delete", "2", "status", taskid="t1")
        assert nas.count(*key) == 2

    def test_manual_mode_never_renews_or_repeats_anything(self, manual_mode, monkeypatch):
        import utils.synology_api as api

        renewed = []
        monkeypatch.setattr(api, "_try_relogin", lambda *args: renewed.append(args) or ("X", "Y"))
        nas = ScriptedNas({("SYNO.FileStation.Rename", "rename"): dsm_error(119)}).install(
            monkeypatch
        )
        with pytest.raises(AuthenticationRequired):
            _fs().rename_file("/docs/a.txt", "b.txt")
        assert nas.count("SYNO.FileStation.Rename", "rename") == 1 and renewed == []


class TestDownloadStationRepeatsReadsOnly:
    @pytest.mark.parametrize(
        "call,key",
        [
            (lambda ds: ds.delete_tasks(["t1"]), ("SYNO.DownloadStation2.Task", "delete")),
            (lambda ds: ds.pause_tasks(["t1"]), ("SYNO.DownloadStation2.Task", "pause")),
            (lambda ds: ds.resume_tasks(["t1"]), ("SYNO.DownloadStation2.Task", "resume")),
            (lambda ds: ds.create_task(URL, "downloads"), CREATE),
        ],
        ids=["delete", "pause", "resume", "create"],
    )
    def test_r11_a_change_is_sent_once_the_session_is_renewed_and_the_caller_told(
        self, renewals, monkeypatch, call, key
    ):
        nas = ScriptedNas({**DESTINATION_EXISTS, key: dsm_error(119)}).install(monkeypatch)
        ds = _ds()

        with pytest.raises(Exception) as error:
            call(ds)

        assert nas.count(*key) == 1
        assert "run it again" in str(error.value)
        assert len(renewals) == 1 and ds.session_id == "NEW-SID"

    def test_the_older_form_failing_for_an_ordinary_reason_is_not_an_empty_list(self, monkeypatch):
        """Only DSM saying neither form exists means there is no task list to show.
        A network failure in the older form used to be reported as "no tasks"."""
        ScriptedNas(
            {TASK_LIST: [dsm_error(104), requests.exceptions.ReadTimeout("timed out")]}
        ).install(monkeypatch)
        with pytest.raises(Exception, match="Network error"):
            _ds().list_tasks()

    @pytest.mark.parametrize("code", [101, 105, 400])
    def test_the_older_form_refused_for_another_reason_is_not_an_empty_list(
        self, monkeypatch, code
    ):
        ScriptedNas({TASK_LIST: [dsm_error(104), dsm_error(code)]}).install(monkeypatch)
        with pytest.raises(Exception, match="Download Station API error"):
            _ds().list_tasks()

    def test_a_nas_with_neither_form_has_no_task_list_to_show(self, monkeypatch):
        nas = ScriptedNas({TASK_LIST: [dsm_error(104), dsm_error(102)]}).install(monkeypatch)
        assert _ds().list_tasks() == {"total": 0, "offset": 0, "tasks": []}
        assert nas.count(*TASK_LIST) == 2

    def test_the_task_list_is_repeated_once_with_the_renewed_session(self, renewals, monkeypatch):
        nas = ScriptedNas({TASK_LIST: [dsm_error(119), dsm_ok({"tasks": [], "total": 0})]}).install(
            monkeypatch
        )

        assert _ds().list_tasks()["total"] == 0

        first, second = nas.requests_for(*TASK_LIST)
        assert (first["fields"]["_sid"], second["fields"]["_sid"]) == ("OLD-SID", "NEW-SID")


class TestTheSharedClientRepeatsReadsOnly:
    @staticmethod
    def _client():
        from utils.synology_api import SynologyAPIClient

        return SynologyAPIClient(NAS, "OLD-SID", True, "OLD-TOKEN")

    @pytest.mark.parametrize("verb", ["get", "post"])
    def test_r11_a_change_is_sent_once_whichever_verb_carries_it(self, renewals, monkeypatch, verb):
        key = ("SYNO.Core.User", "set")
        nas = ScriptedNas({key: dsm_error(119)}).install(monkeypatch)
        client = self._client()

        with pytest.raises(SessionRenewedNotRepeated) as error:
            getattr(client, verb)("SYNO.Core.User", "set", 1, {"name": "x"})

        assert nas.count(*key) == 1
        assert "run it again" in str(error.value)
        assert len(renewals) == 1 and client.session_id == "NEW-SID"

    @pytest.mark.parametrize(
        "api,method",
        [
            ("SYNO.Docker.Container", "list"),
            ("SYNO.Docker.Container", "get"),
            ("SYNO.Docker.Registry", "search"),
            ("SYNO.Docker.Registry", "tags"),
            ("SYNO.Core.System", "info"),
            ("SYNO.DSM.Info", "getinfo"),
            ("SYNO.Storage.CGI.Storage", "load_info"),
            ("SYNO.Core.Share.Permission", "list_by_user"),
            ("SYNO.Core.Storage.Disk", "get_smart_info"),
            ("SYNO.DownloadStation.Info", "getconfig"),
            ("SYNO.FileStation.List", "list_share"),
            ("SYNO.FileStation.Delete", "status"),
        ],
    )
    def test_a_read_is_repeated_once_even_when_it_is_sent_as_a_post(
        self, renewals, monkeypatch, api, method
    ):
        """Every container call is a POST, reads included."""
        nas = ScriptedNas({(api, method): [dsm_error(119), dsm_ok({"ok": 1})]}).install(monkeypatch)
        result = self._client().post(api, method)

        assert result == dsm_ok({"ok": 1})
        first, second = nas.requests_for(api, method)
        assert (first["fields"]["_sid"], second["fields"]["_sid"]) == ("OLD-SID", "NEW-SID")

    @pytest.mark.parametrize(
        "api,method",
        [
            ("SYNO.Docker.Container", "start"),
            ("SYNO.Docker.Container", "stop"),
            ("SYNO.Docker.Container", "delete"),
            ("SYNO.Docker.Image", "pull_start"),
            ("SYNO.Docker.Network", "remove"),
            ("SYNO.Core.User", "create"),
            ("SYNO.Core.User", "delete"),
            ("SYNO.Core.FileServ.NFS", "set"),
            ("SYNO.Core.Share", "create"),
        ],
    )
    def test_no_change_is_repeated(self, renewals, monkeypatch, api, method):
        nas = ScriptedNas({(api, method): dsm_error(119)}).install(monkeypatch)
        with pytest.raises(SessionRenewedNotRepeated):
            self._client().post(api, method)
        assert nas.count(api, method) == 1

    def test_manual_mode_still_asks_for_a_person_not_a_renewal(self, manual_mode, monkeypatch):
        nas = ScriptedNas({("SYNO.Core.System", "info"): dsm_error(119)}).install(monkeypatch)
        with pytest.raises(AuthenticationRequired):
            self._client().get("SYNO.Core.System", "info")
        assert nas.count("SYNO.Core.System", "info") == 1


class TestASearchIsARead:
    """`start` is a change for a delete or a move and a read for a search, so the
    method alone cannot say; the API it is sent to does."""

    SEARCH = {
        ("SYNO.FileStation.Search", "status"): dsm_ok({"finished": True}),
        ("SYNO.FileStation.Search", "list"): dsm_ok({"files": []}),
        ("SYNO.FileStation.Search", "stop"): dsm_ok({}),
    }

    def test_a_search_that_finds_the_session_gone_is_repeated_once(self, renewals, monkeypatch):
        key = ("SYNO.FileStation.Search", "start")
        script = {**self.SEARCH, key: [dsm_error(119), dsm_ok({"taskid": "t1"})]}
        nas = ScriptedNas(script).install(monkeypatch)

        assert _fs().search_files("/docs", "a*") == []

        first, second = nas.requests_for(*key)
        assert first["fields"]["_sid"] == "OLD-SID" and second["fields"]["_sid"] == "NEW-SID"
        assert len(renewals) == 1

    @pytest.mark.parametrize(
        "api,method",
        [
            ("SYNO.FileStation.Delete", "start"),
            ("SYNO.FileStation.CopyMove", "start"),
            ("SYNO.FileStation.Search", "stop"),
            ("SYNO.FileStation.Delete", "stop"),
        ],
    )
    def test_the_same_method_on_another_api_is_still_a_change(self, api, method):
        from utils.synology_api import is_read_only

        assert is_read_only(api, method) is False

    def test_only_the_search_start_is_a_read_of_its_name(self):
        from utils.synology_api import is_read_only

        assert is_read_only("SYNO.FileStation.Search", "start") is True
        assert is_read_only("SYNO.FileStation.List", "list") is True
        assert is_read_only("SYNO.Anything", "delete") is False


class TestEveryServiceTellsTheClientTheSameThing:
    """A change that found the session gone is not repeated. File Station and
    Download Station raise `SessionRenewedNotRepeated`; the shared client behind
    containers, health, NFS and users used to return an error result instead, so
    the client saw different words (and a JSON dump) for the same event."""

    @pytest.fixture
    def server(self, renewals, monkeypatch):
        import mcp_server

        monkeypatch.setattr(mcp_server.config, "restricted_mode", False)
        server = mcp_server.SynologyMCPServer()
        server.install_session(NAS, "OLD-SID", "OLD-TOKEN")
        return server

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "tool,arguments,key",
        [
            ("synology_container_start", {"name": "web"}, ("SYNO.Docker.Container", "start")),
            (
                "rename_file",
                {"path": "/docs/a.txt", "new_name": "b.txt"},
                ("SYNO.FileStation.Rename", "rename"),
            ),
            ("ds_delete_tasks", {"task_ids": ["t1"]}, ("SYNO.DownloadStation2.Task", "delete")),
        ],
        ids=["shared-client", "file-station", "download-station"],
    )
    async def test_the_message_is_the_same_plain_sentence(
        self, server, monkeypatch, tool, arguments, key
    ):
        nas = ScriptedNas({key: dsm_error(119), GETINFO: _A_FILE}).install(monkeypatch)

        result = await server._call_tool(tool, {"base_url": NAS, **arguments})

        assert result.is_error is True
        assert result.content[0].text == str(SessionRenewedNotRepeated())
        assert nas.count(*key) == 1
        # The session was renewed, not lost: it is kept, unlike one that needs a sign-in.
        assert NAS in server.sessions


class TestTheTypedError:
    def test_it_has_a_stable_code_and_a_message_with_no_value_in_it(self):
        from broker.errors import SESSION_RENEWED, SessionRenewedNotRepeated

        error = SessionRenewedNotRepeated()
        assert error.code == SESSION_RENEWED == "SESSION_RENEWED"
        assert "run it again" in str(error) and "renewed" in str(error)
