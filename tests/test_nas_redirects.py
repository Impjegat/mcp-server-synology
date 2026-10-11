"""A NAS that answers with a redirect must never make the server send a second,
authenticated request somewhere else (implementation review R03).

`requests` follows redirects by default and carries the request body, and any
custom header such as `X-SYNO-TOKEN`, to the new address. A login POST carries
the password and one-time code; every other request carries the session id and
the session token. So every call to the NAS has to refuse redirects.

These tests patch only the transport adapter, so `requests`' own redirect
engine decides whether a redirect is followed: on code that follows redirects a
second request to `other.example.test` is recorded, on code that refuses them
exactly one request ever leaves, and it goes to the NAS. Everything is a fake;
nothing here opens a socket.
"""

import ast
import io
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
import requests.adapters

NAS_URL = "https://nas.example.test:5001"
NAS_HOST = "nas.example.test"
OTHER_HOST = "other.example.test"
DUMMY_PASSWORD = "Dummy-Password-5e1c"
DUMMY_OTP = "Dummy-Otp-9b2d"
SESSION_ID = "Dummy-Sid-7f3a"
SYNO_TOKEN = "Dummy-SynoToken-1c8e"

SRC = Path(__file__).resolve().parent.parent / "src"


def _response(request, status, *, headers=None, body=b""):
    response = requests.Response()
    response.status_code = status
    response.headers.update(headers or {})
    response._content = body
    response._content_consumed = True
    response.url = request.url
    response.request = request
    response.raw = io.BytesIO(body)
    return response


def _api_and_method(request):
    """The DSM `api` and `method` of a request, from its query, its form body or
    its multipart body."""
    fields = parse_qs(urlsplit(request.url).query)
    body = request.body
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else (body or "")
    if 'name="api"' in text:
        api = re.search(r'name="api"\r\n\r\n([^\r]*)', text)
        method = re.search(r'name="method"\r\n\r\n([^\r]*)', text)
        return (api.group(1) if api else "", method.group(1) if method else "")
    fields.update(parse_qs(text))
    return (fields.get("api", [""])[0], fields.get("method", [""])[0])


class FakeNetwork:
    """Answers on the real `HTTPAdapter.send`. The NAS redirects the requests named
    in `redirect_on` (`"all"` for every one) to another host; every host answers
    everything else as a cooperative DSM would, so a client that follows the
    redirect appears to succeed."""

    def __init__(self, redirect_on="all"):
        self.redirect_on = redirect_on
        self.sent = []

    def hosts(self):
        return {urlsplit(item["url"]).hostname for item in self.sent}

    def to(self, host):
        return [item for item in self.sent if urlsplit(item["url"]).hostname == host]

    def send(self, request):
        key = _api_and_method(request)
        self.sent.append(
            {
                "method": request.method,
                "url": request.url,
                "body": request.body,
                "headers": dict(request.headers),
                "key": key,
            }
        )
        on_nas = urlsplit(request.url).hostname == NAS_HOST
        if on_nas and (self.redirect_on == "all" or key in self.redirect_on):
            return _response(
                request, 307, headers={"Location": f"https://{OTHER_HOST}/webapi/stolen.cgi"}
            )
        if key == ("SYNO.FileStation.Download", "download"):
            return _response(request, 200, headers={"Content-Type": "text/plain"}, body=b"hello")
        data = {}
        if key == ("SYNO.API.Auth", "login"):
            data = {"sid": "SID-FROM-WHEREVER", "synotoken": "TOKEN-FROM-WHEREVER"}
        elif key == ("SYNO.FileStation.List", "getinfo"):
            data = {
                "files": [
                    {
                        "name": "downloads",
                        "path": "/downloads",
                        "isdir": True,
                        "size": 5,
                        "additional": {"size": 5},
                    }
                ]
            }
        return _response(
            request,
            200,
            headers={"Content-Type": "application/json"},
            body=json.dumps({"success": True, "data": data}).encode(),
        )


@pytest.fixture
def network(monkeypatch):
    def install(redirect_on="all"):
        fake = FakeNetwork(redirect_on)
        monkeypatch.setattr(
            requests.adapters.HTTPAdapter,
            "send",
            lambda adapter, request, **kwargs: fake.send(request),
        )
        return fake

    return install


def _attempt(call):
    """Run `call` and hand back what it raised, so the requests it made can be
    judged first and its outcome second."""
    try:
        call()
    except Exception as error:  # noqa: BLE001 - the outcome is judged by the caller
        return error
    return None


def _nothing_left_the_nas(fake, *, requests_to_nas=1):
    assert fake.hosts() == {NAS_HOST}, f"a request went to {fake.hosts() - {NAS_HOST}}"
    assert len(fake.sent) == requests_to_nas


def _is_refusal(error):
    from broker.errors import RedirectRefused

    return isinstance(error, RedirectRefused)


# ---------------------------------------------------------------------------
# Logging in and out
# ---------------------------------------------------------------------------


class TestLogin:
    @pytest.mark.parametrize("manual_mode", [True, False], ids=["manual", "legacy"])
    def test_r03_a_login_redirect_never_carries_the_password_elsewhere(self, network, manual_mode):
        from auth import synology_auth
        from auth.synology_auth import SynologyAuth

        fake = network()
        auth = SynologyAuth(NAS_URL, manual_mode=manual_mode)
        try:
            result = auth.login("alice", DUMMY_PASSWORD, otp_code=DUMMY_OTP)
        finally:
            synology_auth._AUTH_REGISTRY.pop(NAS_URL, None)

        _nothing_left_the_nas(fake)
        assert not fake.to(OTHER_HOST)
        assert result["success"] is False
        assert result["error"]["code"] == "redirect_refused"

    def test_r03_the_login_message_gives_no_destination_and_no_secret(self, network):
        from auth.synology_auth import SynologyAuth

        network()
        result = SynologyAuth(NAS_URL, manual_mode=True).login(
            "alice", DUMMY_PASSWORD, otp_code=DUMMY_OTP
        )
        message = result["error"]["message"]
        assert "redirect" in message.lower()
        for value in (OTHER_HOST, "stolen", DUMMY_PASSWORD, DUMMY_OTP):
            assert value not in message

    def test_r03_a_login_redirect_is_not_retried_on_another_api_version(self, network):
        """Every version goes to the same address and would meet the same redirect."""
        from auth.synology_auth import SynologyAuth

        fake = network()
        SynologyAuth(NAS_URL, manual_mode=True).login("alice", DUMMY_PASSWORD)
        assert len(fake.sent) == 1

    def test_r03_a_logout_redirect_never_carries_the_session_elsewhere(self, network):
        from auth.synology_auth import SynologyAuth

        fake = network()
        result = SynologyAuth(NAS_URL, manual_mode=True).logout(SESSION_ID)

        _nothing_left_the_nas(fake)
        assert result["success"] is False
        assert result["error"]["code"] == "redirect_refused"


# ---------------------------------------------------------------------------
# The shared client (health, NFS, containers, accounts)
# ---------------------------------------------------------------------------


class TestSharedClient:
    @pytest.mark.parametrize("verb", ["get", "post"])
    def test_r03_a_redirect_does_not_forward_the_session_header(self, network, verb):
        from utils.synology_api import SynologyAPIClient

        fake = network()
        client = SynologyAPIClient(NAS_URL, SESSION_ID, True, SYNO_TOKEN)
        result = getattr(client, verb)("SYNO.Core.System", "info")

        _nothing_left_the_nas(fake)
        assert result["success"] is False
        assert result["error"]["code"] == "redirect_refused"
        assert SESSION_ID not in json.dumps(result)
        assert OTHER_HOST not in json.dumps(result)


# ---------------------------------------------------------------------------
# File Station
# ---------------------------------------------------------------------------


@pytest.fixture
def file_station():
    from filestation.synology_filestation import SynologyFileStation

    return SynologyFileStation(NAS_URL, SESSION_ID, True, SYNO_TOKEN)


class TestFileStation:
    def test_r03_a_listing_redirect_is_refused(self, network, file_station):
        fake = network()
        error = _attempt(file_station.list_shares)
        _nothing_left_the_nas(fake)
        assert _is_refusal(error)

    def test_r03_a_post_redirect_is_refused(self, network, file_station):
        fake = network()
        error = _attempt(
            lambda: file_station._make_request(
                "SYNO.FileStation.CreateFolder", "2", "create", use_post=True, folder_path="/x"
            )
        )
        _nothing_left_the_nas(fake)
        assert _is_refusal(error)

    def test_r03_an_upload_redirect_does_not_forward_the_file_or_session(
        self, network, file_station
    ):
        fake = network()
        error = _attempt(
            lambda: file_station._make_upload_request(
                "SYNO.FileStation.Upload",
                "2",
                "upload",
                {"file": ("a.txt", b"payload", "text/plain")},
                path="/docs",
            )
        )
        _nothing_left_the_nas(fake)
        assert _is_refusal(error)

    def test_r03_creating_a_file_does_not_forward_it_on_a_redirect(self, network, file_station):
        fake = network({("SYNO.FileStation.Upload", "upload")})
        error = _attempt(lambda: file_station.create_file("/docs/a.txt", "payload"))
        assert fake.hosts() == {NAS_HOST}
        assert len(fake.sent) == 1
        assert _is_refusal(error)
        assert OTHER_HOST not in str(error)

    def test_r03_a_download_redirect_is_refused(self, network, file_station):
        fake = network({("SYNO.FileStation.Download", "download")})
        error = _attempt(lambda: file_station.get_file_content("/docs/a.txt"))
        # The size check came first (one request), then the download (one more).
        assert fake.hosts() == {NAS_HOST}
        assert len(fake.sent) == 2
        assert _is_refusal(error)


# ---------------------------------------------------------------------------
# Download Station
# ---------------------------------------------------------------------------


@pytest.fixture
def download_station():
    from downloadstation.synology_downloadstation import SynologyDownloadStation

    return SynologyDownloadStation(NAS_URL, SESSION_ID, True, SYNO_TOKEN)


class TestDownloadStation:
    def test_r03_a_task_list_redirect_is_refused_not_hidden(self, network, download_station):
        fake = network({("SYNO.DownloadStation2.Task", "list")})
        error = _attempt(download_station.list_tasks)
        _nothing_left_the_nas(fake)
        assert _is_refusal(error)

    def test_r03_an_info_redirect_is_not_turned_into_made_up_details(
        self, network, download_station
    ):
        fake = network({("SYNO.DownloadStation.Info", "getinfo")})
        error = _attempt(download_station.get_info)
        _nothing_left_the_nas(fake)
        assert _is_refusal(error)

    def test_r03_a_create_redirect_is_refused_and_not_retried(self, network, download_station):
        fake = network({("SYNO.DownloadStation2.Task", "create")})
        error = _attempt(
            lambda: download_station.create_task("https://files.example.test/a.iso", "downloads")
        )
        assert fake.hosts() == {NAS_HOST}
        assert len(fake.to(NAS_HOST)) == 2  # the destination check, then the one create
        assert _is_refusal(error)

    def test_r03_a_destination_check_redirect_is_not_read_as_a_missing_folder(
        self, network, download_station
    ):
        fake = network({("SYNO.FileStation.List", "getinfo")})
        error = _attempt(lambda: download_station._check_destination_exists("downloads"))
        _nothing_left_the_nas(fake)
        assert _is_refusal(error)

    def test_r03_a_downloaded_files_redirect_is_refused(self, network, download_station):
        fake = network({("SYNO.FileStation.List", "list")})
        error = _attempt(lambda: download_station.list_downloaded_files("downloads"))
        _nothing_left_the_nas(fake)
        assert error is not None
        assert OTHER_HOST not in str(error)


# ---------------------------------------------------------------------------
# The check itself, and a guard against a call that forgets it
# ---------------------------------------------------------------------------


class TestRefuseRedirect:
    @pytest.mark.parametrize("status", [300, 301, 302, 303, 307, 308, 399])
    def test_every_redirect_status_is_refused(self, status):
        from broker.errors import RedirectRefused
        from utils.synology_api import refuse_redirect

        response = requests.Response()
        response.status_code = status
        response.headers["Location"] = f"https://{OTHER_HOST}/x"
        with pytest.raises(RedirectRefused) as error:
            refuse_redirect(response)
        assert OTHER_HOST not in str(error.value)

    @pytest.mark.parametrize("status", [200, 204, 299, 400, 404, 500])
    def test_other_statuses_pass(self, status):
        from utils.synology_api import refuse_redirect

        response = requests.Response()
        response.status_code = status
        refuse_redirect(response)

    def test_a_response_without_a_real_status_is_not_a_redirect(self):
        """Test doubles carry no status; the check must not guess one."""
        from utils.synology_api import refuse_redirect

        refuse_redirect(object())
        refuse_redirect(type("Stub", (), {"status_code": "307"})())

    def test_the_error_names_its_code(self):
        from broker.errors import REDIRECT_REFUSED, RedirectRefused

        assert RedirectRefused.code == REDIRECT_REFUSED == "REDIRECT_REFUSED"


_HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
# Every module that talks to the NAS with `requests`. A new one has to be added
# here on purpose, which is the moment to give its calls `allow_redirects=False`.
_MODULES_THAT_CALL_THE_NAS = {
    "auth/synology_auth.py",
    "utils/synology_api.py",
    "filestation/synology_filestation.py",
    "downloadstation/synology_downloadstation.py",
}


def _calls_to_the_nas(path):
    """Every `requests.<verb>(...)` call and every `<session>.<verb>(..., verify=...)`
    call (a request on a `Session` always says how to verify the certificate)."""
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in _HTTP_VERBS:
            continue
        on_requests = isinstance(node.func.value, ast.Name) and node.func.value.id == "requests"
        says_verify = any(keyword.arg == "verify" for keyword in node.keywords)
        if on_requests or says_verify:
            yield node


def test_the_modules_that_call_the_nas_are_the_ones_this_test_covers():
    importing = {
        path.relative_to(SRC).as_posix()
        for path in SRC.rglob("*.py")
        if re.search(r"^\s*import requests\b", path.read_text(encoding="utf-8"), re.M)
    }
    assert importing == _MODULES_THAT_CALL_THE_NAS
    for relative in importing:
        assert list(_calls_to_the_nas(SRC / relative)), relative


@pytest.mark.parametrize("relative", sorted(_MODULES_THAT_CALL_THE_NAS))
def test_r03_every_call_to_the_nas_refuses_redirects(relative):
    path = SRC / relative
    offenders = []
    for call in _calls_to_the_nas(path):
        keyword = next((k for k in call.keywords if k.arg == "allow_redirects"), None)
        refused = (
            keyword is not None
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
        )
        if not refused:
            offenders.append(f"{relative}:{call.lineno}")
    assert not offenders, f"calls that may follow a redirect: {offenders}"
