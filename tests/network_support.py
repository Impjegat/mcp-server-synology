"""A fake network for tests that need `requests`' real machinery.

It answers on the real `HTTPAdapter.send`, so redirects, timeouts and the way the
service modules read a response are all the real code's. Nothing here opens a
socket. A test says what the NAS replies for each DSM `(api, method)` and then
looks at what was actually sent.
"""

import io
import json
import re
from urllib.parse import parse_qs, urlsplit

import requests
import requests.adapters


def make_response(request, status, *, headers=None, body=b""):
    response = requests.Response()
    response.status_code = status
    response.headers.update(headers or {})
    response._content = body
    response._content_consumed = True
    response.url = request.url
    response.request = request
    response.raw = io.BytesIO(body)
    return response


def api_and_method(request):
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


def request_fields(request):
    """Every form or query field of a request, as a dict of single values."""
    fields = parse_qs(urlsplit(request.url).query)
    body = request.body
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else (body or "")
    if 'name="api"' not in text:
        fields.update(parse_qs(text))
    return {key: values[0] for key, values in fields.items()}


def dsm_error(code):
    """What DSM answers when it says no."""
    return {"success": False, "error": {"code": code}}


def dsm_ok(data=None):
    return {"success": True, "data": data if data is not None else {}}


class ScriptedNas:
    """The NAS, on the real transport.

    `script` maps a DSM `(api, method)` to its replies, used in order with the last
    one repeating. A reply is a DSM answer (a dict, sent as JSON with status 200), an
    `int` (a bare HTTP status), `bytes` (a raw 200 body), or an exception instance
    (raised from the send, as a timeout or a refused connection would be). A request
    that matches nothing in the script gets `{"success": True, "data": {}}`.
    Every request that was sent is kept in `sent`."""

    def __init__(self, script=None):
        self.script = {
            key: list(value) if isinstance(value, list) else [value]
            for key, value in (script or {}).items()
        }
        self.sent = []

    def install(self, monkeypatch):
        monkeypatch.setattr(
            requests.adapters.HTTPAdapter,
            "send",
            lambda adapter, request, **kwargs: self._send(request),
        )
        return self

    def count(self, api, method):
        """How many requests for this `(api, method)` were sent."""
        return len([item for item in self.sent if item["key"] == (api, method)])

    def requests_for(self, api, method):
        return [item for item in self.sent if item["key"] == (api, method)]

    def _send(self, request):
        key = api_and_method(request)
        self.sent.append(
            {
                "http_method": request.method,
                "url": request.url,
                "key": key,
                "fields": request_fields(request),
                "headers": dict(request.headers),
            }
        )
        replies = self.script.get(key)
        if not replies:
            reply = dsm_ok()
        else:
            reply = replies.pop(0) if len(replies) > 1 else replies[0]
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, bool):  # not a status
            raise TypeError("a reply is a dict, an int, bytes or an exception")
        if isinstance(reply, int):
            return make_response(request, reply)
        if isinstance(reply, bytes):
            return make_response(request, 200, body=reply)
        return make_response(
            request,
            200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(reply).encode(),
        )
