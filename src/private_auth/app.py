# src/private_auth/app.py - The private login interface.
#
# A small HTTPS site for the owner, on its own port and apart from the MCP API.
# The owner proves who they are with a passkey; then sees which clients are
# waiting for a NAS sign-in, checks which NAS, which account, which client and
# what access is involved, and types the NAS password (and a one-time code, if
# the account has one). Nothing here is reachable with an MCP client's bearer
# token, and an MCP call cannot approve, start or alter a sign-in.
#
# What it guarantees (plans/2026-10-06-manual-authentication/PLAN.md §5.1):
#   - every response carries no-store, a strict CSP and framing/referrer limits;
#   - every state-changing request needs the owner session, a CSRF token and a
#     matching Origin;
#   - cookies are Secure, HttpOnly and SameSite=Strict;
#   - the page loads nothing from another origin and has no inline script;
#   - passwords, codes and sessions never appear in a URL, a cookie, a log line,
#     a response body or a redirect.

import html
import json
import logging
import re
import urllib.parse
from typing import Any, Dict, Optional, Protocol, Sequence, Tuple

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from broker.runtime import BrokerRuntime
from private_auth.login import LoginService
from private_auth.security import (
    SECURITY_HEADERS,
    OwnerSession,
    OwnerSessions,
    RateLimiter,
    constant_time_equal,
    origin_allowed,
)

logger = logging.getLogger("synology-private-login")

MAX_FORM_BYTES = 8 * 1024
MAX_JSON_BYTES = 64 * 1024

# What `?m=` may say after a redirect: fixed sentences, never a value.
_NOTICES = {
    "connected": "Connected. The client can use the NAS now.",
    "disconnected": "Disconnected.",
    "cancelled": "Sign-in request cancelled.",
    "expired": "That sign-in request has expired. Start a new one.",
}


class OwnerAuthenticator(Protocol):
    def has_owner(self) -> bool: ...

    def begin_authentication(self) -> Optional[Tuple[str, Dict[str, Any]]]: ...

    def finish_authentication(self, state: str, credential: Dict[str, Any]) -> bool: ...

    def begin_enrollment(self, code: str) -> Optional[Tuple[str, Dict[str, Any]]]: ...

    def finish_enrollment(
        self, state: str, credential: Dict[str, Any], label: str = "passkey"
    ) -> bool: ...


class SecurityHeadersMiddleware:
    """Adds the security headers to every response, errors included."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.decode().lower() not in {h.lower() for h in SECURITY_HEADERS}
                ]
                headers += [(k.lower().encode(), v.encode()) for k, v in SECURITY_HEADERS.items()]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


_CSS = """
body{font:16px/1.5 system-ui,sans-serif;max-width:42rem;margin:2rem auto;padding:0 1rem;color:#1b1f23;background:#fff}
h1{font-size:1.4rem} table{border-collapse:collapse;width:100%} th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #d0d7de}
button,input{font:inherit} input[type=password],input[type=text]{width:100%;padding:.4rem;box-sizing:border-box}
button{padding:.45rem .9rem;cursor:pointer} label{display:block;margin:.8rem 0 .2rem}
form.inline{display:inline}
.note{background:#f6f8fa;border:1px solid #d0d7de;padding:.6rem .8rem;border-radius:4px;margin:1rem 0}
.error{background:#fff1f0;border:1px solid #ffa39e}.facts dt{font-weight:600;margin-top:.6rem} .facts dd{margin:0}
@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}.note{background:#161b22;border-color:#30363d}.error{background:#2d1517}th,td{border-color:#30363d}}
"""

_PASSKEY_JS = """
const b64 = {
  toBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';const r=atob(s),u=new Uint8Array(r.length);for(let i=0;i<r.length;i++)u[i]=r.charCodeAt(i);return u.buffer;},
  toStr(b){const u=new Uint8Array(b);let s='';for(const c of u)s+=String.fromCharCode(c);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}
};
async function post(path, body){
  const r = await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)});
  return {status:r.status, data: await r.json().catch(()=>({}))};
}
function say(id,text){const e=document.getElementById(id); if(e){e.textContent=text; e.hidden=false;}}
async function signIn(){
  try{
    const begin = await post('/auth/begin',{});
    if(begin.status!==200){say('msg','Sign-in is not available.');return;}
    const o = begin.data.options;
    o.challenge=b64.toBuf(o.challenge);
    (o.allowCredentials||[]).forEach(c=>c.id=b64.toBuf(c.id));
    const cred = await navigator.credentials.get({publicKey:o});
    const done = await post('/auth/finish',{state:begin.data.state,credential:{
      id:cred.id,rawId:b64.toStr(cred.rawId),type:cred.type,clientExtensionResults:cred.getClientExtensionResults(),
      response:{clientDataJSON:b64.toStr(cred.response.clientDataJSON),authenticatorData:b64.toStr(cred.response.authenticatorData),
        signature:b64.toStr(cred.response.signature),userHandle:cred.response.userHandle?b64.toStr(cred.response.userHandle):null}}});
    if(done.status===200){location.href='/';}else{say('msg','That passkey was not accepted.');}
  }catch(e){say('msg','Sign-in was cancelled or failed.');}
}
async function enroll(){
  try{
    const code = document.getElementById('code').value.trim();
    const begin = await post('/enroll/begin',{code});
    if(begin.status!==200){say('msg','That code was not accepted.');return;}
    const o = begin.data.options;
    o.challenge=b64.toBuf(o.challenge);o.user.id=b64.toBuf(o.user.id);
    (o.excludeCredentials||[]).forEach(c=>c.id=b64.toBuf(c.id));
    const cred = await navigator.credentials.create({publicKey:o});
    const done = await post('/enroll/finish',{state:begin.data.state,label:'passkey',credential:{
      id:cred.id,rawId:b64.toStr(cred.rawId),type:cred.type,clientExtensionResults:cred.getClientExtensionResults(),
      response:{clientDataJSON:b64.toStr(cred.response.clientDataJSON),attestationObject:b64.toStr(cred.response.attestationObject),
        transports:cred.response.getTransports?cred.response.getTransports():[]}}});
    if(done.status===200){say('msg','Passkey enrolled. You can sign in now.');}else{say('msg','Enrollment failed.');}
  }catch(e){say('msg','Enrollment was cancelled or failed.');}
}
document.addEventListener('DOMContentLoaded',()=>{
  const a=document.getElementById('signin'); if(a)a.addEventListener('click',signIn);
  const b=document.getElementById('enroll'); if(b)b.addEventListener('click',enroll);
});
"""


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{html.escape(title)}</title><link rel="stylesheet" href="/static/app.css">'
        '<script src="/static/passkey.js" defer></script></head>'
        f"<body><h1>{html.escape(title)}</h1>{body}</body></html>",
        status_code=status,
    )


def _notice(text: str, error: bool = False) -> str:
    return f'<p class="note{" error" if error else ""}" role="status">{html.escape(text)}</p>'


def _hidden(csrf: str) -> str:
    return f'<input type="hidden" name="csrf" value="{html.escape(csrf)}">'


class PrivateLoginApp:
    def __init__(
        self,
        runtime: BrokerRuntime,
        login: LoginService,
        owner: OwnerAuthenticator,
        *,
        allowed_origins: Sequence[str],
        allowed_hosts: Sequence[str],
        secure_cookies: bool = True,
        sessions: Optional[OwnerSessions] = None,
        auth_limiter: Optional[RateLimiter] = None,
        enroll_limiter: Optional[RateLimiter] = None,
    ):
        if not allowed_origins or not allowed_hosts:
            raise ValueError("allowed_origins and allowed_hosts are required")
        self.runtime = runtime
        self.login = login
        self.owner = owner
        self.allowed_origins = tuple(allowed_origins)
        # TrustedHostMiddleware compares the Host header WITHOUT its port, so a
        # name written with one ("broker.example:8444") could never match and
        # every request would be refused. Accept either spelling.
        self.allowed_hosts = sorted({re.sub(r":\d+$", "", h) for h in allowed_hosts})
        self.secure_cookies = secure_cookies
        self.sessions = sessions or OwnerSessions()
        # Ten failed passkey checks per address in five minutes; five wrong
        # enrollment codes in ten, and the code is long enough that this is a
        # courtesy, not the control.
        self.auth_limiter = auth_limiter or RateLimiter(10, 300, lockout_seconds=300)
        self.enroll_limiter = enroll_limiter or RateLimiter(5, 600, lockout_seconds=600)

    @property
    def cookie_name(self) -> str:
        # The __Host- prefix makes a browser refuse the cookie unless it is
        # Secure, host-only and set on the root path.
        return "__Host-owner" if self.secure_cookies else "owner"

    # -- helpers -------------------------------------------------------------

    def _owner(self, request: Request) -> Optional[OwnerSession]:
        return self.sessions.get(request.cookies.get(self.cookie_name))

    @staticmethod
    def _client_address(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def _origin_ok(self, request: Request) -> bool:
        return origin_allowed(request.headers.get("origin"), self.allowed_origins)

    async def _form(self, request: Request) -> Optional[Dict[str, str]]:
        """The urlencoded body as a dict, or None if it is too large or not valid.
        Read as bytes with a size limit; never logged."""
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_FORM_BYTES:
                return None
        try:
            parsed = urllib.parse.parse_qs(
                body.decode("utf-8"), keep_blank_values=True, strict_parsing=False
            )
        except (UnicodeDecodeError, ValueError):
            return None
        finally:
            body.clear()
        return {key: values[-1] for key, values in parsed.items()}

    async def _json(self, request: Request) -> Optional[Dict[str, Any]]:
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_JSON_BYTES:
                return None
        try:
            data = json.loads(bytes(body) or b"{}")
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def _authorize(self, request: Request) -> Tuple[Optional[OwnerSession], Optional[Response]]:
        """The owner session for a state-changing request, or the refusal: the
        wrong Origin is 403 and no owner session is 401. Decided before the body
        is read, so an unauthenticated request costs nothing to refuse."""
        if not self._origin_ok(request):
            return None, PlainTextResponse("Forbidden", status_code=403)
        session = self._owner(request)
        if session is None:
            return None, PlainTextResponse("Sign in first", status_code=401)
        return session, None

    async def _authorized_form(
        self, request: Request
    ) -> Tuple[Optional[OwnerSession], Optional[Dict[str, str]], Optional[Response]]:
        """Origin, then owner session, then the body (bounded), then the CSRF
        token, in that order. Returns the session and the form, or the refusal."""
        session, refusal = self._authorize(request)
        if refusal is not None:
            return None, None, refusal
        form = await self._form(request)
        if form is None:
            return None, None, PlainTextResponse("Bad request", status_code=400)
        if not constant_time_equal(form.get("csrf", ""), session.csrf_token):
            return None, None, PlainTextResponse("Forbidden", status_code=403)
        return session, form, None

    def _require_owner(self, request: Request) -> Tuple[Optional[OwnerSession], Optional[Response]]:
        session = self._owner(request)
        if session is None:
            return None, RedirectResponse("/", status_code=303)
        return session, None

    def _set_session_cookie(self, response: Response, token: str) -> None:
        response.set_cookie(
            self.cookie_name,
            token,
            httponly=True,
            secure=self.secure_cookies,
            samesite="strict",
            path="/",
            max_age=3600,
        )

    # -- pages ---------------------------------------------------------------

    async def home(self, request: Request) -> Response:
        session = self._owner(request)
        if session is None:
            if not self.owner.has_owner():
                return _page(
                    "No owner enrolled",
                    _notice(
                        "Nobody can sign in yet. On the broker host, run the enroll command, then open /enroll here."
                    )
                    + '<p><a href="/enroll">Enroll a passkey</a></p>',
                )
            return _page(
                "Private sign-in",
                _notice("Sign in with the passkey on this device to continue.")
                + '<p><button id="signin" type="button">Sign in with passkey</button></p>'
                '<p id="msg" class="note error" role="status" hidden></p>',
            )

        notice = _NOTICES.get(request.query_params.get("m", ""))
        rows = []
        for client in self.runtime.policy.clients.values():
            status = self.runtime.sessions.status(client.name)
            for nas in sorted(client.nas):
                name, nas_name = html.escape(client.name), html.escape(nas)
                pending = self.runtime.sessions.pending(client.name, nas)
                if nas in status:
                    left = int(status[nas]["idle_seconds_left"]) // 60
                    state = f"connected (idle limit in about {left} min)"
                    action = (
                        f'<form method="post" action="/disconnect">{_hidden(session.csrf_token)}'
                        f'<input type="hidden" name="client" value="{name}"><input type="hidden" name="nas" value="{nas_name}">'
                        '<button type="submit">Disconnect</button></form>'
                    )
                elif pending is not None:
                    state = "waiting for you to sign in"
                    action = (
                        f'<a href="/login/{html.escape(pending.request_id)}">Continue</a> '
                        f'<form method="post" action="/pending/cancel" class="inline">{_hidden(session.csrf_token)}'
                        f'<input type="hidden" name="client" value="{name}"><input type="hidden" name="nas" value="{nas_name}">'
                        '<button type="submit">Cancel</button></form>'
                    )
                else:
                    state = "not connected"
                    action = (
                        f'<form method="post" action="/pending/new">{_hidden(session.csrf_token)}'
                        f'<input type="hidden" name="client" value="{name}"><input type="hidden" name="nas" value="{nas_name}">'
                        '<button type="submit">Sign in</button></form>'
                    )
                rows.append(
                    f"<tr><td>{name}</td><td>{nas_name}</td><td>{state}</td><td>{action}</td></tr>"
                )
        body = (
            (_notice(notice) if notice else "")
            + "<table><thead><tr><th>Client</th><th>NAS</th><th>State</th><th></th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
            + f'<form method="post" action="/logout">{_hidden(session.csrf_token)}<p><button type="submit">End this session</button></p></form>'
        )
        return _page("Synology broker", body)

    async def login_page(self, request: Request) -> Response:
        session, refusal = self._require_owner(request)
        if refusal:
            return refusal
        return self._render_login(request.path_params["request_id"], session, message=None)

    def _render_login(
        self,
        request_id: str,
        session: OwnerSession,
        message: Optional[Tuple[str, bool]],
        status: int = 200,
    ) -> Response:
        pending = self.runtime.sessions.find_pending(request_id)
        if pending is None:
            return _page(
                "Request expired",
                _notice(_NOTICES["expired"], True) + '<p><a href="/">Back</a></p>',
                404,
            )
        client = self.runtime.policy.clients[pending.owner]
        account = self.login.account_for(pending.nas)
        roots = client.folders.get(pending.nas, ())
        facts = (
            '<dl class="facts">'
            f"<dt>NAS</dt><dd>{html.escape(pending.nas)}</dd>"
            f"<dt>Account</dt><dd>{html.escape(account) if account else 'not set; you will type it'}</dd>"
            f"<dt>Requested by</dt><dd>{html.escape(client.name)}</dd>"
            f"<dt>Tools it may use</dt><dd>{len(client.allowed_tools())}</dd>"
            f"<dt>Folders it may reach</dt><dd>{html.escape(', '.join(roots)) if roots else 'none'}</dd>"
            "</dl>"
        )
        username_field = (
            ""
            if account
            else '<label for="username">NAS account name</label><input id="username" name="username" type="text" autocomplete="username">'
        )
        form = (
            f'<form method="post" action="/login/{html.escape(request_id)}" autocomplete="off">{_hidden(session.csrf_token)}'
            f"{username_field}"
            '<label for="password">NAS password</label>'
            '<input id="password" name="password" type="password" autocomplete="current-password" required>'
            '<label for="otp">Verification code (only if the account uses one)</label>'
            '<input id="otp" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="10">'
            '<p><button type="submit">Sign in</button> <a href="/">Cancel</a></p></form>'
        )
        note = _notice(message[0], message[1]) if message else ""
        return _page("Sign in to the NAS", note + facts + form, status)

    # -- actions -------------------------------------------------------------

    async def login_submit(self, request: Request) -> Response:
        session, form, refusal = await self._authorized_form(request)
        if refusal is not None:
            return refusal
        request_id = request.path_params["request_id"]
        pending = self.runtime.sessions.find_pending(request_id)
        if pending is None:
            return RedirectResponse("/?m=expired", status_code=303)

        outcome = await self.login.attempt(
            pending,
            password=form.get("password", ""),
            otp=form.get("otp"),
            username=form.get("username"),
        )
        form.clear()
        if outcome.ok:
            logger.info("A private sign-in succeeded for %s on %s", pending.owner, pending.nas)
            return RedirectResponse("/?m=connected", status_code=303)
        logger.info("A private sign-in did not complete (%s)", outcome.code)
        return self._render_login(
            request_id,
            session,
            (outcome.message, True),
            status=429 if outcome.code == "locked" else 200,
        )

    async def _pair_action(self, request: Request, action: str) -> Response:
        _, form, refusal = await self._authorized_form(request)
        if refusal is not None:
            return refusal
        client_name, nas = form.get("client", ""), form.get("nas", "")
        client = self.runtime.policy.clients.get(client_name)
        if client is None or nas not in client.nas:
            return PlainTextResponse("Not found", status_code=404)
        if action == "new":
            pending = self.runtime.sessions.begin_pending(client_name, nas)
            return RedirectResponse(f"/login/{pending.request_id}", status_code=303)
        if action == "cancel":
            self.runtime.sessions.cancel_pending(client_name, nas)
            return RedirectResponse("/?m=cancelled", status_code=303)
        self.runtime.revoke(client_name, nas)
        return RedirectResponse("/?m=disconnected", status_code=303)

    async def pending_new(self, request: Request) -> Response:
        return await self._pair_action(request, "new")

    async def pending_cancel(self, request: Request) -> Response:
        return await self._pair_action(request, "cancel")

    async def disconnect(self, request: Request) -> Response:
        return await self._pair_action(request, "disconnect")

    async def logout(self, request: Request) -> Response:
        _, _, refusal = await self._authorized_form(request)
        if refusal is not None:
            return refusal
        self.sessions.end(request.cookies.get(self.cookie_name))
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie(
            self.cookie_name, path="/", secure=self.secure_cookies, httponly=True, samesite="strict"
        )
        return response

    # -- passkey ceremonies --------------------------------------------------

    async def auth_begin(self, request: Request) -> Response:
        if not self._origin_ok(request):
            return JSONResponse({"ok": False}, status_code=403)
        begun = self.owner.begin_authentication()
        if begun is None:
            return JSONResponse({"ok": False, "error": "not_enrolled"}, status_code=409)
        state, options = begun
        return JSONResponse({"state": state, "options": options})

    async def auth_finish(self, request: Request) -> Response:
        if not self._origin_ok(request):
            return JSONResponse({"ok": False}, status_code=403)
        address = self._client_address(request)
        if not self.auth_limiter.allow(address):
            return JSONResponse({"ok": False}, status_code=429)
        data = await self._json(request)
        state, credential = (data or {}).get("state"), (data or {}).get("credential")
        if (
            not isinstance(state, str)
            or not isinstance(credential, dict)
            or not self.owner.finish_authentication(state, credential)
        ):
            self.auth_limiter.record(address)
            return JSONResponse({"ok": False}, status_code=401)
        self.auth_limiter.reset(address)
        token, _ = self.sessions.create()
        response = JSONResponse({"ok": True})
        self._set_session_cookie(response, token)
        return response

    async def enroll_page(self, request: Request) -> Response:
        return _page(
            "Enroll a passkey",
            _notice(
                "Run the enroll command on the broker host, then type the one-time code it prints."
            )
            + '<label for="code">One-time code</label><input id="code" type="text" autocomplete="off">'
            '<p><button id="enroll" type="button">Create passkey</button></p>'
            '<p id="msg" class="note" role="status" hidden></p>',
        )

    async def enroll_begin(self, request: Request) -> Response:
        if not self._origin_ok(request):
            return JSONResponse({"ok": False}, status_code=403)
        address = self._client_address(request)
        if not self.enroll_limiter.allow(address):
            return JSONResponse({"ok": False}, status_code=429)
        data = await self._json(request)
        code = (data or {}).get("code")
        begun = self.owner.begin_enrollment(code) if isinstance(code, str) and code else None
        if begun is None:
            self.enroll_limiter.record(address)
            return JSONResponse({"ok": False}, status_code=403)
        state, options = begun
        return JSONResponse({"state": state, "options": options})

    async def enroll_finish(self, request: Request) -> Response:
        if not self._origin_ok(request):
            return JSONResponse({"ok": False}, status_code=403)
        data = await self._json(request)
        state, credential = (data or {}).get("state"), (data or {}).get("credential")
        label = (
            (data or {}).get("label") if isinstance((data or {}).get("label"), str) else "passkey"
        )
        if (
            not isinstance(state, str)
            or not isinstance(credential, dict)
            or not self.owner.finish_enrollment(state, credential, label)
        ):
            return JSONResponse({"ok": False}, status_code=403)
        return JSONResponse({"ok": True})

    # -- static --------------------------------------------------------------

    async def css(self, request: Request) -> Response:
        return Response(_CSS, media_type="text/css")

    async def js(self, request: Request) -> Response:
        return Response(_PASSKEY_JS, media_type="text/javascript")

    async def healthz(self, request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    def build(self) -> Starlette:
        post = ["POST"]
        return Starlette(
            routes=[
                Route("/", self.home, methods=["GET"]),
                Route("/login/{request_id}", self.login_page, methods=["GET"]),
                Route("/login/{request_id}", self.login_submit, methods=post),
                Route("/pending/new", self.pending_new, methods=post),
                Route("/pending/cancel", self.pending_cancel, methods=post),
                Route("/disconnect", self.disconnect, methods=post),
                Route("/logout", self.logout, methods=post),
                Route("/auth/begin", self.auth_begin, methods=post),
                Route("/auth/finish", self.auth_finish, methods=post),
                Route("/enroll", self.enroll_page, methods=["GET"]),
                Route("/enroll/begin", self.enroll_begin, methods=post),
                Route("/enroll/finish", self.enroll_finish, methods=post),
                Route("/static/app.css", self.css, methods=["GET"]),
                Route("/static/passkey.js", self.js, methods=["GET"]),
                Route("/healthz", self.healthz, methods=["GET"]),
            ],
            middleware=[
                # Outermost, so that even a refusal for a wrong Host header
                # carries the security headers.
                Middleware(SecurityHeadersMiddleware),
                Middleware(TrustedHostMiddleware, allowed_hosts=self.allowed_hosts),
            ],
        )


def create_private_app(
    runtime: BrokerRuntime,
    login: LoginService,
    owner: OwnerAuthenticator,
    *,
    allowed_origins: Sequence[str],
    allowed_hosts: Sequence[str],
    **kwargs: Any,
) -> Starlette:
    return PrivateLoginApp(
        runtime,
        login,
        owner,
        allowed_origins=allowed_origins,
        allowed_hosts=allowed_hosts,
        **kwargs,
    ).build()
