# src/private_auth/app.py - The private login interface.
#
# A small HTTPS site for the owner, on its own port and apart from the MCP API.
# The owner proves who they are with a passkey; then sees which clients are
# waiting for a NAS sign-in, checks which NAS, which account, which client and
# what access is involved, and types the NAS password (and a one-time code, if
# the account has one). Nothing here is reachable with an MCP client's bearer
# token, and an MCP call cannot approve, start or alter a sign-in.
#
# What it guarantees (plans/shipped/2026-10-06-manual-authentication/PLAN.md §5.1):
#   - every response carries no-store, a strict CSP and framing/referrer limits;
#   - every state-changing request needs the owner session, a CSRF token and a
#     matching Origin;
#   - cookies are Secure, HttpOnly and SameSite=Strict;
#   - the page loads nothing from another origin and has no inline script;
#   - passwords, codes and sessions never appear in a URL, a cookie, a log line,
#     a response body or a redirect.

import datetime
import html
import json
import logging
import re
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence, Tuple

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

from broker.policy import GRANT_WARN_SECONDS
from broker.runtime import BrokerRuntime
from private_auth.logbuffer import RingLogHandler
from private_auth.login import LoginService
from private_auth.security import (
    SECURITY_HEADERS,
    OwnerSession,
    OwnerSessions,
    RateLimiter,
    constant_time_equal,
    origin_allowed,
)
from private_auth.settings import SettingsError, SettingsService

logger = logging.getLogger("synology-private-login")

MAX_FORM_BYTES = 8 * 1024
MAX_JSON_BYTES = 64 * 1024

# A session counts as "ending soon" in /attention when its absolute deadline is this
# close. Its idle deadline does not count: an unused session runs that down by itself.
ENDING_SOON_SECONDS = 600

# What `?m=` may say after a redirect: fixed sentences, never a value.
_NOTICES = {
    "connected": "Connected. The client can use the NAS now.",
    "disconnected": "Disconnected.",
    "cancelled": "Sign-in request cancelled.",
    "expired": (
        "That sign-in request has expired or was already used. If you have just signed in, "
        "the table below shows whether it worked."
    ),
    "progress": (
        "A sign-in for this request is already in progress. This page updates by itself "
        "and shows Connected when it finishes. If it does not connect, choose Continue "
        "to try again."
    ),
    "withdrawn": (
        "That sign-in was cancelled or expired before it finished, so it was not used. "
        "Start a new one."
    ),
    "all_disconnected": "Every client is disconnected.",
}


def _span(seconds: Optional[int]) -> str:
    """A length of time for a person: '5 min', '7 h 30 min', '3 days'. Only ever
    rounded down to the minute, so a deadline is never described as further off
    than it is."""
    if seconds is None:
        return ""
    if seconds <= 0:
        return "ended"
    minutes = seconds // 60
    if minutes < 1:
        return "under a minute"
    if minutes < 60:
        return f"{minutes} min"
    hours, rest = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} h {rest} min" if rest else f"{hours} h"
    return f"{hours // 24} days"


def _number_text(value: float) -> str:
    """`value` for a number field: as many decimals as it needs, up to six, and no more.
    A value that is shown and saved back untouched must come back as the same number of
    seconds: six decimals of an hour is under two milliseconds, and `%g` (six significant
    figures) is not that precise for a value like 167.99972 hours."""
    return f"{value:.6f}".rstrip("0").rstrip(".")


def _grant_text(left: Optional[int], ends_at: Optional[float]) -> str:
    if left is None or ends_at is None:
        return ""
    day = datetime.datetime.fromtimestamp(ends_at, datetime.timezone.utc).strftime("%Y-%m-%d")
    if left <= 0:
        return f"ended {day}: renew it"
    if left <= GRANT_WARN_SECONDS:
        return f"ends {day} (in {_span(left)}): renew soon"
    return f"ends {day}"


class OwnerAuthenticator(Protocol):
    def has_owner(self) -> bool: ...

    def begin_authentication(self) -> Optional[Tuple[str, Dict[str, Any]]]: ...

    def finish_authentication(self, state: str, credential: Dict[str, Any]) -> bool: ...

    def begin_enrollment(self, code: str) -> Optional[Tuple[str, Dict[str, Any]]]: ...

    def finish_enrollment(
        self, state: str, credential: Dict[str, Any], label: str = "passkey"
    ) -> bool: ...

    def begin_confirmation(self, binding: str) -> Optional[Tuple[str, Dict[str, Any]]]: ...

    def finish_confirmation(self, state: str, credential: Dict[str, Any]) -> Optional[str]: ...


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
nav{margin:0 0 1rem} nav a{margin-right:1rem}
.muted{color:#57606a} .warn{color:#9a6700;font-weight:600}
pre.log{white-space:pre-wrap;word-break:break-word;font:.8rem/1.4 ui-monospace,Consolas,monospace;background:#f6f8fa;border:1px solid #d0d7de;border-radius:4px;padding:.6rem;max-height:70vh;overflow:auto}
td.num{white-space:nowrap}
.note{background:#f6f8fa;border:1px solid #d0d7de;padding:.6rem .8rem;border-radius:4px;margin:1rem 0}
.error{background:#fff1f0;border:1px solid #ffa39e}.facts dt{font-weight:600;margin-top:.6rem} .facts dd{margin:0}
@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}.note{background:#161b22;border-color:#30363d}.error{background:#2d1517}th,td{border-color:#30363d}.muted{color:#8b949e}.warn{color:#d29922}pre.log{background:#161b22;border-color:#30363d}}
"""

# Keeps the dashboard's figures current and reloads it when something changed state.
# It asks /api/state without touching the owner session's idle clock, so a window left
# open cannot keep the owner signed in.
_DASHBOARD_JS = """
(function(){
  const table = document.getElementById('rows');
  if(!table) return;
  let busy = false;
  async function tick(){
    if(busy || document.hidden) return;
    busy = true;
    try{
      const r = await fetch('/api/state',{credentials:'same-origin',cache:'no-store'});
      if(r.status===401){location.href='/';return;}
      if(!r.ok) return;
      const data = await r.json();
      if(data.signature !== table.dataset.signature){location.reload();return;}
      data.rows.forEach(row=>{
        document.querySelectorAll('td[data-client][data-nas]').forEach(td=>{
          if(td.dataset.client===row.client && td.dataset.nas===row.nas){
            td.textContent = row.left;
            // The cell before it is the state, which carries the idle clock.
            if(td.previousElementSibling){td.previousElementSibling.textContent = row.state_text;}
          }
        });
      });
    }catch(e){}finally{busy=false;}
  }
  setInterval(tick, 5000);
})();
"""

_LOG_JS = """
(function(){
  const box = document.getElementById('log');
  if(!box) return;
  async function tick(){
    if(document.hidden) return;
    try{
      const r = await fetch('/api/log',{credentials:'same-origin',cache:'no-store'});
      if(r.status===401){location.href='/';return;}
      if(!r.ok) return;
      const data = await r.json();
      const atEnd = box.scrollTop + box.clientHeight >= box.scrollHeight - 20;
      box.textContent = data.lines.join('\\n');
      if(atEnd) box.scrollTop = box.scrollHeight;
    }catch(e){}
  }
  box.scrollTop = box.scrollHeight;
  setInterval(tick, 3000);
})();
"""

# Signs in several client/NAS pairs from one password entry, one pair at a time. The
# password lives only in the page's field: it is sent with each step, never stored,
# and the field is cleared as soon as the run ends, wrongly or not. It stops at the
# first failure, so a typo costs one attempt on one pair and not one on every pair.
_LOGIN_ALL_JS = """
(function(){
  const form = document.getElementById('loginall');
  if(!form) return;
  const msg = document.getElementById('msg');
  const go = document.getElementById('go');
  const csrf = form.elements.csrf.value;
  function say(text, bad){msg.textContent = text; msg.className = 'note' + (bad ? ' error' : ''); msg.hidden = false;}
  form.addEventListener('submit', async (event)=>{
    event.preventDefault();
    const password = form.elements.password, otp = form.elements.otp, user = form.elements.username;
    const todo = Array.from(form.querySelectorAll('input.pair')).filter(box=>box.checked && !box.disabled);
    if(!todo.length){say('Tick at least one client.', true); return;}
    if(!password.value){say('Enter the NAS password.', true); password.focus(); return;}
    go.disabled = true;
    try{
      for(const box of todo){
        const label = box.dataset.client + ' on ' + box.dataset.nas;
        say('Signing in ' + label + '...', false);
        let response, answer = {};
        try{
          response = await fetch('/api/login-all/step',{
            method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
            body: JSON.stringify({csrf:csrf, client:box.dataset.client, nas:box.dataset.nas,
              password:password.value, otp:otp.value, username:user ? user.value : ''})});
          answer = await response.json().catch(()=>({}));
        }catch(error){say('The broker could not be reached.', true); return;}
        if(response.status===401 || (response.status===403 && !answer.code)){
          say('Your passkey sign-in has ended. Reload this page and sign in again.', true); return;
        }
        if(answer.ok){
          box.checked = false; box.disabled = true;
          const cell = box.closest('tr').querySelector('.st'); if(cell){cell.textContent = 'connected';}
          continue;
        }
        const code = answer.code, text = answer.message || 'The sign-in did not complete.';
        if(code==='403' || code==='404'){
          otp.value = ''; otp.focus();
          say(label + ': ' + text + ' Enter a code, then press the button again to carry on with the rest.', true);
        }else if(code==='400'){
          password.value = ''; otp.value = ''; password.focus();
          say(label + ': ' + text + ' Nothing else was tried. Retype the password and press the button again.', true);
        }else{
          say(label + ': ' + text, true);
        }
        return;
      }
      password.value = ''; otp.value = '';
      say('Every ticked client is connected.', false);
    }finally{go.disabled = false;}
  });
})();
"""

# Saves settings in two steps: the server checks the change and says what it would do
# and asks for a passkey bound to exactly that change; only the passkey's answer lets
# the server apply it. `b64` is the base64url helper that passkey.js defines.
_SETTINGS_JS = """
(function(){
  const form = document.getElementById('settings');
  if(!form) return;
  const msg = document.getElementById('msg');
  const save = document.getElementById('save');
  const csrf = form.elements.csrf.value;
  function say(lines, bad){
    msg.textContent = '';
    (Array.isArray(lines) ? lines : [lines]).forEach((line, i)=>{
      if(i) msg.appendChild(document.createElement('br'));
      msg.appendChild(document.createTextNode(line));
    });
    msg.className = 'note' + (bad ? ' error' : ''); msg.hidden = false;
  }
  function syncDelete(){
    form.querySelectorAll('fieldset[data-client]').forEach(box=>{
      const write = box.querySelector('input[data-kind=write]'), del = box.querySelector('input[data-kind=delete]');
      del.disabled = !write.checked; if(!write.checked) del.checked = false;
    });
  }
  form.addEventListener('change', syncDelete); syncDelete();
  function collect(){
    const session = {};
    form.querySelectorAll('input[data-field]').forEach(input=>{
      session[input.dataset.field] = input.value === '' ? null : Number(input.value);
    });
    const clients = {};
    form.querySelectorAll('fieldset[data-client]').forEach(box=>{
      const folders = {};
      box.querySelectorAll('textarea[data-nas]').forEach(area=>{folders[area.dataset.nas] = area.value.split('\\n');});
      clients[box.dataset.client] = {
        write: box.querySelector('input[data-kind=write]').checked,
        delete: box.querySelector('input[data-kind=delete]').checked,
        folders: folders};
    });
    return {session, clients};
  }
  async function post(path, body){
    const response = await fetch(path,{method:'POST', headers:{'Content-Type':'application/json'},
      credentials:'same-origin', body: JSON.stringify(body)});
    return {status: response.status, data: await response.json().catch(()=>({}))};
  }
  form.addEventListener('submit', async (event)=>{
    event.preventDefault();
    save.disabled = true;
    try{
      const begun = await post('/api/settings/begin', {csrf, proposal: collect()});
      if(begun.status===401 || (begun.status===403 && !begun.data.message)){
        say('Your passkey sign-in has ended. Reload this page and sign in again.', true); return;
      }
      if(!begun.data.ok){say(begun.data.message || 'The change was not accepted.', true); return;}
      if(!begun.data.changes.length){say('Nothing has changed.', false); return;}
      say(['Confirm with your passkey to apply:'].concat(begun.data.changes.map(line=>'- ' + line)), false);
      const options = begun.data.options;
      options.challenge = b64.toBuf(options.challenge);
      (options.allowCredentials || []).forEach(c=>c.id = b64.toBuf(c.id));
      let credential;
      try{ credential = await navigator.credentials.get({publicKey: options}); }
      catch(error){say('The passkey check was cancelled. Nothing was changed.', true); return;}
      const done = await post('/api/settings/commit', {csrf, state: begun.data.state, credential:{
        id: credential.id, rawId: b64.toStr(credential.rawId), type: credential.type,
        clientExtensionResults: credential.getClientExtensionResults(),
        response:{clientDataJSON: b64.toStr(credential.response.clientDataJSON),
          authenticatorData: b64.toStr(credential.response.authenticatorData),
          signature: b64.toStr(credential.response.signature),
          userHandle: credential.response.userHandle ? b64.toStr(credential.response.userHandle) : null}}});
      if(done.data.ok){say(['Saved and active now:'].concat(done.data.changes.map(line=>'- ' + line)), false);}
      else{say(done.data.message || 'The change was not saved.', true);}
    }catch(error){say('The change could not be sent.', true);}
    finally{save.disabled = false;}
  });
})();
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


_NAV = (
    '<nav><a href="/">Dashboard</a><a href="/login-all">Sign in all</a>'
    '<a href="/settings">Settings</a><a href="/log">Log</a></nav>'
)


def _page(
    title: str,
    body: str,
    status: int = 200,
    *,
    scripts: Sequence[str] = (),
    nav: bool = False,
    refresh_to: Optional[str] = None,
) -> HTMLResponse:
    # `refresh_to` is a fixed path of ours, never a value taken from the request.
    refresh = f'<meta http-equiv="refresh" content="3;url={refresh_to}">' if refresh_to else ""
    script_tags = "".join(
        f'<script src="/static/{name}" defer></script>' for name in ("passkey.js", *scripts)
    )
    return HTMLResponse(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'{refresh}<title>{html.escape(title)}</title><link rel="stylesheet" href="/static/app.css">'
        f"{script_tags}</head>"
        f"<body><h1>{html.escape(title)}</h1>{_NAV if nav else ''}{body}</body></html>",
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
        begin_limiter: Optional[RateLimiter] = None,
        log_buffer: Optional[RingLogHandler] = None,
        wall_clock: Callable[[], float] = time.time,
        settings: Optional[SettingsService] = None,
    ):
        if not allowed_origins or not allowed_hosts:
            raise ValueError("allowed_origins and allowed_hosts are required")
        self.log_buffer = log_buffer
        self.settings = settings
        # Calendar time, for the dates a client's grant ends. Session deadlines
        # keep using the session manager's own monotonic clock.
        self._wall_clock = wall_clock
        self.runtime = runtime
        self.login = login
        self.owner = owner
        self.allowed_origins = tuple(allowed_origins)
        # TrustedHostMiddleware compares the Host header WITHOUT its port, so a
        # name written with one ("broker.example:8444") could never match and
        # every request would be refused. Accept either spelling.
        self.allowed_hosts = sorted({re.sub(r":\d+$", "", h) for h in allowed_hosts})
        self.secure_cookies = secure_cookies
        # How long the owner stays signed in comes from the policy, which the owner can
        # change on the settings page.
        owner_limits = runtime.policy.session
        self.sessions = sessions or OwnerSessions(
            idle_seconds=owner_limits.owner_idle_seconds,
            absolute_seconds=owner_limits.owner_absolute_seconds,
        )
        # Ten failed passkey checks per address in five minutes; five wrong
        # enrollment codes in ten, and the code is long enough that this is a
        # courtesy, not the control.
        self.auth_limiter = auth_limiter or RateLimiter(10, 300, lockout_seconds=300)
        self.enroll_limiter = enroll_limiter or RateLimiter(5, 600, lockout_seconds=600)
        # /auth/begin and /enroll/begin need no sign-in and each makes a challenge
        # and reads the store, so every call counts, not only a failure. Thirty a
        # minute per address is far more than a person needs.
        self.begin_limiter = begin_limiter or RateLimiter(30, 60)

    @property
    def cookie_name(self) -> str:
        # The __Host- prefix makes a browser refuse the cookie unless it is
        # Secure, host-only and set on the root path.
        return "__Host-owner" if self.secure_cookies else "owner"

    # -- helpers -------------------------------------------------------------

    def _owner(self, request: Request, *, touch: bool = True) -> Optional[OwnerSession]:
        return self.sessions.get(request.cookies.get(self.cookie_name), touch=touch)

    def _snapshot(self) -> List[Dict[str, Any]]:
        """One row per client and NAS: its state, the time left on a live session and
        how long the client's grant lasts. Names and numbers only; no credential or
        session value is ever part of it."""
        now = self._wall_clock()
        rows: List[Dict[str, Any]] = []
        for client in self.runtime.policy.clients.values():
            status = self.runtime.sessions.status(client.name)
            grant_left = None if client.expires_at is None else int(client.expires_at - now)
            for nas in sorted(client.nas):
                live = status.get(nas)
                pending = self.runtime.sessions.pending(client.name, nas)
                idle_left = absolute_left = None
                if live is not None:
                    state = "connected"
                    idle_left = int(live["idle_seconds_left"])  # type: ignore[call-overload]
                    absolute_left = int(live["absolute_seconds_left"])  # type: ignore[call-overload]
                    state_text = f"connected (idle limit in about {idle_left // 60} min)"
                elif pending is not None:
                    state = "waiting"
                    state_text = "waiting for you to sign in"
                else:
                    state = "not connected"
                    state_text = "not connected"
                rows.append(
                    {
                        "client": client.name,
                        "nas": nas,
                        "state": state,
                        # The sentence the table shows for it. It carries the idle clock,
                        # so the page refreshes it with the other clocks (`_DASHBOARD_JS`).
                        "state_text": state_text,
                        "idle_left": idle_left,
                        "absolute_left": absolute_left,
                        "left": (
                            f"ends in {_span(absolute_left)}" if absolute_left is not None else ""
                        ),
                        "request_id": pending.request_id if pending is not None else None,
                        "grant": _grant_text(grant_left, client.expires_at),
                        "grant_soon": grant_left is not None and grant_left <= GRANT_WARN_SECONDS,
                    }
                )
        return rows

    @staticmethod
    def _signature(rows: Sequence[Dict[str, Any]]) -> str:
        """What the dashboard shows apart from its running clocks: when this changes,
        the page reloads."""
        return ";".join(f"{r['client']}|{r['nas']}|{r['state']}" for r in rows)

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

    async def _authorized_json(
        self, request: Request
    ) -> Tuple[Optional[OwnerSession], Optional[Dict[str, Any]], Optional[Response]]:
        """As `_authorized_form`, for a JSON body: Origin, then the owner session, then
        the bounded body, then the CSRF token carried in it as `csrf`."""
        session, refusal = self._authorize(request)
        if refusal is not None:
            return None, None, refusal
        data = await self._json(request)
        if data is None:
            return None, None, JSONResponse({"ok": False, "code": "bad_request"}, status_code=400)
        csrf_value = data.get("csrf")
        if not isinstance(csrf_value, str) or not constant_time_equal(
            csrf_value, session.csrf_token
        ):
            return None, None, PlainTextResponse("Forbidden", status_code=403)
        return session, data, None

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
            # Fixed when the cookie is issued: if the owner later changes the limit in
            # Settings, a cookie already in the browser keeps the old lifetime. Harmless,
            # because the server's own check (`OwnerSessions`) is the one that decides.
            max_age=int(self.sessions.absolute_seconds),
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

        snapshot = self._snapshot()
        progress = request.query_params.get("m") == "progress"
        running = progress and any(
            self.runtime.sessions.attempt_running(client.name, nas)
            for client in self.runtime.policy.clients.values()
            for nas in client.nas
        )
        # "In progress" is only worth saying while one is: afterwards the table itself
        # shows the result, and a notice asked for by hand has nothing to report.
        notice = (
            None if progress and not running else _NOTICES.get(request.query_params.get("m", ""))
        )
        rows = []
        for entry in snapshot:
            name, nas_name = html.escape(entry["client"]), html.escape(entry["nas"])
            pair = (
                f'<input type="hidden" name="client" value="{name}">'
                f'<input type="hidden" name="nas" value="{nas_name}">'
            )
            state = entry["state_text"]
            if entry["state"] == "connected":
                action = (
                    f'<form method="post" action="/disconnect">{_hidden(session.csrf_token)}'
                    f'{pair}<button type="submit">Disconnect</button></form>'
                )
            elif entry["state"] == "waiting":
                action = (
                    f'<a href="/login/{html.escape(entry["request_id"])}">Continue</a> '
                    f'<form method="post" action="/pending/cancel" class="inline">{_hidden(session.csrf_token)}'
                    f'{pair}<button type="submit">Cancel</button></form>'
                )
            else:
                action = (
                    f'<form method="post" action="/pending/new">{_hidden(session.csrf_token)}'
                    f'{pair}<button type="submit">Sign in</button></form>'
                )
            grant_class = ' class="warn"' if entry["grant_soon"] else ""
            rows.append(
                f"<tr><td>{name}</td><td>{nas_name}</td><td>{state}</td>"
                f'<td class="num" data-client="{name}" data-nas="{nas_name}">{html.escape(entry["left"])}</td>'
                f"<td{grant_class}>{html.escape(entry['grant'])}</td><td>{action}</td></tr>"
            )
        any_live = any(entry["state"] == "connected" for entry in snapshot)
        disconnect_all = (
            f'<form method="post" action="/disconnect-all">{_hidden(session.csrf_token)}'
            '<button type="submit">Disconnect all</button></form> '
            if any_live
            else ""
        )
        body = (
            (_notice(notice) if notice else "")
            + f'<table id="rows" data-signature="{html.escape(self._signature(snapshot))}">'
            "<thead><tr><th>Client</th><th>NAS</th><th>State</th><th>Session</th>"
            "<th>Grant</th><th></th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
            + '<p><a href="/login-all">Sign in all clients with one password</a></p>'
            + f"<div>{disconnect_all}"
            + f'<form method="post" action="/logout" class="inline">{_hidden(session.csrf_token)}'
            '<button type="submit">End this session</button></form></div>'
        )
        # After a duplicate submission, look again in a moment for as long as the first
        # one is running; the table says Connected once it has finished, and then the
        # refreshing stops because there is nothing left to wait for.
        return _page(
            "Synology broker",
            body,
            scripts=("dashboard.js",),
            nav=True,
            refresh_to="/?m=progress" if running else None,
        )

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
        if outcome.code == "request_withdrawn":
            # Cancelled, expired or disconnected while the worker ran: the page for
            # that request is gone, so go back to the start.
            return RedirectResponse("/?m=withdrawn", status_code=303)
        if outcome.code == "in_progress":
            # A second submission (a double click, or a password manager that submits
            # as well) while the first is running. A browser shows the answer to the
            # last submission, so re-showing the form here made a sign-in that had
            # worked look as though nothing happened. Show the table instead.
            return RedirectResponse("/?m=progress", status_code=303)
        status = {"locked": 429}.get(outcome.code, 200)
        return self._render_login(request_id, session, (outcome.message, True), status=status)

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

    async def disconnect_all(self, request: Request) -> Response:
        _, _, refusal = await self._authorized_form(request)
        if refusal is not None:
            return refusal
        for name in list(self.runtime.policy.clients):
            self.runtime.revoke(name)
        return RedirectResponse("/?m=all_disconnected", status_code=303)

    # -- status, for the page and for the desktop app ------------------------

    async def attention(self, request: Request) -> Response:
        """Counts, and nothing else, for a tray icon to turn into a notification: how
        many sign-ins are waiting, how many sessions are live, how many of those reach
        their absolute deadline soon, and how many client grants have ended or end
        within two weeks. It needs no owner session, so it still answers after the
        owner has been signed out, and for that reason it names no client, NAS or
        session and says nothing a stranger on this machine could use."""
        counts = self.runtime.sessions.counts(ENDING_SOON_SECONDS)
        now = self._wall_clock()
        counts["grants_ending_soon"] = sum(
            1
            for client in self.runtime.policy.clients.values()
            if client.expires_at is not None and client.expires_at - now <= GRANT_WARN_SECONDS
        )
        return JSONResponse(counts)

    async def api_state(self, request: Request) -> Response:
        # Not touching the owner session: a window left open must not keep it alive.
        if self._owner(request, touch=False) is None:
            return PlainTextResponse("Sign in first", status_code=401)
        rows = self._snapshot()
        return JSONResponse({"rows": rows, "signature": self._signature(rows)})

    async def log_page(self, request: Request) -> Response:
        _, refusal = self._require_owner(request)
        if refusal:
            return refusal
        if self.log_buffer is None:
            return _page("Log", _notice("This broker keeps no log to show here."), nav=True)
        lines = html.escape("\n".join(self.log_buffer.lines()))
        body = (
            _notice("The broker's recent log lines, newest last. Kept in memory only.")
            + f'<pre id="log" class="log">{lines}</pre>'
        )
        return _page("Log", body, scripts=("log.js",), nav=True)

    async def api_log(self, request: Request) -> Response:
        if self._owner(request, touch=False) is None:
            return PlainTextResponse("Sign in first", status_code=401)
        if self.log_buffer is None:
            # Signed in, but there is no log to show: not a sign-in problem, so not 401
            # (the page's script sends a 401 back to the sign-in page).
            return PlainTextResponse("This broker keeps no log", status_code=404)
        return JSONResponse({"lines": self.log_buffer.lines()})

    # -- sign in several clients at once -------------------------------------

    async def login_all_page(self, request: Request) -> Response:
        session, refusal = self._require_owner(request)
        if refusal:
            return refusal
        state = {(r["client"], r["nas"]): r["state"] for r in self._snapshot()}
        rows = []
        needs_account = False
        for client in self.runtime.policy.clients.values():
            roots = client.folders
            for nas in sorted(client.nas):
                account = self.login.account_for(nas)
                needs_account = needs_account or not account
                live = state.get((client.name, nas)) == "connected"
                folders = ", ".join(roots.get(nas, ())) or "none"
                name, nas_name = html.escape(client.name), html.escape(nas)
                box = (
                    f'<input type="checkbox" class="pair" data-client="{name}" data-nas="{nas_name}"'
                    f'{" disabled" if live else " checked"} aria-label="Sign in {name} on {nas_name}">'
                )
                rows.append(
                    f"<tr><td>{box}</td><td>{name}</td><td>{nas_name}</td>"
                    f"<td>{html.escape(account) if account else 'you type it'}</td>"
                    f"<td>{len(client.allowed_tools())}</td><td>{html.escape(folders)}</td>"
                    f'<td class="st">{"connected" if live else "not connected"}</td></tr>'
                )
        username_field = (
            '<label for="username">NAS account name (for units with no configured account)</label>'
            '<input id="username" name="username" type="text" autocomplete="username">'
            if needs_account
            else ""
        )
        body = (
            _notice(
                "Check which NAS account each client signs in as, how many tools it gets and "
                "which folders it can reach. Then type the password once: it signs in every "
                "ticked client, one after the other, and stops at the first one that fails."
            )
            + '<form id="loginall" method="post" action="/login-all" autocomplete="off">'
            + _hidden(session.csrf_token)
            + "<table><thead><tr><th></th><th>Client</th><th>NAS</th><th>Account</th>"
            "<th>Tools</th><th>Folders</th><th>State</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
            + username_field
            + '<label for="password">NAS password</label>'
            '<input id="password" name="password" type="password" autocomplete="current-password">'
            '<label for="otp">Verification code (if the account uses one)</label>'
            '<input id="otp" name="otp" type="text" inputmode="numeric" '
            'autocomplete="one-time-code" maxlength="10">'
            '<p><button id="go" type="submit">Sign in ticked clients</button></p></form>'
            '<p id="msg" class="note" role="status" hidden></p>'
        )
        return _page("Sign in all", body, scripts=("login_all.js",), nav=True)

    async def login_all_fallback(self, request: Request) -> Response:
        """The form was posted without the page's script. The body is never read, so
        no password is kept, logged or echoed."""
        return PlainTextResponse(
            "This page needs JavaScript to sign in several clients. Use the dashboard's "
            "Sign in button for one at a time.",
            status_code=400,
        )

    async def login_all_step(self, request: Request) -> Response:
        """One client and NAS of a sign-in-all run. The password arrives in the JSON
        body and is handed straight to the login service. The request's own copy is
        cleared afterwards; Python gives no way to wipe the string itself, which goes when
        the local variable does, as this function returns. Outcomes are the login
        service's stable codes and fixed sentences.

        Every call counts against a per-address limit, as the settings calls do, on top of
        the login service's own lockout after repeated wrong answers: a run signs a handful
        of clients in, so the limit is far above what a person needs."""
        _, data, refusal = await self._authorized_json(request)
        if refusal is not None:
            return refusal
        throttle = f"login-all:{self._client_address(request)}"
        if not self.begin_limiter.allow(throttle):
            return JSONResponse(
                {
                    "ok": False,
                    "code": "rate_limited",
                    "message": "Too many sign-in attempts at once. Wait a minute and try again.",
                },
                status_code=429,
            )
        self.begin_limiter.record(throttle)
        client_name, nas = data.get("client"), data.get("nas")
        password, otp, username = data.get("password"), data.get("otp"), data.get("username")
        if (
            not isinstance(client_name, str)
            or not isinstance(nas, str)
            or not isinstance(password, str)
            or not password
        ):
            return JSONResponse({"ok": False, "code": "bad_request"}, status_code=400)
        client = self.runtime.policy.clients.get(client_name)
        if client is None or nas not in client.nas:
            return JSONResponse({"ok": False, "code": "not_found"}, status_code=404)
        pending = self.runtime.sessions.begin_pending(client_name, nas)
        outcome = await self.login.attempt(
            pending,
            password=password,
            otp=otp if isinstance(otp, str) else None,
            username=username if isinstance(username, str) else None,
        )
        data.clear()
        if outcome.ok:
            logger.info("A private sign-in succeeded for %s on %s", client_name, nas)
        else:
            logger.info("A private sign-in did not complete (%s)", outcome.code)
        status = {"locked": 429, "in_progress": 409}.get(outcome.code, 200)
        return JSONResponse(
            {"ok": outcome.ok, "code": outcome.code, "message": outcome.message}, status_code=status
        )

    # -- settings ------------------------------------------------------------

    async def settings_page(self, request: Request) -> Response:
        session, refusal = self._require_owner(request)
        if refusal:
            return refusal
        if self.settings is None:
            return _page(
                "Settings",
                _notice("This broker was started without settings that can be changed here."),
                nav=True,
            )
        view = self.settings.view()

        def number(label: str, field: str, step: str) -> str:
            return (
                f'<label for="{field}">{html.escape(label)}</label>'
                f'<input id="{field}" type="number" min="0" step="{step}" '
                f'data-field="{field}" value="{_number_text(view[field])}">'
            )

        parts = [
            _notice(
                "Saving a change asks for your passkey again. It takes effect at once, and "
                "clients stay connected. Client tokens, NAS units and grant dates are not "
                "changed here."
            )
        ]
        if not self.settings.writable():
            parts.append(
                _notice(
                    "The policy file is read-only here, so changes cannot be saved from this "
                    "page.",
                    True,
                )
            )
        parts.append(
            f'<form id="settings" method="post" action="/settings">{_hidden(session.csrf_token)}'
        )
        parts.append("<h2>This page</h2>")
        parts.append(number("Sign out after being unused for (minutes)", "owner_idle_minutes", "1"))
        parts.append(number("Sign out after (hours, however busy)", "owner_absolute_hours", "0.5"))
        parts.append("<h2>NAS sessions</h2>")
        parts.append(number("End a session after being unused for (minutes)", "idle_minutes", "1"))
        parts.append(number("End a session after (hours, however busy)", "absolute_hours", "0.5"))
        parts.append("<h2>Clients</h2>")
        for client in view["clients"]:
            name = html.escape(client["name"])
            parts.append(f'<fieldset data-client="{name}"><legend>{name}</legend>')
            parts.append(
                f'<label><input type="checkbox" data-kind="write"{" checked" if client["write"] else ""}> '
                "Write access: create files and folders, rename and move</label>"
                f'<label><input type="checkbox" data-kind="delete"{" checked" if client["delete"] else ""}> '
                "Allow delete as well (cannot be undone)</label>"
            )
            for nas in client["nas"]:
                alias = html.escape(nas["alias"])
                field = f"folders-{name}-{alias}"
                parts.append(
                    f'<label for="{field}">Folders on {alias} (one per line, such as /docs)</label>'
                    f'<textarea id="{field}" rows="4" data-nas="{alias}" spellcheck="false">'
                    f'{html.escape(chr(10).join(nas["roots"]))}</textarea>'
                )
            parts.append("</fieldset>")
        parts.append('<p><button id="save" type="submit">Review and save</button></p></form>')
        parts.append('<div id="msg" class="note" role="status" hidden></div>')
        return _page("Settings", "".join(parts), scripts=("settings.js",), nav=True)

    async def settings_fallback(self, request: Request) -> Response:
        return PlainTextResponse("This page needs JavaScript to save settings.", status_code=400)

    async def settings_begin(self, request: Request) -> Response:
        """Check a proposed change and, if it changes something, start the passkey
        confirmation for exactly that change. Nothing is written here."""
        _, data, refusal = await self._authorized_json(request)
        if refusal is not None:
            return refusal
        if self.settings is None:
            return JSONResponse({"ok": False, "message": "Settings are not available."}, 404)
        throttle = f"settings:{self._client_address(request)}"
        if not self.begin_limiter.allow(throttle):
            return JSONResponse({"ok": False, "message": "Too many requests."}, 429)
        self.begin_limiter.record(throttle)
        try:
            prepared = self.settings.prepare(data.get("proposal"))
        except SettingsError as error:
            return JSONResponse({"ok": False, "message": str(error)}, 400)
        if not prepared.digest:
            return JSONResponse({"ok": True, "changes": []})
        begun = self.owner.begin_confirmation(prepared.digest)
        if begun is None:
            return JSONResponse({"ok": False, "message": "No passkey is enrolled."}, 409)
        state, options = begun
        return JSONResponse(
            {"ok": True, "changes": prepared.changes, "state": state, "options": options}
        )

    async def settings_commit(self, request: Request) -> Response:
        """Apply the change the passkey just confirmed.

        A confirmation that fails counts against the same per-address limit as a failed
        passkey sign-in (`auth_limiter`), on purpose: it is the same proof, and the same
        address trying it."""
        _, data, refusal = await self._authorized_json(request)
        if refusal is not None:
            return refusal
        if self.settings is None:
            return JSONResponse({"ok": False, "message": "Settings are not available."}, 404)
        address = self._client_address(request)
        if not self.auth_limiter.allow(address):
            return JSONResponse({"ok": False, "message": "Too many attempts."}, 429)
        state, credential = data.get("state"), data.get("credential")
        digest = (
            self.owner.finish_confirmation(state, credential)
            if isinstance(state, str) and isinstance(credential, dict)
            else None
        )
        if not digest:
            self.auth_limiter.record(address)
            return JSONResponse({"ok": False, "message": "That passkey was not accepted."}, 401)
        try:
            changes = self.settings.commit(digest)
        except SettingsError as error:
            return JSONResponse({"ok": False, "message": str(error)}, 409)
        limits = self.runtime.policy.session
        self.sessions.set_limits(limits.owner_idle_seconds, limits.owner_absolute_seconds)
        logger.info("The owner changed the broker's settings (%d change(s))", len(changes))
        return JSONResponse({"ok": True, "changes": changes})

    # -- passkey ceremonies --------------------------------------------------

    async def auth_begin(self, request: Request) -> Response:
        if not self._origin_ok(request):
            return JSONResponse({"ok": False}, status_code=403)
        throttle = f"auth:{self._client_address(request)}"
        if not self.begin_limiter.allow(throttle):
            return JSONResponse({"ok": False}, status_code=429)
        self.begin_limiter.record(throttle)
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
        throttle = f"enroll:{address}"
        if not self.begin_limiter.allow(throttle):
            return JSONResponse({"ok": False}, status_code=429)
        self.begin_limiter.record(throttle)
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

    async def dashboard_js(self, request: Request) -> Response:
        return Response(_DASHBOARD_JS, media_type="text/javascript")

    async def log_js(self, request: Request) -> Response:
        return Response(_LOG_JS, media_type="text/javascript")

    async def login_all_js(self, request: Request) -> Response:
        return Response(_LOGIN_ALL_JS, media_type="text/javascript")

    async def settings_js(self, request: Request) -> Response:
        return Response(_SETTINGS_JS, media_type="text/javascript")

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
                Route("/disconnect-all", self.disconnect_all, methods=post),
                Route("/login-all", self.login_all_page, methods=["GET"]),
                Route("/login-all", self.login_all_fallback, methods=post),
                Route("/api/login-all/step", self.login_all_step, methods=post),
                Route("/api/state", self.api_state, methods=["GET"]),
                Route("/api/log", self.api_log, methods=["GET"]),
                Route("/log", self.log_page, methods=["GET"]),
                Route("/attention", self.attention, methods=["GET"]),
                Route("/settings", self.settings_page, methods=["GET"]),
                Route("/settings", self.settings_fallback, methods=post),
                Route("/api/settings/begin", self.settings_begin, methods=post),
                Route("/api/settings/commit", self.settings_commit, methods=post),
                Route("/auth/begin", self.auth_begin, methods=post),
                Route("/auth/finish", self.auth_finish, methods=post),
                Route("/enroll", self.enroll_page, methods=["GET"]),
                Route("/enroll/begin", self.enroll_begin, methods=post),
                Route("/enroll/finish", self.enroll_finish, methods=post),
                Route("/static/app.css", self.css, methods=["GET"]),
                Route("/static/passkey.js", self.js, methods=["GET"]),
                Route("/static/dashboard.js", self.dashboard_js, methods=["GET"]),
                Route("/static/log.js", self.log_js, methods=["GET"]),
                Route("/static/login_all.js", self.login_all_js, methods=["GET"]),
                Route("/static/settings.js", self.settings_js, methods=["GET"]),
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
