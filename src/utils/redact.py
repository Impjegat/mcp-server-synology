# src/utils/redact.py - Central credential/token redaction
#
# Session IDs, SynoTokens, device tokens and passwords can end up in tool
# output or logs via more paths than "the auth module returns them": a DSM
# GET request's URL contains `_sid=...`, and `requests`' own exception text
# (ConnectionError, HTTPError, Timeout, ...) commonly embeds that full URL.
# Rather than hunting down and fixing every call site that might format an
# error message, this module gives one place to scrub text before it leaves
# the process — as a tool-response wrapper and as a logging filter.

import logging
import re
from typing import Iterable, Optional

_MASK = "***REDACTED***"

# A live-secret value shorter than this is excluded from the verbatim
# substring pass in redact() below (the key=value pattern pass further down
# still catches it in that specific shape, e.g. `otp_code=123456`). DSM's
# 2FA codes are always exactly 6 digits, and a configured password can be
# short too — masking every occurrence of a short/common value as a bare
# substring risks corrupting unrelated legitimate output that happens to
# contain the same digits or characters (a file size, a port number, a
# filename, ...), rather than actually protecting anything: session
# IDs/SynoTokens/device IDs are always much longer than this in practice,
# so this doesn't weaken redaction of those.
_MIN_LIVE_SECRET_LENGTH = 8

# Matches `key=value` for known-sensitive query/body parameter names, stopping
# at the next `&`, whitespace, or end of string. Covers values we weren't
# told about in advance (e.g. a stale SID baked into a cached exception, or a
# URL assembled by hand rather than through a params dict). The negative
# lookbehind anchors each key to a boundary so e.g. `foo_sid=` doesn't also
# match on the `_sid=` suffix of an unrelated key name.
_PARAM_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])(_sid|passwd|password|synotoken|device_id|otp_code)=([^&\s\"']*)",
    re.IGNORECASE,
)


def _mask_known_params(text: str) -> str:
    return _PARAM_PATTERN.sub(lambda m: f"{m.group(1)}={_MASK}", text)


def redact(text: Optional[str], *, live_secrets: Iterable[Optional[str]] = ()) -> Optional[str]:
    """Return `text` with known/likely secret values masked.

    Args:
        text: The string to scrub. None passes through unchanged.
        live_secrets: Concrete secret values known to be currently live
            (session IDs, SynoTokens, device IDs, configured passwords)
            across all connected NAS units. Each non-empty value is masked
            wherever it appears verbatim, even outside a `key=value` shape
            (e.g. in a "Session ID: <sid>" log line).

    Returns:
        The scrubbed text, or the original value unchanged if it wasn't a
        string (so callers can pass this through helpers that sometimes
        hand back None or non-string values without special-casing it).
    """
    if not isinstance(text, str):
        return text

    result = text
    for secret in live_secrets:
        if secret and len(secret) >= _MIN_LIVE_SECRET_LENGTH:
            result = result.replace(secret, _MASK)

    result = _mask_known_params(result)
    return result


# Used only to render exception tracebacks via formatException() below —
# never for the record's own message formatting (Formatter.format() isn't
# called here, just this one helper method, which doesn't depend on any
# per-formatter state like fmt/datefmt).
_TRACEBACK_FORMATTER = logging.Formatter()

_REDACTION_FAILED_PLACEHOLDER = "<redaction failed — content suppressed>"


def _safe_redact(text: Optional[str], live_secrets: Iterable[Optional[str]]) -> Optional[str]:
    """Like `redact()`, but never raises and never lets unredacted text
    through on failure — a placeholder is returned instead.

    `redact()` itself isn't expected to raise on a plain string (its only
    operations are str.replace and a regex sub, both total functions), but
    if it ever does, letting that exception propagate out of a logging
    filter is one failure mode, and quietly catching it and using the
    original *unredacted* text would be a worse one: a redaction path must
    fail closed, not open. None passes through unchanged, matching
    `redact()`'s own contract for non-string input.
    """
    if text is None:
        return None
    try:
        return redact(text, live_secrets=live_secrets)
    except Exception:
        return _REDACTION_FAILED_PLACEHOLDER


class RedactingFilter(logging.Filter):
    """Logging filter that redacts known/likely secrets from log records.

    Pulls the current set of live secret values from `secrets_provider` on
    each record, so it stays current as sessions are created, refreshed, and
    torn down over the process lifetime — rather than being frozen at filter
    construction time.
    """

    def __init__(self, secrets_provider):
        super().__init__()
        self._secrets_provider = secrets_provider

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            live_secrets = list(self._secrets_provider())
        except Exception:
            # Never let a broken secrets provider suppress logging or crash
            # the app — fall back to pattern-only redaction.
            live_secrets = []

        # Render the message fully (this is what getMessage() does: str(msg)
        # % args) and redact the result, rather than redacting record.msg and
        # each arg separately. A non-string arg — including an exception
        # object passed as `logger.warning("token: %s", did)` — only ever
        # becomes text at this %-substitution step, so redacting the pieces
        # beforehand can't catch a secret that only appears once they're
        # combined. Clearing record.args afterward stops the logging
        # module's own formatter from re-applying % substitution to a
        # message that's already fully rendered.
        try:
            formatted = record.getMessage()
        except Exception:
            # getMessage() can raise on a malformed format string (e.g. a
            # %s with no matching arg). Fall back to redacting msg/args
            # independently rather than losing the record's redaction —
            # _safe_redact() never lets unredacted text through even if
            # this fallback hits its own edge case.
            if isinstance(record.msg, str):
                record.msg = _safe_redact(record.msg, live_secrets)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {
                        k: _safe_redact(v, live_secrets) if isinstance(v, str) else v
                        for k, v in record.args.items()
                    }
                else:
                    record.args = tuple(
                        _safe_redact(a, live_secrets) if isinstance(a, str) else a
                        for a in record.args
                    )
        else:
            record.msg = _safe_redact(formatted, live_secrets)
            record.args = None

        # A traceback (exc_info=True) or an explicit stack trace
        # (stack_info=True) is appended by Formatter.format() separately
        # from the message above, and can itself carry a secret — most
        # commonly a `requests` exception's str(), which often embeds the
        # full request URL including `_sid=`. Pre-render and redact it here
        # into record.exc_text; the stdlib formatter uses that pre-filled
        # value instead of re-rendering the raw (unredacted) traceback. If
        # rendering the traceback itself fails, exc_info is cleared rather
        # than left set with exc_text empty: Formatter.format() only calls
        # formatException() itself when exc_text is still falsy at format
        # time, which would render the raw, unredacted traceback — leaving
        # this failure silent would fail open into exactly the leak this
        # exists to prevent.
        if record.exc_info and not record.exc_text:
            try:
                traceback_text = _TRACEBACK_FORMATTER.formatException(record.exc_info)
            except Exception:
                record.exc_text = _REDACTION_FAILED_PLACEHOLDER
                record.exc_info = None
            else:
                record.exc_text = _safe_redact(traceback_text, live_secrets)
        if record.stack_info:
            record.stack_info = _safe_redact(record.stack_info, live_secrets)

        return True
