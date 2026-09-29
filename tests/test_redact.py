"""Unit tests for src/utils/redact.py — the central credential/token redaction
used at the tool-response boundary (mcp_server.py) and in log filtering
(main.py)."""

import logging
import sys
from pathlib import Path

import pytest

# Add src directory to Python path (mirrors conftest.py's own setup, so this
# file also runs standalone via `pytest tests/test_redact.py`).
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from utils.redact import RedactingFilter, redact  # noqa: E402


def test_redact_masks_known_live_secret_values():
    text = 'Session ID: SID_abc123\nResponse: {"sid": "SID_abc123"}'
    result = redact(text, live_secrets=["SID_abc123"])
    assert "SID_abc123" not in result
    assert "***REDACTED***" in result


def test_redact_masks_unlisted_key_value_pairs():
    """A secret the caller didn't know about in advance (e.g. a stale SID
    baked into a cached exception message) is still masked by the
    `key=value` pattern pass."""
    text = "Network error: ...?_sid=STALE_SID_999&api=SYNO.API.Auth"
    result = redact(text, live_secrets=[])
    assert "STALE_SID_999" not in result
    assert "_sid=***REDACTED***" in result


def test_redact_masks_password_and_token_param_names():
    text = "url with passwd=hunter2&otp_code=123456&device_id=DID_x&synotoken=TOK_y"
    result = redact(text, live_secrets=[])
    assert "hunter2" not in result
    assert "123456" not in result
    assert "DID_x" not in result
    assert "TOK_y" not in result


def test_redact_leaves_non_secret_text_untouched():
    text = "Successfully authenticated with https://192.168.1.100:5001"
    assert redact(text, live_secrets=["irrelevant"]) == text


def test_redact_does_not_match_unrelated_key_ending_in_sid():
    """The `_sid=` pattern is anchored to a key-name boundary — it must not
    also match on an unrelated key that merely ends with `_sid`."""
    text = "foo_sid=not_a_session_id&other=fine"
    result = redact(text, live_secrets=[])
    assert result == text


def test_redact_passes_through_non_string_and_none():
    assert redact(None) is None
    assert redact(42) == 42  # type: ignore[arg-type]


def test_redact_masks_a_short_live_secret_unconditionally():
    """redact() itself applies no length or shape exception to live_secrets
    — every non-empty value is masked verbatim, however short. A DSM 2FA
    code (always exactly 6 digits) has the same collision risk as any other
    short value pasted into arbitrary text, but that risk is handled by
    callers choosing what to pass, not by redact() second-guessing them:
    see `config.iter_configured_secrets`, which deliberately never yields
    an otp_code for exactly this reason. redact() staying unconditional
    keeps every other short secret (a short configured password, say) — the
    values this module actually exists to protect — fully covered."""
    text = "Login attempt with note: pw1"
    result = redact(text, live_secrets=["pw1"])
    assert "pw1" not in result
    assert "***REDACTED***" in result


def test_redact_does_not_leave_a_partial_remainder_when_one_secret_is_a_substring_of_another():
    """If one live secret is a substring of another (e.g. a cached device_id
    that's a prefix of a newer one during a relogin transition), replacing
    the shorter one first would fragment the longer one's literal text,
    leaving the non-overlapping remainder of the longer secret exposed as
    plaintext — since the longer secret's own replacement pass then finds
    nothing (its literal text no longer exists verbatim in the already-
    modified result). redact() must process longest-first regardless of
    the order live_secrets is given in."""
    text = "token: SID_abc123"
    result = redact(text, live_secrets=["SID_abc", "SID_abc123"])
    assert result == "token: ***REDACTED***"
    assert "123" not in result

    # Order-independent: the same result regardless of which comes first.
    result2 = redact(text, live_secrets=["SID_abc123", "SID_abc"])
    assert result2 == "token: ***REDACTED***"


def test_redact_still_blanket_replaces_a_long_live_secret():
    """A real session ID/SynoToken/device ID/typical password is always far
    longer than a 2FA code, but this path doesn't depend on length at all —
    included for symmetry with the short-secret case above."""
    text = "Session ID: SID_abcdefgh123"
    result = redact(text, live_secrets=["SID_abcdefgh123"])
    assert "SID_abcdefgh123" not in result


def test_redacting_filter_scrubs_log_message_and_args():
    secrets = ["LIVE_SID"]
    filt = RedactingFilter(lambda: secrets)

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="session %s established",
        args=("LIVE_SID",),
        exc_info=None,
    )
    assert filt.filter(record) is True
    # The filter now redacts the fully-rendered message (msg % args) rather
    # than each arg independently, and clears args so the logging module's
    # own formatter doesn't re-apply % substitution to already-rendered
    # text — record.getMessage() is what a handler actually emits.
    assert record.args is None
    assert record.getMessage() == "session ***REDACTED*** established"

    record2 = logging.LogRecord(
        name="test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="token: LIVE_SID",
        args=None,
        exc_info=None,
    )
    assert filt.filter(record2) is True
    assert "LIVE_SID" not in record2.msg


def test_redacting_filter_scrubs_a_non_string_arg_like_an_exception_object():
    """A secret can reach the log only once %-substitution turns a non-string
    arg into text (e.g. `logger.warning("failed: %s", some_exception)`), so
    redacting args independently — each of which is skipped for not being a
    plain string — can't catch this; only redacting the rendered message can."""
    secrets = ["LIVE_SID"]
    filt = RedactingFilter(lambda: secrets)

    record = logging.LogRecord(
        name="test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="request failed: %s",
        args=(ConnectionError("could not reach https://nas:5001/webapi/?_sid=LIVE_SID"),),
        exc_info=None,
    )
    assert filt.filter(record) is True
    assert "LIVE_SID" not in record.getMessage()
    assert "***REDACTED***" in record.getMessage()


def test_redacting_filter_leaves_a_literal_percent_in_the_rendered_message_alone():
    """The filter renders the message once via getMessage() (msg % args),
    then stores the *already-rendered* text back into record.msg and clears
    record.args. If the rendered text happens to contain a literal `%`
    (e.g. from `%%`-escaping in the original format string, or one already
    present in an arg's own text), it must survive untouched rather than
    being reinterpreted as a new format specifier the next time something
    calls record.getMessage() — safe here specifically because
    LogRecord.getMessage() only attempts % substitution when record.args is
    truthy, and this filter always clears it to None on the success path."""
    secrets = ["LIVE_SID"]
    filt = RedactingFilter(lambda: secrets)

    class Obj:
        def __str__(self):
            return "obj-with-LIVE_SID-inside"

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Battery: %d%% (%s)",
        args=(100, Obj()),
        exc_info=None,
    )
    assert filt.filter(record) is True
    assert record.args is None
    # Calling getMessage() again (as the real handler will, at emit time)
    # must not raise and must not re-run % substitution against the
    # literal "%" now sitting in the already-rendered text.
    assert record.getMessage() == "Battery: 100% (obj-with-***REDACTED***-inside)"


def test_redacting_filter_scrubs_a_non_string_arg_in_the_malformed_format_fallback():
    """When getMessage() itself raises (a malformed format string — here,
    too few args for its placeholders), the filter falls back to redacting
    msg/args independently. A non-string arg must still be redacted in that
    fallback, not skipped for failing an `isinstance(a, str)` check — it
    can carry a live secret in its own str() form regardless of whether
    %-substitution against the (broken) format string ever succeeds."""
    secrets = ["LIVE_SID"]
    filt = RedactingFilter(lambda: secrets)

    record = logging.LogRecord(
        name="test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="count: %d and %s",  # two placeholders
        args=(ConnectionError("could not reach https://nas:5001/webapi/?_sid=LIVE_SID"),),
        exc_info=None,
    )
    with pytest.raises(TypeError):
        record.getMessage()  # sanity: this really is the malformed-format case

    assert filt.filter(record) is True
    assert all("LIVE_SID" not in str(a) for a in record.args)


def test_redacting_filter_survives_an_arg_whose_str_raises_in_the_malformed_format_fallback():
    """A non-string arg's own str() (or the __repr__ it falls back to) can
    itself raise for a pathological object. In the malformed-format-string
    fallback, that conversion happens before the value reaches redact(), so
    it must be guarded there too, the same way redact() itself is — a
    failure here must not raise out of the filter, and must not fall back
    to some other unredacted representation of the value."""
    secrets = ["LIVE_SID"]
    filt = RedactingFilter(lambda: secrets)

    class Unstringable:
        def __str__(self):
            raise RuntimeError("boom")

        def __repr__(self):
            raise RuntimeError("boom")

    record = logging.LogRecord(
        name="test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="count: %d and %s",  # two placeholders, one arg supplied
        args=(Unstringable(),),
        exc_info=None,
    )
    with pytest.raises(TypeError):
        record.getMessage()  # sanity: this really is the malformed-format case

    assert filt.filter(record) is True  # must not raise


def test_redacting_filter_scrubs_a_chained_exception_traceback():
    """A traceback logged via exc_info=True is appended by the stdlib
    Formatter separately from the message, and most commonly carries a
    secret through a `requests` exception's own str() (which often embeds
    the full request URL, including `_sid=`) — including when that
    exception is chained (`raise ... from cause`), which is exactly the
    shape `raise Exception(...)` from an `except requests.RequestException`
    block produces throughout this codebase."""
    secrets = ["LIVE_SID"]
    filt = RedactingFilter(lambda: secrets)

    try:
        try:
            raise ConnectionError("GET https://nas:5001/webapi/?_sid=LIVE_SID failed")
        except ConnectionError as cause:
            raise Exception("Network error") from cause
    except Exception:
        exc_info = sys.exc_info()

    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="unexpected error",
        args=None,
        exc_info=exc_info,
    )
    assert filt.filter(record) is True
    assert "LIVE_SID" not in record.exc_text
    assert "***REDACTED***" in record.exc_text
    # The chained cause's own traceback text is part of the same rendered
    # block, so it must be scrubbed too, not just the outer exception.
    assert "ConnectionError" in record.exc_text  # sanity: it's really there


def test_redacting_filter_never_raises_on_broken_provider():
    """A broken secrets provider must degrade to pattern-only redaction,
    never crash the logger or suppress the record."""

    def _broken():
        raise RuntimeError("boom")

    filt = RedactingFilter(_broken)
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="passwd=hunter2",
        args=None,
        exc_info=None,
    )
    assert filt.filter(record) is True
    assert "hunter2" not in record.msg


def test_redacting_filter_suppresses_traceback_rather_than_render_it_raw_on_failure():
    """If rendering the traceback itself fails, leaving exc_text unset would
    fail open: Formatter.format() only calls formatException() itself when
    exc_text is still falsy at format time, which would emit the raw,
    unredacted traceback — silently reproducing the exact `_sid=` leak this
    filter exists to close. It must instead suppress the traceback and
    clear exc_info so nothing downstream can recompute the raw version."""
    from unittest.mock import patch

    import utils.redact as redact_module

    filt = RedactingFilter(lambda: ["LIVE_SID"])

    try:
        raise ConnectionError("GET https://nas:5001/webapi/?_sid=LIVE_SID failed")
    except ConnectionError:
        exc_info = sys.exc_info()

    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="unexpected error",
        args=None,
        exc_info=exc_info,
    )
    with patch.object(
        redact_module._TRACEBACK_FORMATTER,
        "formatException",
        side_effect=RuntimeError("boom"),
    ):
        assert filt.filter(record) is True

    assert record.exc_info is None
    assert record.exc_text  # a placeholder, not falsy
    assert "LIVE_SID" not in record.exc_text


def test_redacting_filter_redacts_an_exc_text_already_populated_before_it_runs():
    """exc_text can be populated on the record before this filter ever sees
    it: Formatter.format() caches it the first time ANY handler formats the
    record, so a different handler (without this filter attached) running
    first would leave the raw, unredacted traceback cached there. This
    filter must redact an already-present exc_text too, not just render
    and redact its own — skipping it because exc_info/exc_text already
    looks "handled" would fail open into the leak this filter exists to
    close."""
    filt = RedactingFilter(lambda: ["LIVE_SID"])

    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="unexpected error",
        args=None,
        exc_info=None,
    )
    # Simulate a prior handler's Formatter.format() having already cached
    # the raw traceback text onto the shared record object.
    record.exc_text = "Traceback (most recent call last):\n...?_sid=LIVE_SID failed"

    assert filt.filter(record) is True
    assert "LIVE_SID" not in record.exc_text
    assert "***REDACTED***" in record.exc_text


def test_redacting_filter_suppresses_message_rather_than_leave_it_unredacted_on_failure():
    """If redact() itself somehow raises while scrubbing the rendered
    message, the record must not fall back to the original (potentially
    secret-bearing) text — a redaction path failing must never mean the
    unredacted version gets emitted instead."""
    from unittest.mock import patch

    import utils.redact as redact_module

    filt = RedactingFilter(lambda: ["LIVE_SID"])
    record = logging.LogRecord(
        name="test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="token: LIVE_SID",
        args=None,
        exc_info=None,
    )
    with patch.object(redact_module, "redact", side_effect=RuntimeError("boom")):
        assert filt.filter(record) is True

    assert "LIVE_SID" not in record.msg
