"""Unit tests for src/utils/redact.py — the central credential/token redaction
used at the tool-response boundary (mcp_server.py) and in log filtering
(main.py)."""

import logging
import sys
from pathlib import Path

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
