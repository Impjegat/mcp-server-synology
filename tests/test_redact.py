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
    assert record.args[0] == "***REDACTED***"

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
