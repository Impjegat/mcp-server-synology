# src/private_auth/logbuffer.py - The broker's recent log lines, in memory only.
#
# The private interface shows the owner the last few hundred log lines, so the
# broker can run without a terminal window. Nothing is written to a file: the
# lines live in this process and go when it does. The handler is given the same
# redacting filter as every other handler (see `attach`), so a session id or a
# password that found its way into a message is masked here too.

import copy
import logging
import re
from collections import deque
from typing import Deque, List

# Requests a page or the desktop app makes by itself, every few seconds. They
# would push everything worth reading out of the buffer.
_ROUTINE_PATHS = frozenset({"/attention", "/api/state", "/healthz", "/readyz"})
_ROUTINE_PREFIXES = ("/static/",)


def _is_routine(request_target: str) -> bool:
    """Whether a request target (a path, with or without a query string) is one of
    the routine ones. Only the path counts: a query string, or text elsewhere in the
    log line, that merely contains one of these names does not make a request routine."""
    path = request_target.split("?", 1)[0]
    return path in _ROUTINE_PATHS or path.startswith(_ROUTINE_PREFIXES)


# `/login/<request id>` is the address of one waiting sign-in. The owner already has it,
# and opening it needs the owner's session as well, but a capability-shaped value has no
# business in a log that people read and paste, so the buffer keeps the path without it.
_LOGIN_ID = re.compile(r"^(/login/)[^/?#\s]+")


def _masked(record: logging.LogRecord) -> logging.LogRecord:
    """`record`, or a copy of it with a sign-in request's id masked in an access line.
    A copy, so the other handlers (the terminal's, say) are not affected."""
    args = record.args
    if (
        record.name == "uvicorn.access"
        and isinstance(args, tuple)
        and len(args) == 5
        and isinstance(args[2], str)
        and _LOGIN_ID.match(args[2])
    ):
        clean = copy.copy(record)
        clean.args = (args[0], args[1], _LOGIN_ID.sub(r"\1***", args[2]), args[3], args[4])
        return clean
    return record


class _SkipRoutineRequests(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name != "uvicorn.access":
            return True
        # uvicorn logs (client address, method, request target, HTTP version, status).
        # A line in any other shape is kept: a log meant for diagnosing problems should
        # err towards showing too much.
        args = record.args
        if isinstance(args, tuple) and len(args) == 5 and isinstance(args[2], str):
            return not _is_routine(args[2])
        return True


class RingLogHandler(logging.Handler):
    """Keeps the last `capacity` formatted log lines."""

    def __init__(self, capacity: int = 400):
        super().__init__()
        self._lines: Deque[str] = deque(maxlen=capacity)
        self.addFilter(_SkipRoutineRequests())

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._lines.append(self.format(_masked(record)))
        except Exception:
            self.handleError(record)

    def lines(self) -> List[str]:
        return list(self._lines)


def attach(capacity: int = 400) -> RingLogHandler:
    """Add a ring buffer to the root logger, formatted and redacted exactly as the
    handlers already there. Call it after logging has been set up."""
    root = logging.getLogger()
    handler = RingLogHandler(capacity)
    for existing in root.handlers:
        if existing.formatter is not None and handler.formatter is None:
            handler.setFormatter(existing.formatter)
        for log_filter in existing.filters:
            if log_filter not in handler.filters:
                handler.addFilter(log_filter)
    root.addHandler(handler)
    return handler
