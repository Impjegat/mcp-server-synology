# src/private_auth/logbuffer.py - The broker's recent log lines, in memory only.
#
# The private interface shows the owner the last few hundred log lines, so the
# broker can run without a terminal window. Nothing is written to a file: the
# lines live in this process and go when it does. The handler is given the same
# redacting filter as every other handler (see `attach`), so a session id or a
# password that found its way into a message is masked here too.

import logging
from collections import deque
from typing import Deque, List

# Requests a page or the desktop app makes by itself, every few seconds. They
# would push everything worth reading out of the buffer.
_ROUTINE_PATHS = ("/attention", "/api/state", "/healthz", "/readyz", "/static/")


class _SkipRoutineRequests(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name != "uvicorn.access":
            return True
        message = record.getMessage()
        return not any(path in message for path in _ROUTINE_PATHS)


class RingLogHandler(logging.Handler):
    """Keeps the last `capacity` formatted log lines."""

    def __init__(self, capacity: int = 400):
        super().__init__()
        self._lines: Deque[str] = deque(maxlen=capacity)
        self.addFilter(_SkipRoutineRequests())

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._lines.append(self.format(record))
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
