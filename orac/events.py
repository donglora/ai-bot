"""Structured JSONL event logger for DM reliability observability.

Each event is written as one JSON object per line to :data:`EVENTS_FILE`
(default ``~/.donglora/orac-events.jsonl``). Non-blocking best-effort writes
from any thread.

Use :func:`emit` to log an event with ``event`` name and arbitrary kwargs.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

from orac.constants import DATA_DIR, EVENTS_FILE

log = logging.getLogger("orac")

_events_lock = threading.Lock()
_events_file: Path = EVENTS_FILE
_initialized = False


def init() -> None:
    """Open the events file (creating parent directory if needed)."""
    global _initialized
    if _initialized:
        return
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _initialized = True
    except Exception as e:
        log.warning("Events file init failed: %s", e)


def set_path(path: Path) -> None:
    """Override the events file path (used by tests)."""
    global _events_file, _initialized
    _events_file = path
    _initialized = False


def emit(event: str, **fields: Any) -> None:
    """Write one JSON event line. Never raises."""
    if not _initialized:
        init()
    rec: dict[str, Any] = {"ts": time.time(), "event": event}
    for k, v in fields.items():
        # Coerce bytes to hex for JSON
        if isinstance(v, (bytes, bytearray)):
            rec[k] = v.hex()
        else:
            rec[k] = v
    line = json.dumps(rec, default=str, separators=(",", ":"))
    try:
        with _events_lock, open(_events_file, "a") as f:
            f.write(line + "\n")
    except Exception as e:
        # Don't let observability failures break the bot.
        log.debug("events.emit failed: %s", e)
