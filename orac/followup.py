"""Track recent bot activity per channel, for follow-up detection.

Used by :class:`orac.dispatch.RxRouter` to decide whether a non-triggered
channel message might be a follow-up to Orac (and therefore worth screening
with a cheap classifier) or routine chatter between other participants
(ignore without any API call).

All state is in-memory and thread-safe — state is intentionally NOT persisted
across restarts so a bot restart gives everyone a fresh conversational slate.
"""

from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_last_interaction: dict[str, float] = {}
_last_screener: dict[str, float] = {}


def touch(channel: str) -> None:
    """Mark a channel as having just had Orac activity (trigger reply, screener
    hit, or an ADVERT from a peer we were just talking to)."""
    now = time.monotonic()
    with _lock:
        _last_interaction[channel] = now


def was_recent(channel: str, window_s: float) -> bool:
    """True if the bot was last active in *channel* within *window_s* seconds."""
    with _lock:
        ts = _last_interaction.get(channel)
    return ts is not None and (time.monotonic() - ts) < window_s


def last_interaction_age(channel: str) -> float | None:
    """Seconds since last bot activity in *channel*, or None if never seen."""
    with _lock:
        ts = _last_interaction.get(channel)
    return (time.monotonic() - ts) if ts is not None else None


def screener_ok(channel: str, min_interval_s: float) -> bool:
    """Per-channel rate limit for screener API calls.

    Returns True if a screener call may fire now, and records the intent. Returns
    False if the last screener call for this channel was within ``min_interval_s``.
    """
    now = time.monotonic()
    with _lock:
        last = _last_screener.get(channel)
        if last is not None and (now - last) < min_interval_s:
            return False
        _last_screener[channel] = now
        return True


def reset() -> None:
    """Test helper: clear all state."""
    with _lock:
        _last_interaction.clear()
        _last_screener.clear()
