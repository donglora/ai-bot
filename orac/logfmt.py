"""Structured log formatting: fixed-width colored categories for readable TTY.

Emit via helper functions (:func:`dm_in`, :func:`dm_out`, :func:`net`, etc.)
so each line carries a category tag that the formatter colors and labels.

Environment overrides:
- ``ORAC_LOG_LEVEL=DEBUG`` or ``ORAC_DEBUG=1`` raises verbosity to DEBUG.
- ``NO_COLOR=1`` disables ANSI color regardless of TTY.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any

log = logging.getLogger("orac")


class Cat:
    """Semantic log categories. Each maps to a tag + color in :data:`_CATS`."""

    BOOT = "boot"
    NET = "net"
    DM_IN = "dm_in"
    DM_OUT = "dm_out"
    CH_IN = "ch_in"
    CH_OUT = "ch_out"
    ACK_OK = "ack_ok"
    RETRY = "retry"
    GONE = "gone"
    RAW = "raw"


# Each entry: (5-char tag, ANSI color code). Tag is rendered inside [brackets].
_CATS: dict[str, tuple[str, str]] = {
    Cat.BOOT: ("BOOT ", "\033[36m"),  # cyan
    Cat.NET: ("  NET", "\033[90m"),  # bright black (dim gray)
    Cat.DM_IN: ("DM <-", "\033[1;96m"),  # bold bright cyan
    Cat.DM_OUT: ("DM ->", "\033[1;95m"),  # bold bright magenta
    Cat.CH_IN: ("CH <-", "\033[32m"),  # green
    Cat.CH_OUT: ("CH ->", "\033[1;32m"),  # bold green
    Cat.ACK_OK: ("ACK v", "\033[2;32m"),  # dim green
    Cat.RETRY: ("RETRY", "\033[33m"),  # yellow
    Cat.GONE: ("GONE!", "\033[31m"),  # red
    Cat.RAW: (" raw ", "\033[2m"),  # dim
}

_LEVEL_FALLBACK: dict[int, tuple[str, str]] = {
    logging.DEBUG: (" DBG ", "\033[2m"),
    logging.INFO: ("INFO ", ""),
    logging.WARNING: ("WARN ", "\033[33m"),
    logging.ERROR: ("ERROR", "\033[31m"),
    logging.CRITICAL: (" CRIT", "\033[1;31m"),
}
_RESET = "\033[0m"

# Column widths (characters).
_PEER_WIDTH = 14
_CHAN_WIDTH = 12


# ── Formatter ──────────────────────────────────────────────────


class LogFormatter(logging.Formatter):
    """``HH:MM:SS.ms  [TAG  ]  body`` with per-category ANSI color on TTY."""

    def __init__(self, use_color: bool = True) -> None:
        super().__init__()
        self._use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        ms = int((record.created - int(record.created)) * 1000)
        timestamp = f"{time.strftime('%H:%M:%S', time.localtime(record.created))}.{ms:03d}"

        cat_attr: Any = getattr(record, "cat", None)
        if isinstance(cat_attr, str) and cat_attr in _CATS:
            tag, color = _CATS[cat_attr]
        else:
            tag, color = _LEVEL_FALLBACK.get(record.levelno, ("     ", ""))

        msg = record.getMessage()
        line = f"{timestamp}  [{tag}]  {msg}"
        if self._use_color and color:
            return f"{color}{line}{_RESET}"
        return line


# ── Setup helper ────────────────────────────────────────────────


def setup_logging() -> None:
    """Install the orac logger with the structured formatter."""
    level_name = os.environ.get("ORAC_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    if os.environ.get("ORAC_DEBUG"):
        level = logging.DEBUG

    logger = logging.getLogger("orac")
    logger.setLevel(level)
    # Avoid stacking handlers if setup_logging is called twice.
    for h in list(logger.handlers):
        logger.removeHandler(h)
    handler = logging.StreamHandler(sys.stderr)
    use_color = sys.stderr.isatty() and not os.environ.get("NO_COLOR")
    handler.setFormatter(LogFormatter(use_color=use_color))
    logger.addHandler(handler)


# ── Category helpers (call sites use these) ─────────────────────


def boot(msg: str, *args: Any) -> None:
    """Startup / shutdown / lifecycle."""
    log.info(msg, *args, extra={"cat": Cat.BOOT})


def net(msg: str, *args: Any) -> None:
    """Control-plane traffic: adverts, path returns, TX wire confirmation."""
    log.info(msg, *args, extra={"cat": Cat.NET})


def dm_in(peer: str, text: str, route: str | None = None) -> None:
    """DM arrived addressed to us."""
    label = _peer_label(peer, route)
    log.info("%s  %s", label, text, extra={"cat": Cat.DM_IN})


def dm_out(peer: str, text: str, route: str | None = None) -> None:
    """DM we are sending."""
    label = _peer_label(peer, route)
    log.info("%s  %s", label, text, extra={"cat": Cat.DM_OUT})


def ch_in(channel: str, sender: str, text: str) -> None:
    """Channel message arrived (not necessarily to us)."""
    log.info(
        "%s  %s: %s",
        _left(channel, _CHAN_WIDTH),
        sender,
        text,
        extra={"cat": Cat.CH_IN},
    )


def ch_out(channel: str, text: str) -> None:
    """Channel message we are sending."""
    log.info("%s  %s", _left(channel, _CHAN_WIDTH), text, extra={"cat": Cat.CH_OUT})


def ack_ok(peer: str, attempt: int, elapsed_ms: int) -> None:
    """Inbound ACK confirms one of our outbound DMs."""
    log.info(
        "%s  attempt %d, %d ms",
        _left(peer, _PEER_WIDTH),
        attempt,
        elapsed_ms,
        extra={"cat": Cat.ACK_OK},
    )


def retry(peer: str, attempt: int, max_attempts: int, route: str) -> None:
    """Reply retry fired."""
    log.info(
        "%s  attempt %d/%d via %s",
        _left(peer, _PEER_WIDTH),
        attempt,
        max_attempts,
        route,
        extra={"cat": Cat.RETRY},
    )


def gone(peer: str, attempts: int, reason: str = "max_attempts") -> None:
    """Reply exhausted; peer did not ACK within our retry budget."""
    log.warning(
        "%s  gave up after %d attempts (%s)",
        _left(peer, _PEER_WIDTH),
        attempts,
        reason,
        extra={"cat": Cat.GONE},
    )


def raw(msg: str, *args: Any) -> None:
    """Low-level parse / debug traffic; only visible at DEBUG level."""
    log.debug(msg, *args, extra={"cat": Cat.RAW})


# ── Internal helpers ────────────────────────────────────────────


def _peer_label(peer: str, route: str | None) -> str:
    core = peer if not route else f"{peer}/{route}"
    return _left(core, _PEER_WIDTH)


def _left(s: str, width: int) -> str:
    """Pad/truncate *s* to exactly *width* columns (no trailing whitespace trim)."""
    if len(s) > width:
        return s[: width - 1] + "\u2026"
    return s.ljust(width)
