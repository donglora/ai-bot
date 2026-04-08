"""Persistent state (JSON), history tracking, rate limiting."""

from __future__ import annotations

import json
import logging
import time

from orac.constants import (
    CHANNEL_HISTORY_SIZE,
    DATA_DIR,
    DM_HISTORY_SIZE,
    STATE_FILE,
)

log = logging.getLogger("orac")

# ── Persistent state ─────────────────────────────────────────────

_state: dict[str, dict[str, object]] = {
    "channel_history": {},  # channel_name -> list of messages
    "dm_history": {},  # peer_pubkey_hex -> list of messages
    "known_nodes": {},  # pubkey_hex -> {"name": str, "seen": float}
}


def load_state() -> None:
    """Load persisted state from disk."""
    global _state
    if STATE_FILE.is_file():
        try:
            with open(STATE_FILE) as f:
                loaded = json.load(f)
            for key in _state:
                if key in loaded:
                    _state[key] = loaded[key]
            log.info("Loaded state from %s", STATE_FILE)
        except Exception as e:
            log.warning("Failed to load state: %s", e)


def save_state() -> None:
    """Persist state to disk (atomic write via tmp + rename)."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(_state, f, indent=2)
        tmp.rename(STATE_FILE)
    except Exception as e:
        log.error("Failed to save state: %s", e)


# ── Node registry (state-backed) ────────────────────────────────


def register_node(pubkey: bytes, name: str) -> bool:
    """Register a node. Returns True if this is a NEW node (not just an update)."""
    pk_hex = pubkey.hex()
    is_new = pk_hex not in _state["known_nodes"]
    _state["known_nodes"][pk_hex] = {"name": name, "seen": time.time()}  # type: ignore[index]
    save_state()
    return is_new


def lookup_node_by_hash(hash_byte: int) -> list[tuple[bytes, str]]:
    """Find all known nodes whose pubkey first byte matches.

    Never expires keys -- once we learn a peer's pubkey, we can always decrypt
    their DMs. Peers shouldn't need to re-advertise just to message the bot.
    """
    results: list[tuple[bytes, str]] = []
    for pk_hex, info in _state["known_nodes"].items():  # type: ignore[union-attr]
        pk_bytes = bytes.fromhex(pk_hex)
        if pk_bytes[0] == hash_byte:
            results.append((pk_bytes, info["name"]))  # type: ignore[index]
    return results


def node_name(pubkey_hex: str) -> str:
    """Human-readable name for a node, or truncated hex."""
    info = _state["known_nodes"].get(pubkey_hex)  # type: ignore[union-attr]
    return info["name"] if info else pubkey_hex[:8]  # type: ignore[index]


def evict_node(pubkey_hex: str) -> None:
    """Remove a node from the registry (e.g., bad key)."""
    _state["known_nodes"].pop(pubkey_hex, None)  # type: ignore[union-attr]
    save_state()


def known_node_count() -> int:
    """Number of known nodes."""
    return len(_state["known_nodes"])


# ── Channel history ──────────────────────────────────────────────


def record_channel_msg(channel: str, text: str) -> None:
    """Append a message to channel history and persist."""
    hist = _state["channel_history"]
    if channel not in hist:  # type: ignore[operator]
        hist[channel] = []  # type: ignore[index]
    hist[channel].append(text)  # type: ignore[index]
    if len(hist[channel]) > CHANNEL_HISTORY_SIZE:  # type: ignore[index]
        hist[channel] = hist[channel][-CHANNEL_HISTORY_SIZE:]  # type: ignore[index]
    save_state()


def get_channel_history(channel: str) -> list[str]:
    """Get recent channel history."""
    return list(_state["channel_history"].get(channel, []))  # type: ignore[union-attr]


# ── DM history ───────────────────────────────────────────────────


def record_dm_msg(peer_pubkey_hex: str, text: str) -> None:
    """Append a message to DM history and persist."""
    hist = _state["dm_history"]
    if peer_pubkey_hex not in hist:  # type: ignore[operator]
        hist[peer_pubkey_hex] = []  # type: ignore[index]
    hist[peer_pubkey_hex].append(text)  # type: ignore[index]
    if len(hist[peer_pubkey_hex]) > DM_HISTORY_SIZE:  # type: ignore[index]
        hist[peer_pubkey_hex] = hist[peer_pubkey_hex][-DM_HISTORY_SIZE:]  # type: ignore[index]
    save_state()


def get_dm_history(peer_pubkey_hex: str) -> list[str]:
    """Get recent DM history for a peer."""
    return list(_state["dm_history"].get(peer_pubkey_hex, []))  # type: ignore[union-attr]
