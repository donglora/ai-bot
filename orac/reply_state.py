"""Pending-ACK tracking and reply caching for DM reliability.

- :class:`PendingAckTable` — outbound replies awaiting an ACK. Workers register
  on send; the RxRouter consumes on inbound ACK; the RetryScheduler walks
  expired entries to fire retries.

- :class:`ReplyCache` — per-peer cache of the last reply we sent. If a peer
  retransmits the same DM (their ACK to us got through but our reply did not),
  we re-send the cached packet bytes instead of re-calling Claude.

Both are bounded in size and time and are safe for concurrent access.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from orac.constants import (
    PENDING_ACK_CAP,
    PENDING_ACK_TTL_S,
    REPLY_CACHE_CAP,
    REPLY_CACHE_TTL_S,
)

# ── Pending-ACK table ───────────────────────────────────────────


@dataclass
class PendingReply:
    """An outbound DM reply awaiting an ACK from its recipient.

    Each retry *rebuilds* the packet with an incremented ``attempt`` counter
    and (for the flood retry) freshly-decided routing. Keeping ``text`` and
    ``first_ts`` here lets :class:`RetryScheduler` recreate the exact plaintext
    on each retry and recompute the expected ACK CRC.
    """

    expected_ack: bytes  # 4-byte CRC the peer will emit; may be re-keyed on retry
    peer_pk: bytes
    peer_name: str
    text: str  # reply text
    first_ts: int  # wall-clock timestamp used in the plaintext; stable across retries
    first_sent_at: float = field(default_factory=time.monotonic)
    attempt: int = 1  # 1 for first TX; 2 for first retry, etc.
    retry_at: float = 0.0
    max_attempts: int = 5


class PendingAckTable:
    """Thread-safe bounded table keyed on the expected ACK CRC.

    Capacity-bounded (LRU-ish: insertion-order eviction when full). TTL-bounded
    at registration time — callers can call :meth:`expired` to find deadlines.
    """

    def __init__(self, cap: int = PENDING_ACK_CAP) -> None:
        self._cap = cap
        self._by_ack: dict[bytes, PendingReply] = {}
        self._lock = threading.Lock()

    def register(self, entry: PendingReply) -> None:
        """Insert a new pending-reply entry."""
        with self._lock:
            if len(self._by_ack) >= self._cap and entry.expected_ack not in self._by_ack:
                # Evict the oldest registration (dict insertion order in CPython ≥3.7)
                oldest = next(iter(self._by_ack))
                self._by_ack.pop(oldest, None)
            self._by_ack[entry.expected_ack] = entry

    def consume(self, ack_crc: bytes) -> PendingReply | None:
        """Remove and return a pending entry matching *ack_crc*, or None."""
        with self._lock:
            return self._by_ack.pop(ack_crc, None)

    def drop(self, ack_crc: bytes) -> PendingReply | None:
        """Remove an entry without the 'matched' semantic. Same shape as consume()."""
        with self._lock:
            return self._by_ack.pop(ack_crc, None)

    def expired(self, now: float) -> list[PendingReply]:
        """Return entries whose retry_at ≤ now. Caller handles them.

        Does NOT remove them — the scheduler decides whether to retry or drop.
        """
        with self._lock:
            return [e for e in self._by_ack.values() if e.retry_at <= now]

    def sweep_stale(self, now: float) -> list[PendingReply]:
        """Remove and return entries older than PENDING_ACK_TTL_S."""
        cutoff = now - PENDING_ACK_TTL_S
        with self._lock:
            stale = [e for e in self._by_ack.values() if e.first_sent_at < cutoff]
            for e in stale:
                self._by_ack.pop(e.expected_ack, None)
            return stale

    def update(
        self,
        ack_crc: bytes,
        mutator: Callable[[PendingReply], None],
    ) -> PendingReply | None:
        """Apply *mutator* to an existing entry atomically.

        Returns the (now-mutated) entry, or None if no match.
        """
        with self._lock:
            entry = self._by_ack.get(ack_crc)
            if entry is None:
                return None
            mutator(entry)
            return entry

    def replace_key(self, old_ack: bytes, new_ack: bytes) -> None:
        """Re-key an entry after path-reset rebuilds the packet (and ACK CRC)."""
        with self._lock:
            entry = self._by_ack.pop(old_ack, None)
            if entry is not None:
                entry.expected_ack = new_ack
                self._by_ack[new_ack] = entry

    def depth(self) -> int:
        """Current entry count."""
        with self._lock:
            return len(self._by_ack)

    def snapshot(self) -> list[PendingReply]:
        """Return a shallow copy of current entries for debug inspection."""
        with self._lock:
            return list(self._by_ack.values())

    def has_pending_for_peer(self, peer_pk: bytes) -> bool:
        """True if any entry is still waiting for an ACK from *peer_pk*."""
        with self._lock:
            return any(e.peer_pk == peer_pk for e in self._by_ack.values())


# ── Reply cache ─────────────────────────────────────────────────


@dataclass
class _CachedReply:
    peer_pk: bytes
    peer_name: str
    dm_text: str  # the DM plaintext we're replying TO (dedup key)
    reply_packet: bytes
    reply_text: str
    expected_ack: bytes
    ts: float = field(default_factory=time.monotonic)


class ReplyCache:
    """Last-reply cache per peer; retransmitted DMs get the cached reply resend.

    Keyed by ``peer_pubkey_hex``. If the peer's next DM plaintext matches the
    stored ``dm_text``, we know the same DM is being retried and we re-send
    the original reply instead of calling Claude again.
    """

    def __init__(self, cap: int = REPLY_CACHE_CAP, ttl: float = REPLY_CACHE_TTL_S) -> None:
        self._cap = cap
        self._ttl = ttl
        self._entries: dict[str, _CachedReply] = {}
        self._lock = threading.Lock()

    def put(
        self,
        peer_pk: bytes,
        peer_name: str,
        dm_text: str,
        reply_packet: bytes,
        reply_text: str,
        expected_ack: bytes,
    ) -> None:
        key = peer_pk.hex()
        now = time.monotonic()
        with self._lock:
            if len(self._entries) >= self._cap and key not in self._entries:
                # Drop oldest by ts
                oldest = min(self._entries, key=lambda k: self._entries[k].ts)
                self._entries.pop(oldest, None)
            self._entries[key] = _CachedReply(
                peer_pk=peer_pk,
                peer_name=peer_name,
                dm_text=dm_text,
                reply_packet=reply_packet,
                reply_text=reply_text,
                expected_ack=expected_ack,
                ts=now,
            )

    def get(self, peer_pk_hex: str, dm_text: str) -> _CachedReply | None:
        """Return the cached reply if the DM text matches and TTL fresh."""
        with self._lock:
            entry = self._entries.get(peer_pk_hex)
            if entry is None:
                return None
            if time.monotonic() - entry.ts > self._ttl:
                self._entries.pop(peer_pk_hex, None)
                return None
            if entry.dm_text != dm_text:
                return None
            return entry

    def drop(self, peer_pk_hex: str) -> None:
        with self._lock:
            self._entries.pop(peer_pk_hex, None)

    def depth(self) -> int:
        with self._lock:
            return len(self._entries)
