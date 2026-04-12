"""Concurrency runtime: TxQueue, RetryScheduler, IOThread, Metrics.

Three threads cooperate:

- **IOThread** — sole owner of the donglora ``conn``. Polls RX with a short
  timeout, ticks the retry scheduler, fires the ADVERT timer, and transmits
  the next ready ``TxItem`` from the priority queue.

- **Worker** (defined in :mod:`orac.worker`) — processes DM reply work items,
  calls Claude off the IO loop, and enqueues reply packets onto the TxQueue.

- **main** — setup + CLI + signal handlers only; no hot-path responsibility.

The TxQueue serializes all outbound packets through a single priority heap.
The RetryScheduler drives reply retransmission against :class:`PendingAckTable`.
"""

from __future__ import annotations

import heapq
import itertools
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

import donglora as dl
from orac import logfmt
from orac.constants import (
    ADVERT_INTERVAL,
    IO_POLL_TIMEOUT_S,
    PENDING_ACK_TTL_S,
    REPLY_FLOOD_FIRST_ATTEMPT,
    RETRY_SCHEDULE_S,
    RX_DRAIN_PER_TICK,
    TX_QUEUE_CAP,
    TX_RESPONSE_TIMEOUT_S,
)
from orac.reply_state import PendingAckTable, PendingReply

log = logging.getLogger("orac")


# ── TX priorities ────────────────────────────────────────────────


class TxPriority(IntEnum):
    """Ordering priorities for outbound packets. Lower = higher priority."""

    ACK = 0
    PATH = 1
    REPLY_DIRECT = 2
    REPLY_FLOOD = 3
    LOGIN_RESP = 4
    GRP_TXT = 5
    ADVERT = 6


# ── TxItem ───────────────────────────────────────────────────────


@dataclass
class TxItem:
    """A packet queued for transmission.

    :attr:`not_before` lets us schedule jittered / delayed sends without
    blocking the IO loop. :attr:`expected_ack` ties a REPLY TX to its entry
    in :class:`PendingAckTable` so we can cancel it if the ACK arrives while
    the reply is still queued.
    """

    priority: int
    not_before: float
    packet: bytes
    label: str
    expected_ack: bytes | None = None
    peer_pk: bytes | None = None
    attempt: int = 1
    cached_reply: bool = False


# ── TxQueue ──────────────────────────────────────────────────────


@dataclass(order=True)
class _HeapEntry:
    """Min-heap ordering key. Secondary counter breaks priority/deadline ties."""

    not_before: float
    priority: int
    seq: int
    item: TxItem = field(compare=False)


class TxQueue:
    """Thread-safe priority queue of TxItems.

    Ordering: earliest ``not_before`` wins; ties broken by priority, then seq.
    Capacity-bounded at :data:`TX_QUEUE_CAP` — when full, the lowest-priority
    (largest priority int) oldest entry is evicted.
    """

    def __init__(self, cap: int = TX_QUEUE_CAP) -> None:
        self._heap: list[_HeapEntry] = []
        self._cap = cap
        self._seq = itertools.count()
        self._lock = threading.Lock()
        # Counter-based snapshot access for metrics without holding the lock
        # longer than necessary.

    def push(self, item: TxItem) -> None:
        with self._lock:
            if len(self._heap) >= self._cap:
                victim = max(self._heap, key=lambda e: (e.priority, e.not_before))
                try:
                    self._heap.remove(victim)
                    heapq.heapify(self._heap)
                    log.warning(
                        "TxQueue full (%d); evicted %s (prio=%d)",
                        self._cap,
                        victim.item.label,
                        victim.priority,
                    )
                except ValueError:
                    pass
            entry = _HeapEntry(
                not_before=item.not_before,
                priority=item.priority,
                seq=next(self._seq),
                item=item,
            )
            heapq.heappush(self._heap, entry)

    def pop_ready(self, now: float) -> TxItem | None:
        """Return the highest-priority ready item, or None if nothing due."""
        with self._lock:
            if not self._heap:
                return None
            # Find the earliest-ready entry; if its not_before > now, nothing ready.
            top = self._heap[0]
            if top.not_before > now:
                return None
            # Pop it
            heapq.heappop(self._heap)
            # There may be another ready item with higher priority (lower int)
            # whose not_before is also ≤ now but was ordered later in the heap.
            # Scan the remaining heap for a better candidate to keep fairness tight.
            better_idx = -1
            best_prio = top.priority
            for i, entry in enumerate(self._heap):
                if entry.not_before <= now and entry.priority < best_prio:
                    best_prio = entry.priority
                    better_idx = i
            if better_idx >= 0:
                swapped = self._heap[better_idx]
                # Put `top` back; take `swapped` instead.
                self._heap[better_idx] = top
                heapq.heapify(self._heap)
                return swapped.item
            return top.item

    def cancel_by_ack(self, ack_crc: bytes) -> int:
        """Remove any queued TxItems whose ``expected_ack`` matches. Returns count."""
        with self._lock:
            before = len(self._heap)
            self._heap = [e for e in self._heap if e.item.expected_ack != ack_crc]
            heapq.heapify(self._heap)
            return before - len(self._heap)

    def depth(self) -> int:
        with self._lock:
            return len(self._heap)


# ── Metrics ──────────────────────────────────────────────────────


class Metrics:
    """Simple threadsafe counters + gauges for SIGUSR1 dump / periodic log."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}
        self._gauges: dict[str, int] = {}
        self.started_at = time.monotonic()

    def inc(self, key: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + amount

    def gauge(self, key: str, value: int) -> None:
        with self._lock:
            self._gauges[key] = value

    def snapshot(self) -> tuple[dict[str, int], dict[str, int], float]:
        with self._lock:
            return dict(self._counters), dict(self._gauges), time.monotonic() - self.started_at

    def summary(self) -> str:
        counters, gauges, uptime_s = self.snapshot()
        parts = [f"uptime={int(uptime_s)}s"]
        for k in sorted(counters):
            parts.append(f"{k}={counters[k]}")
        for k in sorted(gauges):
            parts.append(f"{k}={gauges[k]}")
        return " ".join(parts)


# ── RetryScheduler ───────────────────────────────────────────────


# Callback signature: (entry, attempt, force_flood) -> (packet, new_ack_crc)
RebuildReplyFn = Callable[[PendingReply, int, bool], tuple[bytes, bytes]]


class RetryScheduler:
    """Drives reply retries against :class:`PendingAckTable`.

    On :meth:`tick`, expired pending replies are either (a) rebuilt for the
    next attempt and re-queued, or (b) dropped with a WARN if exhausted.
    Attempt :data:`REPLY_FLOOD_FIRST_ATTEMPT` forgets the peer's learned route
    and rebuilds the packet with ``force_flood=True``.
    """

    def __init__(
        self,
        pending: PendingAckTable,
        tx_queue: TxQueue,
        metrics: Metrics,
        rebuild_reply: RebuildReplyFn,
        forget_route_fn: Callable[[int], bool],
        has_route_fn: Callable[[int], bool] | None = None,
        event_emit: Callable[..., None] | None = None,
    ) -> None:
        self._pending = pending
        self._tx = tx_queue
        self._metrics = metrics
        self._rebuild = rebuild_reply
        self._forget = forget_route_fn
        # Optional predicate to check whether a learned route exists for a peer.
        # Used only for honest log labeling; if not provided we assume no route.
        self._has_route = has_route_fn or (lambda _h: False)
        self._emit = event_emit or _noop_emit

    def tick(self, now: float) -> None:
        """Fire retries/exhaustion for any expired entries."""
        # 1) Sweep very-old entries defensively
        stale = self._pending.sweep_stale(now)
        for entry in stale:
            self._metrics.inc("reply_exhausted")
            self._emit(
                "reply.exhausted",
                peer=entry.peer_name,
                peer_pk=entry.peer_pk.hex(),
                total_elapsed_ms=int((now - entry.first_sent_at) * 1000),
                reason="ttl_sweep",
            )
            logfmt.gone(entry.peer_name, entry.attempt, reason=f"stale>{int(PENDING_ACK_TTL_S)}s")

        # 2) Fire retries for entries whose retry_at has elapsed
        for entry in self._pending.expired(now):
            if entry.attempt >= entry.max_attempts:
                self._pending.drop(entry.expected_ack)
                self._metrics.inc("reply_exhausted")
                self._emit(
                    "reply.exhausted",
                    peer=entry.peer_name,
                    peer_pk=entry.peer_pk.hex(),
                    total_elapsed_ms=int((now - entry.first_sent_at) * 1000),
                    attempt=entry.attempt,
                    reason="max_attempts",
                )
                logfmt.gone(entry.peer_name, entry.attempt, reason="max_attempts")
                continue

            next_attempt = entry.attempt + 1
            force_flood = next_attempt >= REPLY_FLOOD_FIRST_ATTEMPT
            reason = "no_ack"

            if next_attempt == REPLY_FLOOD_FIRST_ATTEMPT:
                # First flood retry: forget the learned route so the rebuild
                # actually produces a flood packet.
                removed = self._forget(entry.peer_pk[0])
                if removed:
                    self._metrics.inc("route_forgot")
                    self._emit(
                        "route.forgot",
                        peer=entry.peer_name,
                        peer_pk=entry.peer_pk.hex(),
                        reason="reply_retry",
                    )
                reason = "path_reset"

            try:
                packet, new_ack = self._rebuild(entry, next_attempt, force_flood)
            except Exception as e:
                log.error(
                    "Failed to rebuild reply for %s on attempt %d: %s",
                    entry.peer_name,
                    next_attempt,
                    e,
                )
                # Drop the entry rather than retrying forever on a rebuild bug.
                self._pending.drop(entry.expected_ack)
                self._metrics.inc("reply_exhausted")
                continue

            old_ack = entry.expected_ack
            # Index i of RETRY_SCHEDULE_S is the delay BEFORE attempt (i+2),
            # i.e., the delay from firing attempt (i+2) back to this entry.
            # After firing attempt `next_attempt`, we need the delay until
            # attempt (next_attempt+1): that's RETRY_SCHEDULE_S[next_attempt-1].
            # Clamp to the final entry if we've run out of explicit deltas.
            schedule_idx = min(next_attempt - 1, len(RETRY_SCHEDULE_S) - 1)
            retry_at = now + RETRY_SCHEDULE_S[schedule_idx]
            # Default-arg binding to freeze the loop variables into the closure.
            self._pending.update(
                old_ack,
                lambda e, _a=next_attempt, _n=new_ack, _r=retry_at: _apply_retry_update(
                    e, _a, _n, _r
                ),
            )
            # Re-key if the ACK CRC changed (different attempt byte → different hash)
            if new_ack != old_ack:
                self._pending.replace_key(old_ack, new_ack)

            # Honest route label: force_flood means we definitely flooded.
            # Otherwise, the actual transmission falls back to flood if we
            # don't have a cached route — reflect that in the log.
            if force_flood:
                priority = TxPriority.REPLY_FLOOD
                route_label = "flood"
            elif self._has_route(entry.peer_pk[0]):
                priority = TxPriority.REPLY_DIRECT
                route_label = "direct"
            else:
                priority = TxPriority.REPLY_FLOOD
                route_label = "flood(no-route)"
            self._tx.push(
                TxItem(
                    priority=priority,
                    not_before=now,
                    packet=packet,
                    label=f"DM({route_label}, retry {next_attempt})->{entry.peer_name}",
                    expected_ack=new_ack,
                    peer_pk=entry.peer_pk,
                    attempt=next_attempt,
                )
            )
            self._metrics.inc("reply_retried")
            self._metrics.inc(f"reply_retried_attempt_{next_attempt}")
            self._emit(
                "reply.retry",
                peer=entry.peer_name,
                peer_pk=entry.peer_pk.hex(),
                attempt=next_attempt,
                route=route_label,
                reason=reason,
            )
            logfmt.retry(entry.peer_name, next_attempt, entry.max_attempts, route_label)


# ── IOThread ─────────────────────────────────────────────────────


class IOThread(threading.Thread):
    """Sole owner of the donglora ``conn``; drives RX, retries, TX.

    Runs a single-threaded event loop. Does NOT call Claude — Worker does that
    on a different thread and enqueues the resulting reply onto :class:`TxQueue`.
    """

    def __init__(
        self,
        conn: Any,
        tx_queue: TxQueue,
        retry_sched: RetryScheduler,
        rx_handler: Callable[[dict[str, Any]], None],
        advert_fn: Callable[[TxQueue], None],
        metrics: Metrics,
        advert_interval: float = ADVERT_INTERVAL,
        gauge_collector: Callable[[], None] | None = None,
        name: str = "orac-io",
    ) -> None:
        super().__init__(daemon=True, name=name)
        self._conn = conn
        self._tx = tx_queue
        self._retry = retry_sched
        self._rx_handler = rx_handler
        self._advert_fn = advert_fn
        self._metrics = metrics
        self._advert_interval = advert_interval
        self._gauge_collector = gauge_collector
        self._stop_event = threading.Event()
        self._last_gauge_dump = 0.0
        self.last_error: BaseException | None = None

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        try:
            self._conn.timeout = IO_POLL_TIMEOUT_S
            # Advert at startup to announce ourselves; timer starts from monotonic.
            self._advert_fn(self._tx)
            last_advert = time.monotonic()

            while not self._stop_event.is_set():
                # 1) Drain RX — up to N per cycle
                for _ in range(RX_DRAIN_PER_TICK):
                    if self._stop_event.is_set():
                        return
                    pkt = dl.recv(self._conn)
                    if pkt is None:
                        break
                    self._metrics.inc("rx_total")
                    try:
                        self._rx_handler(pkt)
                    except Exception as e:
                        log.exception("rx_handler error: %s", e)

                if self._stop_event.is_set():
                    return

                now = time.monotonic()

                # 2) Tick retry scheduler
                try:
                    self._retry.tick(now)
                except Exception as e:
                    log.exception("retry scheduler error: %s", e)

                # 3) Advert timer
                if now - last_advert >= self._advert_interval:
                    self._advert_fn(self._tx)
                    last_advert = now

                # 4) Fire one TX item if ready
                item = self._tx.pop_ready(now)
                if item is not None:
                    self._transmit(item)

                # 5) Periodic gauge dump (every 60 s)
                if now - self._last_gauge_dump > 60.0:
                    self._metrics.gauge("tx_queue_depth", self._tx.depth())
                    if self._gauge_collector is not None:
                        try:
                            self._gauge_collector()
                        except Exception:
                            log.exception("gauge_collector failed")
                    self._last_gauge_dump = now
        except BaseException as e:  # surface fatal errors to main thread
            self.last_error = e
            log.exception("IOThread died: %s", e)
            raise

    def _transmit(self, item: TxItem) -> None:
        """Drive one TX via donglora.send. Does not retry on error — the retry
        scheduler already covers reply failures; ACK/PATH/ADVERT are single-shot
        by design.

        donglora.send() reads the TxDone response using the serial port's
        timeout. Raise it around the call (LoRa airtime for a max DM is
        ~425 ms + CAD) and restore after so the rest of the loop stays
        responsive at IO_POLL_TIMEOUT_S.
        """
        old_timeout = self._conn.timeout
        self._conn.timeout = TX_RESPONSE_TIMEOUT_S
        try:
            resp = dl.send(self._conn, "Transmit", payload=item.packet)
            rtype = resp.get("type")
            if rtype == "TxDone":
                self._metrics.inc("tx_sent")
                self._metrics.inc(f"tx_{_priority_tag(item.priority)}_sent")
                logfmt.net("TX %s [%dB]", item.label, len(item.packet))
            elif rtype == "Timeout":
                self._metrics.inc("tx_error_timeout")
                log.error("TX %s: firmware timeout", item.label)
            elif rtype == "Error":
                code = resp.get("code")
                self._metrics.inc(f"tx_error_code_{code}")
                if code == 1:  # RadioBusy
                    self._metrics.inc("tx_radio_busy")
                log.error("TX %s: firmware error code=%s", item.label, code)
            else:
                self._metrics.inc("tx_error_other")
                log.error("TX %s: unexpected response %s", item.label, resp)
        except Exception as e:
            self._metrics.inc("tx_error_exception")
            log.exception("TX %s exception: %s", item.label, e)
        finally:
            self._conn.timeout = old_timeout


def _priority_tag(prio: int) -> str:
    try:
        return TxPriority(prio).name.lower()
    except ValueError:
        return f"prio{prio}"


def _noop_emit(*_args: Any, **_kwargs: Any) -> None:
    """Default event_emit when caller doesn't provide one."""
    return None


def _apply_retry_update(entry: PendingReply, attempt: int, new_ack: bytes, retry_at: float) -> None:
    entry.attempt = attempt
    entry.expected_ack = new_ack
    entry.retry_at = retry_at
