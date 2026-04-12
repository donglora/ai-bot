"""Worker thread: drains DM reply work, calls Claude, builds replies, queues TX.

Decouples the 3-15 s Claude round trip from the RX/ACK hot path. Reply
composition + enqueueing happens here; the IOThread handles actual transmission
and retry firing.
"""

from __future__ import annotations

import contextlib
import logging
import queue
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from orac import events, followup, logfmt
from orac.ai import call_claude, screen_channel_message
from orac.constants import (
    BOT_NAME,
    MAX_DM_TEXT,
    MAX_RESPONSE_CHARS,
    REPLY_INITIAL_JITTER_MAX_S,
    REPLY_INITIAL_JITTER_MIN_S,
    REPLY_MAX_ATTEMPTS,
    RETRY_SCHEDULE_S,
    WORKER_QUEUE_CAP,
)
from orac.crypto import pubkey_bytes
from orac.meshcore import (
    build_dm_packet_with_plaintext,
    build_grp_channel_packet,
    compute_ack_hash,
    get_route,
)
from orac.reply_state import PendingAckTable, PendingReply, ReplyCache
from orac.runtime import Metrics, TxItem, TxPriority, TxQueue
from orac.state import get_channel_history, get_dm_history, record_channel_msg, record_dm_msg

log = logging.getLogger("orac")


# ── Work items ───────────────────────────────────────────────────


@dataclass
class DmReplyWork:
    """Request to compose a reply to an inbound DM."""

    peer_pk: bytes
    peer_name: str
    dm_text: str
    received_at: float


@dataclass
class ChannelReplyWork:
    """Request to compose a reply to a channel query (trigger or @mention)."""

    channel_name: str
    sender: str
    query: str
    received_at: float
    rl_key: str  # for post-send rate-limit record


@dataclass
class ChannelScreenWork:
    """Classify whether a non-triggered channel message is meant for Orac.

    Fires a cheap Haiku screener; on YES, dispatches a :class:`ChannelReplyWork`
    inline.
    """

    channel_name: str
    sender: str
    text: str
    history_snapshot: list[str]
    received_at: float
    rl_key: str


# Sentinel pushed by :meth:`Worker.stop`.
class _Stop:
    pass


_STOP = _Stop()


# ── Worker ───────────────────────────────────────────────────────


class Worker(threading.Thread):
    """Single-threaded Claude-call worker.

    Serializes Claude calls by design — the Anthropic API is thread-safe but
    the radio is the bottleneck; running multiple Claude calls in parallel
    only helps if we'd otherwise starve TX, which we don't.
    """

    def __init__(
        self,
        tx_queue: TxQueue,
        pending_acks: PendingAckTable,
        reply_cache: ReplyCache,
        metrics: Metrics,
        on_reply_recorded: Callable[[str], None] | None = None,
        queue_cap: int = WORKER_QUEUE_CAP,
        name: str = "orac-worker",
    ) -> None:
        super().__init__(daemon=True, name=name)
        self._tx = tx_queue
        self._pending = pending_acks
        self._cache = reply_cache
        self._metrics = metrics
        self._on_recorded = on_reply_recorded
        self._queue: queue.Queue[DmReplyWork | ChannelReplyWork | ChannelScreenWork | _Stop] = (
            queue.Queue(maxsize=queue_cap)
        )
        self._stop_flag = threading.Event()

    # -- public API -----------------------------------------------

    def submit(self, work: DmReplyWork | ChannelReplyWork | ChannelScreenWork) -> bool:
        """Enqueue a work item. Drops oldest if full. Returns True on accept."""
        try:
            self._queue.put_nowait(work)
            self._metrics.gauge("worker_queue_depth", self._queue.qsize())
            return True
        except queue.Full:
            # Drop oldest to make room
            try:
                dropped = self._queue.get_nowait()
                if isinstance(dropped, DmReplyWork):
                    log.warning(
                        "Worker queue full; dropped DM from %s: %s",
                        dropped.peer_name,
                        dropped.dm_text[:40],
                    )
                    self._metrics.inc("worker_queue_dropped_dm")
                    events.emit(
                        "worker.dropped",
                        peer=dropped.peer_name,
                        peer_pk=dropped.peer_pk.hex(),
                        reason="queue_full",
                    )
                elif isinstance(dropped, ChannelReplyWork):
                    log.warning(
                        "Worker queue full; dropped channel query on %s from %s",
                        dropped.channel_name,
                        dropped.sender,
                    )
                    self._metrics.inc("worker_queue_dropped_channel")
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(work)
                self._metrics.gauge("worker_queue_depth", self._queue.qsize())
                return True
            except queue.Full:
                log.error("Worker queue still full after eviction; rejecting")
                return False

    def stop(self) -> None:
        self._stop_flag.set()
        with contextlib.suppress(queue.Full):
            self._queue.put_nowait(_STOP)

    # -- main loop ------------------------------------------------

    def run(self) -> None:
        while not self._stop_flag.is_set():
            try:
                work = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            if isinstance(work, _Stop):
                return
            self._metrics.gauge("worker_queue_depth", self._queue.qsize())
            try:
                if isinstance(work, DmReplyWork):
                    self._handle_dm_work(work)
                elif isinstance(work, ChannelReplyWork):
                    self._handle_channel_work(work)
                elif isinstance(work, ChannelScreenWork):
                    self._handle_channel_screen_work(work)
            except Exception as e:
                log.exception("Worker error: %s", e)

    # -- reply composition ----------------------------------------

    def _handle_dm_work(self, work: DmReplyWork) -> None:
        pk_hex = work.peer_pk.hex()

        # Record the inbound side of the conversation before calling Claude,
        # matching legacy behavior.
        record_dm_msg(pk_hex, f"{work.peer_name}: {work.dm_text}")
        history = get_dm_history(pk_hex)

        claude_start = time.monotonic()
        response = call_claude(
            work.dm_text,
            work.peer_name,
            history,
            MAX_DM_TEXT,
            f"DM with {work.peer_name}",
        )
        claude_ms = int((time.monotonic() - claude_start) * 1000)
        self._metrics.inc("claude_calls")

        if response is None:
            log.warning("Claude returned no text for DM from %s", work.peer_name)
            self._metrics.inc("claude_empty")
            events.emit(
                "claude.empty",
                peer=work.peer_name,
                peer_pk=pk_hex,
                elapsed_ms=claude_ms,
            )
            return

        # Build packet + plaintext with a stable ts we can reuse on retries.
        route_known = get_route(work.peer_pk[0]) is not None
        force_flood = not route_known
        first_ts = int(time.time())
        packet, plaintext = build_dm_packet_with_plaintext(
            work.peer_pk,
            response,
            force_flood=force_flood,
            ts=first_ts,
            attempt=0,
        )
        expected_ack = compute_ack_hash(plaintext, pubkey_bytes())
        now = time.monotonic()

        entry = PendingReply(
            expected_ack=expected_ack,
            peer_pk=work.peer_pk,
            peer_name=work.peer_name,
            text=response,
            first_ts=first_ts,
            first_sent_at=now,
            attempt=1,
            max_attempts=REPLY_MAX_ATTEMPTS,
            retry_at=now + RETRY_SCHEDULE_S[0],
        )
        self._pending.register(entry)

        # Cache for duplicate-DM resend
        self._cache.put(
            peer_pk=work.peer_pk,
            peer_name=work.peer_name,
            dm_text=work.dm_text,
            reply_packet=packet,
            reply_text=response,
            expected_ack=expected_ack,
        )

        jitter = random.uniform(REPLY_INITIAL_JITTER_MIN_S, REPLY_INITIAL_JITTER_MAX_S)
        route_label = "flood" if force_flood else "direct"
        priority = TxPriority.REPLY_FLOOD if force_flood else TxPriority.REPLY_DIRECT
        self._tx.push(
            TxItem(
                priority=priority,
                not_before=now + jitter,
                packet=packet,
                label=f"DM({route_label})->{work.peer_name}",
                expected_ack=expected_ack,
                peer_pk=work.peer_pk,
                attempt=1,
            )
        )
        record_dm_msg(pk_hex, f"{BOT_NAME}: {response}")
        self._metrics.inc("reply_sent")
        self._metrics.gauge("pending_ack_depth", self._pending.depth())

        events.emit(
            "reply.sent",
            peer=work.peer_name,
            peer_pk=pk_hex,
            attempt=1,
            route=route_label,
            ack_crc=expected_ack.hex(),
            text_len=len(response),
            claude_ms=claude_ms,
            jitter_ms=int(jitter * 1000),
        )
        logfmt.dm_out(work.peer_name, response, route=route_label)

        if self._on_recorded is not None:
            try:
                self._on_recorded(f"dm:{pk_hex}")
            except Exception:
                log.exception("on_reply_recorded callback raised")

    # -- channel reply composition -------------------------------

    def _handle_channel_work(self, work: ChannelReplyWork) -> None:
        history = get_channel_history(work.channel_name)
        claude_start = time.monotonic()
        response = call_claude(
            work.query,
            work.sender,
            history,
            MAX_RESPONSE_CHARS,
            f"channel {work.channel_name}",
        )
        claude_ms = int((time.monotonic() - claude_start) * 1000)
        self._metrics.inc("claude_calls")

        if response is None:
            self._metrics.inc("claude_empty")
            events.emit(
                "claude.empty",
                channel=work.channel_name,
                sender=work.sender,
                elapsed_ms=claude_ms,
            )
            return

        packet = build_grp_channel_packet(work.channel_name, BOT_NAME, response)
        if packet is None:
            log.error("Channel unknown: %s", work.channel_name)
            return

        self._tx.push(
            TxItem(
                priority=TxPriority.GRP_TXT,
                not_before=time.monotonic(),
                packet=packet,
                label=f"GRP({work.channel_name})",
                expected_ack=None,
                peer_pk=None,
                attempt=1,
            )
        )
        record_channel_msg(work.channel_name, f"{BOT_NAME}: {response}")
        logfmt.ch_out(work.channel_name, response)
        # Mark this channel as having had bot activity so follow-ups get screened.
        followup.touch(work.channel_name)

        events.emit(
            "channel.reply_sent",
            channel=work.channel_name,
            sender=work.sender,
            claude_ms=claude_ms,
            text_len=len(response),
        )

        if self._on_recorded is not None:
            try:
                self._on_recorded(work.rl_key)
            except Exception:
                log.exception("on_reply_recorded callback raised")

    # -- channel screener (cheap classifier) ---------------------

    def _handle_channel_screen_work(self, work: ChannelScreenWork) -> None:
        verdict_start = time.monotonic()
        try:
            verdict = screen_channel_message(
                work.channel_name, work.sender, work.text, work.history_snapshot
            )
        except Exception as e:
            log.exception("Screener call raised: %s", e)
            return
        elapsed_ms = int((time.monotonic() - verdict_start) * 1000)
        self._metrics.inc("screener_calls")
        self._metrics.inc("screener_yes" if verdict else "screener_no")
        events.emit(
            "screener.verdict",
            channel=work.channel_name,
            sender=work.sender,
            verdict=bool(verdict),
            elapsed_ms=elapsed_ms,
        )
        if not verdict:
            return
        # YES: treat as if triggered. Refresh the followup window now so
        # immediate successive messages also get screened.
        followup.touch(work.channel_name)
        logfmt.net(
            "screener: follow-up from %s on %s (%d ms) -> replying",
            work.sender,
            work.channel_name,
            elapsed_ms,
        )
        self._handle_channel_work(
            ChannelReplyWork(
                channel_name=work.channel_name,
                sender=work.sender,
                query=work.text,
                received_at=work.received_at,
                rl_key=work.rl_key,
            )
        )
