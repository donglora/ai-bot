"""Orchestration: wire up runtime + dispatch + worker, manage connect loop + signals."""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import sys
import time

import serial

import donglora as dl
from orac import events, logfmt
from orac.constants import (
    BOT_NAME,
    MAX_DM_TEXT,
    MAX_RESPONSE_CHARS,
    RADIO_CONFIG,
    TRIGGERS,
)
from orac.crypto import (
    channel_count,
    init_channels,
    init_identity,
    my_hash,
    pubkey_bytes,
)
from orac.dispatch import RateLimiter, RxRouter, make_advert_pusher
from orac.logfmt import boot
from orac.meshcore import (
    build_advert_packet,
    build_dm_packet_with_plaintext,
    compute_ack_hash,
    forget_route,
    get_route,
    route_table_size,
)
from orac.reply_state import PendingAckTable, PendingReply, ReplyCache
from orac.runtime import IOThread, Metrics, RetryScheduler, TxQueue
from orac.state import known_node_count, load_state, save_state
from orac.worker import Worker

log = logging.getLogger("orac")


# ── Retry rebuild callback ───────────────────────────────────────


def _make_rebuild_reply(metrics: Metrics):
    """Return a rebuild-reply fn for the RetryScheduler."""

    def _rebuild(entry: PendingReply, attempt: int, force_flood: bool) -> tuple[bytes, bytes]:
        # `attempt` is 1-indexed (1 = first send). The wire byte uses attempt-1
        # so attempt=2 (first retry) sets txt_type_attempt byte = 1.
        attempt_byte = max(0, min(63, attempt - 1))
        packet, plaintext = build_dm_packet_with_plaintext(
            entry.peer_pk,
            entry.text,
            force_flood=force_flood,
            ts=entry.first_ts,
            attempt=attempt_byte,
        )
        new_ack = compute_ack_hash(plaintext, pubkey_bytes())
        metrics.inc("reply_rebuilt")
        return packet, new_ack

    return _rebuild


# ── Orchestration ────────────────────────────────────────────────


class BotRuntime:
    """Holds the per-connection runtime: threads + queues + state tables."""

    def __init__(self, conn) -> None:
        self.conn = conn
        self.metrics = Metrics()
        self.tx_queue = TxQueue()
        self.pending_acks = PendingAckTable()
        self.reply_cache = ReplyCache()
        self.rate_limiter = RateLimiter()

        self.worker = Worker(
            tx_queue=self.tx_queue,
            pending_acks=self.pending_acks,
            reply_cache=self.reply_cache,
            metrics=self.metrics,
            on_reply_recorded=self.rate_limiter.record,
        )

        self.rx_router = RxRouter(
            tx_queue=self.tx_queue,
            worker=self.worker,
            pending_acks=self.pending_acks,
            reply_cache=self.reply_cache,
            rate_limiter=self.rate_limiter,
            metrics=self.metrics,
        )

        self.retry_scheduler = RetryScheduler(
            pending=self.pending_acks,
            tx_queue=self.tx_queue,
            metrics=self.metrics,
            rebuild_reply=_make_rebuild_reply(self.metrics),
            forget_route_fn=forget_route,
            has_route_fn=lambda h: get_route(h) is not None,
            event_emit=events.emit,
        )

        self.advert_pusher = make_advert_pusher(build_advert_packet, self.metrics)

        self.io_thread = IOThread(
            conn=self.conn,
            tx_queue=self.tx_queue,
            retry_sched=self.retry_scheduler,
            rx_handler=self.rx_router.handle,
            advert_fn=self.advert_pusher,
            metrics=self.metrics,
            gauge_collector=self._collect_gauges,
        )

    # -- gauge dumper called by IOThread every 60s ----------------

    def _collect_gauges(self) -> None:
        self.metrics.gauge("tx_queue_depth", self.tx_queue.depth())
        self.metrics.gauge("pending_ack_depth", self.pending_acks.depth())
        self.metrics.gauge("reply_cache_depth", self.reply_cache.depth())
        self.metrics.gauge("route_table_size", route_table_size())

    # -- lifecycle ------------------------------------------------

    def start(self) -> None:
        self.worker.start()
        self.io_thread.start()

    def stop(self) -> None:
        self.io_thread.stop()
        self.worker.stop()

    def join(self, timeout: float = 5.0) -> None:
        """Wait for both threads to exit. Bounded so Ctrl+C can't hang us forever."""
        self.io_thread.join(timeout=timeout)
        self.worker.join(timeout=timeout)

    def dump_metrics(self) -> None:
        self._collect_gauges()
        boot("METRICS %s", self.metrics.summary())


# ── Single-instance signal wiring ───────────────────────────────

_active_runtime: BotRuntime | None = None


def _handle_sigusr1(signum: int, _frame: object) -> None:  # noqa: ARG001
    rt = _active_runtime
    if rt is not None:
        rt.dump_metrics()


# ── Connect loop ─────────────────────────────────────────────────


def connect_and_run(port: str | None) -> None:
    """Connect to a donglora dongle, spin up the runtime, and run until disconnect."""
    global _active_runtime

    boot("Connecting...")
    conn = dl.connect(port=port, timeout=2)
    boot("Connected")

    dl.send(conn, "Ping")
    dl.send(conn, "SetConfig", config=RADIO_CONFIG)
    dl.send(conn, "StartRx")

    triggers_str = ", ".join(TRIGGERS)
    boot("%s listening (Ctrl+C to stop)", BOT_NAME)
    boot(
        "Channels: %d | Triggers: %s | DMs: enabled",
        channel_count(),
        triggers_str,
    )

    runtime = BotRuntime(conn)
    _active_runtime = runtime

    try:
        runtime.start()
        # Block main thread until IOThread exits (via stop() or crash).
        # Short timed joins keep Ctrl+C responsive.
        while runtime.io_thread.is_alive():
            runtime.io_thread.join(timeout=0.5)
        if runtime.io_thread.last_error is not None:
            raise runtime.io_thread.last_error
    except KeyboardInterrupt:
        boot("Shutting down...")
        raise
    finally:
        runtime.stop()
        runtime.join(timeout=3.0)
        runtime.dump_metrics()
        _active_runtime = None
        with contextlib.suppress(Exception):
            conn.timeout = 2
            dl.send(conn, "StopRx")


# ── Entry point ──────────────────────────────────────────────────


def main() -> None:
    logfmt.setup_logging()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        log.error("ANTHROPIC_API_KEY environment variable not set")
        sys.exit(1)

    init_identity()
    init_channels()
    events.init()
    load_state()

    boot("%s -- MeshCore AI Bot", BOT_NAME)
    boot(
        "Max GRP response: %d chars | Max DM response: %d chars",
        MAX_RESPONSE_CHARS,
        MAX_DM_TEXT,
    )
    boot("Channels: %d | Known nodes: %d", channel_count(), known_node_count())
    boot("Pubkey hash: 0x%02x", my_hash())

    # SIGUSR1 dumps metrics; not available on all platforms (e.g. Windows).
    with contextlib.suppress(ValueError, AttributeError):
        signal.signal(signal.SIGUSR1, _handle_sigusr1)

    port = sys.argv[1] if len(sys.argv) > 1 else None

    while True:
        try:
            connect_and_run(port)
        except (serial.SerialException, ConnectionError, OSError) as e:
            log.error("Disconnected: %s", e)
            boot("Reconnecting when device reappears...")
            time.sleep(1)
        except KeyboardInterrupt:
            print()
            save_state()
            break
