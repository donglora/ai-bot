"""Tests for orac.runtime.RetryScheduler: attempt progression, path reset, exhaustion."""

from __future__ import annotations

import itertools
import time

from orac.constants import (
    PENDING_ACK_TTL_S,
    REPLY_FLOOD_FIRST_ATTEMPT,
    REPLY_MAX_ATTEMPTS,
    RETRY_SCHEDULE_S,
)
from orac.reply_state import PendingAckTable, PendingReply, ReplyCache  # noqa: F401
from orac.runtime import Metrics, RetryScheduler, TxQueue


def _entry(
    ack: bytes,
    attempt: int = 1,
    retry_at_offset: float = 0.0,
    max_attempts: int = 5,
) -> PendingReply:
    now = time.monotonic()
    return PendingReply(
        expected_ack=ack,
        peer_pk=b"\xaa" * 32,
        peer_name="peer_aa",
        text="hi",
        first_ts=1234567890,
        first_sent_at=now,
        attempt=attempt,
        max_attempts=max_attempts,
        retry_at=now + retry_at_offset,
    )


def _noop_rebuild(_entry: PendingReply, attempt: int, force_flood: bool) -> tuple[bytes, bytes]:
    """Rebuild stub: new ACK differs from old so replace_key is exercised."""
    new_ack = bytes([attempt & 0xFF, 0xAA, 0xBB, 0xCC])
    return (b"REBUILT-%d-%s" % (attempt, b"F" if force_flood else b"D"), new_ack)


def test_direct_retry_arms_next_attempt() -> None:
    pending = PendingAckTable()
    tx = TxQueue()
    m = Metrics()
    forgot: list[int] = []

    sched = RetryScheduler(
        pending=pending,
        tx_queue=tx,
        metrics=m,
        rebuild_reply=_noop_rebuild,
        forget_route_fn=lambda h: (forgot.append(h), True)[1],
    )

    # First attempt (entry.attempt=1) with retry_at already passed.
    e = _entry(b"\x00\x00\x00\x01", attempt=1, retry_at_offset=-0.1)
    pending.register(e)
    sched.tick(time.monotonic())

    # Next attempt (2) is a direct retry — route should NOT have been forgotten.
    assert forgot == []
    # The entry's expected_ack has been re-keyed.
    assert pending.consume(b"\x00\x00\x00\x01") is None
    # New key from _noop_rebuild is (attempt=2, ...).
    item = tx.pop_ready(time.monotonic())
    assert item is not None
    assert item.attempt == 2
    assert item.expected_ack == bytes([0x02, 0xAA, 0xBB, 0xCC])


def test_flood_retry_forgets_route() -> None:
    pending = PendingAckTable()
    tx = TxQueue()
    m = Metrics()
    forgot: list[int] = []
    sched = RetryScheduler(
        pending=pending,
        tx_queue=tx,
        metrics=m,
        rebuild_reply=_noop_rebuild,
        forget_route_fn=lambda h: (forgot.append(h), True)[1],
    )

    # Entry attempt = REPLY_FLOOD_FIRST_ATTEMPT - 1; next tick hits flood attempt.
    e = _entry(
        b"\x00\x00\x00\x02",
        attempt=REPLY_FLOOD_FIRST_ATTEMPT - 1,
        retry_at_offset=-0.1,
    )
    pending.register(e)
    sched.tick(time.monotonic())

    # route should have been forgotten for the peer's 1-byte hash.
    assert forgot == [e.peer_pk[0]]
    item = tx.pop_ready(time.monotonic())
    assert item is not None
    assert item.attempt == REPLY_FLOOD_FIRST_ATTEMPT
    # The rebuilt packet's label tag for flood is 'F' in our stub.
    assert item.packet.endswith(b"F")


def test_exhausted_drops_and_counts() -> None:
    pending = PendingAckTable()
    tx = TxQueue()
    m = Metrics()
    sched = RetryScheduler(
        pending=pending,
        tx_queue=tx,
        metrics=m,
        rebuild_reply=_noop_rebuild,
        forget_route_fn=lambda _h: False,
    )

    e = _entry(b"\x00\x00\x00\x03", attempt=5, retry_at_offset=-0.1, max_attempts=5)
    pending.register(e)
    sched.tick(time.monotonic())
    assert pending.depth() == 0
    counters, _, _ = m.snapshot()
    assert counters.get("reply_exhausted", 0) == 1


def test_retry_schedule_is_airtime_headroom() -> None:
    # Guardrail: encourage authors to keep realistic spacing.
    assert RETRY_SCHEDULE_S[0] >= 3.0, "attempt-2 must leave headroom for a 2-hop RTT"
    for prev, cur in itertools.pairwise(RETRY_SCHEDULE_S):
        assert cur >= prev, "retry schedule should be monotonically non-decreasing"


def test_schedule_covers_all_retries_for_max_attempts() -> None:
    """Each retry after the initial send needs an explicit delay entry."""
    # REPLY_MAX_ATTEMPTS counts the initial send, so retries = MAX - 1.
    assert len(RETRY_SCHEDULE_S) >= REPLY_MAX_ATTEMPTS - 1, (
        "RETRY_SCHEDULE_S too short for REPLY_MAX_ATTEMPTS — the final retry clamps "
        "back to the last entry rather than using a distinct delay"
    )


def test_pending_ack_ttl_exceeds_final_retry_plus_headroom() -> None:
    """TTL sweep must not kill pending entries before the last retry's ACK window."""
    total_retry_delay = sum(RETRY_SCHEDULE_S[: REPLY_MAX_ATTEMPTS - 1])
    # At least 20 s past the final retry's send time for its ACK to arrive.
    min_required = total_retry_delay + 20
    assert min_required <= PENDING_ACK_TTL_S, (
        f"PENDING_ACK_TTL_S={PENDING_ACK_TTL_S} cuts the last retry short; "
        f"needs >= {min_required}s (sum of retry delays + 20s ACK window)"
    )
