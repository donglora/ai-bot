"""Tests for orac.reply_state.PendingAckTable and ReplyCache."""

from __future__ import annotations

import time

from orac.reply_state import PendingAckTable, PendingReply, ReplyCache


def _entry(ack: bytes, peer_pk: bytes, attempt: int = 1) -> PendingReply:
    now = time.monotonic()
    return PendingReply(
        expected_ack=ack,
        peer_pk=peer_pk,
        peer_name=f"peer{peer_pk[0]:02x}",
        text="hello",
        first_ts=1234567890,
        first_sent_at=now,
        attempt=attempt,
        max_attempts=5,
        retry_at=now + 6.0,
    )


def test_register_and_consume_roundtrip() -> None:
    table = PendingAckTable(cap=4)
    ack = b"\x01\x02\x03\x04"
    table.register(_entry(ack, b"\xaa" * 32))
    assert table.depth() == 1
    entry = table.consume(ack)
    assert entry is not None
    assert entry.expected_ack == ack
    assert table.depth() == 0
    # Consuming again returns None.
    assert table.consume(ack) is None


def test_expired_returns_entries_past_retry_at() -> None:
    table = PendingAckTable()
    ack = b"\x00\x00\x00\x01"
    e = _entry(ack, b"\x11" * 32)
    table.register(e)
    # retry_at was set to now + 6.0 — force expiry by passing a far-future "now".
    expired = table.expired(time.monotonic() + 10.0)
    assert len(expired) == 1
    assert expired[0].expected_ack == ack
    # expired() does not remove.
    assert table.depth() == 1


def test_replace_key_rekeys_entry() -> None:
    table = PendingAckTable()
    old = b"\x00\x00\x00\x01"
    new = b"\x00\x00\x00\x02"
    table.register(_entry(old, b"\x22" * 32))
    table.replace_key(old, new)
    assert table.consume(old) is None
    got = table.consume(new)
    assert got is not None and got.expected_ack == new


def test_has_pending_for_peer() -> None:
    table = PendingAckTable()
    pk_a = b"\x10" + b"\x00" * 31
    pk_b = b"\x20" + b"\x00" * 31
    table.register(_entry(b"\x00\x00\x00\x01", pk_a))
    assert table.has_pending_for_peer(pk_a) is True
    assert table.has_pending_for_peer(pk_b) is False


def test_cap_evicts_oldest_on_overflow() -> None:
    table = PendingAckTable(cap=2)
    table.register(_entry(b"\x01\x00\x00\x00", b"\xaa" * 32))
    table.register(_entry(b"\x02\x00\x00\x00", b"\xbb" * 32))
    table.register(_entry(b"\x03\x00\x00\x00", b"\xcc" * 32))
    # Oldest (first registered) should be gone.
    assert table.consume(b"\x01\x00\x00\x00") is None
    assert table.consume(b"\x02\x00\x00\x00") is not None
    assert table.consume(b"\x03\x00\x00\x00") is not None


def test_reply_cache_roundtrip() -> None:
    cache = ReplyCache(cap=4, ttl=100.0)
    pk = b"\x55" * 32
    cache.put(
        peer_pk=pk,
        peer_name="alice",
        dm_text="hi",
        reply_packet=b"\xff\xee",
        reply_text="hello back",
        expected_ack=b"\x01\x02\x03\x04",
    )
    got = cache.get(pk.hex(), "hi")
    assert got is not None and got.reply_text == "hello back"
    # Different DM text misses.
    assert cache.get(pk.hex(), "different") is None


def test_reply_cache_ttl_expires() -> None:
    cache = ReplyCache(cap=4, ttl=0.001)
    pk = b"\x66" * 32
    cache.put(
        peer_pk=pk,
        peer_name="bob",
        dm_text="q",
        reply_packet=b"\x00",
        reply_text="a",
        expected_ack=b"\x00\x00\x00\x00",
    )
    time.sleep(0.01)
    assert cache.get(pk.hex(), "q") is None


def test_reply_cache_ts_lets_caller_gate_on_age() -> None:
    """Caller can decide whether a hit is within the loss-recovery window."""
    cache = ReplyCache(cap=4, ttl=100.0)
    pk = b"\x77" * 32
    cache.put(
        peer_pk=pk,
        peer_name="carol",
        dm_text="status?",
        reply_packet=b"\x00",
        reply_text="ok",
        expected_ack=b"\x00\x00\x00\x01",
    )
    got = cache.get(pk.hex(), "status?")
    assert got is not None
    # Caller interprets .ts; entry is fresh right now.
    assert (time.monotonic() - got.ts) < 1.0
