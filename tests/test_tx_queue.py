"""Tests for orac.runtime.TxQueue: priority ordering, not_before gating, eviction."""

from __future__ import annotations

import time

from orac.runtime import TxItem, TxPriority, TxQueue


def _item(
    priority: int,
    not_before: float,
    *,
    label: str = "x",
    expected_ack: bytes | None = None,
) -> TxItem:
    return TxItem(
        priority=priority,
        not_before=not_before,
        packet=b"\x00\x01\x02",
        label=label,
        expected_ack=expected_ack,
    )


def test_pop_ready_none_when_nothing_due() -> None:
    q = TxQueue(cap=8)
    now = time.monotonic()
    q.push(_item(TxPriority.ACK, now + 10.0))
    assert q.pop_ready(now) is None


def test_pop_ready_highest_priority_wins_when_all_ready() -> None:
    q = TxQueue(cap=8)
    now = time.monotonic()
    q.push(_item(TxPriority.ADVERT, now - 1.0, label="advert"))
    q.push(_item(TxPriority.REPLY_FLOOD, now - 1.0, label="reply_flood"))
    q.push(_item(TxPriority.ACK, now - 1.0, label="ack"))
    q.push(_item(TxPriority.PATH, now - 1.0, label="path"))
    order: list[str] = []
    for _ in range(4):
        item = q.pop_ready(now)
        assert item is not None
        order.append(item.label)
    assert order == ["ack", "path", "reply_flood", "advert"]


def test_not_before_gates_lower_priority_first() -> None:
    q = TxQueue(cap=8)
    now = time.monotonic()
    q.push(_item(TxPriority.ACK, now + 5.0, label="future_ack"))
    q.push(_item(TxPriority.ADVERT, now - 1.0, label="advert"))
    item = q.pop_ready(now)
    assert item is not None
    assert item.label == "advert"
    # Future ACK still gated
    assert q.pop_ready(now) is None


def test_eviction_drops_lowest_priority_oldest_when_cap() -> None:
    q = TxQueue(cap=3)
    now = time.monotonic()
    q.push(_item(TxPriority.ACK, now, label="a"))
    q.push(_item(TxPriority.PATH, now, label="b"))
    q.push(_item(TxPriority.ADVERT, now, label="c"))
    # Cap hit; new ACK should evict ADVERT.
    q.push(_item(TxPriority.ACK, now, label="d"))
    labels: set[str] = set()
    for _ in range(3):
        item = q.pop_ready(now)
        assert item is not None
        labels.add(item.label)
    assert labels == {"a", "b", "d"}


def test_cancel_by_ack_removes_matching_items() -> None:
    q = TxQueue(cap=8)
    now = time.monotonic()
    q.push(_item(TxPriority.REPLY_DIRECT, now, label="x", expected_ack=b"\xde\xad\xbe\xef"))
    q.push(_item(TxPriority.REPLY_DIRECT, now, label="y", expected_ack=b"\x01\x02\x03\x04"))
    q.push(_item(TxPriority.ACK, now, label="ack_bare"))
    removed = q.cancel_by_ack(b"\xde\xad\xbe\xef")
    assert removed == 1
    # The other two items survive.
    remaining: set[str] = set()
    for _ in range(2):
        item = q.pop_ready(now)
        assert item is not None
        remaining.add(item.label)
    assert remaining == {"y", "ack_bare"}
