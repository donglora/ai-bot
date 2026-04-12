"""ACK-hash stability across retry rebuilds.

The retry scheduler must be able to recompute the expected ACK CRC using the
same plaintext (ts + attempt byte + text) that the receiver will compute against.
"""

from __future__ import annotations

from orac.crypto import build_peer_plaintext
from orac.meshcore import compute_ack_hash


def test_ack_hash_stable_for_same_inputs() -> None:
    ts = 1700000000
    pt1 = build_peer_plaintext("hello", ts=ts, attempt=0)
    pt2 = build_peer_plaintext("hello", ts=ts, attempt=0)
    sender = b"\x11" * 32
    assert compute_ack_hash(pt1, sender) == compute_ack_hash(pt2, sender)


def test_ack_hash_changes_with_attempt_byte() -> None:
    ts = 1700000000
    pt0 = build_peer_plaintext("hello", ts=ts, attempt=0)
    pt1 = build_peer_plaintext("hello", ts=ts, attempt=1)
    sender = b"\x22" * 32
    assert compute_ack_hash(pt0, sender) != compute_ack_hash(pt1, sender)


def test_ack_hash_changes_with_text() -> None:
    ts = 1700000000
    sender = b"\x33" * 32
    a = compute_ack_hash(build_peer_plaintext("hello", ts=ts, attempt=0), sender)
    b = compute_ack_hash(build_peer_plaintext("world", ts=ts, attempt=0), sender)
    assert a != b


def test_ack_hash_changes_with_sender() -> None:
    ts = 1700000000
    pt = build_peer_plaintext("hello", ts=ts, attempt=0)
    a = compute_ack_hash(pt, b"\x44" * 32)
    b = compute_ack_hash(pt, b"\x55" * 32)
    assert a != b
