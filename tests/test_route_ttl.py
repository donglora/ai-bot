"""Tests for orac.meshcore route table TTL and SNR upgrade rule."""

from __future__ import annotations

import time
from unittest.mock import patch

import orac.meshcore as mc


def _clear_route_table() -> None:
    with mc._route_lock:
        mc._route_table.clear()


def test_learn_and_get_roundtrip() -> None:
    _clear_route_table()
    mc.learn_route(0xAB, [b"\x11\x22"], hash_size=2, snr=10.0)
    got = mc.get_route(0xAB)
    assert got is not None
    hops, hs = got
    # path stored reversed
    assert hops == [b"\x11\x22"]
    assert hs == 2


def test_ttl_expiry_and_lazy_eviction() -> None:
    _clear_route_table()
    mc.learn_route(0xCD, [b"\x01\x02"], hash_size=2, snr=5.0)

    # Fast-forward monotonic time by patching time.monotonic to return now+TTL+1
    fake_future = time.monotonic() + mc.ROUTE_TTL_S + 1.0
    with patch("orac.meshcore.time.monotonic", return_value=fake_future):
        assert mc.get_route(0xCD) is None

    # Entry should have been lazy-evicted.
    assert mc.get_route(0xCD) is None


def test_forget_route_removes_entry() -> None:
    _clear_route_table()
    mc.learn_route(0x55, [b"\xaa\xbb"], hash_size=2)
    assert mc.forget_route(0x55) is True
    assert mc.get_route(0x55) is None
    # Double-forget is a no-op.
    assert mc.forget_route(0x55) is False


def test_snr_upgrade_rule_rejects_bad_path() -> None:
    _clear_route_table()
    mc.learn_route(0x77, [b"\x01\x02", b"\x03\x04"], hash_size=2, snr=10.0)
    # New path arrives with much worse SNR → existing path kept.
    mc.learn_route(0x77, [b"\xff\xff"], hash_size=2, snr=-5.0)
    got = mc.get_route(0x77)
    assert got is not None
    hops, _ = got
    assert hops == [b"\x03\x04", b"\x01\x02"]  # original (reversed) hops


def test_snr_upgrade_rule_accepts_comparable_path() -> None:
    _clear_route_table()
    mc.learn_route(0x88, [b"\x01\x02", b"\x03\x04"], hash_size=2, snr=5.0)
    # New path with slightly worse SNR (within 3 dB tolerance) → upgrade (refreshes learned_at).
    mc.learn_route(0x88, [b"\xaa\xbb"], hash_size=2, snr=3.0)
    got = mc.get_route(0x88)
    assert got is not None
    hops, _ = got
    assert hops == [b"\xaa\xbb"]


def test_hash_size_downgrade_rejected() -> None:
    _clear_route_table()
    mc.learn_route(0x99, [b"\x01\x02"], hash_size=2, snr=10.0)
    # Smaller hash size should NOT replace a larger one.
    mc.learn_route(0x99, [b"\xff"], hash_size=1, snr=10.0)
    got = mc.get_route(0x99)
    assert got is not None
    _, hs = got
    assert hs == 2


def test_one_byte_hash_paths_are_never_learned() -> None:
    """Policy: we refuse to learn routes with 1-byte hashes (MIN_HASH_SIZE=2)."""
    _clear_route_table()
    mc.learn_route(0xAA, [b"\xff"], hash_size=1, snr=10.0)
    assert mc.get_route(0xAA) is None


def test_build_path_return_rejects_one_byte_hashes() -> None:
    """Policy: refuse to echo 1-byte PATH returns."""
    import pytest

    peer_pk = b"\x55" * 32
    with pytest.raises(ValueError):
        mc.build_path_return_packet(peer_pk, [b"\xff"], hash_size=1)
