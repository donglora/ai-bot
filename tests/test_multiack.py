"""Protocol fidelity: MULTIPART ACK packet layout + RX unwrap.

Mirrors upstream MeshCore:
- `createMultiAck(crc, remaining)` (src/Mesh.cpp:570-583)
- `createAck(crc)` (src/Mesh.cpp:556-568)
- Receiver unwrap (src/Mesh.cpp:270-282)
"""

from __future__ import annotations

from orac import meshcore
from orac.meshcore import build_ack_packet, build_multiack_packet, parse_header_and_path


def _clear_routes() -> None:
    with meshcore._route_lock:
        meshcore._route_table.clear()


def test_multiack_flood_layout() -> None:
    """With no learned route, MULTIPART uses flood route_type = 1."""
    _clear_routes()
    crc = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    packet = build_multiack_packet(crc, remaining=1, dest_hash=0x42)
    # Expect: header(1) + path_len(1) + payload(5)
    # header: PAYLOAD_TYPE_MULTIPART(0x0A) << 2 | ROUTE_TYPE_FLOOD(0x01)
    # = (0x0A << 2) | 0x01 = 0x29
    assert packet[0] == 0x29, f"header byte wrong: {packet[0]:#04x}"
    # path_len byte: 0x40 = hash_size_code=1 (2-byte), 0 hops
    assert packet[1] == 0x40
    # Payload: (remaining << 4) | 0x03 + crc
    assert packet[2] == (1 << 4) | 0x03
    assert packet[3:7] == crc


def test_multiack_direct_layout_with_route() -> None:
    """With a learned direct route, header uses ROUTE_TYPE_DIRECT = 2."""
    _clear_routes()
    # Seed a 2-byte single-hop route
    meshcore.learn_route(0x77, [b"\xaa\xbb"], hash_size=2, snr=10.0)
    crc = bytes([0x01, 0x02, 0x03, 0x04])
    packet = build_multiack_packet(crc, remaining=2, dest_hash=0x77)
    # header = (0x0A << 2) | 0x02 (ROUTE_TYPE_DIRECT) = 0x2A
    assert packet[0] == 0x2A, f"direct-route header wrong: {packet[0]:#04x}"
    # path_len byte: hash_size_code=1 (2-byte), 1 hop -> 0x41
    assert packet[1] == 0x41
    # Path data
    assert packet[2:4] == b"\xaa\xbb"
    # Payload: (remaining << 4) | 0x03 + crc
    assert packet[4] == (2 << 4) | 0x03
    assert packet[5:9] == crc


def test_multiack_remaining_nibble_bounds() -> None:
    import pytest

    with pytest.raises(ValueError):
        build_multiack_packet(b"\x00\x00\x00\x00", remaining=-1, dest_hash=0x11)
    with pytest.raises(ValueError):
        build_multiack_packet(b"\x00\x00\x00\x00", remaining=16, dest_hash=0x11)
    # 0 and 15 are valid
    build_multiack_packet(b"\x00\x00\x00\x00", remaining=0, dest_hash=0x11)
    build_multiack_packet(b"\x00\x00\x00\x00", remaining=15, dest_hash=0x11)


def test_multiack_crc_length_enforced() -> None:
    import pytest

    with pytest.raises(ValueError):
        build_multiack_packet(b"\x00\x00\x00", remaining=1, dest_hash=0x11)
    with pytest.raises(ValueError):
        build_multiack_packet(b"\x00\x00\x00\x00\x00", remaining=1, dest_hash=0x11)


def test_plain_ack_layout_unchanged() -> None:
    """Regression: plain PAYLOAD_TYPE_ACK (0x03) still works as before."""
    _clear_routes()
    crc = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    packet = build_ack_packet(crc, dest_hash=0x99)
    # header = (0x03 << 2) | 0x01 = 0x0D (flood)
    assert packet[0] == 0x0D
    assert packet[1] == 0x40
    # Payload is just the 4-byte CRC, no remaining-nibble byte.
    assert packet[2:6] == crc
    assert len(packet) == 6


def test_round_trip_parse_extracts_multiack_payload() -> None:
    """Firmware-style RX: parse_header_and_path strips header+path and hands us
    the 5-byte MULTIPART payload; our handler expects [nibble|type][crc:4]."""
    _clear_routes()
    crc = bytes([0xC0, 0xDE, 0xCA, 0xFE])
    packet = build_multiack_packet(crc, remaining=1, dest_hash=0x33)
    parsed = parse_header_and_path(packet)
    assert parsed is not None
    payload_type, route_type, _ver, _pos, payload, _path_hops, _hash_size = parsed
    assert payload_type == 0x0A  # PAYLOAD_TYPE_MULTIPART
    assert route_type == 0x01  # flood (no route learned)
    assert len(payload) == 5
    assert payload[0] & 0x0F == 0x03  # inner type == PAYLOAD_TYPE_ACK
    assert payload[0] >> 4 == 1  # remaining = 1
    assert payload[1:5] == crc
