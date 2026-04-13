"""MeshCore packet parsing/building, routing, dedup, node registry, ADVERT, ACK, PATH."""

from __future__ import annotations

import hashlib
import logging
import os
import struct
import threading
import time
from dataclasses import dataclass, field

from orac.constants import (
    DEDUP_TTL,
    DM_DEDUP_TTL,
    MIN_HASH_SIZE,
    PENDING_DM_TTL,
    RESP_SERVER_LOGIN_OK,
    ROUTE_TTL_S,
)
from orac.crypto import (
    build_advert_payload,
    build_peer_plaintext,
    ecdh_shared_secret,
    grp_encrypt,
    my_hash,
    peer_encrypt_plaintext,
    raw_peer_encrypt,
    verify_advert_signature,
)

log = logging.getLogger("orac")

# ── Route table ──────────────────────────────────────────────────


@dataclass
class RouteEntry:
    """Learned return route with TTL and SNR metadata."""

    hops: list[bytes]  # closest-relay-first after reversal of inbound path
    hash_size: int
    learned_at: float = field(default_factory=time.monotonic)
    last_snr: float | None = None


_route_table: dict[int, RouteEntry] = {}
_route_lock = threading.Lock()

_RT_NAMES: dict[int, str] = {0: "tflood", 1: "flood", 2: "direct", 3: "tdirect"}


def learn_route(
    src_hash: int,
    path_hops: list[bytes],
    hash_size: int,
    snr: float | None = None,
) -> None:
    """Learn a return route from an incoming packet's path.

    path_hops is ordered closest-relay-first as received. We reverse it
    so our outgoing path traverses the same relays back toward the sender.

    Upgrade rule: newer entry wins if its hash_size is not smaller AND
    its SNR is not >=3 dB worse than the existing entry's last SNR.

    Policy: 1-byte hashes are rejected (see :data:`MIN_HASH_SIZE`). A peer
    using 1-byte path encoding simply won't get a cached route — our replies
    to them will flood instead (flood packets always use 2-byte hash mode).
    """
    if hash_size < MIN_HASH_SIZE:
        return
    reversed_hops = list(reversed(path_hops))
    with _route_lock:
        existing = _route_table.get(src_hash)
        if existing is not None:
            if hash_size < existing.hash_size:
                return  # never downgrade hash size
            if snr is not None and existing.last_snr is not None and snr < existing.last_snr - 3.0:
                # New path is ≥3 dB worse; keep current path and just refresh
                # last-seen snr for TTL purposes.
                existing.learned_at = time.monotonic()
                return
        _route_table[src_hash] = RouteEntry(
            hops=reversed_hops,
            hash_size=hash_size,
            learned_at=time.monotonic(),
            last_snr=snr,
        )


def get_route(dest_hash: int) -> tuple[list[bytes], int] | None:
    """Return a learned route if it exists and hasn't expired, else None.

    Legacy tuple return preserved so callers that only care about (hops,
    hash_size) keep working. Use :func:`get_route_entry` to access SNR.
    """
    with _route_lock:
        entry = _route_table.get(dest_hash)
        if entry is None:
            return None
        if time.monotonic() - entry.learned_at > ROUTE_TTL_S:
            # Expired: lazy-evict so the next learn can re-populate.
            del _route_table[dest_hash]
            return None
        return (list(entry.hops), entry.hash_size)


def get_route_entry(dest_hash: int) -> RouteEntry | None:
    """Return the full RouteEntry if live, else None."""
    with _route_lock:
        entry = _route_table.get(dest_hash)
        if entry is None:
            return None
        if time.monotonic() - entry.learned_at > ROUTE_TTL_S:
            del _route_table[dest_hash]
            return None
        return entry


def forget_route(dest_hash: int) -> bool:
    """Hard-delete a learned route. Returns True if an entry was removed."""
    with _route_lock:
        return _route_table.pop(dest_hash, None) is not None


def route_table_size() -> int:
    """Current live route table size (after lazy eviction — call sparingly)."""
    with _route_lock:
        return len(_route_table)


def route_name(route_type: int) -> str:
    """Human-readable name for a route type."""
    return _RT_NAMES.get(route_type, f"rt{route_type}")


# ── Node registry ────────────────────────────────────────────────
# Stored in state module; these helpers bridge to it.

from orac import state as _state_mod  # noqa: E402


def register_node(pubkey: bytes, name: str) -> bool:
    """Register a node. Returns True if this is a NEW node."""
    return _state_mod.register_node(pubkey, name)


def lookup_node_by_hash(hash_byte: int) -> list[tuple[bytes, str]]:
    """Find all known nodes whose pubkey first byte matches."""
    return _state_mod.lookup_node_by_hash(hash_byte)


def node_name(pubkey_hex: str) -> str:
    """Human-readable name for a node, or truncated hex."""
    return _state_mod.node_name(pubkey_hex)


# ── Deduplication ────────────────────────────────────────────────

_seen_packets: dict[bytes, float] = {}
_seen_dm_texts: dict[str, float] = {}  # "pubkey_hex:text" -> monotonic timestamp


def is_duplicate(payload_type: int, payload: bytes) -> bool:
    """Dedup via 8-byte packet hash (spec Section 16)."""
    now = time.monotonic()
    if len(_seen_packets) > 500:
        expired = [k for k, t in _seen_packets.items() if now - t > DEDUP_TTL]
        for k in expired:
            del _seen_packets[k]

    pkt_hash = hashlib.sha256(bytes([payload_type]) + payload).digest()[:8]
    if pkt_hash in _seen_packets and now - _seen_packets[pkt_hash] < DEDUP_TTL:
        return True
    _seen_packets[pkt_hash] = now
    return False


def is_dm_duplicate(peer_pubkey_hex: str, text: str) -> bool:
    """Dedup on decrypted DM text (catches retries with different attempt counters)."""
    now = time.monotonic()
    if len(_seen_dm_texts) > 200:
        expired = [k for k, t in _seen_dm_texts.items() if now - t > DM_DEDUP_TTL]
        for k in expired:
            del _seen_dm_texts[k]

    key = f"{peer_pubkey_hex}:{text}"
    if key in _seen_dm_texts and now - _seen_dm_texts[key] < DM_DEDUP_TTL:
        return True
    _seen_dm_texts[key] = now
    return False


# ── Pending DMs from unknown senders ─────────────────────────────

_pending_dms: dict[int, list[tuple[bytes, float]]] = {}


def queue_pending_dm(src_hash: int, raw_payload: bytes) -> bool:
    """Queue a DM from an unknown sender. Returns True if this is the first queued."""
    _pending_dms.setdefault(src_hash, []).append((raw_payload, time.monotonic()))
    return len(_pending_dms[src_hash]) == 1


def pop_pending_dms(node_hash: int) -> list[tuple[bytes, float]]:
    """Pop and return all pending DMs for a node hash."""
    return _pending_dms.pop(node_hash, [])


def has_pending_dms(node_hash: int) -> bool:
    """Check if there are pending DMs for a node hash."""
    return bool(_pending_dms.get(node_hash))


def is_pending_expired(timestamp: float) -> bool:
    """Check if a pending DM timestamp is expired."""
    return time.monotonic() - timestamp > PENDING_DM_TTL


# ── Packet parsing ───────────────────────────────────────────────


def parse_header_and_path(
    packet: bytes,
) -> tuple[int, int, int, int, bytes, list[bytes], int] | None:
    """Parse MeshCore header + path.

    Returns (payload_type, route_type, payload_ver, pos, payload, path_hops, hash_size)
    or None. path_hops is a list of raw hash bytes for each hop (closest relay first).
    """
    if len(packet) < 3:
        return None

    header = packet[0]
    route_type = header & 0x03
    payload_type = (header >> 2) & 0x0F
    payload_ver = (header >> 6) & 0x03

    if payload_ver != 0:
        return None

    has_tc = route_type in (0, 3)

    for skip_tc in [True, False] if has_tc else [False]:
        pos = 5 if skip_tc else 1
        if pos >= len(packet):
            continue

        path_len_byte = packet[pos]
        pos += 1
        hash_size_code = path_len_byte >> 6
        if hash_size_code == 3:
            continue
        hash_size = hash_size_code + 1
        hop_count = path_len_byte & 0x3F
        path_bytes = hop_count * hash_size
        if path_bytes > 64 or pos + path_bytes > len(packet):
            continue

        hops: list[bytes] = []
        for i in range(hop_count):
            hops.append(packet[pos + i * hash_size : pos + (i + 1) * hash_size])
        pos += path_bytes

        payload = packet[pos:]
        if payload and len(payload) <= 184:
            return payload_type, route_type, payload_ver, pos, payload, hops, hash_size

    return None


# ── Packet building ──────────────────────────────────────────────


def _build_routed_packet(payload_type: int, payload: bytes, dest_hash: int) -> bytes:
    """Build a packet using a learned route if available, otherwise flood."""
    route = get_route(dest_hash)
    if route is not None:
        hops, hash_size = route
        hash_size_code = hash_size - 1
        path_len_byte = (hash_size_code << 6) | (len(hops) & 0x3F)
        path_data = b"".join(hops)
        header = bytes([(payload_type << 2) | 2])  # direct route_type = 2
        return header + bytes([path_len_byte]) + path_data + payload
    else:
        header = bytes([(payload_type << 2) | 1])  # flood route_type = 1
        path_len = bytes([0x40])  # 0 hops, 2-byte hash mode
        return header + path_len + payload


def build_grp_packet(channel_payload: bytes) -> bytes:
    """Wrap channel payload in a GRP_TXT flood packet."""
    header = bytes([0x15])  # GRP_TXT flood: (5 << 2) | 1
    path_len = bytes([0x40])  # 0 hops, 2-byte hash mode
    return header + path_len + channel_payload


def build_advert_packet() -> bytes:
    """Build a MeshCore ADVERT packet for this node."""
    advert_payload = build_advert_payload()
    header = bytes([0x11])  # ADVERT flood: (4 << 2) | 1
    path_len = bytes([0x40])  # 0 hops, 2-byte hash mode
    return header + path_len + advert_payload


def build_dm_packet(peer_pubkey: bytes, text: str) -> bytes:
    """Build a TXT_MSG DM packet using learned route or flood."""
    packet, _ = build_dm_packet_with_plaintext(peer_pubkey, text)
    return packet


def build_dm_packet_with_plaintext(
    peer_pubkey: bytes,
    text: str,
    force_flood: bool = False,
    ts: int | None = None,
    attempt: int = 0,
) -> tuple[bytes, bytes]:
    """Build a TXT_MSG DM packet and return (packet, plaintext).

    Plaintext is needed to precompute the expected ACK CRC that the
    recipient's firmware will emit back to us.

    :param ts: override the plaintext timestamp; defaults to ``int(time.time())``.
        Callers that need retry-stable ACK CRCs should pass a fixed ts and
        increment ``attempt`` on each retry.
    :param attempt: value for the ``txt_type_attempt`` plaintext byte (0-63).
    :param force_flood: if True, emit a flood route-type packet regardless of
        any learned route in the table.
    """
    plaintext = build_peer_plaintext(text, ts=ts, attempt=attempt)
    shared_secret = ecdh_shared_secret(peer_pubkey)
    mac_ct = peer_encrypt_plaintext(shared_secret, plaintext)
    dm_payload = bytes([peer_pubkey[0], my_hash()]) + mac_ct
    if force_flood:
        header = bytes([(0x02 << 2) | 1])  # flood route_type = 1
        path_len = bytes([0x40])  # 0 hops, 2-byte hash mode
        packet = header + path_len + dm_payload
    else:
        packet = _build_routed_packet(0x02, dm_payload, peer_pubkey[0])
    return packet, plaintext


def build_ack_packet(ack_crc: bytes, dest_hash: int) -> bytes:
    """Build an ACK packet using learned route or flood."""
    return _build_routed_packet(0x03, ack_crc, dest_hash)


def build_multiack_packet(ack_crc: bytes, remaining: int, dest_hash: int) -> bytes:
    """Build a MULTIPART ACK (PAYLOAD_TYPE_MULTIPART = 0x0A).

    Upstream `createMultiAck()` (src/Mesh.cpp:570-583 in commit b1ca3d1):
    the payload is 5 bytes — ``(remaining << 4) | PAYLOAD_TYPE_ACK(0x03)``
    followed by the 4-byte ACK CRC.

    MULTIPART ACKs are emitted ONLY on direct-routed returns (see
    :func:`Mesh::routeDirectRecvAcks` upstream). Caller should verify a
    direct route exists for ``dest_hash`` and skip MULTIPART otherwise.
    """
    if len(ack_crc) != 4:
        raise ValueError(f"ack_crc must be 4 bytes, got {len(ack_crc)}")
    if not 0 <= remaining <= 15:
        raise ValueError(f"remaining must fit a nibble (0..15), got {remaining}")
    payload = bytes([(remaining << 4) | 0x03]) + ack_crc
    return _build_routed_packet(0x0A, payload, dest_hash)


def build_path_return_packet(peer_pubkey: bytes, path_hops: list[bytes], hash_size: int) -> bytes:
    """Build a PATH return (0x08) so the sender can learn a direct route to us.

    Rejects 1-byte hash encodings (see :data:`MIN_HASH_SIZE`).
    """
    if hash_size < MIN_HASH_SIZE:
        raise ValueError(f"refusing to build PATH_RETURN with hash_size={hash_size}")
    reversed_hops = list(reversed(path_hops))
    hash_size_code = hash_size - 1
    path_len_byte = (hash_size_code << 6) | (len(reversed_hops) & 0x3F)
    path_data = b"".join(reversed_hops)

    # Inner plaintext: path_len + path + 0xFF (dummy extra) + 4 random bytes
    inner = bytes([path_len_byte]) + path_data + b"\xff" + os.urandom(4)

    shared_secret = ecdh_shared_secret(peer_pubkey)
    mac_ct = raw_peer_encrypt(shared_secret, inner)

    # Outer: dest_hash + src_hash + mac + ciphertext
    path_payload = bytes([peer_pubkey[0], my_hash()]) + mac_ct
    return _build_routed_packet(0x08, path_payload, peer_pubkey[0])


def build_login_response_packet(peer_pubkey: bytes) -> bytes:
    """Build a RESPONSE packet (login OK) back to the peer."""
    shared_secret = ecdh_shared_secret(peer_pubkey)

    # Response payload: timestamp(4) + RESP_SERVER_LOGIN_OK(1) + zero(1) + permissions(2)
    reply = struct.pack("<I", int(time.time()))
    reply += bytes([RESP_SERVER_LOGIN_OK, 0x00, 0x00, 0xFF])

    mac_ct = raw_peer_encrypt(shared_secret, reply)
    resp_payload = bytes([peer_pubkey[0], my_hash()]) + mac_ct
    return _build_routed_packet(0x01, resp_payload, peer_pubkey[0])


def build_grp_channel_packet(channel_name: str, sender: str, text: str) -> bytes | None:
    """Build a complete GRP_TXT packet for a channel. Returns None if channel unknown."""
    from orac.crypto import get_channel_secret

    secret = get_channel_secret(channel_name)
    if secret is None:
        return None
    payload = grp_encrypt(secret, sender, text)
    return build_grp_packet(payload)


# ── ACK hash computation ────────────────────────────────────────


def compute_ack_hash(plaintext: bytes, sender_pubkey: bytes) -> bytes:
    """Compute 4-byte ACK hash per MeshCore BaseChatMesh.cpp.

    Hash = SHA-256(frag1 || sender_pubkey)[0:4]
    frag1 = timestamp(4) + txt_type_attempt(1) + text (no null terminator)
    """
    text_bytes = plaintext[5:]
    null_pos = text_bytes.find(b"\x00")
    text_len = null_pos if null_pos >= 0 else len(text_bytes)
    frag1 = plaintext[: 5 + text_len]
    return hashlib.sha256(frag1 + sender_pubkey).digest()[:4]


# ── GRP_TXT interception ────────────────────────────────────────


def try_decrypt_grp(raw_payload: bytes) -> tuple[str, str] | None:
    """Try to decrypt a GRP_TXT payload. Returns (channel_name, text) or None."""
    from orac.crypto import get_channels_by_hash, grp_verify_and_decrypt, parse_grp_plaintext

    if len(raw_payload) < 19:
        return None
    ch = raw_payload[0]
    mac_bytes = raw_payload[1:3]
    ciphertext = raw_payload[3:]

    candidates = get_channels_by_hash(ch)
    for chan_name, secret in candidates:
        plaintext = grp_verify_and_decrypt(secret, mac_bytes, ciphertext)
        if plaintext is not None:
            parsed = parse_grp_plaintext(plaintext)
            if parsed:
                _, text = parsed
                return chan_name, text
    return None


# ── DM interception ──────────────────────────────────────────────


def try_decrypt_dm(raw_payload: bytes) -> tuple[bytes, str, str, bytes] | None:
    """Try to decrypt a TXT_MSG DM addressed to us.

    Returns (sender_pubkey, sender_name, message_text, raw_plaintext) or None.
    """
    from orac.crypto import parse_peer_plaintext, peer_verify_and_decrypt

    if len(raw_payload) < 20:
        return None

    dest_hash = raw_payload[0]
    src_hash = raw_payload[1]
    mac_bytes = raw_payload[2:4]
    ciphertext = raw_payload[4:]

    log.debug(
        "TXT_MSG dest=0x%02x src=0x%02x me=0x%02x [%dB]",
        dest_hash,
        src_hash,
        my_hash(),
        len(ciphertext),
    )

    if dest_hash != my_hash():
        return None

    candidates = lookup_node_by_hash(src_hash)
    if not candidates:
        log.warning("DM for us but no known node with hash 0x%02x", src_hash)
        return None

    for peer_pubkey, peer_name in candidates:
        try:
            shared_secret = ecdh_shared_secret(peer_pubkey)
            plaintext = peer_verify_and_decrypt(shared_secret, mac_bytes, ciphertext)
            if plaintext is not None:
                text = parse_peer_plaintext(plaintext)
                if text:
                    return peer_pubkey, peer_name, text, plaintext
        except Exception:
            pk_hex = peer_pubkey.hex()
            log.warning("Evicting bad key for %s (%s...)", peer_name, pk_hex[:16])
            _state_mod.evict_node(pk_hex)
            continue

    return None


def try_decrypt_anon_req(
    raw_payload: bytes,
) -> tuple[bytes, str, bytes | None] | None:
    """Try to decrypt an ANON_REQ (login).

    Returns (sender_pubkey, sender_name, plaintext_or_None) or None.
    """
    from orac.crypto import peer_verify_and_decrypt

    if len(raw_payload) < 51:
        return None

    dest_hash = raw_payload[0]
    sender_pubkey = raw_payload[1:33]
    mac_bytes = raw_payload[33:35]
    ciphertext = raw_payload[35:]

    log.info(
        "ANON_REQ dest=0x%02x sender=%s... [%dB]",
        dest_hash,
        sender_pubkey.hex()[:16],
        len(ciphertext),
    )

    if dest_hash != my_hash():
        return None

    # Register sender -- we now have their full pubkey
    peer_name = node_name(sender_pubkey.hex())
    is_new = register_node(sender_pubkey, peer_name)
    if is_new:
        log.info(
            "Registered new peer from ANON_REQ: %s (hash=0x%02x)",
            peer_name,
            sender_pubkey[0],
        )

    try:
        shared_secret = ecdh_shared_secret(sender_pubkey)
        plaintext = peer_verify_and_decrypt(shared_secret, mac_bytes, ciphertext)
        if plaintext is not None:
            return sender_pubkey, peer_name, plaintext
        else:
            log.warning("ANON_REQ MAC mismatch")
    except Exception as e:
        log.error("ANON_REQ decrypt error: %s", e)

    return sender_pubkey, peer_name, None


def try_decode_advert(
    raw_payload: bytes,
) -> tuple[bytes, str, int, tuple[float, float] | None] | None:
    """Decode and verify an ADVERT payload.

    Returns (pubkey, name, node_type, position_or_None) or None on failure.
    node_type: low nibble of app_data flags (1=chat, 2=repeater, 3=room).
    position: (lat, lon) in degrees, or None if advert lacks location.
    """
    if len(raw_payload) < 100:
        return None

    pubkey = raw_payload[0:32]
    timestamp = raw_payload[32:36]
    signature = raw_payload[36:100]
    app_data = raw_payload[100:]

    if not verify_advert_signature(pubkey, timestamp, app_data, signature):
        return None

    name = ""
    node_type = 0
    position: tuple[float, float] | None = None
    if app_data:
        flags = app_data[0]
        node_type = flags & 0x0F
        pos = 1
        if flags & 0x10 and pos + 8 <= len(app_data):  # has location
            lat_i, lon_i = struct.unpack("<ii", app_data[pos : pos + 8])
            position = (lat_i / 1_000_000.0, lon_i / 1_000_000.0)
            pos += 8
        if flags & 0x20:  # feat1
            pos += 2
        if flags & 0x40:  # feat2
            pos += 2
        if flags & 0x80 and pos < len(app_data):  # has name
            name = app_data[pos:].decode("utf-8", errors="replace")

    return pubkey, name if name else pubkey.hex()[:8], node_type, position
