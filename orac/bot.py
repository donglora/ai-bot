"""Main bot loop, packet dispatch, ADVERT scheduling, connection management, CLI."""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, ClassVar

import serial

import donglora as dl
from orac.ai import call_claude, extract_trigger_query, rate_limit_message
from orac.constants import (
    ADVERT_INTERVAL,
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
from orac.meshcore import (
    build_ack_packet,
    build_advert_packet,
    build_dm_packet,
    build_grp_channel_packet,
    build_login_response_packet,
    build_path_return_packet,
    compute_ack_hash,
    get_route,
    has_pending_dms,
    is_dm_duplicate,
    is_duplicate,
    is_pending_expired,
    learn_route,
    lookup_node_by_hash,
    node_name,
    parse_header_and_path,
    pop_pending_dms,
    queue_pending_dm,
    register_node,
    route_name,
    try_decode_advert,
    try_decrypt_anon_req,
    try_decrypt_dm,
    try_decrypt_grp,
)
from orac.state import (
    get_channel_history,
    get_dm_history,
    known_node_count,
    load_state,
    record_channel_msg,
    record_dm_msg,
    save_state,
)

log = logging.getLogger("orac")

# ── Rate limiting (bot-level timers) ─────────────────────────────

_last_response: dict[str, float] = {}
_last_global_response: float = 0.0
_last_rate_limit_reply: dict[str, float] = {}


def _rate_limit_check(key: str) -> bool:
    """Check if we're allowed to respond. Returns True if OK."""
    global _last_global_response
    from orac.constants import RATE_LIMIT_DM, RATE_LIMIT_GLOBAL, RATE_LIMIT_PER_SENDER

    now = time.monotonic()
    if now - _last_global_response < RATE_LIMIT_GLOBAL:
        return False
    limit = RATE_LIMIT_DM if key.startswith("dm:") else RATE_LIMIT_PER_SENDER
    return not (key in _last_response and now - _last_response[key] < limit)


def _rate_limit_reply_ok(key: str) -> bool:
    """Check if we should send a rate-limit reply (not too often)."""
    from orac.constants import RATE_LIMIT_REPLY_COOLDOWN

    now = time.monotonic()
    if (
        key in _last_rate_limit_reply
        and now - _last_rate_limit_reply[key] < RATE_LIMIT_REPLY_COOLDOWN
    ):
        return False
    _last_rate_limit_reply[key] = now
    return True


def _rate_limit_record(key: str) -> None:
    """Record that we just responded."""
    global _last_global_response
    now = time.monotonic()
    _last_response[key] = now
    _last_global_response = now


# ── Transmit helpers ─────────────────────────────────────────────


def _transmit_packet(conn: Any, packet: bytes, label: str = "Transmit") -> None:  # noqa: ARG001
    """Transmit a raw MeshCore packet via the donglora library."""
    try:
        resp = dl.send(conn, "Transmit", payload=packet)
        if resp["type"] == "Timeout":
            log.error("TX failed: no response from radio")
        elif resp["type"] == "Error":
            log.error("TX failed: %s", resp)
    except Exception as e:
        log.error("TX exception: %s", e)


def _send_advert(conn: Any) -> None:
    """Transmit our ADVERT."""
    packet = build_advert_packet()
    log.info("Sending ADVERT as %s (hash=0x%02x)", BOT_NAME, my_hash())
    _transmit_packet(conn, packet, label="ADVERT")


def _grp_transmit(conn: Any, channel_name: str, sender: str, text: str) -> None:
    """Encrypt and transmit a GRP_TXT on a channel."""
    packet = build_grp_channel_packet(channel_name, sender, text)
    if packet is None:
        log.error("TX failed: unknown channel %s", channel_name)
        return
    _transmit_packet(conn, packet)


def _dm_transmit(conn: Any, peer_pubkey: bytes, text: str) -> None:
    """Encrypt and transmit a DM with simulated typing delay."""
    delay = min(max(len(text) * 0.04, 1.0), 5.0)
    time.sleep(delay)
    packet = build_dm_packet(peer_pubkey, text)
    peer = node_name(peer_pubkey.hex())
    route_str = "direct" if get_route(peer_pubkey[0]) else "flood"
    _transmit_packet(conn, packet, label=f"DM({route_str})->{peer}")


def _send_ack(conn: Any, ack_crc: bytes, dest_hash: int) -> None:
    """Send an ACK with a brief delay for the DM flood to clear."""
    time.sleep(0.5)
    packet = build_ack_packet(ack_crc, dest_hash)
    _transmit_packet(conn, packet, label="ACK")


def _send_path_return(
    conn: Any, peer_pubkey: bytes, path_hops: list[bytes], hash_size: int
) -> None:
    """Send a PATH return so the sender can learn a direct route to us."""
    packet = build_path_return_packet(peer_pubkey, path_hops, hash_size)
    _transmit_packet(conn, packet, label="PATH")


def _send_login_response(conn: Any, peer_pubkey: bytes) -> None:
    """Send a login OK response."""
    packet = build_login_response_packet(peer_pubkey)
    _transmit_packet(conn, packet, label=f"LOGIN_RESP->{node_name(peer_pubkey.hex())}")


# ── Pending DM processing ───────────────────────────────────────


def _process_pending_dms(conn: Any, node_hash: int, peer_label: str) -> None:
    """Process queued DMs that were waiting for an ADVERT or ANON_REQ."""
    pending = pop_pending_dms(node_hash)
    if not pending:
        return
    log.info("Processing %d pending DM(s) from %s", len(pending), peer_label)
    for pending_payload, ts in pending:
        if is_pending_expired(ts):
            continue
        dm_result = try_decrypt_dm(pending_payload)
        if dm_result is None:
            continue
        peer_pubkey, peer_name, dm_text, dm_plaintext = dm_result
        pk_hex = peer_pubkey.hex()
        _send_ack(conn, compute_ack_hash(dm_plaintext, peer_pubkey), peer_pubkey[0])
        if is_dm_duplicate(pk_hex, dm_text):
            continue
        log.info("DM(flood) from %s: %s", peer_name, dm_text)
        record_dm_msg(pk_hex, f"{peer_name}: {dm_text}")
        history = get_dm_history(pk_hex)
        response = call_claude(dm_text, peer_name, history, MAX_DM_TEXT, f"DM with {peer_name}")
        if response:
            rt = "direct" if get_route(peer_pubkey[0]) else "flood"
            log.info("<<< DM(%s) %s -> %s: %s", rt, BOT_NAME, peer_name, response)
            _dm_transmit(conn, peer_pubkey, response)
            record_dm_msg(pk_hex, f"{BOT_NAME}: {response}")
            _rate_limit_record(f"dm:{pk_hex}")


# ── Packet dispatch ──────────────────────────────────────────────


def _handle_advert(conn: Any, raw_payload: bytes) -> None:
    """Handle an incoming ADVERT packet."""
    result = try_decode_advert(raw_payload)
    if result is None:
        return
    adv_pubkey, name = result
    if adv_pubkey == pubkey_bytes():
        return  # ignore our own ADVERT echo
    register_node(adv_pubkey, name)
    log.info("ADVERT %s (hash=0x%02x pk=%s...)", name, adv_pubkey[0], adv_pubkey.hex()[:16])

    if has_pending_dms(adv_pubkey[0]):
        _process_pending_dms(conn, adv_pubkey[0], name)


def _handle_grp_txt(conn: Any, raw_payload: bytes) -> None:
    """Handle an incoming GRP_TXT packet."""
    result = try_decrypt_grp(raw_payload)
    if result is None:
        return

    channel_name, text = result
    log.info("GRP_TXT %s %s", channel_name, text)
    record_channel_msg(channel_name, text)

    if ": " not in text:
        return
    sender, _, body = text.partition(": ")
    if sender == BOT_NAME:
        return

    query = extract_trigger_query(body)
    if query is None:
        return

    log.info(">>> Query from %s on %s: %s", sender, channel_name, query)

    rl_key = f"ch:{channel_name}:{sender}"
    if not _rate_limit_check(rl_key):
        log.warning("Rate limited: %s on %s", sender, channel_name)
        if _rate_limit_reply_ok(f"ch:{channel_name}"):
            msg = rate_limit_message()
            log.info("<<< %s: %s", BOT_NAME, msg)
            _grp_transmit(conn, channel_name, BOT_NAME, msg)
            _rate_limit_record(rl_key)
        return

    history = get_channel_history(channel_name)
    response = call_claude(query, sender, history, MAX_RESPONSE_CHARS, f"channel {channel_name}")
    if response is None:
        return

    log.info("<<< %s: %s", BOT_NAME, response)
    _grp_transmit(conn, channel_name, BOT_NAME, response)
    record_channel_msg(channel_name, f"{BOT_NAME}: {response}")
    _rate_limit_record(rl_key)


def _handle_anon_req(
    conn: Any,
    raw_payload: bytes,
    path_hops: list[bytes],
    hash_size: int,
) -> None:
    """Handle an incoming ANON_REQ (login) packet."""
    result = try_decrypt_anon_req(raw_payload)
    if result is None:
        return

    peer_pubkey, peer_name, _plaintext = result

    learn_route(peer_pubkey[0], path_hops, hash_size)

    log.info("LOGIN from %s -- sending login OK", peer_name)
    _send_login_response(conn, peer_pubkey)

    if has_pending_dms(peer_pubkey[0]):
        _process_pending_dms(conn, peer_pubkey[0], peer_name)


def _handle_txt_msg(
    conn: Any,
    raw_payload: bytes,
    route_type: int,
    path_hops: list[bytes],
    hash_size: int,
) -> None:
    """Handle an incoming TXT_MSG (DM) packet."""
    result = try_decrypt_dm(raw_payload)
    if result is None:
        # If addressed to us but sender unknown, queue for later
        if len(raw_payload) >= 4 and raw_payload[0] == my_hash():
            src_hash = raw_payload[1]
            if not lookup_node_by_hash(src_hash):
                is_first = queue_pending_dm(src_hash, raw_payload)
                if is_first:
                    log.info("Queued DM from unknown 0x%02x, waiting for their ADVERT", src_hash)
        return

    peer_pubkey, peer_name, dm_text, raw_plaintext = result

    # Send ACK immediately so the sender stops retrying
    ack_crc = compute_ack_hash(raw_plaintext, peer_pubkey)
    _send_ack(conn, ack_crc, peer_pubkey[0])

    # Send PATH return so sender can learn a direct route to us
    _send_path_return(conn, peer_pubkey, path_hops, hash_size)

    pk_hex = peer_pubkey.hex()

    if is_dm_duplicate(pk_hex, dm_text):
        return

    log.info("DM(%s) from %s: %s", route_name(route_type), peer_name, dm_text)
    record_dm_msg(pk_hex, f"{peer_name}: {dm_text}")

    rl_key = f"dm:{pk_hex}"
    if not _rate_limit_check(rl_key):
        log.warning("Rate limited DM: %s", peer_name)
        return

    history = get_dm_history(pk_hex)
    response = call_claude(dm_text, peer_name, history, MAX_DM_TEXT, f"DM with {peer_name}")
    if response is None:
        return

    rt = "direct" if get_route(peer_pubkey[0]) else "flood"
    log.info("<<< DM(%s) %s -> %s: %s", rt, BOT_NAME, peer_name, response)
    _dm_transmit(conn, peer_pubkey, response)
    record_dm_msg(pk_hex, f"{BOT_NAME}: {response}")
    _rate_limit_record(rl_key)


# ── Bot loop ─────────────────────────────────────────────────────


def bot_loop(conn: Any) -> None:
    """Main receive loop: read packets and dispatch."""
    dl.send(conn, "Ping")
    dl.send(conn, "SetConfig", config=RADIO_CONFIG)
    dl.send(conn, "StartRx")

    _send_advert(conn)
    last_advert = time.monotonic()

    triggers_str = ", ".join(TRIGGERS)
    log.info("%s listening (Ctrl+C to stop)", BOT_NAME)
    log.info("Channels: %d | Triggers: %s | DMs: enabled", channel_count(), triggers_str)
    conn.timeout = 1

    while True:
        # Periodic ADVERT
        now = time.monotonic()
        if now - last_advert >= ADVERT_INTERVAL:
            _send_advert(conn)
            last_advert = now

        pkt = dl.recv(conn)
        if pkt is None:
            continue

        packet: bytes = pkt["payload"]
        parsed = parse_header_and_path(packet)
        if parsed is None:
            continue

        payload_type, route_type, _payload_ver, _pos, raw_payload, path_hops, hash_size = parsed

        # Learn return route from incoming packet's path
        if raw_payload and len(raw_payload) >= 2:
            src_hash: int | None = None
            if payload_type in (0x01, 0x02, 0x08):  # RESPONSE, TXT_MSG, PATH
                src_hash = raw_payload[1]
            elif payload_type == 0x04:  # ADVERT
                src_hash = raw_payload[0]
            if src_hash is not None:
                learn_route(src_hash, path_hops, hash_size)

        # Dedup via packet hash (spec Section 16)
        if is_duplicate(payload_type, raw_payload):
            continue

        # Dispatch by payload type
        if payload_type == 0x03:  # ACK -- ignore (fire-and-forget)
            continue
        elif payload_type == 0x04:  # ADVERT
            _handle_advert(conn, raw_payload)
        elif payload_type == 0x05:  # GRP_TXT
            _handle_grp_txt(conn, raw_payload)
        elif payload_type == 0x07:  # ANON_REQ (login)
            _handle_anon_req(conn, raw_payload, path_hops, hash_size)
        elif payload_type == 0x02:  # TXT_MSG (DM)
            _handle_txt_msg(conn, raw_payload, route_type, path_hops, hash_size)


# ── Logging setup ────────────────────────────────────────────────


class _ColorFormatter(logging.Formatter):
    """Log formatter that adds ANSI colors when stderr is a TTY."""

    _COLORS: ClassVar[dict[int, str]] = {
        logging.DEBUG: "\033[2m",  # dim
        logging.INFO: "\033[32m",  # green
        logging.WARNING: "\033[33m",  # yellow
        logging.ERROR: "\033[31m",  # red
        logging.CRITICAL: "\033[1;31m",  # bold red
    }
    _RESET = "\033[0m"

    def __init__(self, use_color: bool = True) -> None:
        super().__init__(fmt="  %(message)s")
        self._use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if self._use_color:
            color = self._COLORS.get(record.levelno, "")
            return f"{color}{msg}{self._RESET}"
        return msg


def _setup_logging() -> None:
    """Configure the orac logger with colored console output."""
    logger = logging.getLogger("orac")
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_ColorFormatter(use_color=sys.stderr.isatty()))
    logger.addHandler(handler)


# ── Entry point ──────────────────────────────────────────────────


def main() -> None:
    """CLI entry point."""
    _setup_logging()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        log.error("ANTHROPIC_API_KEY environment variable not set")
        sys.exit(1)

    init_identity()
    init_channels()
    load_state()

    log.info("%s -- MeshCore AI Bot", BOT_NAME)
    log.info(
        "Max GRP response: %d chars | Max DM response: %d chars", MAX_RESPONSE_CHARS, MAX_DM_TEXT
    )
    log.info("Channels: %d | Known nodes: %d", channel_count(), known_node_count())

    port = sys.argv[1] if len(sys.argv) > 1 else None

    while True:
        try:
            log.info("Connecting...")
            conn = dl.connect(port=port, timeout=2)
            log.info("Connected")
            bot_loop(conn)
        except (serial.SerialException, ConnectionError, OSError) as e:
            log.error("Disconnected: %s", e)
            log.info("Reconnecting when device reappears...")
            time.sleep(1)
        except KeyboardInterrupt:
            print()
            save_state()
            try:
                conn.timeout = 2  # type: ignore[possibly-undefined]
                dl.send(conn, "StopRx")  # type: ignore[possibly-undefined]
            except Exception:
                pass
            break
