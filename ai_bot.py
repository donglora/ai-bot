#!/usr/bin/env python3
"""Orac: a terse AI assistant on the MeshCore LoRa mesh network.

Monitors all decryptable MeshCore channels for !askai, !ai, !claude, or !orac
triggers. Also accepts direct messages (DMs) — no trigger needed for DMs.
Advertises itself on the mesh and persists state across restarts.
"""
import collections
import csv
import hashlib
import hmac
import json
import os
import random
import struct
import sys
import time

import anthropic
import serial
from cobs import cobs
from Crypto.Cipher import AES
from nacl.bindings import crypto_scalarmult
from nacl.signing import SigningKey, VerifyKey
from pathlib import Path

import donglora as dl


# ── Constants ─────────────────────────────────────────────────────

BOT_NAME = "Orac"
MAX_GRP_TEXT = 163  # max bytes for "SenderName: message" in a GRP_TXT
MAX_RESPONSE_CHARS = MAX_GRP_TEXT - len(BOT_NAME) - 2  # subtract "Orac: "
# DM plaintext: timestamp(4) + txt_type_attempt(1) + text + padding to 16
# Max payload 184 - dst(1) - src(1) - mac(2) = 180 bytes ciphertext
# 180 bytes ciphertext / 16 = 11 blocks → 176 bytes plaintext max
# 176 - 5 (header) = 171 bytes text, minus null terminator padding
MAX_DM_TEXT = 170

TRIGGERS = ("!askai", "!ai", "!claude", "!orac")
AT_MENTIONS = (f"@{BOT_NAME}".lower(), f"@[{BOT_NAME}]".lower())  # "@orac" and "@[Orac]"

CHANNEL_HISTORY_SIZE = 20  # messages per channel
DM_HISTORY_SIZE = 20  # messages per DM peer

RATE_LIMIT_PER_SENDER = 5  # for channel messages
RATE_LIMIT_GLOBAL = 2  # between any two responses
RATE_LIMIT_DM = 2  # for DMs (more interactive)

ADVERT_INTERVAL = 7200  # 2 hours in seconds

DATA_DIR = Path.home() / ".donglora"
KEY_FILE = DATA_DIR / "orac_key.bin"
STATE_FILE = DATA_DIR / "orac_state.json"

RADIO_CONFIG = {
    "freq_hz": 910_525_000,
    "bw": 6,  # 62.5 kHz
    "sf": 7,
    "cr": 5,  # CR 4/5
    "sync_word": 0x3444,
    "tx_power_dbm": -128,  # TX_POWER_MAX
}

SYSTEM_PROMPT = f"""\
You are Orac, a terse AI assistant on a MeshCore LoRa radio mesh network.

ABSOLUTE HARD LIMIT: Your ENTIRE response must be {{max_chars}} characters or fewer.
This is a physical constraint of the radio protocol. Every character beyond this limit
is permanently lost and never transmitted. There is NO exception.

Stay well under {{max_chars}}. Aim for 120 or fewer. NEVER show a character count or HTML tags in your reply.

You can see recent messages for context. When someone asks you a question, they may
be referring to the ongoing conversation — use the chat history to understand what they mean.
For example, "what do you think?" refers to whatever was just discussed. "tell me more" means
elaborate on the recent topic. Read the room.

Rules:
- One sentence or short phrase. Never more.
- Emoji OK but don't overdo it. No markdown, no bullet points, no formatting.
- Use common abbreviations freely (e.g., w/, b/c, approx, etc).
- Skip all pleasantries, greetings, and filler.
- You have a dry, sardonic wit. Be helpful but never wordy.
- If the question requires a long answer, give the most important point only.
- NEVER repeat a previous answer. Always find a fresh angle, new phrasing, or different take.
- Be creative and unpredictable. Surprise the reader.\
"""

# ── ANSI helpers ──────────────────────────────────────────────────

RST = "\033[0m"
DIM = "\033[2m"
RED = "\033[31m"
GRN = "\033[32m"
YEL = "\033[33m"
CYN = "\033[36m"
BCYN = "\033[1;36m"
BGRN = "\033[1;32m"
BMAG = "\033[1;35m"
BWHT = "\033[1;37m"


# ── Persistent state ─────────────────────────────────────────────

_state: dict = {
    "channel_history": {},  # channel_name → list of messages
    "dm_history": {},  # peer_pubkey_hex → list of messages
    "known_nodes": {},  # pubkey_hex → {"name": str, "seen": float}
}


def _load_state():
    global _state
    if STATE_FILE.is_file():
        try:
            with open(STATE_FILE) as f:
                loaded = json.load(f)
            # Merge with defaults
            for key in _state:
                if key in loaded:
                    _state[key] = loaded[key]
            print(f"  {DIM}Loaded state from {STATE_FILE}{RST}")
        except Exception as e:
            print(f"  {YEL}Failed to load state: {e}{RST}")


def _save_state():
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(_state, f, indent=2)
        tmp.rename(STATE_FILE)
    except Exception as e:
        print(f"  {RED}Failed to save state: {e}{RST}")


# ── Identity / Keypair ───────────────────────────────────────────

_signing_key: SigningKey | None = None
_verify_key: VerifyKey | None = None
_pubkey_bytes: bytes = b""


def _init_identity():
    """Load or generate Ed25519 keypair. Persisted to disk."""
    global _signing_key, _verify_key, _pubkey_bytes

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if KEY_FILE.is_file():
        seed = KEY_FILE.read_bytes()
        if len(seed) == 32:
            _signing_key = SigningKey(seed)
            print(f"  {DIM}Loaded keypair from {KEY_FILE}{RST}")
        else:
            print(f"  {YEL}Invalid key file, regenerating{RST}")
            _signing_key = SigningKey.generate()
            KEY_FILE.write_bytes(bytes(_signing_key))
    else:
        _signing_key = SigningKey.generate()
        KEY_FILE.write_bytes(bytes(_signing_key))
        print(f"  {BWHT}Generated new keypair → {KEY_FILE}{RST}")

    _verify_key = _signing_key.verify_key
    _pubkey_bytes = bytes(_verify_key)
    print(f"  {DIM}Pubkey: {_pubkey_bytes.hex()}{RST}")
    print(f"  {DIM}Node hash: 0x{_pubkey_bytes[0]:02x}{RST}")


def _my_hash() -> int:
    """Our 1-byte node hash (first byte of pubkey)."""
    return _pubkey_bytes[0]


# ── MeshCore channel crypto ──────────────────────────────────────


def _channel_secret_from_hashtag(name: str) -> bytes:
    h = hashlib.sha256(name.encode()).digest()
    return h[:16] + b"\x00" * 16


def _channel_hash(secret: bytes) -> int:
    key_len = 16 if secret[16:] == b"\x00" * 16 else 32
    return hashlib.sha256(secret[:key_len]).digest()[0]


def _grp_verify_and_decrypt(
    secret: bytes, mac_bytes: bytes, ciphertext: bytes
) -> bytes | None:
    key_len = 32  # HMAC always uses full 32-byte secret (spec Section 14)
    computed = hmac.new(secret[:key_len], ciphertext, hashlib.sha256).digest()[:2]
    if computed != mac_bytes:
        return None
    cipher = AES.new(secret[:16], AES.MODE_ECB)
    plaintext = b""
    for i in range(0, len(ciphertext), 16):
        plaintext += cipher.decrypt(ciphertext[i : i + 16])
    return plaintext


def _parse_grp_plaintext(plaintext: bytes) -> tuple[int, str] | None:
    if len(plaintext) < 5:
        return None
    timestamp = struct.unpack_from("<I", plaintext, 0)[0]
    text = plaintext[5:].split(b"\x00", 1)[0]
    return timestamp, text.decode("utf-8", errors="replace")


# ── Peer-to-peer (DM) crypto ────────────────────────────────────


def _ecdh_shared_secret(peer_ed25519_pub: bytes) -> bytes:
    """Compute X25519 shared secret from our Ed25519 key and peer's Ed25519 pubkey."""
    my_x25519 = bytes(_signing_key.to_curve25519_private_key())
    peer_verify = VerifyKey(peer_ed25519_pub)
    peer_x25519 = bytes(peer_verify.to_curve25519_public_key())
    return crypto_scalarmult(my_x25519, peer_x25519)


def _peer_encrypt(shared_secret: bytes, text: str) -> bytes:
    """Encrypt a DM plaintext. Returns mac(2) + ciphertext."""
    plaintext = struct.pack("<I", int(time.time())) + b"\x00"
    plaintext += text.encode("utf-8") + b"\x00"
    pad_len = (16 - len(plaintext) % 16) % 16
    plaintext += b"\x00" * pad_len
    cipher = AES.new(shared_secret[:16], AES.MODE_ECB)
    ciphertext = b""
    for i in range(0, len(plaintext), 16):
        ciphertext += cipher.encrypt(plaintext[i : i + 16])
    mac = hmac.new(shared_secret[:32], ciphertext, hashlib.sha256).digest()[:2]
    return mac + ciphertext


def _peer_verify_and_decrypt(shared_secret: bytes, mac_bytes: bytes, ciphertext: bytes) -> bytes | None:
    """Verify MAC then decrypt a peer message. Returns plaintext or None."""
    computed = hmac.new(shared_secret[:32], ciphertext, hashlib.sha256).digest()[:2]
    if computed != mac_bytes:
        return None
    cipher = AES.new(shared_secret[:16], AES.MODE_ECB)
    plaintext = b""
    for i in range(0, len(ciphertext), 16):
        plaintext += cipher.decrypt(ciphertext[i : i + 16])
    return plaintext


def _parse_peer_plaintext(plaintext: bytes) -> str | None:
    """Parse decrypted peer message: timestamp(4) + txt_type_attempt(1) + text."""
    if len(plaintext) < 5:
        return None
    text = plaintext[5:].split(b"\x00", 1)[0]
    return text.decode("utf-8", errors="replace") if text else None


# ── Node registry ────────────────────────────────────────────────

# pubkey_hex → {"name": str, "seen": float}
# Stored in _state["known_nodes"], persisted to disk

ADVERT_MAX_AGE = 43200  # 12 hours — used for display, NOT for key expiry

# Pending DMs from unknown senders — queued until we learn their pubkey via ADVERT
# src_hash → list of (raw_payload, monotonic_timestamp)
_pending_dms: dict[int, list[tuple[bytes, float]]] = {}
PENDING_DM_TTL = 300  # 5 minutes — discard stale pending DMs

# ── Route table ─────────────────────────────────────────────────
# Learned return paths from incoming packets.
# src_hash (int) → (reversed_path_hops: list[bytes], hash_size: int)
_route_table: dict[int, tuple[list[bytes], int]] = {}


def _learn_route(src_hash: int, path_hops: list[bytes], hash_size: int):
    """Learn a return route from an incoming packet's path.

    path_hops is ordered closest-relay-first as received.
    We reverse it so our outgoing path goes through the same relays
    back toward the sender. Always updates the route, but prefers
    larger hash sizes (3 > 2 > 1) for better addressing precision.
    """
    existing = _route_table.get(src_hash)
    if existing is not None:
        _, existing_hs = existing
        if hash_size < existing_hs:
            return  # Don't downgrade hash size
    _route_table[src_hash] = (list(reversed(path_hops)), hash_size)


def _get_route(dest_hash: int) -> tuple[list[bytes], int] | None:
    """Get a learned return route for a destination, or None if unknown."""
    return _route_table.get(dest_hash)


_RT_NAMES = {0: "tflood", 1: "flood", 2: "direct", 3: "tdirect"}


def _route_name(route_type: int) -> str:
    return _RT_NAMES.get(route_type, f"rt{route_type}")


def _register_node(pubkey: bytes, name: str) -> bool:
    """Register a node. Returns True if this is a NEW node (not just an update)."""
    pk_hex = pubkey.hex()
    is_new = pk_hex not in _state["known_nodes"]
    _state["known_nodes"][pk_hex] = {"name": name, "seen": time.time()}
    _save_state()
    return is_new


def _lookup_node_by_hash(hash_byte: int) -> list[tuple[bytes, str]]:
    """Find all known nodes whose pubkey first byte matches. Returns [(pubkey, name)].

    Never expires keys — once we learn a peer's pubkey, we can always decrypt
    their DMs. Peers shouldn't need to re-advertise just to message the bot.
    """
    results = []
    for pk_hex, info in _state["known_nodes"].items():
        pk_bytes = bytes.fromhex(pk_hex)
        if pk_bytes[0] == hash_byte:
            results.append((pk_bytes, info["name"]))
    return results


def _node_name(pubkey_hex: str) -> str:
    info = _state["known_nodes"].get(pubkey_hex)
    return info["name"] if info else pubkey_hex[:8]


# ── Channel registry ─────────────────────────────────────────────

_KNOWN_CHANNELS: dict[str, bytes] = {}
_CHANNEL_BY_HASH: dict[int, list[tuple[str, bytes]]] = {}


def _register_channel(name: str, secret: bytes):
    _KNOWN_CHANNELS[name] = secret
    h = _channel_hash(secret)
    _CHANNEL_BY_HASH.setdefault(h, []).append((name, secret))


_CHANNELS_CSV = Path(__file__).parent / "channels.csv"


def _init_channels():
    if _CHANNELS_CSV.is_file():
        with open(_CHANNELS_CSV, newline="") as f:
            for row in csv.DictReader(f):
                name = row["channel_name"]
                is_hashtag = row["hashtag"].strip().lower() == "true"
                key_hex = row["key_hex"].strip()
                if is_hashtag:
                    secret = _channel_secret_from_hashtag(name)
                else:
                    secret = bytes.fromhex(key_hex) + b"\x00" * 16
                _register_channel(name, secret)
    else:
        print(f"  {RED}channels.csv not found at {_CHANNELS_CSV}{RST}")

    for name in ("#devtest", "#devtestdevtest", "#askai", "#orac", "#ai", "#aibot", "#aibots"):
        _register_channel(name, _channel_secret_from_hashtag(name))


_init_channels()


# ── GRP_TXT encrypt + transmit ───────────────────────────────────


def _grp_encrypt(secret: bytes, sender: str, text: str) -> bytes:
    ch = _channel_hash(secret)
    plaintext = struct.pack("<I", int(time.time())) + b"\x00"
    plaintext += f"{sender}: {text}\x00".encode("utf-8")[:MAX_GRP_TEXT]
    pad_len = (16 - len(plaintext) % 16) % 16
    plaintext += b"\x00" * pad_len
    cipher = AES.new(secret[:16], AES.MODE_ECB)
    ciphertext = b""
    for i in range(0, len(plaintext), 16):
        ciphertext += cipher.encrypt(plaintext[i : i + 16])
    key_len = 32  # HMAC always uses full 32-byte secret (spec Section 14)
    mac = hmac.new(secret[:key_len], ciphertext, hashlib.sha256).digest()[:2]
    return bytes([ch]) + mac + ciphertext


def _grp_build_packet(channel_payload: bytes) -> bytes:
    header = bytes([0x15])  # GRP_TXT flood: (5 << 2) | 1
    path_len = bytes([0x40])  # 0 hops, 2-byte hash mode
    return header + path_len + channel_payload


def _transmit_packet(ser: serial.Serial, packet: bytes, label: str = "Transmit"):
    """Transmit a raw MeshCore packet."""
    try:
        resp = send_cmd(ser, {"type": "Transmit", "payload": packet}, label=label)
        if resp is None:
            print(f"  {RED}TX failed: no response from radio{RST}")
        elif resp["type"] == "Error":
            print(f"  {RED}TX failed: {resp}{RST}")
    except Exception as e:
        print(f"  {RED}TX exception: {e}{RST}")


def _grp_transmit(ser: serial.Serial, channel_name: str, sender: str, text: str):
    secret = _KNOWN_CHANNELS.get(channel_name)
    if secret is None:
        print(f"  {RED}TX failed: unknown channel {channel_name}{RST}")
        return
    payload = _grp_encrypt(secret, sender, text)
    packet = _grp_build_packet(payload)
    _transmit_packet(ser, packet)


# ── ADVERT construction + transmit ───────────────────────────────


def _build_advert_packet() -> bytes:
    """Build a MeshCore ADVERT packet for this node."""
    timestamp = struct.pack("<I", int(time.time()))

    # App data: flags(1) + name(UTF-8, no null terminator)
    # flags: 0x81 = node_type=chat(1) + has_name(bit 7)
    app_data = bytes([0x81]) + BOT_NAME.encode("utf-8")

    # Message to sign: pubkey + timestamp + app_data
    sign_msg = _pubkey_bytes + timestamp + app_data
    signed = _signing_key.sign(sign_msg)
    signature = signed.signature  # 64 bytes

    # ADVERT payload: pubkey(32) + timestamp(4) + signature(64) + app_data
    advert_payload = _pubkey_bytes + timestamp + signature + app_data

    # Wrap in MeshCore packet
    header = bytes([0x11])  # ADVERT flood: (4 << 2) | 1
    path_len = bytes([0x40])  # 0 hops, 2-byte hash mode
    return header + path_len + advert_payload


def _send_advert(ser: serial.Serial):
    """Transmit our ADVERT."""
    packet = _build_advert_packet()
    print(f"  {BCYN}Sending ADVERT as {BOT_NAME} (hash=0x{_my_hash():02x}){RST}")
    _transmit_packet(ser, packet, label="ADVERT")


# ── DM transmit ──────────────────────────────────────────────────


def _build_routed_packet(payload_type: int, payload: bytes, dest_hash: int) -> bytes:
    """Build a packet using a learned route if available, otherwise flood."""
    route = _get_route(dest_hash)
    if route is not None:
        hops, hash_size = route
        hash_size_code = hash_size - 1
        path_len_byte = (hash_size_code << 6) | (len(hops) & 0x3F)
        path_data = b"".join(hops)
        # direct route_type = 2
        header = bytes([(payload_type << 2) | 2])
        return header + bytes([path_len_byte]) + path_data + payload
    else:
        # flood route_type = 1
        header = bytes([(payload_type << 2) | 1])
        path_len = bytes([0x40])  # 0 hops, 2-byte hash mode
        return header + path_len + payload


def _dm_transmit(ser: serial.Serial, peer_pubkey: bytes, text: str):
    """Encrypt and transmit a TXT_MSG DM using learned route or flood."""
    # Simulate human typing delay (~40ms/char, clamped to 1–5s)
    delay = min(max(len(text) * 0.04, 1.0), 5.0)
    time.sleep(delay)
    shared_secret = _ecdh_shared_secret(peer_pubkey)
    mac_ct = _peer_encrypt(shared_secret, text)

    # Payload: dest_hash(1) + src_hash(1) + mac(2) + ciphertext
    dm_payload = bytes([peer_pubkey[0], _my_hash()]) + mac_ct

    packet = _build_routed_packet(0x02, dm_payload, peer_pubkey[0])

    peer_name = _node_name(peer_pubkey.hex())
    route = _get_route(peer_pubkey[0])
    route_str = "direct" if route is not None else "flood"
    _transmit_packet(ser, packet, label=f"DM({route_str})\u2192{peer_name}")


# ── ACK transmit ─────────────────────────────────────────────────


def _compute_ack_hash(plaintext: bytes, sender_pubkey: bytes) -> bytes:
    """Compute 4-byte ACK hash per MeshCore BaseChatMesh.cpp.

    Hash = SHA-256(frag1 || sender_pubkey)[0:4]
    frag1 = timestamp(4) + txt_type_attempt(1) + text (no null terminator)
    sender_pubkey = sender's Ed25519 public key (32 bytes)
    """
    text_bytes = plaintext[5:]
    null_pos = text_bytes.find(b"\x00")
    text_len = null_pos if null_pos >= 0 else len(text_bytes)
    frag1 = plaintext[: 5 + text_len]
    return hashlib.sha256(frag1 + sender_pubkey).digest()[:4]


def _send_ack(ser: serial.Serial, ack_crc: bytes, dest_hash: int):
    """Send an ACK using learned route or flood, with a brief delay for the DM flood to clear."""
    time.sleep(0.5)
    packet = _build_routed_packet(0x03, ack_crc, dest_hash)
    _transmit_packet(ser, packet, label="ACK")


def _send_path_return(ser: serial.Serial, peer_pubkey: bytes, path_hops: list[bytes], hash_size: int):
    """Send a PATH return (0x08) so the sender can learn a direct route to us.

    Per spec Section 9: inner plaintext = path_len(1) + path + extra_type(1) + extra.
    The path is reversed (our incoming path becomes the sender's outgoing path).
    """
    reversed_hops = list(reversed(path_hops))
    hash_size_code = hash_size - 1
    path_len_byte = (hash_size_code << 6) | (len(reversed_hops) & 0x3F)
    path_data = b"".join(reversed_hops)

    # Inner plaintext: path_len + path + 0xFF (dummy extra) + 4 random bytes
    inner = bytes([path_len_byte]) + path_data + b"\xff" + os.urandom(4)
    pad_len = (16 - len(inner) % 16) % 16
    inner += b"\x00" * pad_len

    shared_secret = _ecdh_shared_secret(peer_pubkey)
    cipher = AES.new(shared_secret[:16], AES.MODE_ECB)
    ciphertext = b""
    for i in range(0, len(inner), 16):
        ciphertext += cipher.encrypt(inner[i : i + 16])
    mac = hmac.new(shared_secret[:32], ciphertext, hashlib.sha256).digest()[:2]

    # Outer: dest_hash + src_hash + mac + ciphertext
    path_payload = bytes([peer_pubkey[0], _my_hash()]) + mac + ciphertext
    packet = _build_routed_packet(0x08, path_payload, peer_pubkey[0])
    _transmit_packet(ser, packet, label="PATH")


# ── Serial / USB ─────────────────────────────────────────────────


def open_connection(port: str | None = None):
    """Open a DongLoRa connection (mux auto-detected, falls back to USB)."""
    return dl.connect(port=port, timeout=2)


# ── COBS framing ─────────────────────────────────────────────────


def cobs_frame(payload: bytes) -> bytes:
    return cobs.encode(payload) + b"\x00"


def read_frame(ser: serial.Serial) -> bytes | None:
    buf = b""
    while True:
        b = ser.read(1)
        if not b:
            return None
        if b == b"\x00":
            break
        buf += b
    if not buf:
        return None
    try:
        return cobs.decode(buf)
    except cobs.DecodeError:
        return None


# ── Command encoding / response decoding ─────────────────────────


def encode_radio_config(cfg: dict) -> bytes:
    return struct.pack(
        "<IBBBHBHB",
        cfg["freq_hz"],
        cfg["bw"],
        cfg["sf"],
        cfg["cr"],
        cfg["sync_word"],
        cfg["tx_power_dbm"] & 0xFF,
        cfg.get("preamble_len", 0),
        cfg.get("cad", 1),
    )


def encode_command(cmd: dict) -> bytes:
    kind = cmd["type"]
    tags = {
        "Ping": 0, "GetConfig": 1, "SetConfig": 2, "StartRx": 3,
        "StopRx": 4, "Transmit": 5, "DisplayOn": 6, "DisplayOff": 7,
    }
    out = bytes([tags[kind]])
    if kind == "SetConfig":
        out += encode_radio_config(cmd["config"])
    elif kind == "Transmit":
        config = cmd.get("config")
        if config is None:
            out += b"\x00"
        else:
            out += b"\x01" + encode_radio_config(config)
        payload = cmd["payload"]
        out += struct.pack("<H", len(payload)) + payload
    return out


def decode_response(data: bytes) -> dict:
    if not data:
        return {"type": "Empty"}
    tag = data[0]
    rest = data[1:]
    if tag == 0:
        return {"type": "Pong"}
    elif tag == 1:
        return {"type": "Config", "raw": rest.hex()}
    elif tag == 2:
        rssi = struct.unpack_from("<h", rest, 0)[0]
        snr = struct.unpack_from("<h", rest, 2)[0]
        plen = struct.unpack_from("<H", rest, 4)[0]
        payload = rest[6 : 6 + plen]
        return {"type": "RxPacket", "rssi": rssi, "snr": snr, "payload": payload}
    elif tag == 3:
        return {"type": "TxDone"}
    elif tag == 4:
        return {"type": "Ok"}
    elif tag == 5:
        code = rest[0] if rest else -1
        return {"type": "Error", "code": code}
    else:
        return {"type": f"Unknown({tag})", "raw": rest.hex()}


def send_cmd(
    ser: serial.Serial, cmd: dict, label: str = "", quiet: bool = False
) -> dict | None:
    payload = encode_command(cmd)
    frame = cobs_frame(payload)
    if not quiet:
        print(f"  {DIM}>>>{RST} {label}")
    ser.write(frame)
    ser.flush()
    for _ in range(50):
        resp_data = read_frame(ser)
        if resp_data is None:
            if not quiet:
                print(f"  {DIM}<<<{RST} {YEL}timeout{RST}")
            return None
        resp = decode_response(resp_data)
        if resp["type"] == "RxPacket":
            continue
        if not quiet:
            t = resp["type"]
            print(f"  {DIM}<<<{RST} {t}")
        return resp
    if not quiet:
        print(f"  {DIM}<<<{RST} {YEL}timeout (RxPacket flood){RST}")
    return None


# ── Claude API ───────────────────────────────────────────────────

_client: anthropic.Anthropic | None = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic()
    return _client


def _shorten_with_claude(text: str, max_chars: int) -> str:
    try:
        resp = _get_client().messages.create(
            model="claude-sonnet-4-6",
            max_tokens=256,
            messages=[
                {
                    "role": "user",
                    "content": f"Shorten this to {max_chars} characters: {text}",
                }
            ],
        )
        shortened = resp.content[0].text.strip()
    except Exception as e:
        print(f"  {RED}Shorten API error: {e}{RST}")
        shortened = text
    encoded = shortened.encode("utf-8")
    if len(encoded) > max_chars:
        while len(shortened.encode("utf-8")) > max_chars - 1:
            shortened = shortened[:-1]
        shortened += "…"
    return shortened


def _extract_text(resp) -> str:
    text = ""
    for block in resp.content:
        if block.type == "text" and block.text.strip():
            text = block.text.strip()
    return text


def call_claude(query: str, sender: str, history: list[str], max_chars: int, context_label: str) -> str | None:
    """Send a query to Claude with conversation context. Returns response text or None."""
    try:
        nonce = random.randint(1000, 9999)
        now = time.strftime("%Y-%m-%d %H:%M %Z")
        prompt = SYSTEM_PROMPT.replace("{max_chars}", str(max_chars)) + f"\n\nCurrent date/time: {now}"

        if history:
            context = "\n".join(history)
            user_content = (
                f"[seed:{nonce}]\n"
                f"Recent messages in {context_label}:\n{context}\n\n"
                f"{sender} says: {query}"
            )
        else:
            user_content = f"[seed:{nonce}] {sender} says: {query}"

        messages = [{"role": "user", "content": user_content}]
        tools = [{"type": "web_search_20260209", "name": "web_search"}]

        text = ""
        for round_num in range(3):
            resp = _get_client().messages.create(
                model="claude-sonnet-4-6",
                max_tokens=4096,
                temperature=1.0,
                system=prompt,
                tools=tools,
                messages=messages,
            )

            text = _extract_text(resp)
            if text:
                break

            if resp.stop_reason != "tool_use":
                block_types = [b.type for b in resp.content]
                print(f"  {YEL}No text, stop={resp.stop_reason}, blocks={block_types}{RST}")
                break

            print(f"  {DIM}(web search round {round_num + 1})...{RST}")
            messages.append({"role": "assistant", "content": resp.content})
            tool_results = []
            for block in resp.content:
                if hasattr(block, "id") and block.type == "server_tool_use":
                    tool_results.append(
                        {"type": "tool_result", "tool_use_id": block.id, "content": ""}
                    )
            if tool_results:
                messages.append({"role": "user", "content": tool_results})
            else:
                break

        if not text:
            print(f"  {YEL}No text after tool loop{RST}")
            return None
    except Exception as e:
        print(f"  {RED}Claude API error: {e}{RST}")
        return None

    if len(text.encode("utf-8")) > max_chars:
        print(f"  {YEL}Response too long ({len(text.encode('utf-8'))}B), shortening...{RST}")
        text = _shorten_with_claude(text, max_chars)

    return text


def _rate_limit_message() -> str:
    try:
        nonce = random.randint(1000, 9999)
        resp = _get_client().messages.create(
            model="claude-sonnet-4-6",
            max_tokens=100,
            temperature=1.0,
            system=(
                f"You are Orac, a sardonic AI on a radio mesh network. "
                f"Generate a single short message ({MAX_RESPONSE_CHARS} chars max, ASCII only) "
                f"telling someone to slow down and try again in a few seconds. "
                f"Be witty, varied, and in-character. No quotes around the message."
            ),
            messages=[
                {"role": "user", "content": f"[seed:{nonce}] Rate limit hit."}
            ],
        )
        text = resp.content[0].text.strip().strip('"\'')
        if len(text.encode("utf-8")) <= MAX_RESPONSE_CHARS and text:
            return text
    except Exception:
        pass
    return "Patience. Try again in a moment."


# ── Trigger detection ────────────────────────────────────────────


def _extract_trigger_query(text: str) -> str | None:
    """Check for !triggers and @mentions. Returns the query (everything except the trigger) or None."""
    lower = text.lower()
    for trigger in (*TRIGGERS, *AT_MENTIONS):
        idx = lower.find(trigger)
        if idx != -1:
            before = text[:idx]
            after = text[idx + len(trigger) :]
            query = (before + " " + after).strip()
            if query:
                return query
    return None


# ── Packet parsing helpers ───────────────────────────────────────


def _parse_header_and_path(packet: bytes) -> tuple[int, int, int, int, bytes, list[bytes], int] | None:
    """Parse MeshCore header + path.

    Returns (payload_type, route_type, payload_ver, pos, payload, path_hops, hash_size) or None.
    path_hops is a list of raw hash bytes for each hop (closest relay first).
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

    for skip_tc in ([True, False] if has_tc else [False]):
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

        hops = []
        for i in range(hop_count):
            hops.append(packet[pos + i * hash_size : pos + (i + 1) * hash_size])
        pos += path_bytes

        payload = packet[pos:]
        if payload and len(payload) <= 184:
            return payload_type, route_type, payload_ver, pos, payload, hops, hash_size

    return None


# ── GRP_TXT interception ────────────────────────────────────────


def _try_decrypt_grp(raw_payload: bytes) -> tuple[str, str] | None:
    if len(raw_payload) < 19:
        return None
    ch = raw_payload[0]
    mac_bytes = raw_payload[1:3]
    ciphertext = raw_payload[3:]

    candidates = _CHANNEL_BY_HASH.get(ch, [])
    for chan_name, secret in candidates:
        plaintext = _grp_verify_and_decrypt(secret, mac_bytes, ciphertext)
        if plaintext is not None:
            parsed = _parse_grp_plaintext(plaintext)
            if parsed:
                _, text = parsed
                return chan_name, text
    return None


# ── DM interception ──────────────────────────────────────────────


def _try_decrypt_dm(raw_payload: bytes) -> tuple[bytes, str, str, bytes] | None:
    """Try to decrypt a TXT_MSG DM addressed to us.

    Returns (sender_pubkey, sender_name, message_text, raw_plaintext) or None.
    raw_plaintext is needed for ACK hash computation.
    """
    if len(raw_payload) < 20:
        return None

    dest_hash = raw_payload[0]
    src_hash = raw_payload[1]
    mac_bytes = raw_payload[2:4]
    ciphertext = raw_payload[4:]

    print(f"  {DIM}TXT_MSG dest=0x{dest_hash:02x} src=0x{src_hash:02x} me=0x{_my_hash():02x} [{len(ciphertext)}B]{RST}")

    if dest_hash != _my_hash():
        return None

    candidates = _lookup_node_by_hash(src_hash)
    if not candidates:
        print(f"  {YEL}DM for us but no known node with hash 0x{src_hash:02x}{RST}")
        return None

    for peer_pubkey, peer_name in candidates:
        try:
            shared_secret = _ecdh_shared_secret(peer_pubkey)
            plaintext = _peer_verify_and_decrypt(shared_secret, mac_bytes, ciphertext)
            if plaintext is not None:
                text = _parse_peer_plaintext(plaintext)
                if text:
                    return peer_pubkey, peer_name, text, plaintext
        except Exception:
            # ECDH failed — pubkey is likely corrupted (bad ADVERT). Evict it.
            pk_hex = peer_pubkey.hex()
            print(f"  {YEL}Evicting bad key for {peer_name} ({pk_hex[:16]}...){RST}")
            _state["known_nodes"].pop(pk_hex, None)
            _save_state()
            continue

    return None


RESP_SERVER_LOGIN_OK = 0x01


def _try_decrypt_anon_req(raw_payload: bytes) -> tuple[bytes, str, bytes | None] | None:
    """Try to decrypt an ANON_REQ (login). Returns (sender_pubkey, sender_name, plaintext_or_None) or None."""
    if len(raw_payload) < 51:
        return None

    dest_hash = raw_payload[0]
    sender_pubkey = raw_payload[1:33]
    mac_bytes = raw_payload[33:35]
    ciphertext = raw_payload[35:]

    print(f"  {BCYN}ANON_REQ{RST} dest=0x{dest_hash:02x} sender={sender_pubkey.hex()[:16]}... [{len(ciphertext)}B]")

    if dest_hash != _my_hash():
        return None

    # Register sender — we now have their full pubkey
    peer_name = _node_name(sender_pubkey.hex())
    is_new = _register_node(sender_pubkey, peer_name)
    if is_new:
        print(f"  {BCYN}Registered new peer from ANON_REQ: {peer_name} (hash=0x{sender_pubkey[0]:02x}){RST}")

    try:
        shared_secret = _ecdh_shared_secret(sender_pubkey)
        plaintext = _peer_verify_and_decrypt(shared_secret, mac_bytes, ciphertext)
        if plaintext is not None:
            return sender_pubkey, peer_name, plaintext
        else:
            print(f"  {YEL}ANON_REQ MAC mismatch{RST}")
    except Exception as e:
        print(f"  {RED}ANON_REQ decrypt error: {e}{RST}")

    # Even if decryption failed, we registered the pubkey — return with no plaintext
    return sender_pubkey, peer_name, None


def _send_login_response(ser: serial.Serial, peer_pubkey: bytes):
    """Send a RESPONSE packet (login OK) back to the peer, like a room server."""
    shared_secret = _ecdh_shared_secret(peer_pubkey)

    # Response payload: timestamp(4) + RESP_SERVER_LOGIN_OK(1) + zero(1) + permissions(2)
    reply = struct.pack("<I", int(time.time()))
    reply += bytes([RESP_SERVER_LOGIN_OK, 0x00, 0x00, 0xFF])  # OK, no flags, no admin, full perms

    # Encrypt
    mac_ct = _peer_encrypt(shared_secret, "")  # we'll build raw plaintext instead
    # Actually, build the raw plaintext manually (not a text message)
    plaintext = reply
    pad_len = (16 - len(plaintext) % 16) % 16
    plaintext += b"\x00" * pad_len
    cipher = AES.new(shared_secret[:16], AES.MODE_ECB)
    ciphertext = b""
    for i in range(0, len(plaintext), 16):
        ciphertext += cipher.encrypt(plaintext[i : i + 16])
    mac = hmac.new(shared_secret[:32], ciphertext, hashlib.sha256).digest()[:2]

    # RESPONSE packet: dest_hash(1) + src_hash(1) + mac(2) + ciphertext
    resp_payload = bytes([peer_pubkey[0], _my_hash()]) + mac + ciphertext

    packet = _build_routed_packet(0x01, resp_payload, peer_pubkey[0])

    _transmit_packet(ser, packet, label=f"LOGIN_RESP→{_node_name(peer_pubkey.hex())}")


# ── ADVERT decoding ──────────────────────────────────────────────


def _try_decode_advert(raw_payload: bytes) -> tuple[bytes, str] | None:
    """Decode and verify an ADVERT payload. Returns (pubkey, name) or None."""
    if len(raw_payload) < 100:
        return None

    pubkey = raw_payload[0:32]
    timestamp = raw_payload[32:36]
    signature = raw_payload[36:100]
    app_data = raw_payload[100:]

    # Verify Ed25519 signature to reject corrupted ADVERTs
    try:
        verify_key = VerifyKey(pubkey)
        sign_msg = pubkey + timestamp + app_data
        verify_key.verify(sign_msg, signature)
    except Exception:
        return None

    name = ""
    if app_data:
        flags = app_data[0]
        pos = 1
        if flags & 0x10:  # has location
            pos += 8
        if flags & 0x20:  # feat1
            pos += 2
        if flags & 0x40:  # feat2
            pos += 2
        if flags & 0x80 and pos < len(app_data):  # has name
            name = app_data[pos:].decode("utf-8", errors="replace")

    return pubkey, name if name else pubkey.hex()[:8]


# ── Deduplication ────────────────────────────────────────────────

DEDUP_TTL = 120
_seen_packets: dict[bytes, float] = {}

# DM dedup on decrypted text (catches retries with different attempt counters)
DM_DEDUP_TTL = 60
_seen_dm_texts: dict[str, float] = {}  # "pubkey_hex:text" → monotonic timestamp


def _compute_packet_hash(payload_type: int, payload: bytes) -> bytes:
    """Compute 8-byte packet hash per spec Section 16."""
    return hashlib.sha256(bytes([payload_type]) + payload).digest()[:8]


def _is_duplicate(payload_type: int, payload: bytes) -> bool:
    """Dedup via 8-byte packet hash (spec Section 16)."""
    now = time.monotonic()
    if len(_seen_packets) > 500:
        expired = [k for k, t in _seen_packets.items() if now - t > DEDUP_TTL]
        for k in expired:
            del _seen_packets[k]

    pkt_hash = _compute_packet_hash(payload_type, payload)
    if pkt_hash in _seen_packets and now - _seen_packets[pkt_hash] < DEDUP_TTL:
        return True
    _seen_packets[pkt_hash] = now
    return False


def _is_dm_duplicate(peer_pubkey_hex: str, text: str) -> bool:
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


# ── History (persistent) ────────────────────────────────────────


def _record_channel_msg(channel: str, text: str):
    hist = _state["channel_history"]
    if channel not in hist:
        hist[channel] = []
    hist[channel].append(text)
    # Trim to max size
    if len(hist[channel]) > CHANNEL_HISTORY_SIZE:
        hist[channel] = hist[channel][-CHANNEL_HISTORY_SIZE:]
    _save_state()


def _get_channel_history(channel: str) -> list[str]:
    return list(_state["channel_history"].get(channel, []))


def _record_dm_msg(peer_pubkey_hex: str, text: str):
    hist = _state["dm_history"]
    if peer_pubkey_hex not in hist:
        hist[peer_pubkey_hex] = []
    hist[peer_pubkey_hex].append(text)
    if len(hist[peer_pubkey_hex]) > DM_HISTORY_SIZE:
        hist[peer_pubkey_hex] = hist[peer_pubkey_hex][-DM_HISTORY_SIZE:]
    _save_state()


def _get_dm_history(peer_pubkey_hex: str) -> list[str]:
    return list(_state["dm_history"].get(peer_pubkey_hex, []))


# ── Rate limiting ────────────────────────────────────────────────

_last_response: dict[str, float] = {}
_last_global_response = 0.0
_last_rate_limit_reply: dict[str, float] = {}
RATE_LIMIT_REPLY_COOLDOWN = 30


def _rate_limit_check(key: str) -> bool:
    global _last_global_response
    now = time.monotonic()
    if now - _last_global_response < RATE_LIMIT_GLOBAL:
        return False
    limit = RATE_LIMIT_DM if key.startswith("dm:") else RATE_LIMIT_PER_SENDER
    if key in _last_response and now - _last_response[key] < limit:
        return False
    return True


def _rate_limit_reply_ok(key: str) -> bool:
    now = time.monotonic()
    if key in _last_rate_limit_reply and now - _last_rate_limit_reply[key] < RATE_LIMIT_REPLY_COOLDOWN:
        return False
    _last_rate_limit_reply[key] = now
    return True


def _rate_limit_record(key: str):
    global _last_global_response
    now = time.monotonic()
    _last_response[key] = now
    _last_global_response = now


# ── Bot loop ─────────────────────────────────────────────────────


def bot_loop(ser: serial.Serial):
    send_cmd(ser, {"type": "Ping"}, "Ping")
    send_cmd(
        ser,
        {"type": "SetConfig", "config": RADIO_CONFIG},
        "SetConfig 910.525/62.5k/SF7/CR4/5",
    )
    send_cmd(ser, {"type": "StartRx"}, "StartRx")

    # Send initial ADVERT
    _send_advert(ser)
    last_advert = time.monotonic()

    print(f"\n  {BWHT}{BOT_NAME} listening{RST} {DIM}(Ctrl+C to stop){RST}")
    triggers_str = ", ".join(TRIGGERS)
    print(f"  {DIM}Channels: {len(_KNOWN_CHANNELS)} | Triggers: {triggers_str} | DMs: enabled{RST}\n")
    ser.timeout = 1

    while True:
        # Periodic ADVERT
        now = time.monotonic()
        if now - last_advert >= ADVERT_INTERVAL:
            _send_advert(ser)
            last_advert = now


        data = read_frame(ser)
        if data is None:
            continue
        try:
            resp = decode_response(data)
        except Exception:
            continue
        if resp["type"] != "RxPacket":
            continue
        packet = resp["payload"]
        parsed = _parse_header_and_path(packet)
        if parsed is None:
            continue

        payload_type, route_type, payload_ver, pos, raw_payload, path_hops, hash_size = parsed

        # Learn return route from incoming packet's path
        if raw_payload and len(raw_payload) >= 2:
            if payload_type in (0x01, 0x02, 0x08):  # RESPONSE, TXT_MSG, PATH
                src_hash = raw_payload[1]
            elif payload_type == 0x04:  # ADVERT
                src_hash = raw_payload[0]
            else:
                src_hash = None
            if src_hash is not None:
                _learn_route(src_hash, path_hops, hash_size)

        # Dedup via packet hash (spec Section 16)
        if _is_duplicate(payload_type, raw_payload):
            continue

        # ── ACK (0x03) — ignore (we fire-and-forget DMs) ──
        if payload_type == 0x03:
            continue

        # ── ADVERT (0x04) ──
        if payload_type == 0x04:
            result = _try_decode_advert(raw_payload)
            if result:
                pubkey, name = result
                if pubkey == _pubkey_bytes:
                    continue  # ignore our own ADVERT echo
                is_new = _register_node(pubkey, name)
                print(f"  {BCYN}ADVERT{RST} {name} {DIM}(hash=0x{pubkey[0]:02x} pk={pubkey.hex()[:16]}...){RST}")

                # Check for pending DMs from this node's hash
                node_hash = pubkey[0]
                if node_hash in _pending_dms and _pending_dms[node_hash]:
                    now = time.monotonic()
                    pending = _pending_dms.pop(node_hash)
                    print(f"  {BCYN}Processing {len(pending)} pending DM(s) from {name}{RST}")
                    for pending_payload, ts in pending:
                        if now - ts > PENDING_DM_TTL:
                            continue  # expired
                        dm_result = _try_decrypt_dm(pending_payload)
                        if dm_result:
                            peer_pubkey, peer_name, dm_text, dm_plaintext = dm_result
                            pk_hex = peer_pubkey.hex()
                            _send_ack(ser, _compute_ack_hash(dm_plaintext, peer_pubkey), peer_pubkey[0])
                            if _is_dm_duplicate(pk_hex, dm_text):
                                continue
                            print(f"  {BCYN}DM(flood){RST} from {BWHT}{peer_name}{RST}: {dm_text}")
                            _record_dm_msg(pk_hex, f"{peer_name}: {dm_text}")
                            history = _get_dm_history(pk_hex)
                            response = call_claude(dm_text, peer_name, history, MAX_DM_TEXT, f"DM with {peer_name}")
                            if response:
                                _rt = "direct" if _get_route(peer_pubkey[0]) else "flood"
                                print(f"  {BGRN}<<< DM({_rt}) {BOT_NAME} → {peer_name}: {response}{RST}")
                                _dm_transmit(ser, peer_pubkey, response)
                                _record_dm_msg(pk_hex, f"{BOT_NAME}: {response}")
                                _rate_limit_record(f"dm:{pk_hex}")
            continue

        # ── GRP_TXT (0x05) ──
        if payload_type == 0x05:
            result = _try_decrypt_grp(raw_payload)
            if result is None:
                continue

            channel_name, text = result
            print(f"  {BMAG}GRP_TXT{RST} {BGRN}{channel_name}{RST} {BWHT}{text}{RST}")
            _record_channel_msg(channel_name, text)

            if ": " not in text:
                continue
            sender, _, body = text.partition(": ")
            if sender == BOT_NAME:
                continue

            query = _extract_trigger_query(body)
            if query is None:
                continue

            print(f"  {BMAG}>>> Query from {sender} on {channel_name}: {query}{RST}")

            rl_key = f"ch:{channel_name}:{sender}"
            if not _rate_limit_check(rl_key):
                print(f"  {YEL}Rate limited: {sender} on {channel_name}{RST}")
                if _rate_limit_reply_ok(f"ch:{channel_name}"):
                    msg = _rate_limit_message()
                    print(f"  {BGRN}<<< {BOT_NAME}: {msg}{RST}")
                    _grp_transmit(ser, channel_name, BOT_NAME, msg)
                    _rate_limit_record(rl_key)
                continue

            history = _get_channel_history(channel_name)
            response = call_claude(query, sender, history, MAX_RESPONSE_CHARS, f"channel {channel_name}")
            if response is None:
                continue

            print(f"  {BGRN}<<< {BOT_NAME}: {response}{RST}")
            _grp_transmit(ser, channel_name, BOT_NAME, response)
            _record_channel_msg(channel_name, f"{BOT_NAME}: {response}")
            _rate_limit_record(rl_key)
            continue

        # ── ANON_REQ (0x07) — LOGIN from companion (includes full pubkey) ──
        if payload_type == 0x07:
            result = _try_decrypt_anon_req(raw_payload)
            if result is None:
                continue

            peer_pubkey, peer_name, plaintext = result

            # Learn route before responding so login response can be direct-routed
            _learn_route(peer_pubkey[0], path_hops, hash_size)

            # Send login-OK response so the companion knows we accepted them
            print(f"  {BCYN}LOGIN{RST} from {BWHT}{peer_name}{RST} — sending login OK")
            _send_login_response(ser, peer_pubkey)

            # If we also got a decrypted message, process pending DMs from this peer
            pk_hex = peer_pubkey.hex()
            node_hash = peer_pubkey[0]
            if node_hash in _pending_dms and _pending_dms[node_hash]:
                now_mono = time.monotonic()
                pending = _pending_dms.pop(node_hash)
                print(f"  {BCYN}Processing {len(pending)} pending DM(s) from {peer_name}{RST}")
                for pending_payload, ts in pending:
                    if now_mono - ts > PENDING_DM_TTL:
                        continue
                    dm_result = _try_decrypt_dm(pending_payload)
                    if dm_result:
                        dm_pubkey, dm_name, dm_text, dm_plaintext = dm_result
                        # ACK + dedup
                        _send_ack(ser, _compute_ack_hash(dm_plaintext, dm_pubkey), dm_pubkey[0])
                        if _is_dm_duplicate(pk_hex, dm_text):
                            continue
                        print(f"  {BCYN}DM(flood){RST} from {BWHT}{dm_name}{RST}: {dm_text}")
                        _record_dm_msg(pk_hex, f"{dm_name}: {dm_text}")
                        history = _get_dm_history(pk_hex)
                        response = call_claude(dm_text, dm_name, history, MAX_DM_TEXT, f"DM with {dm_name}")
                        if response:
                            _rt = "direct" if _get_route(dm_pubkey[0]) else "flood"
                            print(f"  {BGRN}<<< DM({_rt}) {BOT_NAME} → {dm_name}: {response}{RST}")
                            _dm_transmit(ser, dm_pubkey, response)
                            _record_dm_msg(pk_hex, f"{BOT_NAME}: {response}")
                            _rate_limit_record(f"dm:{pk_hex}")
            continue

        # ── TXT_MSG DM (0x02) ──
        if payload_type == 0x02:
            result = _try_decrypt_dm(raw_payload)
            if result is None:
                # If addressed to us but sender unknown, queue for later
                if len(raw_payload) >= 4 and raw_payload[0] == _my_hash():
                    src_hash = raw_payload[1]
                    if not _lookup_node_by_hash(src_hash):
                        _pending_dms.setdefault(src_hash, []).append((raw_payload, time.monotonic()))
                        if len(_pending_dms[src_hash]) == 1:
                            print(f"  {BCYN}Queued DM from unknown 0x{src_hash:02x}, waiting for their ADVERT{RST}")
                continue

            peer_pubkey, peer_name, dm_text, raw_plaintext = result

            # Send ACK immediately so the sender stops retrying
            ack_crc = _compute_ack_hash(raw_plaintext, peer_pubkey)
            _send_ack(ser, ack_crc, peer_pubkey[0])

            # Send PATH return so sender can learn a direct route to us
            _send_path_return(ser, peer_pubkey, path_hops, hash_size)

            pk_hex = peer_pubkey.hex()

            # Dedup on decrypted text (catches retries with different attempt counters)
            if _is_dm_duplicate(pk_hex, dm_text):
                continue

            print(f"  {BCYN}DM({_route_name(route_type)}){RST} from {BWHT}{peer_name}{RST}: {dm_text}")
            _record_dm_msg(pk_hex, f"{peer_name}: {dm_text}")

            rl_key = f"dm:{pk_hex}"
            if not _rate_limit_check(rl_key):
                print(f"  {YEL}Rate limited DM: {peer_name}{RST}")
                continue

            history = _get_dm_history(pk_hex)
            response = call_claude(dm_text, peer_name, history, MAX_DM_TEXT, f"DM with {peer_name}")
            if response is None:
                continue

            _rt = "direct" if _get_route(peer_pubkey[0]) else "flood"
            print(f"  {BGRN}<<< DM({_rt}) {BOT_NAME} → {peer_name}: {response}{RST}")
            _dm_transmit(ser, peer_pubkey, response)
            _record_dm_msg(pk_hex, f"{BOT_NAME}: {response}")
            _rate_limit_record(rl_key)
            continue



# ── Main ─────────────────────────────────────────────────────────


def main():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print(f"  {RED}ANTHROPIC_API_KEY environment variable not set{RST}")
        sys.exit(1)

    _init_identity()
    _load_state()

    print(f"  {BWHT}{BOT_NAME}{RST} — MeshCore AI Bot")
    print(f"  {DIM}Max GRP response: {MAX_RESPONSE_CHARS} chars | Max DM response: {MAX_DM_TEXT} chars{RST}")
    print(f"  {DIM}Channels: {len(_KNOWN_CHANNELS)} | Known nodes: {len(_state['known_nodes'])}{RST}")

    port = sys.argv[1] if len(sys.argv) > 1 else None

    while True:
        try:
            print(f"  {DIM}Connecting...{RST}")
            ser = open_connection(port)
            print(f"  {GRN}Connected{RST}")
            bot_loop(ser)
        except (serial.SerialException, ConnectionError, OSError) as e:
            print(f"\n  {RED}Disconnected: {e}{RST}")
            print(f"  {DIM}Reconnecting when device reappears...{RST}")
            time.sleep(1)
        except KeyboardInterrupt:
            print()
            _save_state()
            try:
                ser.timeout = 2
                send_cmd(ser, {"type": "StopRx"}, "StopRx")
            except Exception:
                pass
            break


if __name__ == "__main__":
    main()
