"""Identity (Ed25519 keypair), channel crypto, peer crypto, ECDH."""

from __future__ import annotations

import csv
import hashlib
import hmac
import logging
import struct
import time

from Crypto.Cipher import AES
from nacl.bindings import crypto_scalarmult
from nacl.signing import SigningKey, VerifyKey

from orac.constants import (
    BOT_NAME,
    CHANNELS_CSV,
    DATA_DIR,
    KEY_FILE,
    MAX_GRP_TEXT,
)

log = logging.getLogger("orac")

# ── Identity ─────────────────────────────────────────────────────

_signing_key: SigningKey | None = None
_verify_key: VerifyKey | None = None
_pubkey_bytes: bytes = b""


def init_identity() -> None:
    """Load or generate Ed25519 keypair. Persisted to disk."""
    global _signing_key, _verify_key, _pubkey_bytes

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if KEY_FILE.is_file():
        seed = KEY_FILE.read_bytes()
        if len(seed) == 32:
            _signing_key = SigningKey(seed)
            log.info("Loaded keypair from %s", KEY_FILE)
        else:
            log.warning("Invalid key file, regenerating")
            _signing_key = SigningKey.generate()
            KEY_FILE.write_bytes(bytes(_signing_key))
    else:
        _signing_key = SigningKey.generate()
        KEY_FILE.write_bytes(bytes(_signing_key))
        log.info("Generated new keypair -> %s", KEY_FILE)

    _verify_key = _signing_key.verify_key
    _pubkey_bytes = bytes(_verify_key)
    log.info("Pubkey: %s", _pubkey_bytes.hex())
    log.info("Node hash: 0x%02x", _pubkey_bytes[0])


def my_hash() -> int:
    """Our 1-byte node hash (first byte of pubkey)."""
    return _pubkey_bytes[0]


def pubkey_bytes() -> bytes:
    """Our Ed25519 public key (32 bytes)."""
    return _pubkey_bytes


def sign(message: bytes) -> bytes:
    """Sign *message* with our identity key. Returns the 64-byte signature."""
    assert _signing_key is not None
    signed = _signing_key.sign(message)
    return signed.signature


# ── Channel crypto ───────────────────────────────────────────────


def channel_secret_from_hashtag(name: str) -> bytes:
    """Derive a 32-byte channel secret from a hashtag name."""
    h = hashlib.sha256(name.encode()).digest()
    return h[:16] + b"\x00" * 16


def channel_hash(secret: bytes) -> int:
    """Compute the 1-byte channel hash from a secret."""
    key_len = 16 if secret[16:] == b"\x00" * 16 else 32
    return hashlib.sha256(secret[:key_len]).digest()[0]


def grp_verify_and_decrypt(secret: bytes, mac_bytes: bytes, ciphertext: bytes) -> bytes | None:
    """Verify MAC and decrypt a group message. Returns plaintext or None."""
    key_len = 32  # HMAC always uses full 32-byte secret (spec Section 14)
    computed = hmac.new(secret[:key_len], ciphertext, hashlib.sha256).digest()[:2]
    if computed != mac_bytes:
        return None
    cipher = AES.new(secret[:16], AES.MODE_ECB)
    plaintext = b""
    for i in range(0, len(ciphertext), 16):
        plaintext += cipher.decrypt(ciphertext[i : i + 16])
    return plaintext


def parse_grp_plaintext(plaintext: bytes) -> tuple[int, str] | None:
    """Parse decrypted group plaintext. Returns (timestamp, text) or None."""
    if len(plaintext) < 5:
        return None
    timestamp: int = struct.unpack_from("<I", plaintext, 0)[0]
    text = plaintext[5:].split(b"\x00", 1)[0]
    return timestamp, text.decode("utf-8", errors="replace")


def grp_encrypt(secret: bytes, sender: str, text: str) -> bytes:
    """Encrypt a GRP_TXT payload. Returns channel_hash + mac + ciphertext."""
    ch = channel_hash(secret)
    plaintext = struct.pack("<I", int(time.time())) + b"\x00"
    plaintext += f"{sender}: {text}\x00".encode()[:MAX_GRP_TEXT]
    pad_len = (16 - len(plaintext) % 16) % 16
    plaintext += b"\x00" * pad_len
    cipher = AES.new(secret[:16], AES.MODE_ECB)
    ciphertext = b""
    for i in range(0, len(plaintext), 16):
        ciphertext += cipher.encrypt(plaintext[i : i + 16])
    key_len = 32  # HMAC always uses full 32-byte secret (spec Section 14)
    mac = hmac.new(secret[:key_len], ciphertext, hashlib.sha256).digest()[:2]
    return bytes([ch]) + mac + ciphertext


# ── Peer-to-peer (DM) crypto ────────────────────────────────────


def ecdh_shared_secret(peer_ed25519_pub: bytes) -> bytes:
    """Compute X25519 shared secret from our Ed25519 key and peer's Ed25519 pubkey."""
    assert _signing_key is not None
    my_x25519 = bytes(_signing_key.to_curve25519_private_key())
    peer_verify = VerifyKey(peer_ed25519_pub)
    peer_x25519 = bytes(peer_verify.to_curve25519_public_key())
    return crypto_scalarmult(my_x25519, peer_x25519)


def build_peer_plaintext(text: str, ts: int | None = None, attempt: int = 0) -> bytes:
    """Build a DM plaintext blob: timestamp(4 LE) + txt_type_attempt(1) + text + \\x00 + zero-pad to 16.

    Using the timestamp + attempt fields from the MeshCore TXT_MSG plaintext layout.
    Callers that need the expected ACK hash must keep this plaintext.
    """
    if ts is None:
        ts = int(time.time())
    plaintext = struct.pack("<I", ts) + bytes([attempt & 0xFF])
    plaintext += text.encode("utf-8") + b"\x00"
    pad_len = (16 - len(plaintext) % 16) % 16
    return plaintext + b"\x00" * pad_len


def peer_encrypt(shared_secret: bytes, text: str) -> bytes:
    """Encrypt a DM plaintext. Returns mac(2) + ciphertext.

    Convenience wrapper; callers that also need the plaintext should use
    :func:`build_peer_plaintext` + :func:`peer_encrypt_plaintext`.
    """
    return peer_encrypt_plaintext(shared_secret, build_peer_plaintext(text))


def peer_encrypt_plaintext(shared_secret: bytes, plaintext: bytes) -> bytes:
    """Encrypt a pre-built DM plaintext. Returns mac(2) + ciphertext."""
    cipher = AES.new(shared_secret[:16], AES.MODE_ECB)
    ciphertext = b""
    for i in range(0, len(plaintext), 16):
        ciphertext += cipher.encrypt(plaintext[i : i + 16])
    mac = hmac.new(shared_secret[:32], ciphertext, hashlib.sha256).digest()[:2]
    return mac + ciphertext


def peer_verify_and_decrypt(
    shared_secret: bytes, mac_bytes: bytes, ciphertext: bytes
) -> bytes | None:
    """Verify MAC then decrypt a peer message. Returns plaintext or None."""
    computed = hmac.new(shared_secret[:32], ciphertext, hashlib.sha256).digest()[:2]
    if computed != mac_bytes:
        return None
    cipher = AES.new(shared_secret[:16], AES.MODE_ECB)
    plaintext = b""
    for i in range(0, len(ciphertext), 16):
        plaintext += cipher.decrypt(ciphertext[i : i + 16])
    return plaintext


def parse_peer_plaintext(plaintext: bytes) -> str | None:
    """Parse decrypted peer message: timestamp(4) + txt_type_attempt(1) + text."""
    if len(plaintext) < 5:
        return None
    text = plaintext[5:].split(b"\x00", 1)[0]
    return text.decode("utf-8", errors="replace") if text else None


def verify_advert_signature(
    pubkey: bytes, timestamp: bytes, app_data: bytes, signature: bytes
) -> bool:
    """Verify an ADVERT's Ed25519 signature. Returns True on success."""
    try:
        verify_key = VerifyKey(pubkey)
        sign_msg = pubkey + timestamp + app_data
        verify_key.verify(sign_msg, signature)
        return True
    except Exception:
        return False


# ── Channel registry ─────────────────────────────────────────────

_channels: dict[str, bytes] = {}
_channel_by_hash: dict[int, list[tuple[str, bytes]]] = {}


def register_channel(name: str, secret: bytes) -> None:
    """Register a channel name and its secret."""
    _channels[name] = secret
    h = channel_hash(secret)
    _channel_by_hash.setdefault(h, []).append((name, secret))


def get_channel_secret(name: str) -> bytes | None:
    """Get the secret for a registered channel, or None."""
    return _channels.get(name)


def get_channels_by_hash(h: int) -> list[tuple[str, bytes]]:
    """Get all channel (name, secret) pairs matching a hash byte."""
    return _channel_by_hash.get(h, [])


def channel_count() -> int:
    """Number of registered channels."""
    return len(_channels)


_PUBLIC_PSK_HEX: str = "8b3387e9c5cdea6ac9e5edbaa115cd72"
"""MeshCore Public channel pre-shared key (fixed, not hashtag-derived)."""

_BUILTIN_HASHTAG_CHANNELS: tuple[str, ...] = (
    # --- AI / bot trigger channels ---
    "#askai",
    "#ai",
    "#aibot",
    "#aibots",
    "#orac",
    "#bot",
    # --- Operations ---
    "#nodeops",
    "#repeater-ops",
    "#net",
    "#emcomm",
    # --- General purpose ---
    "#general",
    "#test",
    "#weather",
    "#protest",
    # --- Dev / testing ---
    "#devtest",
    "#devtestdevtest",
)
"""Built-in hashtag channels (key derived from SHA-256 of the name)."""


def init_channels() -> None:
    """Register the MeshCore Public channel, built-in hashtag channels, and any CSV overrides."""
    # Public channel — fixed PSK, not hashtag-derived
    register_channel("Public", bytes.fromhex(_PUBLIC_PSK_HEX) + b"\x00" * 16)

    # Built-in hashtag channels
    for name in _BUILTIN_HASHTAG_CHANNELS:
        register_channel(name, channel_secret_from_hashtag(name))

    # Optional CSV for additional channels (operator-defined)
    if CHANNELS_CSV.is_file():
        with open(CHANNELS_CSV, newline="") as f:
            for row in csv.DictReader(f):
                name: str = row["channel_name"]
                is_hashtag = row["hashtag"].strip().lower() == "true"
                key_hex: str = row["key_hex"].strip()
                if is_hashtag:
                    secret = channel_secret_from_hashtag(name)
                else:
                    secret = bytes.fromhex(key_hex) + b"\x00" * 16
                register_channel(name, secret)


def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-ECB encrypt (16-byte aligned plaintext). Used for PATH and RESPONSE."""
    cipher = AES.new(key[:16], AES.MODE_ECB)
    ciphertext = b""
    for i in range(0, len(plaintext), 16):
        ciphertext += cipher.encrypt(plaintext[i : i + 16])
    return ciphertext


def compute_mac(secret: bytes, ciphertext: bytes) -> bytes:
    """Compute 2-byte HMAC-SHA256 MAC over ciphertext."""
    return hmac.new(secret[:32], ciphertext, hashlib.sha256).digest()[:2]


def build_advert_payload() -> bytes:
    """Build the inner ADVERT payload: pubkey + timestamp + signature + app_data."""
    timestamp = struct.pack("<I", int(time.time()))
    app_data = bytes([0x81]) + BOT_NAME.encode("utf-8")
    sign_msg = _pubkey_bytes + timestamp + app_data
    signature = sign(sign_msg)
    return _pubkey_bytes + timestamp + signature + app_data


def raw_peer_encrypt(shared_secret: bytes, plaintext: bytes) -> bytes:
    """Encrypt raw plaintext (not text message) for a peer. Returns mac(2) + ciphertext."""
    pad_len = (16 - len(plaintext) % 16) % 16
    padded = plaintext + b"\x00" * pad_len
    ciphertext = aes_ecb_encrypt(shared_secret[:16], padded)
    mac = compute_mac(shared_secret, ciphertext)
    return mac + ciphertext


# Silence unused-import linter for `Any` — used only in type annotations
__all__: list[str] = [
    "aes_ecb_encrypt",
    "build_advert_payload",
    "build_peer_plaintext",
    "channel_count",
    "channel_hash",
    "channel_secret_from_hashtag",
    "compute_mac",
    "ecdh_shared_secret",
    "get_channel_secret",
    "get_channels_by_hash",
    "grp_encrypt",
    "grp_verify_and_decrypt",
    "init_channels",
    "init_identity",
    "my_hash",
    "parse_grp_plaintext",
    "parse_peer_plaintext",
    "peer_encrypt",
    "peer_encrypt_plaintext",
    "peer_verify_and_decrypt",
    "pubkey_bytes",
    "raw_peer_encrypt",
    "register_channel",
    "sign",
    "verify_advert_signature",
]
