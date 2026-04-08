"""Orac bot constants: names, radio config, triggers, limits, paths."""

from __future__ import annotations

from pathlib import Path

# ── Bot identity ─────────────────────────────────────────────────

BOT_NAME: str = "Orac"

# ── Payload limits ───────────────────────────────────────────────

MAX_GRP_TEXT: int = 163  # max bytes for "SenderName: message" in a GRP_TXT
MAX_RESPONSE_CHARS: int = MAX_GRP_TEXT - len(BOT_NAME) - 2  # subtract "Orac: "
# DM plaintext: timestamp(4) + txt_type_attempt(1) + text + padding to 16
# Max payload 184 - dst(1) - src(1) - mac(2) = 180 bytes ciphertext
# 180 bytes ciphertext / 16 = 11 blocks -> 176 bytes plaintext max
# 176 - 5 (header) = 171 bytes text, minus null terminator padding
MAX_DM_TEXT: int = 170

# ── Trigger words ────────────────────────────────────────────────

TRIGGERS: tuple[str, ...] = ("!askai", "!ai", "!claude", "!orac")
AT_MENTIONS: tuple[str, ...] = (f"@{BOT_NAME}".lower(), f"@[{BOT_NAME}]".lower())

# ── History / rate-limit sizing ──────────────────────────────────

CHANNEL_HISTORY_SIZE: int = 20
DM_HISTORY_SIZE: int = 20

RATE_LIMIT_PER_SENDER: float = 5  # seconds, channel messages
RATE_LIMIT_GLOBAL: float = 2  # seconds, any two responses
RATE_LIMIT_DM: float = 2  # seconds, DMs (more interactive)
RATE_LIMIT_REPLY_COOLDOWN: float = 30  # seconds between rate-limit replies

# ── Timers ───────────────────────────────────────────────────────

ADVERT_INTERVAL: float = 7200  # 2 hours in seconds

# ── Paths ────────────────────────────────────────────────────────

DATA_DIR: Path = Path.home() / ".donglora"
KEY_FILE: Path = DATA_DIR / "orac_key.bin"
STATE_FILE: Path = DATA_DIR / "orac_state.json"

# ── Radio ────────────────────────────────────────────────────────

RADIO_CONFIG: dict[str, int] = {
    "freq_hz": 910_525_000,
    "bw": 6,  # 62.5 kHz
    "sf": 7,
    "cr": 5,  # CR 4/5
    "sync_word": 0x3444,
    "tx_power_dbm": -128,  # TX_POWER_MAX
}

# ── AI system prompt ─────────────────────────────────────────────

SYSTEM_PROMPT: str = """\
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

# ── MeshCore protocol constants ──────────────────────────────────

ADVERT_MAX_AGE: float = 43200  # 12 hours (display only, not key expiry)
PENDING_DM_TTL: float = 300  # 5 minutes

DEDUP_TTL: float = 120  # seconds
DM_DEDUP_TTL: float = 60  # seconds

RESP_SERVER_LOGIN_OK: int = 0x01

# ── Channels CSV path ────────────────────────────────────────────
# Resolved at import time relative to the project root (ai_bot.py's directory).
CHANNELS_CSV: Path = Path(__file__).resolve().parent.parent / "channels.csv"
