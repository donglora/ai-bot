"""Orac bot constants: names, radio config, triggers, limits, paths."""

from __future__ import annotations

from pathlib import Path

import donglora as dl

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

RADIO_CONFIG: dl.LoRaConfig = dl.LoRaConfig(
    freq_hz=910_525_000,
    bw=dl.LoRaBandwidth.KHZ_62_5,
    sf=7,
    cr=dl.LoRaCodingRate.CR_4_5,
    sync_word=0x3444,
    tx_power_dbm=22,  # Requested max. `connect_and_run` clamps this down to
    # `dongle.info.tx_power_max_dbm` at connect time, so each board
    # transmits at its own PA ceiling (SX1262: 22 dBm, SX1276 PA_BOOST:
    # 20 dBm, …) without needing a per-board config table here.
    preamble_len=16,
    header_mode=dl.LoRaHeaderMode.EXPLICIT,
    payload_crc=True,
    iq_invert=False,
)

# ── AI system prompt ─────────────────────────────────────────────

SYSTEM_PROMPT: str = """\
You are Orac, a terse AI assistant on a MeshCore LoRa radio mesh network.

ABSOLUTE HARD LIMIT: Your ENTIRE response must be {{max_chars}} characters or fewer.
This is a physical constraint of the radio protocol. Every character beyond this limit
is permanently lost and never transmitted. There is NO exception.

Stay well under {{max_chars}}. Aim for 120 or fewer. NEVER show a character count or HTML tags in your reply.

You can see recent messages for context. Use the chat history to understand what
people mean. "what do you think?" refers to whatever was just discussed. "tell me
more" means elaborate on the recent topic.

Social awareness is YOUR TOP PRIORITY — above cleverness, above information density.
Before every response, work out:
- Who is actually talking, and to whom? Are they asking you, or about you?
- What's the vibe: casual banter, technical help, emergency, venting, inside joke?
- What's the group's energy? Are you being invited in, or just name-dropped?
- If someone said "you could always ask @Orac" (or similar), that's a social nudge,
  NOT a request for a factual answer. Acknowledge lightly, or offer to help if the
  invitation was sincere — don't barge in with an essay.
- If the conversation is jokey, match the tone. If serious, be substantive.
  If someone's frustrated, don't be flippant. Read the room like a person would.
- When people are talking among themselves and you're tagged in passing, a short
  witty nod is often the right move — or silence would be, if you could stay silent.
- When you ARE being asked something directly, answer crisply.

NEVER assume location. Weather, traffic, time zones, sunset, local services —
all of these are useless without knowing where the person is. If someone asks
"what's the weather?" or anything else location-sensitive without telling you
where, ask them. A short quip is fine: "Where?" or "Drop a city/airport code
and I'll tell you." Do NOT guess a city. Do NOT default to Denver or anywhere
else. Only answer a location-dependent question after the user has provided
the location (either in the current turn or visible in recent history).

Rules:
- One sentence or short phrase. Never more.
- Emoji OK but don't overdo it. No markdown, no bullet points, no formatting.
- Use common abbreviations freely (e.g., w/, b/c, approx, etc).
- Skip all pleasantries, greetings, and filler.
- You have a dry, sardonic wit. Be helpful but never wordy.
- Cynicism is fine in small doses; punching-down or mean-spirited is not.
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

# ── DM reliability: IO loop ──────────────────────────────────────

IO_POLL_TIMEOUT_S: float = 0.2
RX_DRAIN_PER_TICK: int = 8

# Donglora's send() reads the TxDone response using the serial timeout; LoRa
# airtime at SF7/62.5 kHz for a max-size 180 B DM is ~425 ms, plus up to
# 100 ms of CAD retries in the firmware. 2 s gives a comfortable margin.
TX_RESPONSE_TIMEOUT_S: float = 2.0

# ── DM reliability: ACK scheduling ───────────────────────────────
# Small jitter below single-ACK airtime (~89 ms at SF7/62.5 kHz/CR4/5)
# decouples us from other responders, without delaying the sender's
# firmware retry clock.
ACK_JITTER_MIN_S: float = 0.03
ACK_JITTER_MAX_S: float = 0.09
PATH_RETURN_DELAY_S: float = 0.15

# Multi-ACK protocol (upstream commits b1ca3d1 + 5881b04, `multi_acks` pref).
# When > 0, N extra ACKs are emitted as PAYLOAD_TYPE_MULTIPART (0x0A) packets
# with remaining-count nibbles counting down to 1, followed by a final plain
# PAYLOAD_TYPE_ACK (0x03). Each successive packet is 300 ms + small jitter
# after the previous.
#
# Firmware restricts extra ACKs to direct-routed packets only (see
# Mesh::routeDirectRecvAcks). We do the same: if no learned direct route to
# the peer exists, we fall back to a single plain ACK and skip MULTIPART,
# matching upstream semantics.
#
# Upstream default is 0 (multi_acks pref = 0). MeshCore One's iOS app surfaces
# this as the "2 ACKs" toggle (multi_acks=1 -> 1 MULTIPART + 1 ACK = 2 total).
MULTI_ACK_COUNT: int = 0
MULTI_ACK_SPACING_S: float = 0.3

# ── DM reliability: reply scheduling ─────────────────────────────
# Initial reply jitter keeps the reply from racing our own ACK/PATH
# on the air and below any retry window.
REPLY_INITIAL_JITTER_MIN_S: float = 0.05
REPLY_INITIAL_JITTER_MAX_S: float = 0.20

# Retry delays between attempts. Index i = delay AFTER firing attempt (i+1)
# before attempt (i+2). With REPLY_MAX_ATTEMPTS=5 we need 4 entries (for
# attempts 2-5). Schedule mirrors pymc's 3-direct + 2-flood pattern.
#
# Timeline at current radio config (SF7/62.5 kHz/CR4/5, ~3.3 s 2-hop RTT):
#   Attempt 1 (initial)          at T=0
#   Attempt 2 (direct)           at T=6    (~1.8x 2-hop RTT headroom)
#   Attempt 3 (direct)           at T=20   (bigger gap for congested relays)
#   Attempt 4 (flood, path-reset) at T=50  (mesh quiesce window)
#   Attempt 5 (flood)            at T=95   (last hail-Mary after a long wait)
#   Give up (sweep)              at T=125  (~30s past the last attempt for ACK)
RETRY_SCHEDULE_S: tuple[float, ...] = (6.0, 14.0, 30.0, 45.0)
REPLY_MAX_ATTEMPTS: int = 5  # 1 initial + 2 direct retries + 2 flood retries
REPLY_FLOOD_FIRST_ATTEMPT: int = 4  # 1-indexed: first attempt that forces flood

# ── DM reliability: state bounds ─────────────────────────────────
# TTL must be beyond the final retry's transmit time plus enough for the
# reply's ACK to arrive: 6+14+30+45 = 95s to final retry, +30s for ACK.
PENDING_ACK_TTL_S: float = 125.0
PENDING_ACK_CAP: int = 64
REPLY_CACHE_CAP: int = 32
REPLY_CACHE_TTL_S: float = 300.0  # matches PENDING_DM_TTL

# Duplicate DMs arriving within this window *with a cached reply* trigger a
# cached-reply resend (interpreted as loss recovery). Outside this window, a
# duplicate text is treated as the peer legitimately re-asking after giving up,
# and falls through to normal text-level dedup (silent drop inside DM_DEDUP_TTL
# and a fresh Claude call beyond that).
REPLY_CACHE_RESEND_WINDOW_S: float = 20.0
TX_QUEUE_CAP: int = 64

# ── DM reliability: route table ──────────────────────────────────
ROUTE_TTL_S: float = 1800.0  # 30 min

# Minimum hop-hash size (bytes) we will accept when learning a return path,
# and the minimum we will echo back in a PATH_RETURN. 1-byte hashes have a
# 256-way namespace that collides under any real node population; this bot
# refuses to participate in 1-byte routing.
MIN_HASH_SIZE: int = 2

# ── DM reliability: worker / Claude ──────────────────────────────
WORKER_QUEUE_CAP: int = 8
CLAUDE_TIMEOUT_S: float = 20.0

# ── Channel follow-up screener ───────────────────────────────────
# Inexpensive yes/no classifier that decides whether a NON-TRIGGERED channel
# message is a follow-up to Orac (we should reply) or just chatter between
# other participants (we should not). Keeps Orac capable of natural multi-turn
# conversation without flooding the channel with bot noise.

# Haiku is the cheapest Claude model — suitable for a yes/no gate.
SCREENER_MODEL: str = "claude-haiku-4-5"

# How long after Orac was last active in a channel to keep screening new
# non-triggered messages. Outside this window, non-triggered messages are
# ignored without spending any API call.
CHANNEL_FOLLOWUP_WINDOW_S: float = 180.0  # 3 min

# Per-channel minimum gap between screener API calls, to prevent spam from
# running up cost during a burst of traffic.
SCREENER_PER_CHANNEL_RATE_S: float = 3.0

# Short timeout for the screener — it returns a single token.
SCREENER_TIMEOUT_S: float = 6.0

# ── Events JSONL path ────────────────────────────────────────────
EVENTS_FILE: Path = DATA_DIR / "orac-events.jsonl"

# ── Channels CSV path ────────────────────────────────────────────
# Resolved at import time relative to the project root (ai_bot.py's directory).
CHANNELS_CSV: Path = Path(__file__).resolve().parent.parent / "channels.csv"
