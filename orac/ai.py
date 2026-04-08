"""Claude API integration: query extraction, response shortening."""

from __future__ import annotations

import logging
import random
import time

import anthropic

from orac.constants import (
    AT_MENTIONS,
    MAX_RESPONSE_CHARS,
    SYSTEM_PROMPT,
    TRIGGERS,
)

log = logging.getLogger("orac")

# ── Anthropic client singleton ───────────────────────────────────

_client: anthropic.Anthropic | None = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic()
    return _client


# ── Response shortening ──────────────────────────────────────────


def _shorten_with_claude(text: str, max_chars: int) -> str:
    """Use Claude to shorten text to fit within max_chars."""
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
        shortened: str = resp.content[0].text.strip()
    except Exception as e:
        log.error("Shorten API error: %s", e)
        shortened = text
    encoded = shortened.encode("utf-8")
    if len(encoded) > max_chars:
        while len(shortened.encode("utf-8")) > max_chars - 1:
            shortened = shortened[:-1]
        shortened += "\u2026"
    return shortened


def _extract_text(resp: anthropic.types.Message) -> str:
    """Extract the last non-empty text block from a Claude response."""
    text = ""
    for block in resp.content:
        if block.type == "text" and block.text.strip():
            text = block.text.strip()
    return text


# ── Main query function ─────────────────────────────────────────


def call_claude(
    query: str,
    sender: str,
    history: list[str],
    max_chars: int,
    context_label: str,
) -> str | None:
    """Send a query to Claude with conversation context. Returns response text or None."""
    try:
        nonce = random.randint(1000, 9999)
        now = time.strftime("%Y-%m-%d %H:%M %Z")
        prompt = (
            SYSTEM_PROMPT.replace("{max_chars}", str(max_chars)) + f"\n\nCurrent date/time: {now}"
        )

        if history:
            context = "\n".join(history)
            user_content = (
                f"[seed:{nonce}]\n"
                f"Recent messages in {context_label}:\n{context}\n\n"
                f"{sender} says: {query}"
            )
        else:
            user_content = f"[seed:{nonce}] {sender} says: {query}"

        messages: list[dict[str, object]] = [{"role": "user", "content": user_content}]
        tools: list[dict[str, str]] = [{"type": "web_search_20260209", "name": "web_search"}]

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
                log.warning("No text, stop=%s, blocks=%s", resp.stop_reason, block_types)
                break

            log.info("(web search round %d)...", round_num + 1)
            messages.append({"role": "assistant", "content": resp.content})
            tool_results: list[dict[str, str]] = []
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
            log.warning("No text after tool loop")
            return None
    except Exception as e:
        log.error("Claude API error: %s", e)
        return None

    if len(text.encode("utf-8")) > max_chars:
        log.warning("Response too long (%dB), shortening...", len(text.encode("utf-8")))
        text = _shorten_with_claude(text, max_chars)

    return text


# ── Rate-limit message ───────────────────────────────────────────


def rate_limit_message() -> str:
    """Generate a witty rate-limit message via Claude."""
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
            messages=[{"role": "user", "content": f"[seed:{nonce}] Rate limit hit."}],
        )
        text: str = resp.content[0].text.strip().strip("\"'")
        if len(text.encode("utf-8")) <= MAX_RESPONSE_CHARS and text:
            return text
    except Exception:
        pass
    return "Patience. Try again in a moment."


# ── Trigger detection ────────────────────────────────────────────


def extract_trigger_query(text: str) -> str | None:
    """Check for !triggers and @mentions. Returns query text or None."""
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
