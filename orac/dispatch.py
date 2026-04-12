"""RX dispatch: parse incoming frames, drive ACK/PATH/worker/retry feedback."""

from __future__ import annotations

import logging
import random
import threading
import time
from collections.abc import Callable
from typing import Any

from orac import events, followup, logfmt
from orac.ai import extract_trigger_query, rate_limit_message
from orac.constants import (
    ACK_JITTER_MAX_S,
    ACK_JITTER_MIN_S,
    BOT_NAME,
    CHANNEL_FOLLOWUP_WINDOW_S,
    MIN_HASH_SIZE,
    MULTI_ACK_COUNT,
    MULTI_ACK_SPACING_S,
    PATH_RETURN_DELAY_S,
    RATE_LIMIT_DM,
    RATE_LIMIT_GLOBAL,
    RATE_LIMIT_PER_SENDER,
    RATE_LIMIT_REPLY_COOLDOWN,
    REPLY_CACHE_RESEND_WINDOW_S,
    SCREENER_PER_CHANNEL_RATE_S,
)
from orac.crypto import my_hash, pubkey_bytes
from orac.meshcore import (
    build_ack_packet,
    build_grp_channel_packet,
    build_login_response_packet,
    build_multiack_packet,
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
from orac.reply_state import PendingAckTable, ReplyCache
from orac.runtime import Metrics, TxItem, TxPriority, TxQueue
from orac.state import get_channel_history, record_channel_msg
from orac.worker import ChannelReplyWork, ChannelScreenWork, DmReplyWork, Worker

log = logging.getLogger("orac")


class RateLimiter:
    """Bot-level rate limiter — per-sender + global timers, thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._per_key: dict[str, float] = {}
        self._global_last = 0.0
        self._reply_last: dict[str, float] = {}

    def check(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if now - self._global_last < RATE_LIMIT_GLOBAL:
                return False
            limit = RATE_LIMIT_DM if key.startswith("dm:") else RATE_LIMIT_PER_SENDER
            last = self._per_key.get(key)
            return not (last is not None and now - last < limit)

    def reply_ok(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._reply_last.get(key)
            if last is not None and now - last < RATE_LIMIT_REPLY_COOLDOWN:
                return False
            self._reply_last[key] = now
            return True

    def record(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._per_key[key] = now
            self._global_last = now


class RxRouter:
    """Parses and dispatches every RxPacket the IOThread drains.

    Designed to be cheap and non-blocking — never calls Claude, never sleeps.
    Reply work goes to :class:`Worker`; ACK/PATH transmissions go to
    :class:`TxQueue`; retry cancellation goes to :class:`PendingAckTable` and
    :meth:`TxQueue.cancel_by_ack`.
    """

    def __init__(
        self,
        tx_queue: TxQueue,
        worker: Worker,
        pending_acks: PendingAckTable,
        reply_cache: ReplyCache,
        rate_limiter: RateLimiter,
        metrics: Metrics,
    ) -> None:
        self._tx = tx_queue
        self._worker = worker
        self._pending = pending_acks
        self._cache = reply_cache
        self._rl = rate_limiter
        self._metrics = metrics

    # -- top-level dispatch ---------------------------------------

    def handle(self, pkt: dict[str, Any]) -> None:
        payload_bytes: bytes = pkt.get("payload", b"")
        snr: float = float(pkt.get("snr", 0))

        parsed = parse_header_and_path(payload_bytes)
        if parsed is None:
            return
        (
            payload_type,
            route_type,
            _payload_ver,
            _pos,
            raw_payload,
            path_hops,
            hash_size,
        ) = parsed

        # Route-learn from the incoming path
        if raw_payload and len(raw_payload) >= 2:
            src_hash: int | None = None
            if payload_type in (0x01, 0x02, 0x08):
                src_hash = raw_payload[1]
            elif payload_type == 0x04:
                src_hash = raw_payload[0]
            if src_hash is not None:
                learn_route(src_hash, path_hops, hash_size, snr=snr)

        # Packet-hash dedup (spec Section 16)
        if is_duplicate(payload_type, raw_payload):
            self._metrics.inc("rx_dup")
            return

        if payload_type == 0x03:
            self._handle_ack(raw_payload)
        elif payload_type == 0x0A:
            self._handle_multipart(raw_payload)
        elif payload_type == 0x04:
            self._handle_advert(raw_payload)
        elif payload_type == 0x05:
            self._handle_grp_txt(raw_payload)
        elif payload_type == 0x07:
            self._handle_anon_req(raw_payload, path_hops, hash_size)
        elif payload_type == 0x02:
            self._handle_dm(raw_payload, route_type, path_hops, hash_size, snr)

    # -- ACK ------------------------------------------------------

    def _handle_ack(self, raw_payload: bytes) -> None:
        """Handle a plain PAYLOAD_TYPE_ACK (0x03): payload is 4-byte CRC."""
        if len(raw_payload) < 4:
            return
        self._consume_ack(raw_payload[:4], source="ack")

    def _handle_multipart(self, raw_payload: bytes) -> None:
        """Handle PAYLOAD_TYPE_MULTIPART (0x0A).

        Upstream uses MULTIPART as a transport-level wrapper. For inner
        type == PAYLOAD_TYPE_ACK (0x03), the layout is
        ``[remaining<<4 | 0x03][crc:4]`` (5 bytes). We unwrap it and treat
        the inner CRC identically to a plain ACK — which matches how the
        firmware's receiver handles it (src/Mesh.cpp:270-282).
        """
        if len(raw_payload) < 5:
            return
        inner_type = raw_payload[0] & 0x0F
        if inner_type != 0x03:
            # MULTIPART wrappers for non-ACK inner types aren't something we
            # currently generate or consume — ignore.
            return
        self._consume_ack(raw_payload[1:5], source="multipart")

    def _consume_ack(self, ack_crc: bytes, source: str) -> None:
        entry = self._pending.consume(ack_crc)
        if entry is None:
            return
        now = time.monotonic()
        elapsed_ms = int((now - entry.first_sent_at) * 1000)
        self._tx.cancel_by_ack(ack_crc)
        self._metrics.inc("ack_inbound_consumed")
        self._metrics.inc(f"ack_inbound_source_{source}")
        self._metrics.inc(f"reply_confirmed_attempt_{entry.attempt}")
        events.emit(
            "reply.confirmed",
            peer=entry.peer_name,
            peer_pk=entry.peer_pk.hex(),
            attempt=entry.attempt,
            elapsed_ms=elapsed_ms,
            ack_crc=ack_crc.hex(),
            source=source,
        )
        logfmt.ack_ok(entry.peer_name, entry.attempt, elapsed_ms)

    # -- ADVERT ---------------------------------------------------

    def _handle_advert(self, raw_payload: bytes) -> None:
        result = try_decode_advert(raw_payload)
        if result is None:
            return
        adv_pubkey, name = result
        if adv_pubkey == pubkey_bytes():
            return  # our own advert echo
        register_node(adv_pubkey, name)
        logfmt.net(
            "ADVERT %s (hash=0x%02x pk=%s...)",
            name,
            adv_pubkey[0],
            adv_pubkey.hex()[:16],
        )
        if has_pending_dms(adv_pubkey[0]):
            self._process_pending_dms(adv_pubkey[0], name)

    # -- GRP_TXT --------------------------------------------------

    def _handle_grp_txt(self, raw_payload: bytes) -> None:
        result = try_decrypt_grp(raw_payload)
        if result is None:
            return
        channel_name, text = result
        record_channel_msg(channel_name, text)

        if ": " in text:
            sender, _, body = text.partition(": ")
            logfmt.ch_in(channel_name, sender, body)
        else:
            sender, body = "", text
            logfmt.ch_in(channel_name, "?", body)
        if sender == BOT_NAME:
            return

        rl_key = f"ch:{channel_name}:{sender}"
        query = extract_trigger_query(body)

        if query is not None:
            # Explicit trigger or @mention — always process.
            logfmt.net("trigger from %s on %s: %s", sender, channel_name, query)
            self._dispatch_channel_reply(
                channel_name=channel_name,
                sender=sender,
                query=query,
                rl_key=rl_key,
                origin="trigger",
            )
            return

        # No trigger. Only consider this message as a potential follow-up
        # if Orac has been active in this channel recently. The vast majority
        # of channel chatter hits this early return with zero API cost.
        if not followup.was_recent(channel_name, CHANNEL_FOLLOWUP_WINDOW_S):
            return

        # Rate-limit screener calls per channel to cap cost on busy channels.
        if not followup.screener_ok(channel_name, SCREENER_PER_CHANNEL_RATE_S):
            self._metrics.inc("screener_skipped_rate")
            return

        self._metrics.inc("screener_submitted")
        self._worker.submit(
            ChannelScreenWork(
                channel_name=channel_name,
                sender=sender,
                text=body,
                history_snapshot=get_channel_history(channel_name),
                received_at=time.monotonic(),
                rl_key=rl_key,
            )
        )

    def _dispatch_channel_reply(
        self,
        *,
        channel_name: str,
        sender: str,
        query: str,
        rl_key: str,
        origin: str,
    ) -> None:
        """Run rate-limit gate then enqueue a ChannelReplyWork (or a rate-limit TX)."""
        if not self._rl.check(rl_key):
            log.warning("rate limited: %s on %s (%s)", sender, channel_name, origin)
            if self._rl.reply_ok(f"ch:{channel_name}"):
                msg = rate_limit_message()
                packet = build_grp_channel_packet(channel_name, BOT_NAME, msg)
                if packet is not None:
                    self._tx.push(
                        TxItem(
                            priority=TxPriority.GRP_TXT,
                            not_before=time.monotonic(),
                            packet=packet,
                            label=f"GRP-rate({channel_name})",
                        )
                    )
                    self._rl.record(rl_key)
            return

        # Mark the channel warm so screener activates for subsequent messages.
        followup.touch(channel_name)
        self._worker.submit(
            ChannelReplyWork(
                channel_name=channel_name,
                sender=sender,
                query=query,
                received_at=time.monotonic(),
                rl_key=rl_key,
            )
        )

    # -- ANON_REQ -------------------------------------------------

    def _handle_anon_req(
        self,
        raw_payload: bytes,
        path_hops: list[bytes],
        hash_size: int,
    ) -> None:
        result = try_decrypt_anon_req(raw_payload)
        if result is None:
            return
        peer_pubkey, peer_name, _plaintext = result
        learn_route(peer_pubkey[0], path_hops, hash_size)
        logfmt.net("LOGIN from %s -- sending login OK", peer_name)
        packet = build_login_response_packet(peer_pubkey)
        self._tx.push(
            TxItem(
                priority=TxPriority.LOGIN_RESP,
                not_before=time.monotonic(),
                packet=packet,
                label=f"LOGIN_RESP->{peer_name}",
            )
        )
        if has_pending_dms(peer_pubkey[0]):
            self._process_pending_dms(peer_pubkey[0], peer_name)

    # -- DM -------------------------------------------------------

    def _handle_dm(
        self,
        raw_payload: bytes,
        route_type: int,
        path_hops: list[bytes],
        hash_size: int,
        snr: float,
    ) -> None:
        result = try_decrypt_dm(raw_payload)
        if result is None:
            # Addressed to us but sender unknown: queue for later
            if len(raw_payload) >= 4 and raw_payload[0] == my_hash():
                src_hash = raw_payload[1]
                if not lookup_node_by_hash(src_hash):
                    is_first = queue_pending_dm(src_hash, raw_payload)
                    if is_first:
                        logfmt.net(
                            "queued DM from unknown 0x%02x, waiting for their ADVERT",
                            src_hash,
                        )
            return

        peer_pubkey, peer_name, dm_text, raw_plaintext = result
        pk_hex = peer_pubkey.hex()
        now = time.monotonic()

        # 1) Schedule ACK with jitter — always, regardless of hash_size or dedup.
        # Receiving and ACKing is the highest-priority guarantee.
        self._schedule_ack(raw_plaintext, peer_pubkey, now, route_type=route_type)

        # 2) Schedule PATH return — only if inbound used >=2-byte hashes.
        # We refuse to echo 1-byte paths; if the inbound was 1-byte we skip
        # the optional path hint. The peer still gets ACKed above and will
        # still get our reply below (via flood, since learn_route also
        # rejects 1-byte — see MIN_HASH_SIZE policy).
        if hash_size >= MIN_HASH_SIZE:
            self._schedule_path_return(peer_pubkey, path_hops, hash_size, now)

        events.emit(
            "dm.received",
            peer=peer_name,
            peer_pk=pk_hex,
            route=route_name(route_type),
            path_hops=len(path_hops),
            snr=snr,
            text_len=len(dm_text),
        )

        # 3) Text-level dedup
        if is_dm_duplicate(pk_hex, dm_text):
            self._metrics.inc("dm_text_duplicate")
            cached = self._cache.get(pk_hex, dm_text)
            # Only treat the duplicate as loss-recovery (resend cached reply)
            # if it's close in time to the original reply; older retries are
            # assumed to be the peer legitimately re-asking.
            if cached is None or (now - cached.ts) > REPLY_CACHE_RESEND_WINDOW_S:
                if cached is not None:
                    self._metrics.inc("cached_resend_skipped_stale")
                return
            # Don't pile on if the retry scheduler is still working the original.
            if self._pending.has_pending_for_peer(peer_pubkey):
                self._metrics.inc("cached_resend_skipped_pending")
                return
            jitter = random.uniform(
                ACK_JITTER_MIN_S + PATH_RETURN_DELAY_S, PATH_RETURN_DELAY_S + 0.3
            )
            self._tx.push(
                TxItem(
                    priority=TxPriority.REPLY_DIRECT,
                    not_before=now + jitter,
                    packet=cached.reply_packet,
                    label=f"DM(cached)->{peer_name}",
                    expected_ack=cached.expected_ack,
                    peer_pk=peer_pubkey,
                    attempt=1,
                    cached_reply=True,
                )
            )
            self._metrics.inc("reply_cached_resent")
            events.emit(
                "reply.cached_resend",
                peer=peer_name,
                peer_pk=pk_hex,
                ack_crc=cached.expected_ack.hex(),
                age_ms=int((now - cached.ts) * 1000),
            )
            logfmt.net(
                "duplicate DM from %s within %.0fs; re-sent cached reply",
                peer_name,
                now - cached.ts,
            )
            return

        logfmt.dm_in(peer_name, dm_text, route=route_name(route_type))

        # 4) Rate limit check — drops silently (ACK already queued)
        rl_key = f"dm:{pk_hex}"
        if not self._rl.check(rl_key):
            log.warning("rate limited DM: %s", peer_name)
            self._metrics.inc("dm_rate_limited")
            events.emit(
                "dm.rate_limited",
                peer=peer_name,
                peer_pk=pk_hex,
            )
            return

        # 5) Post reply work to worker (non-blocking)
        self._worker.submit(
            DmReplyWork(
                peer_pk=peer_pubkey,
                peer_name=peer_name,
                dm_text=dm_text,
                received_at=now,
            )
        )

    # -- pending-DM drain (run on IO thread, cheap decrypts only) ---

    def _process_pending_dms(self, node_hash: int, peer_label: str) -> None:
        pending = pop_pending_dms(node_hash)
        if not pending:
            return
        logfmt.net("processing %d pending DM(s) from %s", len(pending), peer_label)
        for pending_payload, ts in pending:
            if is_pending_expired(ts):
                continue
            result = try_decrypt_dm(pending_payload)
            if result is None:
                continue
            peer_pubkey, peer_name, dm_text, raw_plaintext = result
            pk_hex = peer_pubkey.hex()
            now = time.monotonic()

            # ACK always
            self._schedule_ack(raw_plaintext, peer_pubkey, now, route_type=1)

            if is_dm_duplicate(pk_hex, dm_text):
                continue

            logfmt.dm_in(peer_name, dm_text, route="pending")

            rl_key = f"dm:{pk_hex}"
            if not self._rl.check(rl_key):
                log.warning("rate limited pending DM: %s", peer_name)
                continue

            self._worker.submit(
                DmReplyWork(
                    peer_pk=peer_pubkey,
                    peer_name=peer_name,
                    dm_text=dm_text,
                    received_at=now,
                )
            )

    # -- helpers --------------------------------------------------

    def _schedule_ack(
        self,
        plaintext: bytes,
        peer_pubkey: bytes,
        now: float,
        route_type: int,
    ) -> None:
        """Schedule the ACK(s) for a received DM.

        Protocol (upstream Mesh::routeDirectRecvAcks + NodePrefs.multi_acks):

        * When :data:`MULTI_ACK_COUNT` > 0 AND we have a learned direct route
          to the peer: emit N MULTIPART ACKs with ``remaining`` counting down
          to 1, spaced ~300 ms apart, then the final plain ACK 300 ms later.
        * Otherwise: a single plain ACK with small jitter.

        MULTIPART ACKs on flood paths are NOT protocol-correct and would just
        burn airtime (receivers key MULTIPART handling to direct-route recv).
        """
        ack_crc = compute_ack_hash(plaintext, peer_pubkey)
        target_name = node_name(peer_pubkey.hex())
        jitter = random.uniform(ACK_JITTER_MIN_S, ACK_JITTER_MAX_S)

        use_multipart = MULTI_ACK_COUNT > 0 and get_route(peer_pubkey[0]) is not None

        if not use_multipart:
            packet = build_ack_packet(ack_crc, peer_pubkey[0])
            self._tx.push(
                TxItem(
                    priority=TxPriority.ACK,
                    not_before=now + jitter,
                    packet=packet,
                    label=f"ACK->0x{peer_pubkey[0]:02x}",
                )
            )
            self._metrics.inc("ack_sent")
            events.emit(
                "ack.sent",
                target_hash=peer_pubkey[0],
                target=target_name,
                ack_crc=ack_crc.hex(),
                route=route_name(route_type),
                jitter_ms=int(jitter * 1000),
                multipart=False,
            )
            return

        # MULTIPART chain: N MULTIPART packets (remaining N, N-1, ..., 1),
        # then final plain ACK, each 300 ms + jitter after the previous.
        cumulative = jitter
        for i in range(MULTI_ACK_COUNT):
            remaining = MULTI_ACK_COUNT - i
            multi_packet = build_multiack_packet(ack_crc, remaining, peer_pubkey[0])
            self._tx.push(
                TxItem(
                    priority=TxPriority.ACK,
                    not_before=now + cumulative,
                    packet=multi_packet,
                    label=f"MULTIACK->0x{peer_pubkey[0]:02x}(r={remaining})",
                )
            )
            self._metrics.inc("multiack_sent")
            cumulative += MULTI_ACK_SPACING_S
        # Final plain ACK
        final_packet = build_ack_packet(ack_crc, peer_pubkey[0])
        self._tx.push(
            TxItem(
                priority=TxPriority.ACK,
                not_before=now + cumulative,
                packet=final_packet,
                label=f"ACK->0x{peer_pubkey[0]:02x}",
            )
        )
        self._metrics.inc("ack_sent")
        events.emit(
            "ack.sent",
            target_hash=peer_pubkey[0],
            target=target_name,
            ack_crc=ack_crc.hex(),
            route=route_name(route_type),
            jitter_ms=int(jitter * 1000),
            multipart=True,
            multipart_count=MULTI_ACK_COUNT,
        )

    def _schedule_path_return(
        self,
        peer_pubkey: bytes,
        path_hops: list[bytes],
        hash_size: int,
        now: float,
    ) -> None:
        packet = build_path_return_packet(peer_pubkey, path_hops, hash_size)
        self._tx.push(
            TxItem(
                priority=TxPriority.PATH,
                not_before=now + PATH_RETURN_DELAY_S,
                packet=packet,
                label=f"PATH->{node_name(peer_pubkey.hex())}",
            )
        )
        self._metrics.inc("path_sent")


# ── Advert scheduling callback ───────────────────────────────────


def make_advert_pusher(
    build_advert_fn: Callable[[], bytes],
    metrics: Metrics,
) -> Callable[[TxQueue], None]:
    """Return a fn that enqueues an ADVERT onto the TxQueue."""

    def _advert_push(tx: TxQueue) -> None:
        packet = build_advert_fn()
        tx.push(
            TxItem(
                priority=TxPriority.ADVERT,
                not_before=time.monotonic(),
                packet=packet,
                label=f"ADVERT({BOT_NAME})",
            )
        )
        metrics.inc("advert_sent")
        events.emit("advert.sent", bot=BOT_NAME)
        logfmt.net("queued ADVERT as %s (hash=0x%02x)", BOT_NAME, my_hash())

    return _advert_push


__all__ = [
    "RateLimiter",
    "RxRouter",
    "make_advert_pusher",
]
