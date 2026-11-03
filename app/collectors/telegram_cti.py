"""Telegram CTI channel monitor (Vector 1: infostealer / combolist exposure).

Reads message TEXT only from channels the operator configured. Attachments (log archives) are
never downloaded. Matches are converted to pseudonymous account refs immediately; the message
text itself is not persisted. Monitoring criminal channels has legal implications — only watch
channels your organisation is permitted to monitor, from a dedicated research account.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from app.collectors.base import IntelSignal
from app.processors.leak_redactor import find_exposures, stealer_family_hints
from app.schemas.enums import AttackVector, IntelSource


@dataclass(frozen=True, slots=True)
class CtiMessage:
    channel: str
    id: int
    date: datetime
    text: str
    has_media: bool


class MessageSource(Protocol):
    async def fetch(self, channel: str, min_id: int, limit: int) -> list[CtiMessage]: ...


class TelethonSource:
    def __init__(self, api_id: int, api_hash: str, session: str) -> None:
        self._args = (api_id, api_hash, session)

    async def fetch(self, channel: str, min_id: int, limit: int) -> list[CtiMessage]:
        from telethon import TelegramClient
        from telethon.sessions import StringSession

        api_id, api_hash, session = self._args
        out: list[CtiMessage] = []
        async with TelegramClient(StringSession(session), api_id, api_hash) as client:
            async for m in client.iter_messages(channel, min_id=min_id, limit=limit, reverse=True):
                out.append(CtiMessage(channel, m.id, m.date, m.message or "", m.media is not None))
        return out


@dataclass(frozen=True, slots=True)
class TenantWatch:
    tenant_id: uuid.UUID
    domains: list[str]
    portal_hosts: list[str]
    key: bytes


def scan_message(msg: CtiMessage, watches: list[TenantWatch]) -> list[IntelSignal]:
    signals = []
    for w in watches:
        exposures, lines = find_exposures(msg.text, domains=w.domains, portal_hosts=w.portal_hosts, key=w.key)
        if not exposures:
            continue
        signals.append(
            IntelSignal(
                source=IntelSource.TELEGRAM_CTI,
                external_id=f"{msg.channel}:{msg.id}",
                tenant_id=w.tenant_id,
                attack_vector=AttackVector.IDENTITY_AITM_INFOSTEALER,
                title=f"{len(exposures)} account(s) exposed in Telegram channel {msg.channel}",
                observed_at=msg.date,
                raw_payload={
                    "channel": msg.channel,
                    "message_id": msg.id,
                    "matched_lines": lines,
                    "has_media": msg.has_media,
                    "families": stealer_family_hints(msg.text),
                    "accounts": [{"ref": e.ref, "masked": e.masked, "host": e.host} for e in exposures],
                },
                redacted=True,
            )
        )
    return signals


async def collect_telegram(source: MessageSource, channels: list[str], watches: list[TenantWatch], *,
                           cursors: dict[str, int], limit: int = 200) -> tuple[list[IntelSignal], dict[str, int]]:  # fmt: skip
    signals: list[IntelSignal] = []
    new_cursors = dict(cursors)
    for channel in channels:
        for msg in await source.fetch(channel, cursors.get(channel, 0), limit):
            new_cursors[channel] = max(new_cursors.get(channel, 0), msg.id)
            if msg.text:
                signals += scan_message(msg, watches)
    return signals, new_cursors
