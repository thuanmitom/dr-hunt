"""Telegram command bot: long polling, deny by default (TELEGRAM.md §2, §5; DECISIONS.md D-40, D-41, D-45).

* An update is handled only if its chat is in HC_TGBOT_CHAT_IDS **and** its sender is in HC_TGBOT_ALLOWED_USER_IDS.
  Anything else is logged (chat and user IDs only, so the operator can enrol them) and never answered.
* Commands read PostgreSQL (and Redis for health) only. No command makes a network request to user input.
* HC_TGBOT_TENANTS limits the digest **and** every command to those tenants.
* 10 commands per user per minute; extra commands are dropped silently.

Run: ``python -m app.integrations.telegram.bot`` (compose service ``telegram-bot``).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import redis.asyncio as aioredis
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.db.models import HuntingPack, PivotedCluster, RawIntelEvent, Tenant, cluster_event_links
from app.integrations.telegram import digest as digest_mod
from app.integrations.telegram.client import TelegramClient, TelegramError
from app.integrations.telegram.format import (
    IocMatch,
    cluster_label,
    render_cve,
    render_help,
    render_ioc,
    render_latest,
    render_pack_detail,
    render_status,
)
from app.processors.stager_unpacker import refang
from app.processors.whitelist_filter import WhitelistFilter, default_sources
from app.schemas.enums import AttackVector, ClusterStatus, DeliveryStatus
from app.schemas.manifest import TenantManifest
from app.schemas.validators import normalize_domain

log = logging.getLogger("telegram_bot")
RATE_LIMIT = 10
RATE_WINDOW_SECONDS = 60.0
_COMMAND = re.compile(r"^/([A-Za-z]{1,32})(?:@[A-Za-z0-9_]{3,64})?$")
_PACK_PREFIX = re.compile(r"^[0-9a-f]{8}[0-9a-f-]{0,28}$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
OBSERVABLE_KEYS = {"domain": ("domains_block", "domains_hunt"), "ip": ("ips_block", "ips_hunt"), "sha256": ("hashes",)}

WhitelistFactory = Callable[[list[str], list[str]], Awaitable[WhitelistFilter]]


def parse_command(text: str) -> tuple[str | None, list[str]]:
    """``/cmd@BotName arg ...`` -> ("cmd", ["arg", ...]); anything else -> (None, [])."""
    parts = (text or "").strip().split()
    if not parts or not (m := _COMMAND.match(parts[0])):
        return None, []
    return m.group(1).lower(), parts[1:5]


async def default_whitelist(domains: list[str], networks: list[str]) -> WhitelistFilter:
    # The bundled MISP warninglists load in ~10 s (CPU, offline): once, off the event loop.
    sources = await asyncio.to_thread(default_sources)
    return WhitelistFilter(sources, tenant_domains=domains, tenant_networks=networks)


class Bot:
    def __init__(self, settings: Settings, client: TelegramClient, sessionmaker: async_sessionmaker[AsyncSession],
                 redis: Any, *, whitelist_factory: WhitelistFactory = default_whitelist,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None:  # fmt: skip
        self.settings = settings
        self.client = client
        self.sessionmaker = sessionmaker
        self.redis = redis
        self.allowed_chats = frozenset(settings.tgbot_chat_ids)
        self.allowed_users = frozenset(settings.tgbot_allowed_user_ids)
        self.tenants = sorted(set(settings.tgbot_tenants))
        self.tz = ZoneInfo(settings.tgbot_timezone)
        self._whitelist_factory = whitelist_factory
        self._clock = clock
        self._sleep = sleep
        self._hits: dict[int, deque[float]] = defaultdict(deque)
        self._handlers: dict[str, Callable[[int, list[str]], Awaitable[None]]] = {
            "start": self.cmd_help, "help": self.cmd_help, "status": self.cmd_status, "digest": self.cmd_digest,
            "latest": self.cmd_latest, "pack": self.cmd_pack, "ioc": self.cmd_ioc, "cve": self.cmd_cve,
        }  # fmt: skip

    # --- gatekeeping --------------------------------------------------------------------------------
    def is_allowed(self, chat_id: Any, user_id: Any) -> bool:
        return chat_id in self.allowed_chats and user_id in self.allowed_users

    def _within_rate(self, user_id: int) -> bool:
        now, hits = self._clock(), self._hits[user_id]
        while hits and now - hits[0] >= RATE_WINDOW_SECONDS:
            hits.popleft()
        if len(hits) >= RATE_LIMIT:
            return False
        hits.append(now)
        return True

    async def handle_update(self, update: dict[str, Any]) -> None:
        if (cq := update.get("callback_query")) is not None:
            chat_id = ((cq.get("message") or {}).get("chat") or {}).get("id")
            user_id = (cq.get("from") or {}).get("id")
            if not self.is_allowed(chat_id, user_id):
                log.info("ignored callback from chat_id=%s user_id=%s (not in allowlist)", chat_id, user_id)
                return
            await self.client.answer_callback_query(str(cq.get("id", "")))  # no buttons are offered (TQ3)
            return
        msg = update.get("message")
        if not msg:
            return
        chat_id = (msg.get("chat") or {}).get("id")
        user_id = (msg.get("from") or {}).get("id")
        if not self.is_allowed(chat_id, user_id):
            log.info("ignored update from chat_id=%s user_id=%s (not in allowlist)", chat_id, user_id)
            return
        command, args = parse_command(msg.get("text") or "")
        if command is None:
            return
        if not self._within_rate(user_id):
            log.warning("rate limit reached for user_id=%s; command dropped", user_id)
            return
        handler = self._handlers.get(command)
        if handler is None:
            await self.reply(chat_id, "Unknown command. Send /help.")
            return
        try:
            await handler(chat_id, args)
        except TelegramError as exc:
            log.warning("command /%s: reply failed: %s", command, exc)
        except Exception as exc:  # noqa: BLE001 — one failing command must not stop the bot
            log.warning("command /%s failed: %s", command, type(exc).__name__)
            await self.reply(chat_id, "Internal error; details are in the bot log.")

    async def reply(self, chat_id: int, text: str) -> None:
        await self.client.send_message(chat_id, text)

    async def _send_files(self, chat_id: int, files: list[tuple[str, bytes, str]]) -> None:
        for i, (name, content, mime) in enumerate(files):
            if i and chat_id < 0:  # groups: at least 1 s between sends
                await self._sleep(1.0)
            await self.client.send_document(chat_id, name, content, mime=mime)

    def _scoped(self, stmt: Any) -> Any:
        return stmt.where(Tenant.slug.in_(self.tenants)) if self.tenants else stmt

    # --- commands ------------------------------------------------------------------------------------
    async def cmd_help(self, chat_id: int, _args: list[str]) -> None:
        await self.reply(chat_id, render_help())

    async def cmd_status(self, chat_id: int, _args: list[str]) -> None:
        now = datetime.now(UTC)
        async with self.sessionmaker() as session:
            health = await digest_mod.collect_health(session, self.redis, self.settings, now=now,
                                                     since=now - timedelta(hours=24))  # fmt: skip
            tenants = self._scoped(select(func.count(Tenant.id)).where(Tenant.is_active.is_(True)))
            packs = self._scoped(select(func.count(HuntingPack.id)).join(Tenant, Tenant.id == HuntingPack.tenant_id))
            awaiting = packs.where(HuntingPack.delivery_status == DeliveryStatus.AWAITING_PULL)
            counts = {
                "active tenants": int(await session.scalar(tenants) or 0),
                "raw events": int(await session.scalar(select(func.count(RawIntelEvent.id))) or 0),
                "active clusters": int(await session.scalar(
                    select(func.count(PivotedCluster.id)).where(PivotedCluster.status == ClusterStatus.ACTIVE)) or 0),
                "packs": int(await session.scalar(packs) or 0),
                "packs awaiting pull": int(await session.scalar(awaiting) or 0),
            }  # fmt: skip
        await self.reply(chat_id, render_status(health, counts, self.tz))

    async def cmd_digest(self, chat_id: int, _args: list[str]) -> None:
        await digest_mod.run_digest(self.sessionmaker, self.client, self.redis, self.settings,
                                    preview_chat_id=chat_id, sleep=self._sleep)  # fmt: skip

    async def cmd_latest(self, chat_id: int, args: list[str]) -> None:
        try:
            n = int(args[0]) if args else 5
        except ValueError:
            await self.reply(chat_id, "Usage: /latest [n] (1-20)")
            return
        n = max(1, min(20, n))
        async with self.sessionmaker() as session:
            stmt = (
                select(HuntingPack, Tenant.slug, PivotedCluster)
                .join(Tenant, Tenant.id == HuntingPack.tenant_id)
                .join(PivotedCluster, PivotedCluster.id == HuntingPack.cluster_id)
                .order_by(HuntingPack.seq.desc())
                .limit(500)
            )
            rows = list((await session.execute(self._scoped(stmt))).all())
        rank: dict[str, int] = {}
        for row in rows:  # newest pack first: first appearance = most recent cluster
            rank.setdefault(str(row[2].id), len(rank))
        keep = {cid for cid, r in rank.items() if r < n}
        lines = digest_mod.build_lines([r for r in rows if str(r[2].id) in keep], old_cluster_ids=set())
        await self.reply(chat_id, render_latest(sorted(lines, key=lambda line: rank[line.cluster_id])))

    async def cmd_pack(self, chat_id: int, args: list[str]) -> None:
        prefix = (args[0] if args else "").lower().lstrip("#")
        if not _PACK_PREFIX.match(prefix):
            await self.reply(chat_id, "Usage: /pack &lt;pack id prefix&gt; (at least 8 hex characters)")
            return
        async with self.sessionmaker() as session:
            stmt = (
                select(HuntingPack, Tenant.slug, PivotedCluster)
                .join(Tenant, Tenant.id == HuntingPack.tenant_id)
                .join(PivotedCluster, PivotedCluster.id == HuntingPack.cluster_id)
                .where(cast(HuntingPack.id, String).like(f"{prefix}%"))
                .limit(2)
            )
            rows = list((await session.execute(self._scoped(stmt))).all())
        if not rows:
            await self.reply(chat_id, "No pack matches that prefix.")
            return
        if len(rows) > 1:
            await self.reply(chat_id, "Ambiguous prefix: several packs match. Send more characters.")
            return
        pack, tenant, cluster = rows[0]
        payload = pack.payload
        label = cluster_label(cluster.cluster_key, cluster.title)
        await self.reply(chat_id, render_pack_detail(payload, tenant=tenant, label=label, version=pack.version,
                                                     tz=self.tz))  # fmt: skip
        await self._send_files(chat_id, pack_files(payload))

    async def cmd_ioc(self, chat_id: int, args: list[str]) -> None:
        raw = " ".join(args).strip()
        parsed = parse_ioc(raw) if 0 < len(raw) <= 2048 else None
        if parsed is None:
            await self.reply(chat_id, "Usage: /ioc &lt;domain | IP | SHA256&gt; (defanged input is accepted)")
            return
        kind, value = parsed
        async with self.sessionmaker() as session:
            manifests = [
                TenantManifest.model_validate(m)
                for m in (await session.scalars(self._scoped(select(Tenant.manifest).where(Tenant.is_active))))
            ]
            verdict = None
            if kind != "sha256":
                wl = await self._whitelist_factory(
                    [d for m in manifests for d in m.brand.domains + m.brand.email_domains],
                    [n for m in manifests for n in m.public_ip_ranges],
                )
                result = wl.check_domain(value) if kind == "domain" else wl.check_ip(value)
                verdict = (result.action.value, result.reason)
            conditions = [PivotedCluster.observables.contains({k: [value]}) for k in OBSERVABLE_KEYS[kind]]
            stmt = select(PivotedCluster).where(or_(*conditions)).order_by(PivotedCluster.last_seen_at.desc()).limit(10)
            if self.tenants:
                own = select(Tenant.id).where(Tenant.slug.in_(self.tenants))
                stmt = stmt.where(or_(PivotedCluster.tenant_id.is_(None), PivotedCluster.tenant_id.in_(own)))
            clusters = (await session.scalars(stmt)).all()
        matches = [IocMatch(cluster_label(c.cluster_key, c.title), AttackVector(c.attack_vector),
                            c.current_confidence, str(c.status), c.last_seen_at) for c in clusters]  # fmt: skip
        await self.reply(chat_id, render_ioc(value, kind, verdict, matches, self.tz))

    async def cmd_cve(self, chat_id: int, args: list[str]) -> None:
        cve = (args[0] if args else "").upper()
        if not _CVE.match(cve):
            await self.reply(chat_id, "Usage: /cve CVE-YYYY-NNNN")
            return
        async with self.sessionmaker() as session:
            cluster = await session.scalar(select(PivotedCluster).where(PivotedCluster.cluster_key == f"v2:cve:{cve}"))
            found = None
            if cluster is not None:
                event = await session.scalar(
                    select(RawIntelEvent)
                    .join(cluster_event_links, cluster_event_links.c.event_id == RawIntelEvent.id)
                    .where(cluster_event_links.c.cluster_id == cluster.id)
                    .order_by(RawIntelEvent.id.desc())
                    .limit(1)
                )
                matched = sorted(((event.raw_payload or {}).get("matched_tenants") or {}) if event else {})
                if self.tenants:
                    matched = [t for t in matched if t in self.tenants]
                packs_stmt = (
                    select(HuntingPack.id, HuntingPack.version, Tenant.slug)
                    .join(Tenant, Tenant.id == HuntingPack.tenant_id)
                    .where(HuntingPack.cluster_id == cluster.id)
                    .order_by(HuntingPack.seq.desc())
                    .limit(10)
                )
                packs = [{"pack_id": str(i), "version": v, "tenant": t}
                         for i, v, t in (await session.execute(self._scoped(packs_stmt))).all()]  # fmt: skip
                if matched or packs or not self.tenants:
                    features = (cluster.pivot_graph or {}).get("features") or {}
                    found = {
                        "title": cluster.title, "status": str(cluster.status), "confidence": cluster.current_confidence,
                        "last_seen": cluster.last_seen_at, "epss_percentile": features.get("epss_percentile"),
                        "credible_poc": features.get("credible_poc"), "nuclei": features.get("nuclei_template"),
                        "ransomware": features.get("ransomware_use"), "tenants": matched, "packs": packs,
                    }  # fmt: skip
        await self.reply(chat_id, render_cve(cve, found=found, tz=self.tz))

    # --- loop ------------------------------------------------------------------------------------------
    async def run(self) -> None:
        await self.client.delete_webhook()  # getUpdates does not work while a webhook is set
        offset: int | None = None
        backoff = 5.0
        log.info("telegram bot polling; %d chat(s) and %d user(s) allowlisted", len(self.allowed_chats),
                 len(self.allowed_users))  # fmt: skip
        while True:
            try:
                updates = await self.client.get_updates(offset, timeout=30)
                backoff = 5.0
            except TelegramError as exc:
                log.warning("getUpdates failed: %s; retrying in %.0fs", exc, backoff)
                await self._sleep(backoff)
                backoff = min(backoff * 2, 60.0)
                continue
            for update in updates:
                offset = max(offset or 0, int(update.get("update_id", 0)) + 1)
                try:
                    await self.handle_update(update)
                except Exception as exc:  # noqa: BLE001
                    log.warning("update %s failed: %s", update.get("update_id"), type(exc).__name__)


def parse_ioc(raw: str) -> tuple[str, str] | None:
    """Defanged input accepted. -> ("domain" | "ip" | "sha256", normalised value) or None."""
    value = refang(raw.strip()).strip()
    if _SHA256.match(value):
        return "sha256", value.lower()
    if "://" in value:
        value = urlsplit(re.sub(r"(?i)^h[xt]{2}p", "http", value)).hostname or ""
    try:
        return "ip", str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        pass
    try:
        return "domain", normalize_domain(value)
    except ValueError:
        return None


def pack_files(payload: dict[str, Any]) -> list[tuple[str, bytes, str]]:
    """pack-<id>.json, one Sigma .yml per task, queries-<id>.txt (Wazuh DSL + Defender KQL per task)."""
    pack_id = str(payload["pack_id"])
    files = [(f"pack-{pack_id}.json", json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True).encode(),
              "application/json")]  # fmt: skip
    queries = []
    for task in payload.get("internal_hunting_tasks") or []:
        files.append((f"{task['task_id']}.yml", task["sigma_yaml"].encode(), "text/plain"))
        compiled = task.get("compiled_queries") or {}
        queries.append(f"### {task['task_id']}")
        if compiled.get("wazuh_es_dsl") is not None:
            queries += ["# Wazuh / OpenSearch DSL", json.dumps(compiled["wazuh_es_dsl"], indent=2, sort_keys=True)]
        if compiled.get("kql_defender"):
            queries += ["# Microsoft Defender XDR KQL", compiled["kql_defender"]]
        queries.append("")
    files.append((f"queries-{pack_id}.txt", "\n".join(queries).encode(), "text/plain"))
    return files


async def _main(settings: Settings) -> None:
    from app.db.session import get_sessionmaker

    if settings.tgbot_token is None:  # checked by main(); explicit because asserts vanish under -O
        return

    redis = aioredis.from_url(settings.redis_url, socket_timeout=5)
    try:
        async with TelegramClient(settings.tgbot_token.get_secret_value(), timeout=60.0) as client:
            await Bot(settings, client, get_sessionmaker(), redis).run()
    finally:
        await redis.aclose()


def main() -> None:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # a request line every poll otherwise
    if not settings.tgbot_enabled or settings.tgbot_token is None:
        log.error("telegram bot disabled: set HC_TGBOT_ENABLED=true and HC_TGBOT_TOKEN, then restart")
        return
    if not settings.tgbot_chat_ids or not settings.tgbot_allowed_user_ids:
        log.warning("allowlist incomplete: every update is ignored. Send /start, read chat_id and user_id from "
                    "this log, set HC_TGBOT_CHAT_IDS and HC_TGBOT_ALLOWED_USER_IDS, then restart")  # fmt: skip
    asyncio.run(_main(settings))


if __name__ == "__main__":
    main()
