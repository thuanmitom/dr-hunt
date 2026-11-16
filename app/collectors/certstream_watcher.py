"""Long-running CertStream consumer (its own container, not a Celery task).

Matches every newly issued certificate's SANs against tenant brand keywords and hands matches
to Celery (``collectors.ingest_signals``). Run: ``python -m app.collectors.certstream_watcher``.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any

import certstream
import redis

from app.collectors.base import IntelSignal, Observable
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import build_engine, session_scope
from app.processors.brand_matcher import BrandMatcher
from app.schemas.enums import AttackVector, IntelSource
from app.services.tenant_context import load_active_tenants
from app.worker import health
from app.worker.celery_app import celery_app

log = logging.getLogger("certstream_watcher")
REFRESH_SECONDS = 300
DEDUP_TTL_SECONDS = 7 * 24 * 3600
HEARTBEAT_SECONDS = 60


class Watcher:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.redis = redis.Redis.from_url(self.settings.redis_url)
        self._matchers: list[tuple[Any, BrandMatcher]] = []
        self._lock = threading.Lock()
        self._last_beat = 0.0

    def refresh_tenants(self) -> None:
        async def _load() -> list[tuple[Any, BrandMatcher]]:
            engine = build_engine(pooled=False)
            try:
                async with session_scope(engine) as session:
                    tenants = await load_active_tenants(session)
            finally:
                await engine.dispose()
            return [
                (
                    t.id,
                    BrandMatcher(t.manifest.brand.keywords, t.manifest.brand.domains + t.manifest.brand.email_domains),
                )
                for t in tenants
                if t.manifest.brand.keywords
            ]

        matchers = asyncio.run(_load())
        with self._lock:
            self._matchers = matchers
        log.info("brand matchers loaded for %d tenant(s)", len(matchers))

    def _refresh_loop(self) -> None:
        while True:
            time.sleep(REFRESH_SECONDS)
            try:
                self.refresh_tenants()
            except Exception:  # noqa: BLE001 — keep the stream alive on transient DB errors
                log.exception("tenant refresh failed")

    def on_message(self, message: dict[str, Any], _context: Any) -> None:
        if message.get("message_type") != "certificate_update":
            return
        if time.monotonic() - self._last_beat >= HEARTBEAT_SECONDS:  # stale in the digest if the stream stops
            self._last_beat = time.monotonic()
            health.record("certstream", health.Outcome.OK, client=self.redis)
        leaf = message.get("data", {}).get("leaf_cert", {})
        domains = {d.lower().removeprefix("*.") for d in leaf.get("all_domains", [])}
        with self._lock:
            matchers = list(self._matchers)
        signals = []
        for tenant_id, matcher in matchers:
            for domain in domains:
                hit = matcher.match(domain)
                if hit is None or not self.redis.set(f"hc:ct:{tenant_id}:{domain}", 1, nx=True, ex=DEDUP_TTL_SECONDS):
                    continue
                signals.append(
                    IntelSignal(
                        source=IntelSource.CERTSTREAM,
                        tenant_id=tenant_id,
                        attack_vector=AttackVector.IDENTITY_AITM_INFOSTEALER,
                        title=f"Lookalike certificate: {domain} (~'{hit.keyword}', {hit.technique})",
                        raw_payload={
                            "keyword": hit.keyword,
                            "technique": hit.technique,
                            "issuer": (leaf.get("issuer") or {}).get("O"),
                            "not_before": leaf.get("not_before"),
                            "san_count": len(domains),
                        },
                        observables=[Observable(type="domain", value=domain)],
                    ).model_dump(mode="json")
                )
        if signals:
            celery_app.send_task("collectors.ingest_signals", args=[signals])

    def run(self) -> None:
        self.refresh_tenants()
        threading.Thread(target=self._refresh_loop, daemon=True).start()
        certstream.listen_for_events(self.on_message, url=self.settings.certstream_url, setup_logger=False)


if __name__ == "__main__":
    configure_logging(get_settings().log_level, get_settings().log_format)
    Watcher().run()
