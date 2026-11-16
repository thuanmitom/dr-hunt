"""Phase H on PostgreSQL: API rate limits and uniform auth errors (H2), data retention (H3), and the dispatcher no
longer relying on an ``assert`` (H6)."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import yaml

pytestmark = pytest.mark.integration
if not os.environ.get("HC_TEST_DATABASE_URL"):
    pytest.skip("HC_TEST_DATABASE_URL not set", allow_module_level=True)

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import func, select, update  # noqa: E402

from app.api.main import create_app  # noqa: E402
from app.api.ratelimit import RateLimiter  # noqa: E402
from app.collectors.base import IntelSignal, Observable  # noqa: E402
from app.core.crypto import sha256_hex  # noqa: E402
from app.core.signing import build_signed_headers, canonical_json  # noqa: E402
from app.db.models import AiCompilation, HuntingPack, PivotedCluster, RawIntelEvent, Tenant  # noqa: E402
from app.db.models.pivoted_cluster import cluster_event_links  # noqa: E402
from app.db.session import build_engine, get_session, session_scope  # noqa: E402
from app.dispatch.dispatcher import deliver_due  # noqa: E402
from app.schemas.enums import AttackVector, ClusterStatus, DeliveryMode, DeliveryStatus, IntelSource  # noqa: E402
from app.schemas.manifest import TenantManifest  # noqa: E402
from app.services.cluster_builder import cluster_pending_events  # noqa: E402
from app.services.intel_store import store_signals  # noqa: E402
from app.services.pack_builder import build_packs  # noqa: E402
from app.services.retention import purge_old_data  # noqa: E402
from app.services.tenant_registry import upsert_tenant  # noqa: E402
from tests.fakes import synthetic_whitelist  # noqa: E402
from tests.test_phase_h import Clock, MemoryRedis  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PULL_SECRET, PULL_TOKEN, PUSH_SECRET = "p" * 40, "t" * 40, "q" * 40


@pytest.fixture(scope="module", autouse=True)
def migrated_db():
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    yield
    command.downgrade(cfg, "base")


@pytest.fixture
async def engine():
    eng = build_engine(pooled=False)
    yield eng
    await eng.dispose()


def _kev(cve: str, now: datetime) -> IntelSignal:
    return IntelSignal(
        source=IntelSource.CISA_KEV, external_id=cve, attack_vector=AttackVector.EDGE_DEVICE_EXPLOIT,
        title=f"{cve} Fortinet FortiOS (lab)", observed_at=now,
        raw_payload={"kev": {"cveID": cve, "vendorProject": "Fortinet", "product": "FortiOS"},
                     "epss": {"epss": 0.4, "percentile": 0.95}, "epss_alert": True, "nuclei_templates": [],
                     "matched_tenants": {"tencongty": ["fortinet:fortios"]}, "pocs": [], "enrichment_notes": []},
        observables=[Observable(type="cve", value=cve)],
    )  # fmt: skip


def _push_manifest() -> TenantManifest:
    raw = yaml.safe_load((ROOT / "config/tenant_manifest.yaml").read_text(encoding="utf-8"))
    raw["tenant"] = {"slug": "acme-push", "display_name": "Acme"}
    raw["brand"] = {"domains": ["acme-corp.com.vn"], "keywords": ["acmecorp"]}
    raw["delivery"] = {"mode": "push", "webhook_url": "https://soar.acme-corp.com.vn/hook",
                       "secret_env": "HC_TENANT_ACME_HMAC_SECRET"}  # fmt: skip
    return TenantManifest.model_validate(raw)


async def test_dispatcher_hands_packs_to_pull_and_api_limits(engine):
    now = datetime.now(UTC)
    async with session_scope(engine) as s:
        await upsert_tenant(s, TenantManifest.from_yaml_file(ROOT / "config/tenant_manifest.yaml"),
                            webhook_secret=PULL_SECRET, api_token=PULL_TOKEN)  # fmt: skip
        push, _ = await upsert_tenant(s, _push_manifest(), webhook_secret=PUSH_SECRET, api_token=None)
        assert await store_signals(s, [_kev("CVE-2026-4001", now)]) == 1
    async with session_scope(engine) as s:
        assert await cluster_pending_events(s, synthetic_whitelist(), now=now + timedelta(minutes=31)) == 1
    async with session_scope(engine) as s:
        assert await build_packs(s, now=now) == 2

    # H6.1: the push tenant switched to pull after its pack was queued -> handed to the pull API, no crash, no call
    async with session_scope(engine) as s:  # what a manifest reload to `mode: pull` does
        await s.execute(update(Tenant).where(Tenant.id == push.id).values(
            delivery_mode=DeliveryMode.PULL, webhook_url=None, api_token_sha256=sha256_hex("n" * 40)))  # fmt: skip

    def no_network(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected webhook call to {request.url}")

    async with session_scope(engine) as s, httpx.AsyncClient(transport=httpx.MockTransport(no_network)) as client:
        counts = await deliver_due(s, client, now=now)
    assert counts["awaiting_pull"] == 1 and counts["dead_letter"] == 0
    async with session_scope(engine) as s:
        status = await s.scalar(select(HuntingPack.delivery_status).where(HuntingPack.tenant_id == push.id))
    assert status is DeliveryStatus.AWAITING_PULL

    # H2: rate limits and uniform errors
    app = create_app()

    async def _session():
        async with session_scope(engine) as s:
            yield s

    app.dependency_overrides[get_session] = _session
    clock = Clock()
    good = {"Authorization": f"Bearer {PULL_TOKEN}"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://hc") as api:
        app.state.limiter = RateLimiter(MemoryRedis(clock), per_minute=3, auth_failures=5, auth_window=600,
                                        clock=clock)  # fmt: skip
        assert [(await api.get("/api/v1/packs", headers=good)).status_code for _ in range(3)] == [200, 200, 200]
        over = await api.get("/api/v1/packs", headers=good)
        assert over.status_code == 429 and int(over.headers["Retry-After"]) > 0

        # an unknown tenant slug fails exactly like a wrong signature for a real one (no slug enumeration)
        app.state.limiter = RateLimiter(MemoryRedis(clock), per_minute=60, auth_failures=5, auth_window=600,
                                        clock=clock)  # fmt: skip
        body = canonical_json({"pack_id": "00000000-0000-4000-8000-000000000000", "sighting": False,
                               "evaluable": True, "evaluated_at": now.isoformat()})  # fmt: skip
        real = build_signed_headers("wrong-secret-" + "x" * 30, body, tenant_slug="tencongty")
        ghost = build_signed_headers("wrong-secret-" + "x" * 30, body, tenant_slug="no-such-tenant")
        r1 = await api.post("/api/v1/feedback", content=body, headers=real)
        r2 = await api.post("/api/v1/feedback", content=body, headers=ghost)
        assert r1.status_code == r2.status_code == 401 and r1.json() == r2.json() == {"detail": "signature mismatch"}

        # brute force: after the failures allowed, even a valid token from that IP waits
        app.state.limiter = RateLimiter(MemoryRedis(clock), per_minute=60, auth_failures=2, auth_window=600,
                                        clock=clock)  # fmt: skip
        bad = {"Authorization": "Bearer " + "z" * 40}
        assert [(await api.get("/api/v1/packs", headers=bad)).status_code for _ in range(2)] == [401, 401]
        blocked = await api.get("/api/v1/packs", headers=good)
        assert blocked.status_code == 429 and blocked.json() == {"detail": "too many failed authentications"}
        clock.t += 600
        assert (await api.get("/api/v1/packs", headers=good)).status_code == 200


async def test_retention_keeps_active_clusters_and_purges_the_rest(engine):
    now = datetime.now(UTC)
    old, recent = now - timedelta(days=100), now - timedelta(days=5)
    async with session_scope(engine) as s:
        assert await store_signals(s, [_kev("CVE-2026-5001", now), _kev("CVE-2026-5002", now)]) == 2
    async with session_scope(engine) as s:
        assert await cluster_pending_events(s, synthetic_whitelist(), now=now + timedelta(minutes=31)) == 2
    async with session_scope(engine) as s:
        clusters = {c.cluster_key: c for c in (await s.scalars(select(PivotedCluster))).all()}
        active = next(c for k, c in clusters.items() if "cve-2026-5001" in k.lower())
        expired = next(c for k, c in clusters.items() if "cve-2026-5002" in k.lower())
        expired.status = ClusterStatus.EXPIRED
        await s.execute(update(RawIntelEvent).where(RawIntelEvent.external_id.in_(["CVE-2026-5001", "CVE-2026-5002"]))
                        .values(ingested_at=old))  # fmt: skip
        s.add_all([
            RawIntelEvent(source=IntelSource.MALWAREBAZAAR, external_id="old-unlinked", dedup_sha256="a" * 64,
                          observed_at=old, ingested_at=old, raw_payload={}),
            RawIntelEvent(source=IntelSource.MALWAREBAZAAR, external_id="recent-unlinked", dedup_sha256="b" * 64,
                          observed_at=recent, ingested_at=recent, raw_payload={}),
        ])  # fmt: skip
        for age in (200, 10):
            s.add(AiCompilation(cluster_id=active.id, provider="fake", model="lab", prompt_version="v1",
                                input_sha256=f"{age:064d}", input_chars=1, status="accepted",
                                created_at=now - timedelta(days=age)))  # fmt: skip
        active_id, expired_id = active.id, expired.id

    async with session_scope(engine) as s:  # negative: 0 keeps everything
        assert await purge_old_data(s, now=now, raw_event_days=0, ai_compilation_days=0) == {
            "raw_intel_events": 0, "ai_compilations": 0}  # fmt: skip
    async with session_scope(engine) as s:
        deleted = await purge_old_data(s, now=now, raw_event_days=90, ai_compilation_days=180)
    assert deleted == {"raw_intel_events": 2, "ai_compilations": 1}

    async with session_scope(engine) as s:
        left = set((await s.scalars(select(RawIntelEvent.external_id).where(RawIntelEvent.external_id.in_(
            ["CVE-2026-5001", "CVE-2026-5002", "old-unlinked", "recent-unlinked"])))).all())  # fmt: skip
        assert left == {"CVE-2026-5001", "recent-unlinked"}
        assert await s.scalar(select(func.count()).select_from(cluster_event_links)
                              .where(cluster_event_links.c.cluster_id == expired_id)) == 0  # fmt: skip
        assert {c.id for c in (await s.scalars(select(PivotedCluster))).all()} >= {active_id, expired_id}
        assert await s.scalar(select(func.count()).select_from(AiCompilation)) == 1
