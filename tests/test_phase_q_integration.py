"""Phase Q on PostgreSQL: a KEV-only CVE reaches the tenants that run the product, and only them (D-64)."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.integration
if not os.environ.get("HC_TEST_DATABASE_URL"):
    pytest.skip("HC_TEST_DATABASE_URL not set", allow_module_level=True)

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.collectors.base import IntelSignal, Observable  # noqa: E402
from app.db.models import HuntingPack, Tenant  # noqa: E402
from app.db.session import build_engine, session_scope  # noqa: E402
from app.schemas.enums import AttackVector, IntelSource, Severity  # noqa: E402
from app.schemas.manifest import TenantManifest  # noqa: E402
from app.services.cluster_builder import cluster_pending_events  # noqa: E402
from app.services.intel_store import store_signals  # noqa: E402
from app.services.pack_builder import build_packs  # noqa: E402
from app.services.tenant_registry import upsert_tenant  # noqa: E402
from tests.fakes import synthetic_whitelist  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module", autouse=True)
def migrated_db():
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    yield
    command.downgrade(cfg, "base")


def _manifest(slug: str, tags: list[str]) -> TenantManifest:
    raw = yaml.safe_load((ROOT / "config/tenant_manifest.yaml").read_text(encoding="utf-8"))
    raw["tenant"] = {"slug": slug, "display_name": slug}
    raw["brand"] = {"domains": [f"{slug}.example"], "keywords": [slug]}
    raw["tech_stack_tags"] = tags
    return TenantManifest.model_validate(raw)


async def test_kev_alone_reaches_matching_tenants_only():
    now = datetime.now(UTC)
    added = datetime(now.year, now.month, now.day, tzinfo=UTC) - timedelta(days=1)  # dated at 00:00 UTC, a day old
    kev = IntelSignal(
        source=IntelSource.CISA_KEV, external_id="CVE-2026-7777", attack_vector=AttackVector.EDGE_DEVICE_EXPLOIT,
        title="CVE-2026-7777 Fortinet FortiOS (lab)", observed_at=added,
        raw_payload={"kev": {"cveID": "CVE-2026-7777", "vendorProject": "Fortinet", "product": "FortiOS"},
                     "epss": {"epss": 0.004, "percentile": 0.21}, "epss_alert": False, "nuclei_templates": [],
                     "matched_tenants": {"fortishop": ["fortinet:fortios"]}, "pocs": [], "enrichment_notes": []},
        observables=[Observable(type="cve", value="CVE-2026-7777")],
    )  # fmt: skip
    engine = build_engine(pooled=False)
    try:
        async with session_scope(engine) as s:
            await upsert_tenant(s, _manifest("fortishop", ["fortinet:fortios"]), webhook_secret="f" * 40,
                                api_token="g" * 40)  # fmt: skip
            await upsert_tenant(s, _manifest("exchangeshop", ["microsoft:exchange_server"]), webhook_secret="h" * 40,
                                api_token="i" * 40)  # fmt: skip
            assert await store_signals(s, [kev]) == 1
        async with session_scope(engine) as s:
            assert await cluster_pending_events(s, synthetic_whitelist(), now=now + timedelta(minutes=31)) == 1
        async with session_scope(engine) as s:
            assert await build_packs(s, now=now) == 1
        async with session_scope(engine) as s:
            rows = (await s.execute(select(Tenant.slug, HuntingPack.confidence_score, HuntingPack.severity)
                                    .join(Tenant, Tenant.id == HuntingPack.tenant_id))).all()  # fmt: skip
    finally:
        await engine.dispose()
    [(slug, confidence, severity)] = rows  # negative: the tenant without FortiOS gets nothing
    assert slug == "fortishop" and 60 <= confidence <= 70 and severity is Severity.HIGH
