"""Runs the real Alembic migration and exercises the models against PostgreSQL.

Skipped unless HC_TEST_DATABASE_URL points to a disposable database, e.g.
    HC_TEST_DATABASE_URL=postgresql+asyncpg://huntcompiler:devpass@127.0.0.1:5432/huntcompiler_test
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

pytestmark = pytest.mark.integration

if not os.environ.get("HC_TEST_DATABASE_URL"):
    pytest.skip("HC_TEST_DATABASE_URL not set", allow_module_level=True)

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402

from app.db.models import HuntingPack, PivotedCluster, RawIntelEvent, Tenant  # noqa: E402
from app.db.session import build_engine, session_scope  # noqa: E402
from app.schemas.enums import AttackVector, DeliveryStatus, IntelSource  # noqa: E402
from app.schemas.hunting_pack import HuntingPackV2  # noqa: E402
from app.schemas.manifest import TenantManifest  # noqa: E402
from app.services.tenant_registry import ManifestSecretError, upsert_tenant  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SECRET = "s" * 40
TOKEN = "t" * 40


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


def _pack() -> HuntingPackV2:
    data = json.loads((ROOT / "contracts/examples/clickfix_pack.example.json").read_text(encoding="utf-8"))
    data.pop("pack_id")
    data.pop("expires_at")
    return HuntingPackV2.model_validate(data)


async def test_end_to_end_rows(engine):
    manifest = TenantManifest.from_yaml_file(ROOT / "config/tenant_manifest.yaml")

    async with session_scope(engine) as s:
        with pytest.raises(ManifestSecretError):
            await upsert_tenant(s, manifest, webhook_secret="short", api_token=TOKEN)

    async with session_scope(engine) as s:
        tenant, created = await upsert_tenant(s, manifest, webhook_secret=SECRET, api_token=TOKEN)
        assert created
        tenant_id = tenant.id

    async with session_scope(engine) as s:
        _, created = await upsert_tenant(s, manifest, webhook_secret=SECRET, api_token=TOKEN)
        assert not created
        # Secret is encrypted at rest but transparently decrypted by the ORM.
        raw = await s.scalar(text("SELECT webhook_secret FROM tenants WHERE id = :i"), {"i": tenant_id})
        assert raw != SECRET and raw.startswith("gAAAA")
        assert (await s.get(Tenant, tenant_id)).webhook_secret == SECRET
        hits = await s.scalars(select(Tenant).where(Tenant.tech_stack_tags.contains(["fortinet:fortigate"])))
        assert [t.slug for t in hits] == ["tencongty"]

    now = datetime.now(UTC)
    async with session_scope(engine) as s:
        event = RawIntelEvent(
            source=IntelSource.URLSCAN,
            external_id="urlscan-uuid-1",
            dedup_sha256=hashlib.sha256(b"urlscan-uuid-1").hexdigest(),
            attack_vector=AttackVector.CLICKFIX_FILELESS,
            observed_at=now,
            raw_payload={"verdict": "malicious"},
            observables=[{"type": "domain", "value": "verify-human-check.example"}],
        )
        cluster = PivotedCluster(
            cluster_key="v3:c2:verify-human-check.example",
            attack_vector=AttackVector.CLICKFIX_FILELESS,
            title="ClickFix lure cluster",
            base_confidence=72,
            current_confidence=72,
            first_seen_at=now,
            last_seen_at=now,
            observables={"domains": ["verify-human-check.example"]},
            events=[event],
        )
        s.add(cluster)
        await s.flush()
        cluster_id = cluster.id
        assert (
            await s.scalars(
                select(RawIntelEvent.id).where(
                    RawIntelEvent.observables.contains([{"type": "domain", "value": "verify-human-check.example"}])
                )
            )
        ).one() == event.id

    async with session_scope(engine) as s:
        dup = RawIntelEvent(
            source=IntelSource.URLSCAN,
            dedup_sha256=hashlib.sha256(b"urlscan-uuid-1").hexdigest(),
            observed_at=now,
            raw_payload={},
        )
        s.add(dup)
        with pytest.raises(IntegrityError):
            await s.flush()
        await s.rollback()

    tenant = None
    async with session_scope(engine) as s:
        tenant = await s.get(Tenant, tenant_id)
        p1 = HuntingPack.from_contract(
            _pack(), tenant_id=tenant_id, cluster_id=cluster_id, delivery_mode=tenant.delivery_mode
        )
        s.add(p1)
        await s.flush()
        assert p1.delivery_status is DeliveryStatus.AWAITING_PULL
        assert p1.to_contract().content_sha256() == p1.content_sha256
        first_seq = p1.seq

    # Same intelligence re-compiled later (new pack_id/timestamp) must be refused.
    async with session_scope(engine) as s:
        s.add(
            HuntingPack.from_contract(
                _pack(), tenant_id=tenant_id, cluster_id=cluster_id, delivery_mode=tenant.delivery_mode, version=2
            )
        )
        with pytest.raises(IntegrityError, match="uq_hunting_packs_tenant_id_content_sha256"):
            await s.flush()
        await s.rollback()

    async with session_scope(engine) as s:
        changed = _pack()
        changed.confidence_score = 81
        p2 = HuntingPack.from_contract(
            changed, tenant_id=tenant_id, cluster_id=cluster_id, delivery_mode=tenant.delivery_mode, version=2
        )
        s.add(p2)
        await s.flush()
        assert p2.seq > first_seq

    async with session_scope(engine) as s:
        with pytest.raises(IntegrityError, match="ck_hunting_packs_confidence_range"):
            await s.execute(text("UPDATE hunting_packs SET confidence_score = 101"))
        await s.rollback()

    # Cluster deletion is blocked while packs reference it (audit trail).
    async with session_scope(engine) as s:
        with pytest.raises(IntegrityError):
            await s.execute(text("DELETE FROM pivoted_clusters WHERE id = :i"), {"i": cluster_id})
        await s.rollback()

    # Deleting a tenant cascades to its packs.
    async with session_scope(engine) as s:
        await s.execute(text("DELETE FROM tenants WHERE id = :i"), {"i": tenant_id})
    async with session_scope(engine) as s:
        assert (await s.scalar(text("SELECT count(*) FROM hunting_packs"))) == 0
        assert uuid.UUID(str(cluster_id))
