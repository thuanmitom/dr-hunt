from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration
if not os.environ.get("HC_TEST_DATABASE_URL"):
    pytest.skip("HC_TEST_DATABASE_URL not set", allow_module_level=True)

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.collectors.reference_data import Dataset, dataset_signal  # noqa: E402
from app.collectors.telegram_cti import CtiMessage, TenantWatch, scan_message  # noqa: E402
from app.db.models import HuntingPack, ReferenceDataset  # noqa: E402
from app.db.session import build_engine, session_scope  # noqa: E402
from app.processors.leak_redactor import account_key  # noqa: E402
from app.schemas.enums import AttackVector  # noqa: E402
from app.schemas.manifest import TenantManifest  # noqa: E402
from app.services.cluster_builder import cluster_pending_events  # noqa: E402
from app.services.intel_store import store_signals  # noqa: E402
from app.services.pack_builder import build_packs  # noqa: E402
from app.services.tenant_registry import upsert_tenant  # noqa: E402
from tests.fakes import synthetic_whitelist  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SECRET = "z" * 40


@pytest.fixture(scope="module", autouse=True)
def migrated_db():
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    yield
    command.downgrade(cfg, "base")


async def test_leak_and_dataset_to_packs():
    engine = build_engine(pooled=False)
    now = datetime.now(UTC)
    try:
        manifest = TenantManifest.from_yaml_file(ROOT / "config/tenant_manifest.yaml")
        async with session_scope(engine) as s:
            tenant, _ = await upsert_tenant(s, manifest, webhook_secret=SECRET, api_token="t" * 40)
            watch = TenantWatch(tenant.id, ["tencongty.vn"], manifest.portal_hostnames(), account_key(SECRET))
            leak = "URL: https://sso.tencongty.vn/\nUsername: a.nguyen@tencongty.vn\nPassword: x\n\nb.tran@tencongty.vn:pw\nc.le@tencongty.vn:pw"
            signals = scan_message(CtiMessage("@feed", 7, now, leak, False), [watch])
            drivers = Dataset("loldrivers", [{"id": "d1", "category": "vulnerable driver", "created": "2026-10-01",
                                              "filenames": ["rtcore64.sys"], "sha256": ["c" * 64]}])  # fmt: skip
            s.add(ReferenceDataset(name="loldrivers", version=drivers.version, record_count=1, records=drivers.records,
                                   fetched_at=now))  # fmt: skip
            signals.append(dataset_signal(drivers, set()))
            assert await store_signals(s, signals) == 2
        async with session_scope(engine) as s:
            assert await cluster_pending_events(s, synthetic_whitelist(), now=now + timedelta(minutes=31)) == 2
        async with session_scope(engine) as s:
            assert await build_packs(s, now=now) == 2
            packs = {p.attack_vector: p.payload for p in (await s.scalars(select(HuntingPack))).all()}
        leak_pack = packs[AttackVector.IDENTITY_AITM_INFOSTEALER]
        assert len(leak_pack["affected_accounts"]) == 3
        assert leak_pack["soar_playbook_hints"]["notify_only_on_sighting"] is False
        assert "a.nguyen" not in str(leak_pack) and leak_pack["confidence_score"] == 80
        task_ids = {t["task_id"] for t in leak_pack["internal_hunting_tasks"]}
        assert task_ids == {"v1-exposed-account-failed-logons"}
        v5 = packs[AttackVector.BYOVD_DLL_SIDELOAD]
        assert "c" * 64 in str(v5) and {t["task_id"] for t in v5["internal_hunting_tasks"]} >= {
            "v5-loldrivers-hash-load"
        }
    finally:
        await engine.dispose()
