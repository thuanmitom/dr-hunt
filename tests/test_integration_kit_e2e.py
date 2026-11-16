"""End-to-end on PostgreSQL: HuntCompiler builds packs; the reference consumer pulls them through the real API,
verifies and re-validates them, substitutes placeholders, resolves an exposed account against a directory, hunts on
a fake Wazuh indexer, and posts feedback that HuntCompiler records on the packs and clusters."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

pytestmark = pytest.mark.integration
if not os.environ.get("HC_TEST_DATABASE_URL"):
    pytest.skip("HC_TEST_DATABASE_URL not set", allow_module_level=True)

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.api.main import create_app  # noqa: E402
from app.collectors.base import IntelSignal, Observable  # noqa: E402
from app.collectors.reference_data import Dataset, dataset_signal  # noqa: E402
from app.collectors.telegram_cti import CtiMessage, TenantWatch, scan_message  # noqa: E402
from app.db.models import HuntingPack, PivotedCluster, ReferenceDataset  # noqa: E402
from app.db.session import build_engine, get_session, session_scope  # noqa: E402
from app.processors.leak_redactor import account_key  # noqa: E402
from app.schemas.enums import AttackVector, IntelSource  # noqa: E402
from app.schemas.manifest import TenantManifest  # noqa: E402
from app.services.cluster_builder import cluster_pending_events  # noqa: E402
from app.services.intel_store import store_signals  # noqa: E402
from app.services.pack_builder import build_packs  # noqa: E402
from app.services.tenant_registry import upsert_tenant  # noqa: E402
from integration_kit.reference_consumer.accounts import DirectoryUser  # noqa: E402
from integration_kit.reference_consumer.adapters.wazuh import WazuhAdapter  # noqa: E402
from integration_kit.reference_consumer.client import HuntCompilerClient  # noqa: E402
from integration_kit.reference_consumer.config import KitConfig  # noqa: E402
from integration_kit.reference_consumer.runner import Runner  # noqa: E402
from integration_kit.reference_consumer.state import State  # noqa: E402
from tests.fakes import synthetic_whitelist  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SECRET, TOKEN = "k" * 40, "b" * 40
TELEMETRY = frozenset({"sysmon:1", "sysmon:3", "sysmon:6", "sysmon:7", "sysmon:11", "sysmon:13", "sysmon:22",
                       "windows_security:4624", "windows_security:4625", "windows_system:7045"})  # fmt: skip


@pytest.fixture(scope="module", autouse=True)
def migrated_db():
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    yield
    command.downgrade(cfg, "base")


async def _world() -> None:
    now = datetime.now(UTC)
    engine = build_engine(pooled=False)
    try:
        manifest = TenantManifest.from_yaml_file(ROOT / "config/tenant_manifest.yaml")
        async with session_scope(engine) as s:
            tenant, _ = await upsert_tenant(s, manifest, webhook_secret=SECRET, api_token=TOKEN)
            watch = TenantWatch(tenant.id, ["tencongty.vn"], manifest.portal_hostnames(), account_key(SECRET))
            leak = "URL: https://sso.tencongty.vn/\nUsername: a.nguyen@tencongty.vn\nPassword: x\n"
            signals = scan_message(CtiMessage("@feed", 9, now, leak, False), [watch])
            signals.append(IntelSignal(
                source=IntelSource.CISA_KEV, external_id="CVE-2026-2222", attack_vector=AttackVector.EDGE_DEVICE_EXPLOIT,
                title="CVE-2026-2222 Fortinet FortiOS", observed_at=now,
                raw_payload={"kev": {"cveID": "CVE-2026-2222", "vendorProject": "Fortinet", "product": "FortiOS"},
                             "epss": {"epss": 0.5, "percentile": 0.97}, "epss_alert": True, "nuclei_templates": [],
                             "matched_tenants": {"tencongty": ["fortinet:fortios"]}, "pocs": []},
                observables=[Observable(type="cve", value="CVE-2026-2222")]))  # fmt: skip
            drivers = Dataset("loldrivers", [{"id": "d1", "category": "vulnerable driver", "created": "2026-10-01",
                                              "filenames": ["rtcore64.sys"], "sha256": ["c" * 64]}])  # fmt: skip
            s.add(ReferenceDataset(name="loldrivers", version=drivers.version, record_count=1, records=drivers.records,
                                   fetched_at=now))  # fmt: skip
            signals.append(dataset_signal(drivers, set()))
            assert await store_signals(s, signals) == 3
        async with session_scope(engine) as s:
            assert await cluster_pending_events(s, synthetic_whitelist(), now=now + timedelta(minutes=31)) == 3
        async with session_scope(engine) as s:
            assert await build_packs(s, now=now) == 3  # V1 exposure, V2 edge CVE, V5 drivers
    finally:
        await engine.dispose()


def test_reference_consumer_round_trip_through_the_real_api(tmp_path):
    asyncio.run(_world())
    app = create_app()

    async def _session():
        engine = build_engine(pooled=False)
        try:
            async with session_scope(engine) as s:
                yield s
        finally:
            await engine.dispose()

    app.dependency_overrides[get_session] = _session
    wazuh_bodies: list[dict] = []

    def wazuh(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        wazuh_bodies.append(body)
        hits = 2 if '"4625"' in json.dumps(body) else 0  # the exposed account is being tried
        return httpx.Response(200, json={"hits": {"total": {"value": hits}, "hits": []}})

    cfg = KitConfig(base_url="https://testserver", tenant="tencongty", api_token=TOKEN, hmac_secret=SECRET,
                    state_dir=tmp_path / "state", platform="wazuh", telemetry=TELEMETRY,
                    placeholders={"EDGE_DEVICE_INTERNAL_IPS": ["10.0.0.1"]})  # fmt: skip
    with TestClient(app, base_url="https://testserver") as hc_http:
        client = HuntCompilerClient(hc_http, base_url=cfg.base_url, api_token=TOKEN, hmac_secret=SECRET,
                                    tenant="tencongty")  # fmt: skip
        adapter = WazuhAdapter(httpx.Client(transport=httpx.MockTransport(wazuh)), url="https://wazuh.example:9200")
        runner = Runner(cfg, adapter, State(cfg.state_dir), client,
                        directory=[DirectoryUser("a.nguyen@tencongty.vn", "anguyen")])  # fmt: skip
        assert runner.pull() == {"queued": 3, "duplicate": 0, "rejected": 0}
        outcomes = {o.pack_id: o for o in runner.run_inbox()}
        assert runner.pull() == {"queued": 0, "duplicate": 0, "rejected": 0}  # cursor moved past everything

    exposure_body = next(b for b in wazuh_bodies if '"4625"' in json.dumps(b))
    assert "anguyen" in json.dumps(exposure_body)  # the ref was resolved locally into the SAM account name
    assert any("10.0.0.1" in json.dumps(b) for b in wazuh_bodies)  # edge placeholder substituted

    async def check() -> None:
        engine = build_engine(pooled=False)
        try:
            async with session_scope(engine) as s:
                rows = (await s.execute(select(HuntingPack, PivotedCluster).join(
                    PivotedCluster, PivotedCluster.id == HuntingPack.cluster_id))).all()  # fmt: skip
                assert len(rows) == 3
                for pack, cluster in rows:
                    outcome = outcomes[str(pack.id)]
                    assert pack.feedback_received_at is not None and pack.evaluable is True
                    assert pack.sighting is outcome.sighting
                    if cluster.cluster_key.endswith(":credential-exposure"):
                        assert pack.sighting and cluster.sighting_count == 1
                    else:
                        assert not pack.sighting and cluster.clean_count == 1
        finally:
            await engine.dispose()

    asyncio.run(check())
    reports = sorted((tmp_path / "state/done").glob("*.json"))
    assert len(reports) == 3 and all(json.loads(p.read_text(encoding="utf-8"))["feedback_status"] == "recorded"
                                     for p in reports)  # fmt: skip
