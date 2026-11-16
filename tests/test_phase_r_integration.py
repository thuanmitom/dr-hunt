"""Phase R on PostgreSQL: OS or desktop KEV entries become patch reminders instead of edge packs (D-70)."""

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
from sqlalchemy import delete, select  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker  # noqa: E402

from app.collectors.base import IntelSignal, Observable  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.db.models import HuntingPack, PivotedCluster, TelegramDigest, Tenant  # noqa: E402
from app.db.session import build_engine, session_scope  # noqa: E402
from app.integrations.telegram.client import TelegramClient  # noqa: E402
from app.integrations.telegram.digest import run_digest  # noqa: E402
from app.schemas.enums import AttackVector, IntelSource  # noqa: E402
from app.schemas.manifest import TenantManifest  # noqa: E402
from app.services.cluster_builder import cluster_pending_events  # noqa: E402
from app.services.intel_store import store_signals  # noqa: E402
from app.services.pack_builder import build_packs  # noqa: E402
from app.services.tenant_registry import upsert_tenant  # noqa: E402
from tests.fakes import synthetic_whitelist  # noqa: E402
from tests.telegram_fakes import CHAT, TOKEN, USER, FakeAsyncRedis, FakeTelegram, no_sleep  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
WIN = "microsoft:windows_server"
EDGE_TASKS = {"v2-edge-network-logon", "v2-edge-inbound-admin-ports"}


@pytest.fixture(scope="module", autouse=True)
def migrated_db():
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    yield
    command.downgrade(cfg, "base")


@pytest.fixture
async def maker():
    engine = build_engine(pooled=False)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _manifest(slug: str, tags: list[str], portals: list[dict]) -> TenantManifest:
    raw = yaml.safe_load((ROOT / "config/tenant_manifest.yaml").read_text(encoding="utf-8"))
    raw["tenant"] = {"slug": slug, "display_name": slug}
    raw["brand"] = {"domains": [f"{slug}.example"], "keywords": [slug]}
    raw["tech_stack_tags"], raw["login_portals"] = tags, portals
    return TenantManifest.model_validate(raw)


def _kev(cve: str, vendor: str, product: str, matched: dict[str, list[str]], observed: datetime) -> IntelSignal:
    return IntelSignal(
        source=IntelSource.CISA_KEV, external_id=cve, attack_vector=AttackVector.EDGE_DEVICE_EXPLOIT,
        title=f"{cve} {vendor} {product} (lab)", observed_at=observed,
        raw_payload={"kev": {"cveID": cve, "vendorProject": vendor, "product": product},
                     "epss": {"epss": 0.2, "percentile": 0.87}, "epss_alert": False, "nuclei_templates": [],
                     "matched_tenants": matched, "pocs": [], "enrichment_notes": []},
        observables=[Observable(type="cve", value=cve)],
    )  # fmt: skip


@pytest.fixture(scope="module")
def world():
    import asyncio

    now = datetime.now(UTC)
    added = datetime(now.year, now.month, now.day, tzinfo=UTC) - timedelta(days=1)

    async def setup():
        engine = build_engine(pooled=False)
        try:
            async with session_scope(engine) as s:
                rdweb = [{"url": "https://rdweb.rdshop.example", "kind": "rdweb", "product": WIN}]
                for i, (slug, tags, portals) in enumerate([("winshop", [WIN], []), ("rdshop", [WIN], rdweb),
                                                           ("fortishop", ["fortinet:fortios"], [])]):  # fmt: skip
                    await upsert_tenant(s, _manifest(slug, tags, portals), webhook_secret=f"{i}" * 40,
                                        api_token=f"{i + 3}" * 40)  # fmt: skip
                signals = [
                    _kev("CVE-2026-8801", "Microsoft", "Windows Server", {"winshop": [WIN], "rdshop": [WIN]}, added),
                    _kev("CVE-2026-8802", "Fortinet", "FortiOS", {"fortishop": ["fortinet:fortios"]}, added),
                ]
                assert await store_signals(s, signals) == 2
            async with session_scope(engine) as s:
                assert await cluster_pending_events(s, synthetic_whitelist(), now=now + timedelta(minutes=31)) == 2
            async with session_scope(engine) as s:
                assert await build_packs(s, now=now) == 2  # negative: winshop gets no pack for the Windows CVE
        finally:
            await engine.dispose()

    asyncio.run(setup())
    return now


async def test_endpoint_kev_gets_edge_hunts_only_where_the_product_is_a_login_portal(world, maker):
    async with maker() as s:
        rows = (await s.execute(select(Tenant.slug, PivotedCluster.cve_ids, HuntingPack.payload)
                                .join(Tenant, Tenant.id == HuntingPack.tenant_id)
                                .join(PivotedCluster, PivotedCluster.id == HuntingPack.cluster_id)
                                .order_by(Tenant.slug))).all()  # fmt: skip
        windows = await s.scalar(select(PivotedCluster).where(PivotedCluster.cluster_key == "v2:cve:CVE-2026-8801"))
    assert [(slug, cves) for slug, cves, _ in rows] == [("fortishop", ["CVE-2026-8802"]), ("rdshop", ["CVE-2026-8801"])]
    for _, _, payload in rows:
        assert EDGE_TASKS <= {t["task_id"] for t in payload["internal_hunting_tasks"]}
    assert windows.pivot_graph["features"]["kev_class"] == "endpoint"


def _settings(**kw) -> Settings:
    base = {"tgbot_enabled": True, "tgbot_token": TOKEN, "tgbot_chat_ids": [CHAT], "tgbot_allowed_user_ids": [USER]}
    return Settings(**(base | kw))


async def _digest(maker, **settings) -> str:
    async with maker() as s:  # rewind: every run covers the whole window again
        await s.execute(delete(TelegramDigest))
        await s.commit()
    fake = FakeTelegram()
    client = TelegramClient(TOKEN, http=httpx.AsyncClient(transport=fake.transport()), sleep=no_sleep)
    assert (await run_digest(maker, client, FakeAsyncRedis(), _settings(**settings), sleep=no_sleep))[
        "status"
    ] == "sent"
    return "\n".join(fake.texts())


async def test_digest_lists_endpoint_kev_as_patch_reminder_for_tenants_without_a_pack(world, maker):
    text = await _digest(maker)
    patch_section = text.split("<b>Exploited CVEs to patch</b>", 1)[1].split("<b>", 1)[0]
    assert "<code>CVE-2026-8801</code>" in patch_section and "EPSS p87" in patch_section
    assert patch_section.strip().endswith("winshop")  # rdshop got a pack and sees it under Edge CVEs instead
    assert "CVE-2026-8802" not in patch_section  # negative: edge KEV entries are never patch reminders
    assert "Clusters: 2" in text


async def test_patch_reminders_follow_the_tenant_filter(world, maker):
    only_win = await _digest(maker, tgbot_tenants=["winshop"])
    assert "Clusters: 0" in only_win and "<code>CVE-2026-8801</code>" in only_win  # not a heartbeat
    only_rd = await _digest(maker, tgbot_tenants=["rdshop"])
    assert "Exploited CVEs to patch" not in only_rd and "winshop" not in only_rd


# --- R4: daily retry of missed GitHub data (D-71) ------------------------------------------------------
GH = "https://api.github.example"


class FakeGitHub:
    """The GitHub API and raw.githubusercontent.com, shaped like the real responses (see test_phase_h)."""

    def __init__(self, *, repo_search: int = 200) -> None:
        self.repo_search = repo_search
        self.requests: list[tuple[str, str]] = []  # (path, CVE or "")

    def handler(self, request: httpx.Request) -> httpx.Response:
        query = request.url.params.get("q", "")
        cve = next((w for w in query.split() if w.startswith("CVE-")), "")
        self.requests.append((request.url.path, cve))
        if request.url.host == "api.github.example":
            if request.url.path == "/search/repositories":
                if self.repo_search != 200:
                    return httpx.Response(self.repo_search, json={"message": "API rate limit exceeded"})
                return httpx.Response(200, json={"total_count": 1, "items": [{
                    "full_name": f"lab/{cve}-poc", "html_url": f"https://github.com/lab/{cve}-poc",
                    "default_branch": "main", "created_at": "2026-10-01T00:00:00Z",
                    "owner": {"login": "lab", "created_at": "2019-01-01T00:00:00Z"}}]})  # fmt: skip
            if request.url.path.endswith("/git/trees/main"):
                return httpx.Response(200, json={"tree": [{"path": "README.md", "type": "blob"},
                                                          {"path": "exploit.py", "type": "blob"}]})  # fmt: skip
            if request.url.path == "/search/code":
                return httpx.Response(200, json={"items": [{"path": f"http/cves/2026/{cve}.yaml"}]})
        if request.url.host == "raw.githubusercontent.com":
            return httpx.Response(200, text="# PoC\nprint('lab')\n")
        return httpx.Response(404)


def _missed(cve: str, observed: datetime, notes: list[str], attempts: int = 0) -> IntelSignal:
    signal = _kev(cve, "Citrix", "NetScaler ADC", {"retryshop": ["citrix:netscaler_adc"]}, observed)
    payload = signal.raw_payload | {"epss": {"epss": 0.01, "percentile": 0.2}, "enrichment_notes": notes}
    if attempts:
        payload["reenrich_attempts"] = attempts
    return signal.model_copy(update={"raw_payload": payload})


async def _base(cve: str) -> int:
    engine = build_engine(pooled=False)
    try:
        async with session_scope(engine) as s:
            return await s.scalar(select(PivotedCluster.base_confidence)
                                  .where(PivotedCluster.cluster_key == f"v2:cve:{cve}"))  # fmt: skip
    finally:
        await engine.dispose()


async def test_missed_github_data_is_retried_and_the_pack_follows_when_the_score_is_reached(world):
    from app.collectors.edge_exploits import NO_TOKEN_NOTE, EdgeIntelClient
    from app.db.models import RawIntelEvent
    from app.services.kev_reenrich import reenrich_kev

    now = datetime.now(UTC)
    yesterday = datetime(now.year, now.month, now.day, tzinfo=UTC) - timedelta(days=1)
    failed, no_token = ["PoC search failed: HTTP 403", NO_TOKEN_NOTE], [NO_TOKEN_NOTE]
    engine = build_engine(pooled=False)

    async def run(token: str | None, gh: FakeGitHub):
        async with httpx.AsyncClient(transport=httpx.MockTransport(gh.handler)) as client:
            edge = EdgeIntelClient(client, github_token=token, github_api=GH, kev_url="https://kev.example/",
                                   epss_url="https://epss.example/")  # fmt: skip
            return await reenrich_kev(engine, edge, now=now, lookback_days=7, max_attempts=5)

    try:
        manifest = _manifest("retryshop", ["citrix:netscaler_adc"], [])
        manifest = manifest.model_copy(update={"hunting": manifest.hunting.model_copy(
            update={"min_confidence_to_deliver": 85})})  # fmt: skip
        async with session_scope(engine) as s:
            await upsert_tenant(s, manifest, webhook_secret="r" * 40, api_token="s" * 40)
            assert await store_signals(s, [
                _missed("CVE-2026-8803", yesterday, failed),  # GitHub failed on the first run
                _missed("CVE-2026-8804", yesterday, no_token),  # only the token was missing
                _missed("CVE-2026-8805", yesterday, failed, attempts=5),  # gave up already
                _missed("CVE-2026-8806", yesterday - timedelta(days=10), failed),  # out of the KEV window
            ]) == 4  # fmt: skip
        async with session_scope(engine) as s:
            assert await cluster_pending_events(s, synthetic_whitelist(), now=now + timedelta(minutes=31)) == 4
        async with session_scope(engine) as s:
            assert await build_packs(s, now=now) == 0  # KEV alone (70) is below this tenant's threshold (85)

        first = FakeGitHub()
        result = await run(None, first)  # still no token: only the failed PoC search is retried
        assert (result.retried, result.improved, result.errors) == (1, 1, [])
        assert {cve for _, cve in first.requests if cve} == {"CVE-2026-8803"}
        assert "/search/code" not in {path for path, _ in first.requests}  # negative: never without a token
        assert await _base("CVE-2026-8803") == 80
        async with session_scope(engine) as s:
            assert await build_packs(s, now=now) == 0  # 80 is still below 85

        second = FakeGitHub()
        result = await run("ghp_lab", second)  # a token is set now: the Nuclei lookups are retried too
        assert (result.retried, result.improved) == (2, 2)
        assert {cve for _, cve in second.requests if cve} == {"CVE-2026-8803", "CVE-2026-8804"}
        assert await _base("CVE-2026-8803") == 90 and await _base("CVE-2026-8804") == 90
        async with session_scope(engine) as s:
            assert await build_packs(s, now=now) == 2
            stored = {e.external_id: e.raw_payload for e in (await s.scalars(
                select(RawIntelEvent).where(RawIntelEvent.external_id.in_(["CVE-2026-8803", "CVE-2026-8805"])))).all()}  # fmt: skip
        assert stored["CVE-2026-8803"]["reenrich_attempts"] == 2 and stored["CVE-2026-8803"]["enrichment_notes"] == []
        assert stored["CVE-2026-8803"]["nuclei_templates"] == ["http/cves/2026/CVE-2026-8803.yaml"]
        assert stored["CVE-2026-8805"]["reenrich_attempts"] == 5 and stored["CVE-2026-8805"]["pocs"] == []

        third = FakeGitHub(repo_search=403)
        result = await run("ghp_lab", third)  # nothing is incomplete any more within the attempt cap
        assert (result.retried, third.requests) == (0, [])
    finally:
        await engine.dispose()
