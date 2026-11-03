"""Telegram formatting: escaping, defanging, masking, AI labels and the 4,096-character limit (TELEGRAM.md §9)."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from app.integrations.telegram import format as fmt
from app.schemas.enums import AttackVector
from app.worker.health import HealthItem

TZ = ZoneInfo("Asia/Ho_Chi_Minh")
NOW = datetime(2026, 11, 2, 1, 0, tzinfo=UTC)
REF = "ab" * 32


def _health(**kw) -> fmt.HealthReport:
    base = {"items": (), "llm_enabled": False, "llm_tokens_today": 0, "llm_budget": 0, "ai_accepted": 0,
            "ai_rejected": 0, "dead_letters": 0}  # fmt: skip
    return fmt.HealthReport(**(base | kw))


def _line(**kw) -> fmt.ClusterLine:
    base = {"cluster_id": "c1", "cluster_key": "v3:c2:c2.evil-cdn.example", "vector": AttackVector.CLICKFIX_FILELESS,
            "label": "c2.evil-cdn.example", "severity": "high", "confidence": 78, "tasks": 4, "iocs": 2,
            "pack_id": "3f1c2b7e-9a64-4c1d-8e2f-5b7a0d4c6e91", "tenants": ("tencongty",), "is_new": True}  # fmt: skip
    return fmt.ClusterLine(**(base | kw))


def _assert_safe(text: str) -> None:
    assert "http://" not in text and "https://" not in text
    assert REF not in text and "<script>" not in text
    assert fmt.tg_len(text) <= fmt.MAX_MESSAGE_CHARS


def test_defang_and_escape():
    text = fmt.defang_text("see https://c2.evil-cdn.example/x?a=1 then 45.155.205.10 and HTTP://Up.Example")
    assert "hxxps://c2[.]evil-cdn[.]example/x?a=1" in text and "45[.]155[.]205[.]10" in text
    assert "hxxp://Up[.]Example" in text and "http" not in text.lower().replace("hxxp", "")
    assert fmt.defang("2001:db8::1") == "2001[:]db8[:][:]1"
    assert fmt.defang_text("hxxps://already[.]defanged") == "hxxps://already[.]defanged"
    assert fmt.safe("<b>evil.example</b> & co") == "&lt;b&gt;evil[.]example&lt;/b&gt; &amp; co"
    assert fmt.defang_text("version 0.4.0, Sysmon 13") == "version 0.4.0, Sysmon 13"


def test_cluster_line_has_the_specified_shape():
    line = fmt.render_cluster_line(_line(tenants=("acme", "tencongty")))
    assert line == ("<b>[HIGH 78]</b> V3 ClickFix — <code>c2[.]evil-cdn[.]example</code> · 4 tasks · 2 IOCs · "
                    "<code>#3f1c2b7e</code> · acme, tencongty")  # fmt: skip
    assert "1 task ·" in fmt.render_cluster_line(_line(tasks=1, iocs=1)) and "1 IOC ·" in fmt.render_cluster_line(
        _line(tasks=1, iocs=1)
    )


def test_cluster_labels_never_show_tenant_ids():
    uid = "0b9d3c55-1111-4222-8333-444455556666"
    assert fmt.cluster_label(f"v1:{uid}:credential-exposure", "x") == "credential exposure"
    assert fmt.cluster_label(f"v1:{uid}:tencongty-sso.example", "x") == "tencongty-sso.example"
    assert fmt.cluster_label("v2:cve:CVE-2026-1111", "x") == "CVE-2026-1111"
    assert fmt.cluster_label("v5:reference", "x") == "LOLDrivers + HijackLibs reference"
    assert fmt.cluster_label("v1:mb:LummaStealer", "x") == "MalwareBazaar LummaStealer"


def test_digest_is_escaped_defanged_masked_and_split():
    hostile = "<script>alert(1)</script> https://evil.example/" + "a" * 50
    lines = tuple(_line(cluster_id=f"c{i}", label=f"c2-{i}.evil.example", confidence=90 - i % 50) for i in range(120))
    lines = (_line(cluster_id="x", label=hostile), *lines)
    data = fmt.DigestData(
        window_start=NOW - timedelta(days=1), window_end=NOW, lines=lines,
        exposures=(fmt.ExposureItem("tencongty", 7, tuple(f"u{i}***x@tencongty.vn" for i in range(7)),
                                    ("HIBP", "Telegram"), ("lumma",)),),
        cves=(fmt.CveItem("CVE-2026-1111", "Fortinet FortiOS <img> https://vendor.example", 0.951, True, ("tencongty",)),),
        datasets=(fmt.DatasetItem("loldrivers", 713, 12),), health=_health(),
    )  # fmt: skip
    messages = fmt.render_digest(data, top=200, tz=TZ)
    assert len(messages) > 1
    for m in messages:
        _assert_safe(m)
    joined = "\n".join(messages)
    assert "&lt;script&gt;" in joined and "Credential exposure" in joined and "EPSS p95" in joined
    assert joined.count("@tencongty.vn</code>") == fmt.MAX_MASKED_PER_TENANT  # at most 5 masked accounts
    assert "loldrivers: 713 records, 12 new" in joined and "All collectors healthy." in joined
    assert "Period: 2026-11-01 08:00 to 2026-11-02 08:00 (Asia/Ho_Chi_Minh)" in joined
    for section in ("<b>Top items</b>", "<b>Credential exposure</b>", "<b>Health</b>"):  # never split mid-header
        assert sum(section in m for m in messages) == 1


def test_top_limit_and_counts():
    lines = (_line(cluster_id="a"), _line(cluster_id="b", severity="medium", is_new=False))
    data = fmt.DigestData(None, NOW, lines, (), (), (), _health())
    [msg] = fmt.render_digest(data, top=1, tz=TZ)
    assert "since the first run" in msg or "Period: the first run" in msg
    assert "Clusters: 2 (new 1, updated 1)" in msg and "… and 1 more" in msg
    assert "By severity: high 1 · medium 1" in msg


def test_empty_window_is_a_one_line_heartbeat():
    ok = fmt.render_digest(fmt.DigestData(NOW, NOW, (), (), (), (), _health()), top=10, tz=TZ)
    assert ok == ["<b>OutSight digest</b>\nNo new intelligence since 2026-11-02 08:00; all collectors healthy."]
    bad = HealthItem("urlscan_sweep", "URLScan", "failing", None, NOW, "HTTPStatusError")
    [msg] = fmt.render_digest(fmt.DigestData(NOW, NOW, (), (), (), (), _health(items=(bad,))), top=10, tz=TZ)
    assert "problems: URLScan (failing)" in msg
    fresh = HealthItem("hibp_sweep", "HIBP", "unknown", None, None, None)
    off = HealthItem("urlscan_sweep", "URLScan", "not_configured", None, None, "HC_URLSCAN_API_KEY not set")
    assert fmt.health_summary(_health(items=(fresh,))) == "1 collector not reported yet"
    assert fmt.health_summary(_health(items=(off,))) == "all configured collectors healthy"


def test_health_section_reports_states_llm_and_dead_letters():
    items = (
        HealthItem("hibp_sweep", "HIBP", "not_configured", None, None, "HC_HIBP_API_KEY not set"),
        HealthItem("deliver_due", "Push dispatch", "stale", NOW - timedelta(hours=1), None, None),
    )
    text = fmt.render_health(_health(items=items, llm_enabled=True, llm_tokens_today=1234, llm_budget=2_000_000,
                                     ai_accepted=3, ai_rejected=1, dead_letters=2), TZ)  # fmt: skip
    assert "HIBP: <b>not_configured</b>" in text and "HC_HIBP_API_KEY not set" in text
    assert "Push dispatch: <b>stale</b>" in text
    assert "1,234 / 2,000,000 tokens today; AI rules accepted 3, rejected 1" in text and "Push dead letters: 2" in text
    assert "Collector states unavailable" in fmt.render_health(_health(unavailable="Redis: ConnectionError"), TZ)


def test_pack_detail_labels_ai_text_and_masks_accounts():
    payload = {
        "pack_id": "3f1c2b7e-9a64-4c1d-8e2f-5b7a0d4c6e91", "attack_vector": "clickfix_fileless", "severity": "high",
        "confidence_score": 72, "mitre_attack": ["T1059.001"], "expires_at": "2026-11-13T07:00:00+00:00",
        "threat_summary": "ClickFix lure on lure.example\n[AI-assisted summary] mshta pulls https://c2.example/x.hta",
        "prevention_blocklist": {"ttl_days": 14, "domains": ["c2.example"], "ips": [], "hashes": [],
                                 "jarm_fingerprints": []},
        "soar_playbook_hints": {"auto_block_pre_iocs": False, "notify_only_on_sighting": False},
        "affected_accounts": [{"ref": REF, "masked": "n***a@tencongty.vn", "host": None}],
        "internal_hunting_tasks": [{"task_id": "ai-process-creation-1", "description": "[AI-assisted] mshta <b>",
                                    "target_scope": "all_endpoints", "required_telemetry": ["sysmon:1"]}],
    }  # fmt: skip
    text = fmt.render_pack_detail(payload, tenant="tencongty", label="c2.example", version=2, tz=TZ)
    _assert_safe(text)
    assert "<b>[AI]</b> mshta pulls hxxps://c2[.]example/x[.]hta" in text and "[AI-assisted" not in text
    assert "<code>n***a@tencongty.vn</code>" in text and "Expires: 2026-11-13 14:00" in text
    assert "mshta &lt;b&gt;" in text and "v2" in text


def test_split_text_respects_the_limit_and_keeps_lines():
    text = "\n".join(f"line {i} " + "x" * 90 for i in range(200))
    parts = fmt.split_text(text, 1000)
    assert all(fmt.tg_len(p) <= 1000 for p in parts) and "\n".join(parts) == text
    long_line = " ".join(["word"] * 600)
    assert all(fmt.tg_len(p) <= 500 for p in fmt.split_text(long_line, 500))
    emoji = "😀" * 3000  # 2 UTF-16 units each
    assert all(fmt.tg_len(p) <= fmt.MAX_MESSAGE_CHARS for p in fmt.split_text(emoji))


def test_ioc_and_cve_views():
    m = fmt.IocMatch("c2.evil.example", AttackVector.CLICKFIX_FILELESS, 70, "active", NOW)
    text = fmt.render_ioc("c2.evil.example", "domain", ("block", "no_whitelist_match"), [m], TZ)
    _assert_safe(text)
    assert "<code>c2[.]evil[.]example</code> (domain)" in text and "Whitelist: <b>block</b>" in text
    assert "not tracked" in fmt.render_cve("CVE-2099-0001", found=None, tz=TZ)
    assert re.search(r"EPSS: p95", fmt.render_cve("CVE-2026-1111", found={
        "title": "t", "status": "active", "confidence": 85, "last_seen": NOW, "epss_percentile": 0.95,
        "credible_poc": True, "tenants": ["tencongty"], "packs": [{"pack_id": "3f1c2b7e-x", "version": 1,
                                                                    "tenant": "tencongty"}]}, tz=TZ))  # fmt: skip
