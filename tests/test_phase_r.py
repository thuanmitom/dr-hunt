"""Phase R unit tests: KEV classification and per-tenant edge hunts (D-70)."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest

from app.collectors.edge_exploits import KEV_EDGE, KEV_ENDPOINT, classify_kev
from app.compiler.templates import baseline_tasks
from app.integrations.telegram import format as fmt
from app.schemas.enums import AttackVector
from app.services.pack_builder import kev_is_edge_for

NOW = datetime(2026, 11, 14, 1, 0, tzinfo=UTC)


# --- R1: KEV classification (D-70) ---------------------------------------------------------------------
@pytest.mark.parametrize(
    ("vendor", "product", "expected"),
    [
        ("Fortinet", "FortiOS", KEV_EDGE),
        ("Palo Alto Networks", "PAN-OS", KEV_EDGE),
        ("Ivanti", "Connect Secure", KEV_EDGE),
        ("Microsoft", "Exchange Server", KEV_EDGE),
        ("Microsoft", "Internet Information Services (IIS)", KEV_EDGE),
        ("Cisco", "IOS XE", KEV_EDGE),
        ("VMware", "vCenter Server", KEV_EDGE),
        ("Apache", "Tomcat", KEV_EDGE),
        ("Microsoft", "Windows", KEV_ENDPOINT),
        ("Microsoft", "Win32k", KEV_ENDPOINT),
        ("Microsoft", "Office", KEV_ENDPOINT),
        ("Google", "Chromium V8", KEV_ENDPOINT),
        ("Apple", "Multiple Products", KEV_ENDPOINT),
        ("Cisco", "AnyConnect Secure Mobility Client", KEV_ENDPOINT),
        ("VMware", "Workstation", KEV_ENDPOINT),
        # names as they appear in the KEV catalog (checked 2026-11-15)
        ("Broadcom", "VMware vCenter Server", KEV_EDGE),
        ("Broadcom", "VMware ESX", KEV_EDGE),
        ("Broadcom", "Brocade Fabric OS", KEV_ENDPOINT),
        ("VMware", "SD-WAN Edge", KEV_EDGE),
        ("VMware", "Tools", KEV_ENDPOINT),
        ("Cisco", "Secure Email Gateway", KEV_EDGE),
        ("Cisco", "Catalyst SD-WAN Manager", KEV_EDGE),
        ("Cisco", "Cisco IP Phones", KEV_ENDPOINT),
        ("BeyondTrust", "Remote Support", KEV_EDGE),
        ("SimpleHelp ", "SimpleHelp", KEV_EDGE),
        ("Fortra", "GoAnywhere MFT", KEV_EDGE),
        ("ConnectWise", "ScreenConnect", KEV_EDGE),
        ("IBM", "Aspera Faspex", KEV_EDGE),
        ("Zoho", "ManageEngine Desktop Central", KEV_ENDPOINT),
        ("Arista", "VeloCloud Orchestrator", KEV_EDGE),
        ("Unknown Vendor", "Some Product", KEV_ENDPOINT),
        ("", "", KEV_ENDPOINT),
    ],
)
def test_classify_kev(vendor, product, expected):
    assert classify_kev(vendor, product) == expected


def test_classify_kev_matches_whole_words_only():
    # negative: a word that merely contains an edge product name is not an edge product
    assert classify_kev("Microsoft", "Exchangeable Image Viewer") == KEV_ENDPOINT
    assert classify_kev("Cisco", "Webex Meetings") == KEV_ENDPOINT
    assert classify_kev("Fortinetwork", "Thing") == KEV_ENDPOINT


def _cluster(kev_class: str | None, tags: list[str]) -> SimpleNamespace:
    features = {"in_kev": True} | ({"kev_class": kev_class} if kev_class else {})
    return SimpleNamespace(pivot_graph={"features": features}, tech_stack_tags=tags)


def _tenant(tags: list[str], portal_products: list[str | None]) -> SimpleNamespace:
    portals = [SimpleNamespace(product=p) for p in portal_products]
    return SimpleNamespace(manifest=SimpleNamespace(tech_stack_tags=tags, login_portals=portals))


def test_kev_is_edge_for_tenant():
    win = ["microsoft:windows_server"]
    assert kev_is_edge_for(_cluster(KEV_EDGE, ["fortinet:fortios"]), _tenant(["fortinet:fortios"], []))
    assert kev_is_edge_for(_cluster(None, win), _tenant(win, []))  # built before D-70: old behaviour kept
    assert not kev_is_edge_for(_cluster(KEV_ENDPOINT, win), _tenant(win, []))
    assert not kev_is_edge_for(_cluster(KEV_ENDPOINT, win), _tenant(win, [None, "microsoft:entra_id"]))
    assert kev_is_edge_for(_cluster(KEV_ENDPOINT, win), _tenant(win, ["microsoft:windows_server"]))  # RD Web portal
    # negative: the portal product must also be the matched product of this cluster
    assert not kev_is_edge_for(
        _cluster(KEV_ENDPOINT, ["microsoft:windows"]), _tenant(win, ["microsoft:windows_server"])
    )


def test_baseline_tasks_can_leave_out_edge_hunts():
    with_edge = baseline_tasks(AttackVector.EDGE_DEVICE_EXPLOIT, {}, 30)
    without = baseline_tasks(AttackVector.EDGE_DEVICE_EXPLOIT, {}, 30, edge_hunts=False)
    assert {t.task_id for t in with_edge} >= {"v2-edge-network-logon", "v2-edge-inbound-admin-ports"}
    assert without == []
    clickfix = baseline_tasks(AttackVector.CLICKFIX_FILELESS, {}, 14, edge_hunts=False)
    assert clickfix == baseline_tasks(AttackVector.CLICKFIX_FILELESS, {}, 14)  # the flag only touches V2


def _health() -> fmt.HealthReport:
    return fmt.HealthReport(items=(), llm_enabled=False, llm_tokens_today=0, llm_budget=0, ai_accepted=0,
                            ai_rejected=0, dead_letters=0)  # fmt: skip


def test_digest_lists_patch_reminders_safely():
    patch = fmt.PatchItem("CVE-2026-8801", "CVE-2026-8801 Microsoft Windows <b>x</b> http://evil.example/",
                          0.873, ("winshop",))  # fmt: skip
    data = fmt.DigestData(NOW, NOW, (), (), (), (), _health(), patches=(patch,))
    assert not data.is_empty  # a patch reminder alone is worth a digest
    [text] = fmt.render_digest(data, top=10, tz=ZoneInfo("Asia/Ho_Chi_Minh"))
    assert "<b>Exploited CVEs to patch</b>" in text and "<code>CVE-2026-8801</code>" in text
    assert "EPSS p87" in text and text.rstrip().count("winshop") == 1
    assert "<b>x</b>" not in text and "http://" not in text and "hxxp://evil[.]example" in text
    unknown = fmt.render_digest(
        fmt.DigestData(NOW, NOW, (), (), (), (), _health(), patches=(fmt.PatchItem("CVE-1", "t", None, ("a",)),)),
        top=10, tz=ZoneInfo("UTC"),
    )  # fmt: skip
    assert "EPSS n/a" in unknown[0]


# --- R2: quieter HTTP client logs, JSON startup lines (D-58) -------------------------------------------
LOGGER_NAMES = ("", "uvicorn", "uvicorn.error", "uvicorn.access", "httpx", "httpcore")


@pytest.fixture
def restore_logging():
    import logging

    saved = {}
    for name in LOGGER_NAMES:
        lg = logging.getLogger(name)
        saved[name] = (lg.handlers[:], lg.level, lg.propagate, lg.disabled)
    yield
    for name, (handlers, level, propagate, disabled) in saved.items():
        lg = logging.getLogger(name)
        lg.handlers, lg.propagate, lg.disabled = handlers, propagate, disabled
        lg.setLevel(level)


def test_http_client_request_lines_are_held_back_unless_debug(restore_logging):
    import logging

    from app.core.logging import NOISY_LOGGERS, quiet_noisy_loggers
    from app.worker.celery_app import _log_format

    for name in NOISY_LOGGERS:
        logging.getLogger(name).disabled = False  # Alembic's fileConfig in the integration tests may have disabled it
    for level, expected in (("INFO", logging.WARNING), ("warning", logging.WARNING), (logging.INFO, logging.WARNING),
                            ("DEBUG", logging.NOTSET), (logging.DEBUG, logging.NOTSET)):  # fmt: skip
        quiet_noisy_loggers(level)
        assert [logging.getLogger(n).level for n in NOISY_LOGGERS] == [expected, expected], level
    _log_format(logging.getLogger("celery"), loglevel=logging.INFO)  # the worker and beat hook
    assert logging.getLogger("httpx").level == logging.WARNING
    assert not logging.getLogger("httpx").isEnabledFor(logging.INFO)
    assert logging.getLogger("httpx").isEnabledFor(logging.WARNING)  # negative: failures still reach the log


def test_api_startup_lines_are_json(restore_logging, monkeypatch):
    import io
    import json
    import logging
    import logging.config

    import uvicorn.config

    from app.api import main
    from app.core.config import Settings
    from app.core.logging import JsonFormatter

    logging.config.dictConfig(uvicorn.config.LOGGING_CONFIG)  # what uvicorn does before it imports the app
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).disabled = False  # Alembic's fileConfig in the integration tests may have disabled it
    monkeypatch.setattr(main, "get_settings", lambda: Settings(_env_file=None, log_format="json"))
    main.create_app()  # import time in production: before uvicorn logs "Started server process"
    handlers = logging.getLogger("uvicorn").handlers + logging.getLogger("uvicorn.access").handlers
    assert handlers and all(isinstance(h.formatter, JsonFormatter) for h in handlers)
    stream = io.StringIO()
    logging.getLogger("uvicorn").handlers[0].setStream(stream)
    logging.getLogger("uvicorn.error").info("Started server process [%d]", 42)
    assert json.loads(stream.getvalue())["msg"] == "Started server process [42]"


def test_text_format_leaves_uvicorn_formatters_alone(restore_logging, monkeypatch):
    import logging
    import logging.config

    import uvicorn.config

    from app.api import main
    from app.core.config import Settings
    from app.core.logging import JsonFormatter

    logging.config.dictConfig(uvicorn.config.LOGGING_CONFIG)
    monkeypatch.setattr(main, "get_settings", lambda: Settings(_env_file=None))
    main.create_app()
    assert not any(isinstance(h.formatter, JsonFormatter) for h in logging.getLogger("uvicorn").handlers)
    assert logging.getLogger("httpx").level == logging.WARNING


# --- R4: daily retry of missed GitHub data (D-71) ------------------------------------------------------
def test_retry_only_what_can_change():
    from app.collectors.edge_exploits import NO_TOKEN_NOTE
    from app.services.kev_reenrich import needs_retry

    failed = "PoC search failed: HTTP 403"
    assert needs_retry([failed, NO_TOKEN_NOTE], has_token=False)
    assert needs_retry(["nuclei lookup failed: HTTP 422"], has_token=True)
    assert needs_retry([NO_TOKEN_NOTE], has_token=True)
    assert not needs_retry([NO_TOKEN_NOTE], has_token=False)  # negative: the same call would give the same answer
    assert not needs_retry([], has_token=True)


def test_a_failed_retry_never_drops_data_found_earlier():
    from app.collectors.edge_exploits import NO_TOKEN_NOTE
    from app.services.kev_reenrich import merge_enrichment

    poc = {"repo": "lab/poc", "likely_fake": False, "files": {}}
    stored = {"kev": {}, "pocs": [poc], "nuclei_templates": ["t.yaml"], "enrichment_notes": ["x"]}
    again = merge_enrichment(stored, [], [], ["PoC search failed: HTTP 403", "nuclei lookup failed: HTTP 500"], now=NOW)
    assert again["pocs"] == [poc] and again["nuclei_templates"] == ["t.yaml"] and again["reenrich_attempts"] == 1
    no_token = merge_enrichment(again, [], [], [NO_TOKEN_NOTE], now=NOW)
    assert no_token["pocs"] == [] and no_token["nuclei_templates"] == ["t.yaml"]  # the search worked: none found
    assert no_token["reenrich_attempts"] == 2 and no_token["reenriched_at"] == NOW.isoformat()
    assert stored["enrichment_notes"] == ["x"]  # the input is not modified


def test_kev_retry_runs_daily_and_reports_github_failures(monkeypatch):
    import contextlib

    from app.collectors import tasks
    from app.core.config import get_settings
    from app.worker import health
    from app.worker.celery_app import celery_app

    entry = celery_app.conf.beat_schedule["kev-reenrich"]
    assert entry["task"] == "collectors.kev_reenrich" and entry["schedule"].hour == {4}
    assert "kev_reenrich" in {s.name for s in health.sources(get_settings())}
    recorded: list[tuple[str, health.Outcome, str | None]] = []
    monkeypatch.setattr(tasks, "single_flight", lambda *a, **k: contextlib.nullcontext(True))
    monkeypatch.setattr(tasks, "run_with_engine", lambda fn: (3, ["GitHub PoC search: HTTP 403"]))
    monkeypatch.setattr(health, "record", lambda name, outcome, note=None, **k: recorded.append((name, outcome, note)))
    assert tasks.kev_reenrich() == 3
    assert recorded == [("kev_reenrich", health.Outcome.FAILING, "GitHub PoC search: HTTP 403")]


def test_kev_retry_attempt_cap_is_bounded(monkeypatch):
    from app.core.config import Settings

    assert Settings(_env_file=None).kev_reenrich_max_attempts == 5
    monkeypatch.setenv("HC_KEV_REENRICH_MAX_ATTEMPTS", "0")
    with pytest.raises(ValueError):
        Settings(_env_file=None)


# --- R5.2: the reference consumer may use plain HTTP on the same machine only (D-72) -------------------
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://LOCALHOST",
        "http://127.8.9.10:8000",
        "http://[::1]:8000",
    ],
)
def test_kit_accepts_plain_http_to_loopback(url):
    from integration_kit.reference_consumer.config import KitConfig, is_loopback_http

    env = {"HC_KIT_BASE_URL": url, "HC_KIT_TENANT": "t", "HC_KIT_API_TOKEN": "a", "HC_KIT_HMAC_SECRET": "s"}
    assert is_loopback_http(url) and KitConfig.from_env(env).base_url == url.rstrip("/")


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.10:8000",  # a LAN address leaves the machine
        "http://10.0.0.5",
        "http://hc.lan",
        "http://localhost.evil.example",  # lookalikes
        "http://127.0.0.1.nip.io",
        "http://127.0.0.1@evil.example",  # user info: the real host is evil.example
        "http://user:pw@localhost",
        "http://0x7f.0.0.1",
        "http://127.1",
        "http://[::ffff:c0a8:010a]",
        "ftp://127.0.0.1",
        "http://",
    ],
)
def test_kit_still_requires_https_everywhere_else(url):
    from integration_kit.reference_consumer.config import ConfigError, KitConfig, is_loopback_http

    env = {"HC_KIT_BASE_URL": url, "HC_KIT_TENANT": "t", "HC_KIT_API_TOKEN": "a", "HC_KIT_HMAC_SECRET": "s"}
    assert not is_loopback_http(url)
    with pytest.raises(ConfigError, match="https"):
        KitConfig.from_env(env)


# --- R5.1: HTTPS inside a LAN with Caddy's local CA (D-72) ----------------------------------------------
def test_caddy_tls_mode_is_public_or_internal_only():
    import re
    from pathlib import Path

    import yaml

    root = Path(__file__).resolve().parent.parent
    caddyfile = (root / "deploy/Caddyfile").read_text(encoding="utf-8")
    code = "\n".join(line.split("#", 1)[0] for line in caddyfile.splitlines())
    assert set(re.findall(r"^\((tls_\w+)\)", code, re.M)) == {"tls_public", "tls_internal"}  # no other mode exists
    assert re.search(r"^\(tls_public\) \{\s*\}", code, re.M)  # public: Caddy's automatic HTTPS, unchanged
    assert re.search(r"^\(tls_internal\) \{\s*tls internal\s*\}", code, re.M)
    assert "import tls_{$HC_TLS_MODE:public}" in code and "skip_install_trust" in code
    assert "tls_insecure" not in code and "http://" not in code  # negative: never plain HTTP, never skip verification
    compose = yaml.safe_load((root / "docker-compose.yml").read_text(encoding="utf-8"))
    assert compose["services"]["caddy"]["environment"]["HC_TLS_MODE"] == "${HC_TLS_MODE:-public}"


# --- R3: CI workflow and the hash-locked dev dependencies (D-74) ---------------------------------------
def _pins(text: str) -> dict[str, str]:
    import re

    return {m.group(1).lower(): m.group(2) for m in re.finditer(r"^([A-Za-z0-9_.\-\[\],]+)==(\S+)", text, re.M)}


def test_ci_workflow_is_pinned_and_read_only():
    import re
    from pathlib import Path

    import yaml

    root = Path(__file__).resolve().parent.parent
    wf = yaml.safe_load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    triggers = wf.get("on", wf.get(True))  # PyYAML reads the bare key `on` as true
    assert set(triggers) == {"push", "pull_request"}  # negative: no pull_request_target / workflow_run
    assert wf["permissions"] == {"contents": "read"}
    job = wf["jobs"]["checks"]
    assert "@sha256:" in job["services"]["postgres"]["image"]
    uses = [s["uses"] for s in job["steps"] if "uses" in s]
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u) for u in uses)  # commit SHAs, not tags
    assert next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout"))["with"] == {
        "persist-credentials": False
    }
    runs = "\n".join(s.get("run", "") for s in job["steps"])
    assert "pip install --require-hashes -r requirements-dev.txt" in runs
    for check in ("ruff check .", "ruff format --check .", "pytest -q", "alembic check", "git diff --exit-code",
                  "pip-audit --strict --require-hashes"):  # fmt: skip
        assert check in runs, check
    assert "secrets." not in (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    # negative: the audit never gets a blanket exception, only the one advisory accepted in D-74
    audits = [line for line in runs.splitlines() if line.strip().startswith("pip-audit")]
    assert len(audits) == 2 and all(re.findall(r"--ignore-vuln (\S+)", a) == ["PYSEC-2026-2447"] for a in audits)
    assert not re.search(r"--(skip-editable|no-deps|ignore-vuln-file)|\|\| *true", runs)


def test_dev_lock_is_hashed_and_keeps_every_runtime_pin():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    dev_text = (root / "requirements-dev.txt").read_text(encoding="utf-8")
    runtime, dev = _pins((root / "requirements.txt").read_text(encoding="utf-8")), _pins(dev_text)
    assert runtime and {k: dev.get(k) for k in runtime} == runtime  # tests run what the image ships
    assert {"pytest", "pytest-asyncio", "ruff", "pip-audit", "jsonschema", "pysigma-backend-splunk"} <= set(dev)
    entries = [line for line in dev_text.splitlines() if line and not line.startswith((" ", "#"))]
    assert len(entries) == len(dev) and all(line.endswith(" \\") for line in entries)  # each pin carries hashes
    assert "-r requirements.txt" in (root / "requirements-dev.in").read_text(encoding="utf-8")


# --- D-75: the worker loads the warninglists once, before forking its task processes ------------------
def test_worker_preloads_warninglists_before_forking(monkeypatch):
    import weakref

    from celery.signals import worker_init

    from app.processors import whitelist_filter
    from app.worker import celery_app as module

    receivers = [r() if isinstance(r, weakref.ReferenceType) else r for _, r in worker_init.receivers]
    assert module._preload_shared_data in receivers  # runs in the main process, before the pool starts
    calls: list[str] = []
    monkeypatch.setattr(whitelist_filter, "default_sources", lambda: calls.append("load"))
    monkeypatch.setattr(module.gc, "freeze", lambda: calls.append("freeze"))
    module._preload_shared_data()
    assert calls == ["load", "freeze"]


def test_a_failed_preload_never_stops_the_worker(monkeypatch):
    from app.processors import whitelist_filter
    from app.worker import celery_app as module

    def unavailable():
        raise OSError("warninglists missing")

    frozen: list[int] = []
    monkeypatch.setattr(whitelist_filter, "default_sources", unavailable)
    monkeypatch.setattr(module.gc, "freeze", lambda: frozen.append(1))
    module._preload_shared_data()  # negative: no exception; task processes load the lists themselves
    assert frozen == []
