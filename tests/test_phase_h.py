"""Phase H: missing keys never break a sweep (H1), and the production-hardening pieces that follow."""

from __future__ import annotations

import asyncio
import contextlib
import json
from datetime import date

import httpx
import pytest

from app.collectors import edge_exploits as ee
from app.core.config import Settings, get_settings
from app.worker import health

CVE = "CVE-2026-2222"
TAGS = {"tencongty": {"fortinet:fortios"}}
KEV_URL, EPSS_URL, GH = "https://kev.example/kev.json", "https://epss.example/data", "https://api.github.example"


# --- H1.1 blank keys are "not set" ---------------------------------------------------------------------------------
def test_blank_optional_keys_are_not_set(monkeypatch, tmp_path):
    for name in ("HC_URLSCAN_API_KEY", "HC_GITHUB_TOKEN", "HC_ABUSECH_AUTH_KEY", "HC_CONTACT_EMAIL"):
        monkeypatch.setenv(name, "")
    s = Settings(_env_file=None)
    assert s.urlscan_api_key is None and s.github_token is None and s.abusech_auth_key is None
    assert s.contact_email is None
    monkeypatch.setenv("HC_GITHUB_TOKEN", "ghp_lab")
    assert Settings(_env_file=None).github_token.get_secret_value() == "ghp_lab"  # a real value still counts

    for name in ("HC_URLSCAN_API_KEY", "HC_GITHUB_TOKEN"):
        monkeypatch.delenv(name)
    env = tmp_path / ".env"
    env.write_text("HC_URLSCAN_API_KEY=\nHC_GITHUB_TOKEN=\n", encoding="utf-8")  # as shipped in .env.example
    s = Settings(_env_file=env)
    assert s.urlscan_api_key is None and s.github_token is None


def test_urlscan_reports_not_configured_when_the_key_is_blank(monkeypatch):
    from app.collectors.tasks import _urlscan_sweep

    monkeypatch.setenv("HC_URLSCAN_API_KEY", "")
    get_settings.cache_clear()
    try:
        with pytest.raises(health.NotConfigured):
            asyncio.run(_urlscan_sweep(None))  # never reaches the network or the database
    finally:
        get_settings.cache_clear()


# --- H1.2 GitHub is enrichment only ---------------------------------------------------------------------------------
class FakeSources:
    """CISA KEV, FIRST EPSS, the GitHub API and raw.githubusercontent.com, shaped like the real responses."""

    def __init__(self, *, repo_search: int = 200, code_search: int = 200, kev: int = 200) -> None:
        self.repo_search, self.code_search, self.kev = repo_search, code_search, kev
        self.paths: list[str] = []
        self.auth: list[str | None] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.paths.append(request.url.path)
        if url.startswith(KEV_URL):
            if self.kev != 200:
                return httpx.Response(self.kev)
            return httpx.Response(200, json={"catalogVersion": "2026.11.08", "vulnerabilities": [{
                "cveID": CVE, "vendorProject": "Fortinet", "product": "FortiOS",
                "vulnerabilityName": "Fortinet FortiOS Out-of-Bounds Write (lab)", "dateAdded": date.today().isoformat(),
                "shortDescription": "lab", "requiredAction": "Apply mitigations.", "dueDate": "2026-11-29",
                "knownRansomwareCampaignUse": "Unknown", "notes": ""}]})  # fmt: skip
        if url.startswith(EPSS_URL):
            return httpx.Response(200, json={"status": "OK", "data": [
                {"cve": CVE, "epss": "0.421000000", "percentile": "0.973000000", "date": "2026-11-08"}]})  # fmt: skip
        if request.url.host == "api.github.example":
            self.auth.append(request.headers.get("Authorization"))
            if request.url.path == "/search/repositories":
                if self.repo_search != 200:
                    return httpx.Response(self.repo_search, json={"message": "API rate limit exceeded"})
                return httpx.Response(200, json={"total_count": 1, "items": [{
                    "full_name": "lab/CVE-2026-2222-poc", "html_url": "https://github.com/lab/CVE-2026-2222-poc",
                    "default_branch": "main", "created_at": "2026-10-01T00:00:00Z",
                    "owner": {"login": "lab", "created_at": "2019-01-01T00:00:00Z"}}]})  # fmt: skip
            if request.url.path.endswith("/git/trees/main"):
                return httpx.Response(200, json={"tree": [{"path": "README.md", "type": "blob"},
                                                          {"path": "exploit.py", "type": "blob"}]})  # fmt: skip
            if request.url.path == "/search/code":
                if self.code_search != 200:
                    return httpx.Response(self.code_search, json={"message": "Requires authentication"})
                return httpx.Response(200, json={"items": [{"path": f"http/cves/2026/{CVE}.yaml"}]})
        if request.url.host == "raw.githubusercontent.com":
            return httpx.Response(200, text="# PoC\nprint('lab')\n")
        return httpx.Response(404)


def _collect(sources: FakeSources, token: str | None) -> tuple[list, list[str]]:
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(sources.handler)) as client:
            edge = ee.EdgeIntelClient(client, github_token=token, github_api=GH, kev_url=KEV_URL, epss_url=EPSS_URL)
            errors: list[str] = []
            signals = await ee.collect_edge_exploits(edge, TAGS, lookback_days=7, epss_threshold=0.1, errors=errors)
            return signals, errors

    return asyncio.run(go())


def test_kev_signal_ships_when_github_rate_limits_and_there_is_no_token():
    sources = FakeSources(repo_search=403)
    (signal,), errors = _collect(sources, token=None)
    payload = signal.raw_payload
    assert signal.external_id == CVE and payload["matched_tenants"] == {"tencongty": ["fortinet:fortios"]}
    assert payload["epss_alert"] is True  # KEV and EPSS still drive the alert
    assert payload["pocs"] == [] and payload["nuclei_templates"] == []
    assert payload["enrichment_notes"] == ["PoC search failed: HTTP 403", ee.NO_TOKEN_NOTE]
    assert errors == ["GitHub PoC search: HTTP 403"]  # the missing token is a setting, not a failure
    assert "/search/code" not in sources.paths  # code search always answers 401 without a token: never called
    assert set(sources.auth) == {None}


def test_code_search_failure_keeps_the_pocs_that_were_found():
    sources = FakeSources(code_search=422)
    (signal,), errors = _collect(sources, token="ghp_lab")
    payload = signal.raw_payload
    assert [p["repo"] for p in payload["pocs"]] == ["lab/CVE-2026-2222-poc"]
    assert payload["pocs"][0]["files"] == {"exploit.py": "# PoC\nprint('lab')\n"}  # read as text, never run
    assert payload["nuclei_templates"] == [] and payload["enrichment_notes"] == ["nuclei lookup failed: HTTP 422"]
    assert errors == ["GitHub code search: HTTP 422"]
    assert set(sources.auth) == {"Bearer ghp_lab"}


def test_full_enrichment_with_a_token_has_no_notes():
    (signal,), errors = _collect(FakeSources(), token="ghp_lab")
    assert signal.raw_payload["nuclei_templates"] == [f"http/cves/2026/{CVE}.yaml"]
    assert signal.raw_payload["enrichment_notes"] == [] and errors == []


def test_a_kev_feed_failure_still_fails_the_sweep():
    """Negative: only GitHub is optional. Without the KEV feed there is nothing to report."""
    with pytest.raises(httpx.HTTPStatusError):
        _collect(FakeSources(kev=404), token=None)


def test_github_errors_mark_the_sweep_failing_but_keep_its_result(monkeypatch):
    from app.collectors import tasks

    recorded: list[tuple[str, health.Outcome, str | None]] = []
    monkeypatch.setattr(tasks, "single_flight", lambda *a, **k: contextlib.nullcontext(True))
    monkeypatch.setattr(tasks, "run_with_engine", lambda fn: (2, ["GitHub PoC search: HTTP 403"]))
    monkeypatch.setattr(health, "record", lambda name, outcome, note=None, **k: recorded.append((name, outcome, note)))
    assert tasks.edge_exploit_sweep() == 2
    assert recorded == [("edge_exploit_sweep", health.Outcome.FAILING, "GitHub PoC search: HTTP 403")]


def test_enrichment_notes_survive_json_storage():
    (signal,), _ = _collect(FakeSources(repo_search=403), token=None)
    stored = json.loads(json.dumps(signal.raw_payload))
    assert stored["enrichment_notes"][1] == ee.NO_TOKEN_NOTE


# --- H2 rate limits ------------------------------------------------------------------------------------------------
class MemoryRedis:
    """incr/expire/get with expiry on a fake clock, like the Redis commands the limiter uses."""

    def __init__(self, clock) -> None:
        self.clock, self.values, self.expiry, self.calls = clock, {}, {}, 0

    def _live(self, key: str) -> None:
        if key in self.expiry and self.clock() >= self.expiry[key]:
            self.values.pop(key, None), self.expiry.pop(key, None)

    async def incr(self, key: str) -> int:
        self.calls += 1
        self._live(key)
        self.values[key] = self.values.get(key, 0) + 1
        return self.values[key]

    async def expire(self, key: str, seconds: int) -> None:
        self.expiry[key] = self.clock() + seconds

    async def get(self, key: str):
        self.calls += 1
        self._live(key)
        return self.values.get(key)


class BrokenRedis:
    calls = 0

    async def incr(self, key):
        BrokenRedis.calls += 1
        raise ConnectionError("redis down")

    get = incr


class Clock:
    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def test_tenant_budget_per_minute_resets_with_the_window():
    from app.api.ratelimit import RateLimiter

    clock = Clock(1_800_000_000.0)  # start of a minute
    rl = RateLimiter(MemoryRedis(clock), per_minute=3, auth_failures=5, auth_window=600, clock=clock)
    results = [asyncio.run(rl.tenant_over_limit("tencongty")) for _ in range(4)]
    assert results[:3] == [None, None, None] and results[3] == 60
    assert asyncio.run(rl.tenant_over_limit("other")) is None  # budgets are per tenant
    clock.t += 60
    assert asyncio.run(rl.tenant_over_limit("tencongty")) is None


def test_failed_authentications_block_the_ip_for_the_window():
    from app.api.ratelimit import RateLimiter

    clock = Clock(1_800_000_000.0)
    rl = RateLimiter(MemoryRedis(clock), per_minute=60, auth_failures=2, auth_window=600, clock=clock)
    assert asyncio.run(rl.ip_blocked("198.51.100.7")) is None
    for _ in range(2):
        asyncio.run(rl.auth_failed("198.51.100.7"))
    assert asyncio.run(rl.ip_blocked("198.51.100.7")) == 600
    assert asyncio.run(rl.ip_blocked("198.51.100.8")) is None  # another IP is not affected
    clock.t += 600
    assert asyncio.run(rl.ip_blocked("198.51.100.7")) is None


def test_limiter_fails_open_and_backs_off_when_redis_is_down(caplog):
    from app.api.ratelimit import COOLDOWN_SECONDS, RateLimiter
    from tests.telegram_fakes import enable_loggers

    enable_loggers("app.api.ratelimit")  # Alembic's fileConfig disables existing loggers in the full run
    clock = Clock()
    BrokenRedis.calls = 0
    rl = RateLimiter(BrokenRedis(), per_minute=1, auth_failures=1, auth_window=600, clock=clock)
    assert asyncio.run(rl.tenant_over_limit("t")) is None and asyncio.run(rl.ip_blocked("ip")) is None
    assert BrokenRedis.calls == 1  # the second call skipped Redis during the cooldown
    clock.t += COOLDOWN_SECONDS
    asyncio.run(rl.ip_blocked("ip"))
    assert BrokenRedis.calls == 2
    assert "rate limiter disabled" in caplog.text


# --- H4 JSON logs ---------------------------------------------------------------------------------------------------
def test_json_log_lines_parse_and_keep_exceptions():
    import logging

    from app.core.logging import JsonFormatter

    try:
        raise ValueError("boom")
    except ValueError:
        record = logging.LogRecord("hc.test", logging.ERROR, __file__, 1, "pack %s failed", ("abc",), True)
        import sys

        record.exc_info = sys.exc_info()
    doc = json.loads(JsonFormatter().format(record))
    assert doc["level"] == "ERROR" and doc["logger"] == "hc.test" and doc["msg"] == "pack abc failed"
    assert "ValueError: boom" in doc["exc"] and doc["ts"].endswith("+00:00")


def test_json_logs_still_scrub_the_bot_token():
    import io
    import logging

    from app.core.logging import JsonFormatter
    from app.integrations.telegram.client import install_log_scrubber
    from tests.telegram_fakes import TOKEN, enable_loggers

    enable_loggers("httpx")
    install_log_scrubber(TOKEN)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("httpx")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        logger.info("HTTP Request: POST https://api.telegram.org/bot%s/sendMessage", TOKEN)
    finally:
        logger.removeHandler(handler)
    line = stream.getvalue().strip()
    assert TOKEN not in line and json.loads(line)["logger"] == "httpx"


def test_text_format_is_the_default(monkeypatch):
    monkeypatch.delenv("HC_LOG_FORMAT", raising=False)
    assert Settings(_env_file=None).log_format == "text"
    monkeypatch.setenv("HC_LOG_FORMAT", "xml")
    with pytest.raises(ValueError):
        Settings(_env_file=None)


def test_retention_runs_daily_and_reports_health():
    from app.worker import maintenance  # noqa: F401 — registers the beat entry
    from app.worker.celery_app import celery_app

    entry = celery_app.conf.beat_schedule["retention"]
    assert entry["task"] == "maintenance.retention"
    assert "retention" in {s.name for s in health.sources(get_settings())}
