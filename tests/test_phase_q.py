"""Phase Q: opt-in ops alerts (Q5, D-65) and the trusted-proxy setup (Q6, D-66). Q1 is in test_compiler and the
PostgreSQL module test_phase_q_integration."""

from __future__ import annotations

import asyncio
import ipaddress
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import yaml

from app.core.config import Settings
from app.integrations.telegram import ops_alerts as ops
from app.integrations.telegram.client import TelegramClient
from app.worker import health
from tests.telegram_fakes import CHAT, TOKEN, USER, FakeSyncRedis, FakeTelegram, no_sleep

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)


# --- Q5 ops alerts -------------------------------------------------------------------------------------------------
class OpsRedis:
    """hgetall/get/set/delete, the commands the ops alerts use."""

    def __init__(self, hashes: dict[str, dict[str, str]] | None = None) -> None:
        self.hashes = hashes or {}
        self.values: dict[str, str] = {}
        self.ttl: dict[str, int] = {}

    async def hgetall(self, name: str) -> dict[str, str]:
        return dict(self.hashes.get(name, {}))

    async def get(self, name: str) -> str | None:
        return self.values.get(name)

    async def set(self, name: str, value: str, ex: int | None = None) -> None:
        self.values[name] = value
        if ex:
            self.ttl[name] = ex

    async def delete(self, *names: str) -> None:
        for n in names:
            self.values.pop(n, None)


def _settings(**over) -> Settings:
    base = {"tgbot_enabled": True, "tgbot_token": TOKEN, "tgbot_chat_ids": [CHAT], "tgbot_allowed_user_ids": [USER],
            "tgbot_ops_alerts": True}  # fmt: skip
    return Settings(_env_file=None, **(base | over))


def _failing(failures: int, note: str = "HTTPStatusError") -> dict[str, str]:
    return {"state": "failing", "last_failure_at": NOW.isoformat(), "last_success_at": (NOW - timedelta(days=1)).isoformat(),
            "last_error": note, "consecutive_failures": str(failures)}  # fmt: skip


def _run(redis: OpsRedis, settings: Settings, now: datetime = NOW) -> tuple[dict, list[str]]:
    fake = FakeTelegram()

    async def go():
        async with httpx.AsyncClient(transport=fake.transport()) as http:
            client = TelegramClient(TOKEN, http=http, sleep=no_sleep)
            return await ops.run_ops_alerts(client, redis, settings, now=now)

    return asyncio.run(go()), fake.texts()


def test_ops_alerts_are_off_by_default_and_when_disabled():
    assert Settings(_env_file=None).tgbot_ops_alerts is False
    redis = OpsRedis({"hc:health:urlscan_sweep": _failing(9)})
    result, texts = _run(redis, _settings(tgbot_ops_alerts=False))
    assert result == {"status": "disabled"} and texts == []
    assert ops.ops_schedule(_settings(tgbot_ops_alerts=False)) == {}
    assert ops.ops_schedule(_settings())["telegram-ops-alerts"]["task"] == "notify.ops_alerts"


def test_alert_after_n_failures_once_per_cooldown_then_recovery():
    redis = OpsRedis({"hc:health:urlscan_sweep": _failing(2)})
    assert _run(redis, _settings())[1] == []  # 2 < 3: not yet

    redis.hashes["hc:health:urlscan_sweep"] = _failing(3)
    result, [text] = _run(redis, _settings())
    assert result == {"status": "ok", "sent": 1}
    assert "URLScan is failing: failed 3 runs in a row" in text and "<code>HTTPStatusError</code>" in text
    assert redis.ttl["hc:ops:sent:urlscan_sweep"] == 6 * 3600

    assert _run(redis, _settings())[1] == []  # same problem inside the cooldown: no repeat
    redis.values.pop("hc:ops:sent:urlscan_sweep")  # cooldown expired, still failing
    assert len(_run(redis, _settings())[1]) == 1

    redis.hashes["hc:health:urlscan_sweep"] = {"state": "ok", "last_success_at": NOW.isoformat(),
                                               "consecutive_failures": "0"}  # fmt: skip
    _, [recovered] = _run(redis, _settings())
    assert "recovered" in recovered and "URLScan is OK again" in recovered
    assert "hc:ops:open:urlscan_sweep" not in redis.values
    assert _run(redis, _settings())[1] == []  # nothing more to say


def test_stale_jobs_alert_and_unknown_or_unconfigured_do_not():
    redis = OpsRedis({
        "hc:health:certstream": {"state": "ok", "last_success_at": (NOW - timedelta(hours=1)).isoformat()},  # 5-min job
        "hc:health:hibp_sweep": {"state": "not_configured", "consecutive_failures": "0"},
    })  # fmt: skip
    _, texts = _run(redis, _settings())
    assert len(texts) == 1 and "CertStream is stale: no successful run since 2026-11-13 15:00" in texts[0]  # UTC+7


def test_alert_text_is_escaped_and_carries_no_token():
    redis = OpsRedis({"hc:health:edge_exploit_sweep": _failing(5, note="<b>GitHub</b> & co")})
    _, [text] = _run(redis, _settings(tgbot_ops_alert_after_failures=5))
    assert "&lt;b&gt;GitHub&lt;/b&gt; &amp; co" in text and "<b>GitHub</b>" not in text
    assert TOKEN not in text


def test_heartbeat_counts_consecutive_failures_and_resets():
    r = FakeSyncRedis()
    for _ in range(3):
        health.record("urlscan_sweep", health.Outcome.FAILING, "HTTPStatusError", client=r, now=NOW)
    assert r.hashes["hc:health:urlscan_sweep"]["consecutive_failures"] == "3"
    health.record("urlscan_sweep", health.Outcome.OK, client=r, now=NOW)
    assert r.hashes["hc:health:urlscan_sweep"]["consecutive_failures"] == "0"
    health.record("urlscan_sweep", health.Outcome.FAILING, "x", client=r, now=NOW)
    health.record("urlscan_sweep", health.Outcome.NOT_CONFIGURED, "key not set", client=r, now=NOW)
    assert r.hashes["hc:health:urlscan_sweep"]["consecutive_failures"] == "0"


# --- Q6 trusted proxy ----------------------------------------------------------------------------------------------
def _compose() -> dict:
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def _default(expr: str) -> str:
    """'${HC_EDGE_CADDY_IP:-172.31.250.2}' -> '172.31.250.2'"""
    return expr.split(":-", 1)[1].rstrip("}") if expr.startswith("${") else expr


def test_api_trusts_forwarded_headers_only_from_caddy():
    c = _compose()
    cmd = c["services"]["api"]["command"]
    trusted = _default(cmd[cmd.index("--forwarded-allow-ips") + 1])
    assert trusted != "*" and "*" not in cmd  # negative: no wildcard trust any more
    caddy_ip = ipaddress.ip_address(_default(c["services"]["caddy"]["networks"]["edge"]["ipv4_address"]))
    ipam = c["networks"]["edge"]["ipam"]["config"][0]
    subnet, dynamic = ipaddress.ip_network(_default(ipam["subnet"])), ipaddress.ip_network(_default(ipam["ip_range"]))
    assert trusted == str(caddy_ip) and caddy_ip in subnet and dynamic.subnet_of(subnet)
    # the API starts first and gets a dynamic address: it must never be able to take Caddy's (found live, 2026-11-13)
    assert caddy_ip not in dynamic
    assert c["networks"]["edge"]["internal"] is True
    assert "api-edge" in c["services"]["api"]["networks"]["edge"]["aliases"]
    assert "reverse_proxy api-edge:8000" in (ROOT / "deploy/Caddyfile").read_text(encoding="utf-8")


def test_uvicorn_uses_x_forwarded_for_only_from_the_trusted_ip():
    """Behaviour of uvicorn's proxy-headers middleware with the value we configure."""
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    async def echo(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": scope["client"][0].encode()})

    app = ProxyHeadersMiddleware(echo, trusted_hosts="172.31.250.2")

    async def client_ip(peer: str) -> str:
        transport = httpx.ASGITransport(app=app, client=(peer, 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://api") as c:
            return (await c.get("/healthz", headers={"X-Forwarded-For": "198.51.100.7"})).text

    assert asyncio.run(client_ip("172.31.250.2")) == "198.51.100.7"  # from Caddy: the real client
    assert asyncio.run(client_ip("172.31.250.3")) == "172.31.250.3"  # anyone else: the header is ignored
    assert asyncio.run(client_ip("172.18.0.1")) == "172.18.0.1"  # e.g. a direct call through the published port
