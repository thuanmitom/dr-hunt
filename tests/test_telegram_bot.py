"""Bot gatekeeping without a database: allowlist, rate limit, parsing, input validation, heartbeats, schedule."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.core.config import Settings
from app.integrations.telegram.bot import Bot, pack_files, parse_command, parse_ioc
from app.integrations.telegram.client import TelegramClient
from app.integrations.telegram.digest import digest_crontabs
from app.worker import health
from tests.telegram_fakes import (
    CHAT,
    TOKEN,
    USER,
    FakeAsyncRedis,
    FakeSyncRedis,
    FakeTelegram,
    enable_loggers,
    no_sleep,
)

GROUP = -1001234567890


class NoDatabase:
    """A sessionmaker that fails the test if any command touches the database."""

    def __call__(self):
        raise AssertionError("database accessed")


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def _bot(fake: FakeTelegram, *, chats=(CHAT,), users=(USER,), clock=None) -> Bot:
    settings = Settings(tgbot_enabled=True, tgbot_token=TOKEN, tgbot_chat_ids=list(chats)[:1],
                        tgbot_allowed_user_ids=list(users))  # fmt: skip
    client = TelegramClient(TOKEN, http=httpx.AsyncClient(transport=fake.transport()), sleep=no_sleep)
    return Bot(settings, client, NoDatabase(), FakeAsyncRedis(), clock=clock or Clock(), sleep=no_sleep)


def _msg(text: str, *, chat: int = CHAT, user: int = USER) -> dict:
    return {"update_id": 1, "message": {"chat": {"id": chat}, "from": {"id": user}, "text": text}}


def test_parse_command():
    assert parse_command("/status") == ("status", [])
    assert parse_command("/pack@OutSightBot 3f1c2b7e extra") == ("pack", ["3f1c2b7e", "extra"])
    assert parse_command("/IOC evil[.]example") == ("ioc", ["evil[.]example"])
    for text in ("hello", "", "/", "/x-y", "/status@b", " / status"):
        assert parse_command(text) == (None, [])


@pytest.mark.parametrize(
    "update",
    [
        _msg("/status", chat=999),  # stranger's private chat
        _msg("/status", chat=GROUP, user=USER),  # allowlisted user, chat not allowlisted
        _msg("/status", chat=CHAT, user=555),  # allowlisted chat, member not allowlisted
        {"update_id": 2, "callback_query": {"id": "cb", "from": {"id": 555}, "message": {"chat": {"id": CHAT}}}},
    ],
)
async def test_strangers_get_no_reply_and_no_database_access(update, caplog):
    enable_loggers("telegram_bot")
    caplog.set_level(logging.INFO)
    fake = FakeTelegram()
    await _bot(fake).handle_update(update)
    assert fake.calls == []
    assert "not in allowlist" in caplog.text


async def test_group_member_not_in_user_allowlist_is_ignored():
    fake = FakeTelegram()
    bot = _bot(fake, chats=(GROUP,), users=(USER,))
    await bot.handle_update(_msg("/help", chat=GROUP, user=555))
    assert fake.calls == []
    await bot.handle_update(_msg("/help@OutSightBot", chat=GROUP, user=USER))
    assert [m for m, _ in fake.calls] == ["sendMessage"] and "/pack" in fake.texts()[0]


async def test_rate_limit_is_ten_commands_per_user_per_minute():
    fake, clock = FakeTelegram(), Clock()
    bot = _bot(fake, clock=clock)
    for _ in range(12):
        await bot.handle_update(_msg("/help"))
    assert len(fake.calls) == 10
    clock.t += 61
    await bot.handle_update(_msg("/help"))
    assert len(fake.calls) == 11


async def test_plain_text_and_unknown_commands():
    fake = FakeTelegram()
    bot = _bot(fake)
    await bot.handle_update(_msg("just chatting"))
    assert fake.calls == []
    await bot.handle_update(_msg("/scan https://evil.example"))
    assert fake.texts() == ["Unknown command. Send /help."]


@pytest.mark.parametrize(
    "text", ["/pack", "/pack abc", "/pack zzzzzzzz", "/pack 3f1c%' OR 1=1", "/ioc", "/ioc not a host!", "/cve",
             "/cve CVE-26-1", "/latest many"],
)  # fmt: skip
async def test_invalid_input_is_rejected_before_any_query(text):
    fake = FakeTelegram()
    await _bot(fake).handle_update(_msg(text))
    [reply] = fake.texts()
    assert reply.startswith("Usage:")


async def test_allowlisted_callback_is_acknowledged():
    fake = FakeTelegram()
    update = {"update_id": 3, "callback_query": {"id": "cb-9", "from": {"id": USER}, "message": {"chat": {"id": CHAT}}}}
    await _bot(fake).handle_update(update)
    assert fake.calls == [("answerCallbackQuery", {"callback_query_id": "cb-9"})]


def test_parse_ioc_accepts_defanged_input():
    assert parse_ioc("hxxps://C2[.]Evil-CDN[.]example/x.hta") == ("domain", "c2.evil-cdn.example")
    assert parse_ioc("evil(.)example") == ("domain", "evil.example")
    assert parse_ioc("45[.]155[.]205[.]10") == ("ip", "45.155.205.10")
    assert parse_ioc("2001:db8::1") == ("ip", "2001:db8::1")
    assert parse_ioc("A" * 64) == ("sha256", "a" * 64)
    assert parse_ioc("not a host!") is None and parse_ioc("") is None


def test_pack_files_names_and_contents():
    payload = {"pack_id": "p-1", "internal_hunting_tasks": [
        {"task_id": "v3-runmru-paste", "sigma_yaml": "title: t\n", "compiled_queries": {
            "wazuh_es_dsl": {"query": {"term": {"a": "b"}}}, "kql_defender": "DeviceRegistryEvents | take 1"}}]}  # fmt: skip
    files = pack_files(payload)
    assert [name for name, _, _ in files] == ["pack-p-1.json", "v3-runmru-paste.yml", "queries-p-1.txt"]
    queries = files[2][1].decode()
    assert "# Wazuh / OpenSearch DSL" in queries
    assert "DeviceRegistryEvents" not in queries and "KQL" not in queries  # D-63: an older pack's KQL is not shown


def test_digest_schedule_is_converted_to_utc():
    [first, second] = digest_crontabs(["08:00", "20:30"], "Asia/Ho_Chi_Minh")
    assert (first.hour, first.minute) == ({1}, {0}) and (second.hour, second.minute) == ({13}, {30})


# --- heartbeats ------------------------------------------------------------------------------------------
def test_track_records_ok_partial_failure_not_configured_and_errors():
    r = FakeSyncRedis()
    with health.track("reference_sync", client=r):
        pass
    assert r.hashes["hc:health:reference_sync"]["state"] == "ok"

    with health.track("reference_sync", client=r) as hb:
        hb.fail("osv_malicious/npm: HTTPStatusError")
    assert r.hashes["hc:health:reference_sync"]["state"] == "failing"
    assert r.hashes["hc:health:reference_sync"]["last_error"] == "osv_malicious/npm: HTTPStatusError"

    with health.track("hibp_sweep", client=r):
        raise health.NotConfigured("HC_HIBP_API_KEY not set")
    assert r.hashes["hc:health:hibp_sweep"]["state"] == "not_configured"

    with pytest.raises(RuntimeError), health.track("urlscan_sweep", client=r):
        raise RuntimeError("secret detail https://x.example/?key=abc")
    assert r.hashes["hc:health:urlscan_sweep"]["last_error"] == "RuntimeError"  # type only, never the message


def test_derived_states():
    now = datetime(2026, 11, 2, tzinfo=UTC)
    src = health.Source("deliver_due", "Push dispatch", 60)

    def at(minutes: int) -> str:
        return (now - timedelta(minutes=minutes)).isoformat()

    assert health.derive(src, {}, now).state == "unknown"
    assert health.derive(src, {"state": "ok", "last_success_at": at(1)}, now).state == "ok"
    assert health.derive(src, {"state": "ok", "last_success_at": at(5)}, now).state == "stale"
    assert health.derive(src, {"state": "failing", "last_success_at": at(9), "last_failure_at": at(1)}, now).state == (
        "failing"
    )
    assert health.derive(src, {"state": "not_configured"}, now).state == "not_configured"
