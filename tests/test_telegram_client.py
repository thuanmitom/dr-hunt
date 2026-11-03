"""Bot API client: HTML + no previews, 429 handling, splitting, and the token never leaking (TELEGRAM.md §9)."""

from __future__ import annotations

import logging

import httpx
import pytest

from app.integrations.telegram.client import TelegramClient, TelegramError, scrub
from tests.telegram_fakes import CHAT, TOKEN, FakeTelegram, enable_loggers


def _client(fake: FakeTelegram, **kw) -> tuple[TelegramClient, list[float]]:
    slept: list[float] = []

    async def sleep(s: float) -> None:
        slept.append(s)

    return TelegramClient(TOKEN, http=httpx.AsyncClient(transport=fake.transport()), sleep=sleep, **kw), slept


async def test_send_message_uses_html_without_previews_and_splits():
    fake = FakeTelegram()
    client, _ = _client(fake)
    ids = await client.send_message(CHAT, "\n".join("x" * 100 for _ in range(100)))  # ~10,100 characters
    assert len(ids) == 3 and len(fake.calls) == 3
    for method, payload in fake.calls:
        assert method == "sendMessage" and payload["parse_mode"] == "HTML" and payload["chat_id"] == CHAT
        assert payload["link_preview_options"] == {"is_disabled": True} and len(payload["text"]) <= 4096


async def test_429_waits_retry_after_then_succeeds_and_gives_up_on_long_waits():
    fake = FakeTelegram()
    fake.queue_429 = 2
    client, slept = _client(fake)
    assert await client.send_message(CHAT, "hi")
    assert slept == [3.0, 3.0] and len(fake.calls) == 3

    long_wait = FakeTelegram()
    long_wait.fail_with = httpx.Response(
        429, json={"ok": False, "error_code": 429, "parameters": {"retry_after": 3600}}
    )
    client, slept = _client(long_wait)
    with pytest.raises(TelegramError, match="flood wait") as err:
        await client.send_message(CHAT, "hi")
    assert slept == [] and err.value.error_code == 429


async def test_token_never_appears_in_errors_or_logs(caplog):
    enable_loggers("httpx", "httpcore", "app.integrations.telegram.client")
    caplog.set_level(logging.DEBUG)
    fake = FakeTelegram()
    client, _ = _client(fake)
    await client.send_message(CHAT, "hello")  # httpx logs the request URL (with the token) at INFO
    await client.get_updates(None, timeout=1)

    fake.fail_with = httpx.Response(401, json={"ok": False, "error_code": 401, "description": f"bad token {TOKEN}"})
    with pytest.raises(TelegramError) as api_err:
        await client.send_message(CHAT, "x")

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {request.url}", request=request)

    down = TelegramClient(TOKEN, http=httpx.AsyncClient(transport=httpx.MockTransport(refuse)))
    with pytest.raises(TelegramError) as net_err:
        await down.send_message(CHAT, "x")

    fake.fail_with = httpx.Response(502, text="<html>bad gateway</html>")
    with pytest.raises(TelegramError, match="not JSON") as html_err:
        await client.send_message(CHAT, "x")

    for err in (api_err.value, net_err.value, html_err.value):
        assert TOKEN not in str(err) and err.__cause__ is None
        assert err.__context__ is None or err.__suppress_context__  # the httpx exception (with the URL) is hidden
    assert "<redacted>" in str(api_err.value) and "<redacted>" in str(net_err.value)
    assert "HTTP Request" in caplog.text  # the httpx line was emitted...
    assert TOKEN not in caplog.text  # ...but scrubbed


async def test_document_upload_and_other_methods():
    fake = FakeTelegram()
    client, _ = _client(fake)
    await client.send_document(CHAT, "pack-1.json", b'{"a": 1}', caption="<b>pack</b>", mime="application/json")
    await client.answer_callback_query("cb-1")
    await client.delete_webhook()
    await client.get_updates(42, timeout=5)
    methods = [m for m, _ in fake.calls]
    assert methods == ["sendDocument", "answerCallbackQuery", "deleteWebhook", "getUpdates"]
    body = fake.calls[0][1]["_multipart"]
    assert b'filename="pack-1.json"' in body and str(CHAT).encode() in body and b'{"a": 1}' in body
    assert fake.calls[3][1] == {"timeout": 5, "allowed_updates": ["message", "callback_query"], "offset": 42}


def test_scrub_removes_token_shapes_even_without_the_token():
    assert scrub(f"url /bot{TOKEN}/sendMessage") == "url /bot<redacted>/sendMessage"
    assert scrub("bot 987654321:AA" + "z" * 35) == "bot <redacted>"
    with pytest.raises(ValueError):
        TelegramClient("")
