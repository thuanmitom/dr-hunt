"""Shared fakes for the Telegram tests: a recording Bot API transport and in-memory Redis stand-ins."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

TOKEN = "123456789:AAH" + "k" * 33  # shaped like a real token so the generic scrubber is exercised too
CHAT = 424242
USER = 777


class FakeTelegram:
    """Answers Bot API calls like Telegram; records (method, payload). ``fail_with`` makes every call fail."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail_with: httpx.Response | None = None
        self.queue_429: int = 0
        self._next_id = 100

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.telegram.org", f"unexpected network call to {request.url.host}"
        method = request.url.path.rsplit("/", 1)[-1]
        content_type = request.headers.get("content-type", "")
        if content_type.startswith("application/json"):
            payload = json.loads(request.content or b"{}")
        else:
            payload = {"_multipart": request.content, "_file": _multipart_file(request.content, content_type)}
        self.calls.append((method, payload))
        if self.fail_with is not None:
            return self.fail_with
        if self.queue_429:
            self.queue_429 -= 1
            return httpx.Response(429, json={"ok": False, "error_code": 429, "description": "Too Many Requests",
                                             "parameters": {"retry_after": 3}})  # fmt: skip
        if method == "getUpdates":
            return httpx.Response(200, json={"ok": True, "result": []})
        self._next_id += 1
        return httpx.Response(200, json={"ok": True, "result": {"message_id": self._next_id}})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def texts(self) -> list[str]:
        return [p["text"] for m, p in self.calls if m == "sendMessage"]

    def documents(self) -> list[tuple[str, bytes]]:
        """(filename, content) of every sendDocument call."""
        return [p["_file"] for m, p in self.calls if m == "sendDocument"]


def _multipart_file(body: bytes, content_type: str) -> tuple[str, bytes] | None:
    boundary = content_type.split("boundary=", 1)[-1].encode()
    for part in body.split(b"--" + boundary):
        head, _, content = part.partition(b"\r\n\r\n")
        if b'name="document"' in head and (m := re.search(rb'filename="([^"]+)"', head)):
            return m.group(1).decode(), content[:-2] if content.endswith(b"\r\n") else content
    return None


class FakeAsyncRedis:
    def __init__(self, hashes: dict[str, dict[str, str]] | None = None, values: dict[str, str] | None = None):
        self.hashes = hashes or {}
        self.values = values or {}

    async def hgetall(self, name: str) -> dict[str, str]:
        return dict(self.hashes.get(name, {}))

    async def get(self, name: str) -> str | None:
        return self.values.get(name)


class BrokenAsyncRedis:
    async def hgetall(self, name: str) -> dict[str, str]:
        raise ConnectionError("redis down")

    async def get(self, name: str) -> str | None:
        raise ConnectionError("redis down")


class FakeSyncRedis:
    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, str]] = {}

    def hset(self, name: str, mapping: dict[str, str]) -> None:
        self.hashes.setdefault(name, {}).update(mapping)


async def no_sleep(_: float) -> None:
    return None


def enable_loggers(*names: str) -> None:
    """The integration tests run Alembic, whose fileConfig() disables every logger that already exists. Tests that
    assert on log output re-enable the loggers they read."""
    for name in names:
        logging.getLogger(name).disabled = False
