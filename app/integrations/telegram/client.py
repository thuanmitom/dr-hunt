"""Minimal Telegram Bot API client on httpx (DECISIONS.md D-42): getUpdates, sendMessage, sendDocument,
answerCallbackQuery, deleteWebhook.

The bot token is part of every request URL (``/bot<token>/<method>``). It is scrubbed from every exception this
module raises (raised ``from None`` so the original httpx exception, which carries the URL, is not chained into
tracebacks) and from httpx's own request log lines by a logging filter.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable
from types import TracebackType
from typing import Any

import httpx

from app.integrations.telegram.format import MAX_MESSAGE_CHARS, split_text

API_BASE = "https://api.telegram.org"
MAX_RETRY_AFTER = 300  # seconds; a longer flood wait fails the call instead of blocking a worker for an hour
_TOKEN_SHAPE = re.compile(r"\d{6,12}:[A-Za-z0-9_-]{30,}")
log = logging.getLogger(__name__)


def scrub(text: str, token: str | None = None) -> str:
    """Remove the bot token (and anything shaped like a bot token) from text."""
    if token:
        text = text.replace(token, "<redacted>")
    return _TOKEN_SHAPE.sub("<redacted>", text)


class _ScrubFilter(logging.Filter):
    def __init__(self, token: str) -> None:
        super().__init__()
        self.token = token

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        clean = scrub(message, self.token)
        if clean != message:
            record.msg, record.args = clean, None
        return True


def install_log_scrubber(token: str) -> None:
    """httpx logs every request URL at INFO, and that URL contains the token."""
    for name in ("httpx", "httpcore"):
        logger = logging.getLogger(name)
        if not any(isinstance(f, _ScrubFilter) and f.token == token for f in logger.filters):
            logger.addFilter(_ScrubFilter(token))


class TelegramError(RuntimeError):
    """A failed Bot API call. The message never contains the token."""

    def __init__(self, message: str, *, error_code: int | None = None) -> None:
        super().__init__(message)
        self.error_code = error_code


class TelegramClient:
    def __init__(self, token: str, *, http: httpx.AsyncClient | None = None, base_url: str = API_BASE,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep, max_retries: int = 3,
                 timeout: float = 20.0) -> None:  # fmt: skip
        if not token:
            raise ValueError("empty Telegram bot token")
        self._token = token
        self._own_http = http is None
        self._http = http or httpx.AsyncClient(timeout=timeout, follow_redirects=False)
        self._base = f"{base_url.rstrip('/')}/bot{token}"
        self._sleep = sleep
        self._max_retries = max_retries
        self._timeout = timeout
        install_log_scrubber(token)

    async def aclose(self) -> None:
        if self._own_http:
            await self._http.aclose()

    async def __aenter__(self) -> TelegramClient:
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                        tb: TracebackType | None) -> None:  # fmt: skip
        await self.aclose()

    def scrub(self, text: str) -> str:
        return scrub(text, self._token)

    async def _call(self, method: str, *, json: dict[str, Any] | None = None, data: dict[str, str] | None = None,
                    files: dict[str, Any] | None = None, timeout: float | None = None) -> Any:  # fmt: skip
        for attempt in range(self._max_retries + 1):
            try:
                resp = await self._http.post(f"{self._base}/{method}", json=json, data=data, files=files,
                                             timeout=timeout or self._timeout)  # fmt: skip
            except httpx.HTTPError as exc:
                raise TelegramError(self.scrub(f"{method}: {type(exc).__name__}: {exc}")) from None
            try:
                body = resp.json()
            except ValueError:
                raise TelegramError(f"{method}: HTTP {resp.status_code}, response is not JSON") from None
            if body.get("ok"):
                return body.get("result")
            code = int(body.get("error_code") or resp.status_code)
            retry_after = (body.get("parameters") or {}).get("retry_after")
            if code == 429 and retry_after is not None and attempt < self._max_retries:
                wait = float(retry_after)
                if wait > MAX_RETRY_AFTER:
                    raise TelegramError(f"{method}: flood wait {wait:.0f}s > {MAX_RETRY_AFTER}s", error_code=429)
                log.warning("telegram %s rate limited; retrying in %.0fs", method, wait)
                await self._sleep(wait)
                continue
            description = str(body.get("description", ""))[:300]
            raise TelegramError(self.scrub(f"{method}: {code} {description}"), error_code=code)
        raise TelegramError(f"{method}: still rate limited after {self._max_retries} retries", error_code=429)

    # --- methods -------------------------------------------------------------------------------------
    async def get_updates(self, offset: int | None, *, timeout: int = 30) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {"timeout": timeout, "allowed_updates": ["message", "callback_query"]}
        if offset is not None:
            payload["offset"] = offset
        return list(await self._call("getUpdates", json=payload, timeout=timeout + 15) or [])

    async def send_message(self, chat_id: int, text: str) -> list[int]:
        """HTML, link previews off. Text over 4,096 characters is split at line boundaries."""
        ids = []
        for part in split_text(text, MAX_MESSAGE_CHARS):
            result = await self._call("sendMessage", json={
                "chat_id": chat_id, "text": part, "parse_mode": "HTML", "link_preview_options": {"is_disabled": True},
            })  # fmt: skip
            ids.append(int(result["message_id"]))
        return ids

    async def send_document(self, chat_id: int, filename: str, content: bytes, *, caption: str | None = None,
                            mime: str = "text/plain") -> int:  # fmt: skip
        data = {"chat_id": str(chat_id)}
        if caption:
            data |= {"caption": caption[:1024], "parse_mode": "HTML"}
        result = await self._call("sendDocument", data=data, files={"document": (filename, content, mime)})
        return int(result["message_id"])

    async def answer_callback_query(self, callback_query_id: str, text: str | None = None) -> None:
        payload: dict[str, Any] = {"callback_query_id": callback_query_id}
        if text:
            payload["text"] = text[:200]
        await self._call("answerCallbackQuery", json=payload)

    async def delete_webhook(self, *, drop_pending_updates: bool = False) -> None:
        await self._call("deleteWebhook", json={"drop_pending_updates": drop_pending_updates})
