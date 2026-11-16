"""Minimal push endpoint (``delivery.mode: push``). Pull is the recommended path; use this only if HuntCompiler must
call you. Put it behind your TLS reverse proxy; it listens on plain HTTP on the address you give it.

It verifies the HMAC over the raw body, refuses stale timestamps and re-validates the pack, then queues it in the
inbox and answers 202 at once (hunting happens later, in ``run``). HuntCompiler retries on 408/425/429/5xx and
dead-letters other errors.
"""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from integration_kit.reference_consumer.signing import SIGNATURE_HEADER, TIMESTAMP_HEADER, SignatureError, verify
from integration_kit.reference_consumer.state import State
from integration_kit.reference_consumer.validate import PackRejected, validate_pack

log = logging.getLogger("hc_kit.receiver")
MAX_BODY_BYTES = 1024 * 1024


class PushServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], *, secret: str, state: State, path: str = "/huntcompiler") -> None:
        super().__init__(address, PushHandler)
        self.secret, self.state, self.path = secret, state, path.rstrip("/") or "/"


class PushHandler(BaseHTTPRequestHandler):
    server: PushServer

    def _reply(self, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802 — http.server naming
        if self.path.rstrip("/") != self.server.path.rstrip("/"):
            return self._reply(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._reply(411, {"error": "Content-Length required"})
        if length > MAX_BODY_BYTES:
            return self._reply(413, {"error": "body too large"})
        body = self.rfile.read(length)
        try:
            verify(self.server.secret, body, self.headers.get(SIGNATURE_HEADER), self.headers.get(TIMESTAMP_HEADER))
        except SignatureError as exc:
            log.warning("push refused: %s", exc)
            return self._reply(401, {"error": "invalid signature"})
        try:
            pack = json.loads(body)
            validate_pack(pack)
        except (ValueError, PackRejected) as exc:  # json.JSONDecodeError is a ValueError
            log.warning("push refused: invalid pack: %s", exc)
            return self._reply(422, {"error": "invalid pack"})
        if not self.server.state.enqueue(pack):
            return self._reply(200, {"status": "duplicate"})
        return self._reply(202, {"status": "queued"})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 — http.server signature
        log.info("push %s %s", self.address_string(), format % args)


def serve(host: str, port: int, *, secret: str, state: State, path: str = "/huntcompiler") -> None:
    with PushServer((host, port), secret=secret, state=state, path=path) as server:
        log.info("push receiver on http://%s:%d%s (put TLS in front)", host, port, path)
        server.serve_forever()
