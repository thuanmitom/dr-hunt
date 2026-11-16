"""Log output for every HuntCompiler process (API, worker, beat, CertStream watcher, Telegram bot).

``HC_LOG_FORMAT=json`` writes one JSON object per line (D-58) so a SIEM can ingest the logs; the default stays plain
text. Formatting happens after logger filters, so the Telegram token scrubber still applies. No new dependency.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

PLAIN_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
# uvicorn and Celery keep their own handlers; their formatters are replaced too
OWN_HANDLER_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access", "celery", "celery.task")
# HTTP client libraries log one INFO line per request (94 % of the worker's output in the 2026-11-14 run). They are
# held at WARNING unless HC_LOG_LEVEL=DEBUG (D-58).
NOISY_LOGGERS = ("httpx", "httpcore")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        for key in ("task_name", "task_id"):  # set by Celery's task logger
            if value := getattr(record, key, None):
                doc[key] = value
        return json.dumps(doc, ensure_ascii=False)


def formatter_for(log_format: str) -> logging.Formatter:
    return JsonFormatter() if log_format == "json" else logging.Formatter(PLAIN_FORMAT)


def configure_logging(level: str, log_format: str) -> None:
    """Root handler plus the handlers uvicorn/Celery installed themselves."""
    logging.basicConfig(level=level, format=PLAIN_FORMAT)
    root = logging.getLogger()
    root.setLevel(level)
    apply_formatter(log_format, [root, *(logging.getLogger(n) for n in OWN_HANDLER_LOGGERS)])
    quiet_noisy_loggers(level)


def quiet_noisy_loggers(level: str | int) -> None:
    """Request lines from the HTTP clients only at DEBUG; warnings and errors always pass."""
    numeric = level if isinstance(level, int) else logging.getLevelName(str(level).upper())
    debug = isinstance(numeric, int) and numeric <= logging.DEBUG
    for name in NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.NOTSET if debug else logging.WARNING)


def apply_formatter(log_format: str, loggers: list[logging.Logger]) -> None:
    fmt = formatter_for(log_format)
    for logger in loggers:
        for handler in logger.handlers:
            if log_format == "json" or isinstance(handler.formatter, JsonFormatter):
                handler.setFormatter(fmt)
