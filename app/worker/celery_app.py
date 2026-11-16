"""Celery application. Queues are split so slow LLM compilation never starves delivery:
collectors (I/O-bound polling), compiler (Gemini + pySigma), dispatch (webhooks).
``notify.*`` (Telegram digest) runs on the default queue."""

from __future__ import annotations

import gc
import logging

from celery import Celery
from celery.signals import after_setup_logger, after_setup_task_logger, worker_init

from app.core.config import get_settings
from app.core.logging import apply_formatter, quiet_noisy_loggers

_settings = get_settings()

celery_app = Celery(
    "huntcompiler",
    broker=_settings.celery_broker_url,
    backend=_settings.celery_result_backend,
    include=[
        "app.collectors.tasks",
        "app.collectors.tasks_2b",
        "app.compiler.tasks",
        "app.integrations.telegram.digest",
        "app.worker.maintenance",
        "app.integrations.telegram.ops_alerts",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,  # re-deliver if a worker dies mid-task
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_time_limit=600,
    task_soft_time_limit=540,
    result_expires=86_400,
    broker_connection_retry_on_startup=True,
    task_default_queue="default",
    task_routes={
        "collectors.*": {"queue": "collectors"},
        "compiler.*": {"queue": "compiler"},
        "processors.*": {"queue": "collectors"},
        "dispatch.*": {"queue": "dispatch"},
    },
    beat_schedule={},  # filled by app.collectors.tasks
)


@after_setup_logger.connect
@after_setup_task_logger.connect
def _log_format(logger, loglevel: int | str = logging.INFO, **_: object) -> None:
    """HC_LOG_FORMAT=json for the worker and beat too, and no per-request lines from httpx (D-58)."""
    apply_formatter(get_settings().log_format, [logger])
    quiet_noisy_loggers(loglevel)


@worker_init.connect
def _preload_shared_data(**_: object) -> None:
    """Load the MISP warninglists (~300 MiB) once in the worker's main process, before the pool forks its task
    processes (D-75). The processes then share those memory pages instead of each loading its own copy;
    ``gc.freeze()`` keeps the garbage collector from touching, and so copying, the shared objects."""
    try:
        from app.processors.whitelist_filter import default_sources

        default_sources()
    except Exception as exc:  # noqa: BLE001 — each task process still loads the lists on first use
        logging.getLogger(__name__).warning("warninglists not preloaded: %s", type(exc).__name__)
        return
    gc.freeze()


@celery_app.task(name="system.ping")
def ping() -> str:
    return "pong"
