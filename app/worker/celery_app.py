"""Celery application. Queues are split so slow LLM compilation never starves delivery:
collectors (I/O-bound polling), compiler (Gemini + pySigma), dispatch (webhooks).
``notify.*`` (Telegram digest) runs on the default queue."""

from __future__ import annotations

from celery import Celery

from app.core.config import get_settings

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


@celery_app.task(name="system.ping")
def ping() -> str:
    return "pong"
