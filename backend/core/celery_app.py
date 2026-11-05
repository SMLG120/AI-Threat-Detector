from celery import Celery
from celery.schedules import crontab

from core.config import settings

celery_app = Celery(
    "aiwaf",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["tasks.retrain", "tasks.maintenance"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    result_expires=3600,
    worker_prefetch_multiplier=1,  # long-running training jobs
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    broker_connection_retry_on_startup=True,
)

celery_app.conf.beat_schedule = {
    "retrain-models": {
        "task": "tasks.retrain.retrain_models",
        "schedule": crontab(minute=0, hour=f"*/{settings.RETRAIN_INTERVAL_HOURS}"),
    },
    "purge-old-logs": {
        "task": "tasks.maintenance.purge_old_logs",
        "schedule": crontab(minute=30, hour=3),  # daily 03:30 UTC
    },
}
