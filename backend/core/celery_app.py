from celery import Celery
from core.config import settings

celery_app = Celery(
    "aiwaf",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["tasks.detection"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "tasks.detection.*": {"queue": "detection"},
    },
    worker_prefetch_multiplier=4,
    task_acks_late=True,
)

from celery.schedules import crontab
celery_app.conf.beat_schedule = {
    'retrain-models': {
        'task': 'tasks.retrain.retrain_models',
        'schedule': crontab(minute='*/30'),  # Every 30 minutes
    },
}
