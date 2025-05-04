# celery_app.py
from celery import Celery, shared_task
from celery.schedules import crontab
import os

__all__ = ("celery_app", "shared_task")
celery_app = Celery(
    "openvulnscan",
    broker=os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/0"),
    include=["utils.tasks"]
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
)


celery_app.conf.beat_schedule = {
    'run-scheduled-scans-every-minute': {
        'task': 'utils.tasks.process_scheduled_scans',
        'schedule': crontab(minute='*'),
    },
}


