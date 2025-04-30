from celery import Celery, shared_task
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

# Make sure it discovers tasks

