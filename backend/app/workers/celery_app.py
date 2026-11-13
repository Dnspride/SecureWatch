"""
Celery background worker application for asynchronous SIEM tasks.
"""
from __future__ import annotations

import os
from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "securewatch_tasks",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    beat_schedule={
        "check-device-heartbeats-every-minute": {
            "task": "app.workers.tasks.check_device_heartbeats",
            "schedule": 60.0,
        },
        "compute-device-risk-scores-every-5-min": {
            "task": "app.workers.tasks.compute_all_device_risks",
            "schedule": 300.0,
        },
    },
)
