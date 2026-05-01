from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "securepanel",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.ssl_tasks",
        "app.tasks.scan_tasks",
        "app.tasks.migration_tasks",
        "app.tasks.backup_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,
    beat_schedule={
        "ssl-renewal-check": {
            "task": "app.tasks.ssl_tasks.check_expiring_certs",
            "schedule": 86400.0,   # daily
        },
        "brute-force-scan": {
            "task": "app.tasks.scan_tasks.scan_auth_logs",
            "schedule": 300.0,    # every 5 minutes
        },
        "malware-scan": {
            "task": "app.tasks.scan_tasks.run_malware_scan",
            "schedule": 3600.0,   # hourly
        },
    },
)
