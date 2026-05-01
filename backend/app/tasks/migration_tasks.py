import asyncio
import logging
from pathlib import Path
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

UPLOAD_DIR = Path("/var/securepanel/migration_uploads")


@celery_app.task(name="app.tasks.migration_tasks.run_migration", bind=True, max_retries=1)
def run_migration(self, backup_path: str, panel_type: str, task_id: str):
    async def _migrate():
        path = Path(backup_path)
        if not path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")

        if panel_type == "cpanel":
            from app.services.migration.cpanel_parser import CpanelParser
            parser = CpanelParser()
        elif panel_type == "directadmin":
            from app.services.migration.directadmin_parser import DirectAdminParser
            parser = DirectAdminParser()
        else:
            raise ValueError(f"Unknown panel type: {panel_type}")

        account = parser.parse(path)

        from app.services.migration.restore_engine import RestoreEngine
        engine = RestoreEngine()
        result = await engine.restore_account(account, path, task_id)
        return result

    try:
        return asyncio.run(_migrate())
    except Exception as exc:
        logger.exception(f"Migration task failed: {exc}")
        raise self.retry(exc=exc, countdown=30)
