import shutil
import uuid
from pathlib import Path
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status

from app.core.dependencies import require_admin
from app.tasks.migration_tasks import run_migration

UPLOAD_DIR = Path("/var/securepanel/migration_uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTENSIONS = {".tar.gz", ".tgz"}
MAX_UPLOAD_SIZE = 10 * 1024 * 1024 * 1024  # 10 GB

router = APIRouter()


@router.post("/upload")
async def upload_backup(
    file: UploadFile = File(...),
    panel_type: str = "cpanel",
    admin=Depends(require_admin),
):
    if panel_type not in ("cpanel", "directadmin"):
        raise HTTPException(status_code=400, detail="panel_type must be 'cpanel' or 'directadmin'")

    filename = file.filename or ""
    if not (filename.endswith(".tar.gz") or filename.endswith(".tgz")):
        raise HTTPException(status_code=400, detail="Only .tar.gz / .tgz backups accepted")

    task_id = str(uuid.uuid4())
    dest = UPLOAD_DIR / f"{task_id}.tar.gz"

    total = 0
    with open(dest, "wb") as f:
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_UPLOAD_SIZE:
                dest.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="Backup file too large (max 10 GB)")
            f.write(chunk)

    task = run_migration.apply_async(
        args=[str(dest), panel_type, task_id],
        task_id=task_id,
    )

    return {"task_id": task_id, "status": "queued"}


@router.get("/status/{task_id}")
async def migration_status(task_id: str, admin=Depends(require_admin)):
    from app.tasks.celery_app import celery_app
    from celery.result import AsyncResult

    result = AsyncResult(task_id, app=celery_app)
    return {
        "task_id": task_id,
        "state": result.state,
        "result": result.result if result.ready() else None,
    }
