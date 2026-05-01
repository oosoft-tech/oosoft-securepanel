import re
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core.dependencies import get_current_user
from app.models.user import User

router = APIRouter()

CRONTAB_PATTERN = re.compile(
    r"^((\*|[0-9]{1,2}|[0-9]{1,2}-[0-9]{1,2}|[0-9]{1,2}/[0-9]{1,2})\s+){4}"
    r"(\*|[0-9]{1,2}|[0-9]{1,2}-[0-9]{1,2})\s+.+$"
)
DANGEROUS_CMDS = re.compile(r"(rm\s+-rf|mkfs|dd\s+if=|wget|curl|bash\s+-c)", re.IGNORECASE)


class CronJobRequest(BaseModel):
    schedule: str   # e.g. "0 * * * *"
    command: str


@router.post("/", status_code=status.HTTP_201_CREATED)
async def add_cron_job(
    request: CronJobRequest,
    current_user: User = Depends(get_current_user),
):
    cron_line = f"{request.schedule} {request.command}"
    if not CRONTAB_PATTERN.match(cron_line):
        raise HTTPException(status_code=400, detail="Invalid crontab format")
    if DANGEROUS_CMDS.search(request.command):
        raise HTTPException(status_code=400, detail="Command contains disallowed operations")

    import subprocess
    result = subprocess.run(
        ["crontab", "-l", "-u", current_user.username],
        capture_output=True, text=True
    )
    existing = result.stdout if result.returncode == 0 else ""
    new_crontab = existing + cron_line + "\n"

    proc = subprocess.run(
        ["crontab", "-u", current_user.username, "-"],
        input=new_crontab, text=True, capture_output=True
    )
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail="Failed to install crontab")

    return {"detail": "Cron job added", "schedule": request.schedule}


@router.get("/")
async def list_cron_jobs(current_user: User = Depends(get_current_user)):
    import subprocess
    result = subprocess.run(
        ["crontab", "-l", "-u", current_user.username],
        capture_output=True, text=True
    )
    lines = [l for l in result.stdout.splitlines() if l.strip() and not l.startswith("#")]
    return {"jobs": lines}
