from fastapi import APIRouter, Depends
from app.core.dependencies import require_admin
from app.ai.assistant import ask_assistant
from pydantic import BaseModel

router = APIRouter()


class AssistantRequest(BaseModel):
    question: str
    include_logs: bool = False


@router.get("/anomalies")
async def get_anomalies(admin=Depends(require_admin)):
    from app.tasks.scan_tasks import analyze_access_logs
    result = analyze_access_logs.apply_async()
    return {"task_id": result.id, "status": "queued"}


@router.get("/imunify/incidents")
async def get_imunify_incidents(admin=Depends(require_admin)):
    from app.services.imunify_manager import ImunifyManager
    imunify = ImunifyManager()
    return await imunify.get_incidents()


@router.post("/assistant")
async def query_assistant(
    request: AssistantRequest,
    admin=Depends(require_admin),
):
    context_logs = None
    if request.include_logs:
        try:
            with open("/var/log/securepanel/error.log") as f:
                context_logs = f.readlines()[-100:]
        except FileNotFoundError:
            pass

    answer = await ask_assistant(request.question, context_logs)
    return {"answer": answer}


@router.get("/health")
async def health_check():
    return {"status": "ok"}
