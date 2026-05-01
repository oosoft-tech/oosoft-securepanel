from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.dependencies import get_current_user
from app.models.user import User
from app.services.dns_manager import DNSManager

router = APIRouter()


class AddRecordRequest(BaseModel):
    name: str
    record_type: str
    value: str
    ttl: int = 3600


@router.post("/{domain}/records", status_code=201)
async def add_dns_record(
    domain: str,
    request: AddRecordRequest,
    current_user: User = Depends(get_current_user),
):
    dns = DNSManager()
    try:
        await dns.add_record(domain, request.name, request.record_type, request.value, request.ttl)
        return {"detail": "Record added", "domain": domain}
    except (ValueError, FileNotFoundError) as e:
        raise HTTPException(status_code=400, detail=str(e))
