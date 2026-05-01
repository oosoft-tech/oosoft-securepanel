from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core.dependencies import get_current_user
from app.models.user import User
from app.services.mail_manager import MailManager

router = APIRouter()


class CreateMailboxRequest(BaseModel):
    email: str
    password: str
    quota_mb: int = 1024


class MailboxResponse(BaseModel):
    email: str
    quota_mb: int
    maildir: str


@router.post("/mailboxes", response_model=MailboxResponse, status_code=status.HTTP_201_CREATED)
async def create_mailbox(
    request: CreateMailboxRequest,
    current_user: User = Depends(get_current_user),
):
    mail = MailManager()
    if not request.email.endswith(f"@") and "@" not in request.email:
        raise HTTPException(status_code=400, detail="Invalid email address")

    result = await mail.create_mailbox(
        email=request.email,
        password=request.password,
        quota_mb=request.quota_mb,
    )
    return result


@router.delete("/mailboxes/{email}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mailbox(
    email: str,
    current_user: User = Depends(get_current_user),
):
    mail = MailManager()
    await mail.delete_mailbox(email)


@router.post("/dkim/{domain}")
async def setup_dkim(
    domain: str,
    current_user: User = Depends(get_current_user),
):
    mail = MailManager()
    return await mail.setup_dkim(domain)
