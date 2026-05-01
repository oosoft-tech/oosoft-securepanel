from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core.dependencies import get_current_user
from app.models.user import User
from app.services.ftp_manager import FTPManager

router = APIRouter()


class CreateFTPRequest(BaseModel):
    username: str
    password: str
    subdirectory: str = ""


@router.post("/accounts", status_code=status.HTTP_201_CREATED)
async def create_ftp_account(
    request: CreateFTPRequest,
    current_user: User = Depends(get_current_user),
):
    ftp_username = f"{current_user.username}_{request.username}"
    home_dir = f"/home/{current_user.username}/public_html/{request.subdirectory}".rstrip("/")

    ftp = FTPManager()
    try:
        result = await ftp.create_ftp_account(ftp_username, request.password, home_dir)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/accounts/{ftp_username}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ftp_account(
    ftp_username: str,
    current_user: User = Depends(get_current_user),
):
    if not ftp_username.startswith(f"{current_user.username}_"):
        raise HTTPException(status_code=403, detail="Not authorized")
    ftp = FTPManager()
    await ftp.delete_ftp_account(ftp_username)
