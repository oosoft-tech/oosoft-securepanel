from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core.dependencies import get_current_user
from app.models.user import User
from app.services.db_manager import DatabaseManager

router = APIRouter()


class CreateDBRequest(BaseModel):
    db_name: str


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_database(
    request: CreateDBRequest,
    current_user: User = Depends(get_current_user),
):
    db_mgr = DatabaseManager()
    full_name = f"{current_user.username}_{request.db_name}"
    await db_mgr.create_database(full_name, current_user.username)
    return {"database": full_name, "owner": current_user.username}


@router.delete("/{db_name}", status_code=status.HTTP_204_NO_CONTENT)
async def drop_database(
    db_name: str,
    current_user: User = Depends(get_current_user),
):
    if not db_name.startswith(f"{current_user.username}_"):
        raise HTTPException(status_code=403, detail="Not authorized to delete this database")
    db_mgr = DatabaseManager()
    await db_mgr.drop_database(db_name)
