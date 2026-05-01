"""
Domain management API endpoints.

POST /domains          — create a new domain (nginx config + webroot)
GET  /domains          — list domains for the current user
DELETE /domains/{id}   — remove a domain and its nginx config
POST /domains/{id}/ssl — issue and enable SSL for a domain
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.agent_client import AgentClient, AgentError
from app.models.domain import Domain
from app.models.user import User
from app.utils.validators import validate_domain

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class CreateDomainRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        try:
            return validate_domain(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc


class DomainResponse(BaseModel):
    id: int
    domain: str
    php_version: str
    ssl_enabled: bool
    document_root: str

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Helper — map AgentError to an HTTP response without leaking internals
# ---------------------------------------------------------------------------

def _agent_http_error(exc: Exception, context: str) -> HTTPException:
    """
    Log the real error internally; return a generic 502 to the caller.
    Never surfaces agent internals, file paths, or stack traces.
    """
    logger.error("Agent call failed during %s: %s", context, exc)
    return HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail="A server-side error occurred. The administrator has been notified.",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", response_model=list[DomainResponse])
async def list_domains(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Domain).where(Domain.user_id == current_user.id)
    )
    return result.scalars().all()


@router.post("/", response_model=DomainResponse, status_code=status.HTTP_201_CREATED)
async def create_domain(
    request: CreateDomainRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a domain:
      1. Validate domain (Pydantic + validate_domain — normalised to lowercase)
      2. Check it does not already exist in the database
      3. Call the privileged agent to create webroot + nginx config
      4. Persist to database
      5. Return structured response

    The agent performs a second round of validation (defense-in-depth)
    and runs `nginx -t` before any reload.
    """
    domain = request.domain  # already validated and lowercased by Pydantic

    # -- Duplicate check -------------------------------------------------------
    existing = await db.execute(select(Domain).where(Domain.domain == domain))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Domain already exists",
        )

    # -- Privileged agent call -------------------------------------------------
    agent = AgentClient()
    try:
        result = await agent.call("nginx.create_domain", {
            "domain":   domain,
            "username": current_user.username,
        })
    except AgentError as exc:
        raise _agent_http_error(exc, f"create_domain({domain!r})")
    except (RuntimeError, TimeoutError) as exc:
        raise _agent_http_error(exc, f"create_domain({domain!r})")

    webroot = result.get("webroot", f"/var/www/{domain}")

    # -- Persist ---------------------------------------------------------------
    new_domain = Domain(
        user_id=current_user.id,
        domain=domain,
        document_root=webroot,
        php_version="8.1",
        ssl_enabled=False,
    )
    db.add(new_domain)

    try:
        await db.commit()
        await db.refresh(new_domain)
    except Exception as exc:
        # DB failure after agent already succeeded — log for manual reconciliation
        logger.error(
            "DB commit failed after agent created domain=%r for user=%r: %s",
            domain, current_user.username, exc,
        )
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Domain was provisioned but could not be saved. Contact support.",
        )

    logger.info("Domain created: domain=%r user=%r", domain, current_user.username)
    return new_domain


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain(
    domain_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Domain).where(
            Domain.id == domain_id,
            Domain.user_id == current_user.id,
        )
    )
    domain_obj = result.scalar_one_or_none()
    if not domain_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")

    agent = AgentClient()
    try:
        await agent.call("nginx.delete_domain", {
            "domain":   domain_obj.domain,
            "username": current_user.username,
        })
    except (AgentError, RuntimeError, TimeoutError) as exc:
        raise _agent_http_error(exc, f"delete_domain({domain_obj.domain!r})")

    await db.delete(domain_obj)
    await db.commit()
    logger.info("Domain deleted: domain=%r user=%r", domain_obj.domain, current_user.username)


@router.post("/{domain_id}/ssl", status_code=status.HTTP_200_OK)
async def enable_ssl(
    domain_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Domain).where(
            Domain.id == domain_id,
            Domain.user_id == current_user.id,
        )
    )
    domain_obj = result.scalar_one_or_none()
    if not domain_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")

    if domain_obj.ssl_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="SSL is already enabled")

    agent = AgentClient()
    try:
        await agent.call("ssl.issue", {
            "domain":  domain_obj.domain,
            "webroot": f"/home/{current_user.username}/public_html",
        })
        await agent.call("nginx.create_domain", {
            "domain":   domain_obj.domain,
            "username": current_user.username,
            "ssl":      True,
        })
    except (AgentError, RuntimeError, TimeoutError) as exc:
        raise _agent_http_error(exc, f"enable_ssl({domain_obj.domain!r})")

    domain_obj.ssl_enabled = True
    await db.commit()
    logger.info("SSL enabled: domain=%r user=%r", domain_obj.domain, current_user.username)
    return {"detail": "SSL enabled", "domain": domain_obj.domain}
