"""
Domain management API endpoints.

POST   /domains              — create a new domain (nginx + user isolation)
GET    /domains              — list domains for the current user
DELETE /domains/{id}         — remove a domain and its nginx config
POST   /domains/{id}/ssl     — issue and enable SSL for a domain

User isolation
──────────────
Each domain gets a dedicated Linux system user derived from the domain name:
  example.com  →  example_com
  my-site.org  →  my_site_org

The derivation is:
  1. derive_username(domain)  — deterministic, always the same base name
  2. generate_unique_username  — appends _001…_999 if there is a collision
  3. validate_linux_username  — final safety check before hitting the agent

The linux_username is stored in the Domain record so delete / repair flows
can reference it without re-deriving.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_client import AgentClient, AgentError
from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.domain import Domain
from app.models.user import User
from app.utils.username import generate_unique_username, validate_linux_username
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
    id:             int
    domain:         str
    linux_username: str | None   # None for pre-isolation legacy records
    php_version:    str
    ssl_enabled:    bool
    document_root:  str
    status:         str          # "active" | "suspended"

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Internal helpers
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


async def _existing_linux_usernames(db: AsyncSession) -> set[str]:
    """
    Return all linux_username values currently stored in the domains table.
    Used for collision detection during username derivation.
    """
    result = await db.execute(
        select(Domain.linux_username).where(Domain.linux_username.isnot(None))
    )
    return {row[0] for row in result.fetchall()}


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
    Create a domain with full Linux user isolation.

    Steps
    ─────
    1. Validate domain (Pydantic + validate_domain → lowercase)
    2. Duplicate-domain check (DB)
    3. Derive linux_username from domain; resolve collisions against DB
    4. Validate linux_username (reserved-name check, format check)
    5. Duplicate-username check (DB — defence against races)
    6. Call agent: nginx.create_domain
       The agent internally:
         a. Creates the per-domain Linux user (useradd, idempotent)
         b. Creates /var/www/{domain} and writes index.html
         c. chown -R {linux_username}:{linux_username} /var/www/{domain}
         d. Writes HTTP nginx config, tests, reloads
         e. Attempts Let's Encrypt SSL (best-effort)
    7. Persist Domain (with linux_username) to database
    8. Return structured response
    """
    domain = request.domain  # already validated + lowercased by Pydantic

    # ── 2. Duplicate domain check ─────────────────────────────────────────────
    existing_domain = await db.execute(
        select(Domain).where(Domain.domain == domain)
    )
    if existing_domain.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Domain already exists",
        )

    # ── 3. Derive linux_username ──────────────────────────────────────────────
    existing_usernames = await _existing_linux_usernames(db)

    try:
        linux_username = generate_unique_username(domain, existing_usernames)
    except ValueError as exc:
        logger.error(
            "Username derivation failed for domain=%r user=%r: %s",
            domain, current_user.username, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Could not derive a unique system username for this domain.",
        )

    # ── 4. Validate derived username ──────────────────────────────────────────
    try:
        linux_username = validate_linux_username(linux_username)
    except ValueError as exc:
        logger.error(
            "Derived linux_username=%r failed validation for domain=%r: %s",
            linux_username, domain, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Cannot assign a safe system username to this domain.",
        )

    # ── 5. Race-condition guard: re-check username uniqueness ─────────────────
    # Between step 3 and here another request could have claimed the same name.
    collision = await db.execute(
        select(Domain).where(Domain.linux_username == linux_username)
    )
    if collision.scalar_one_or_none():
        logger.warning(
            "Username collision race for linux_username=%r domain=%r",
            linux_username, domain,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A system username conflict occurred. Please retry.",
        )

    # ── 6. Call privileged agent ──────────────────────────────────────────────
    agent = AgentClient()
    try:
        result = await agent.call("nginx.create_domain", {
            "domain":         domain,
            "linux_username": linux_username,
        })
    except AgentError as exc:
        raise _agent_http_error(exc, f"create_domain({domain!r})")
    except (RuntimeError, TimeoutError) as exc:
        raise _agent_http_error(exc, f"create_domain({domain!r})")

    webroot      = result.get("webroot", f"/var/www/{domain}")
    ssl_enabled  = result.get("ssl_enabled", False)
    ssl_error    = result.get("ssl_error")

    if ssl_error:
        logger.info(
            "Domain created without SSL: domain=%r reason=%r", domain, ssl_error
        )

    # ── 7. Persist ────────────────────────────────────────────────────────────
    new_domain = Domain(
        user_id=current_user.id,
        domain=domain,
        linux_username=linux_username,
        document_root=webroot,
        php_version="8.1",
        ssl_enabled=ssl_enabled,
    )
    db.add(new_domain)

    try:
        await db.commit()
        await db.refresh(new_domain)
    except Exception as exc:
        # Agent succeeded but DB failed — log for manual reconciliation.
        logger.error(
            "DB commit failed after agent provisioned domain=%r "
            "linux_username=%r for user=%r: %s",
            domain, linux_username, current_user.username, exc,
        )
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Domain was provisioned on the server but could not be saved "
                "to the database. Please contact support."
            ),
        )

    logger.info(
        "Domain created: domain=%r linux_username=%r user=%r ssl_enabled=%s",
        domain, linux_username, current_user.username, ssl_enabled,
    )
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found"
        )

    # Use the stored linux_username so we don't need to re-derive it.
    # Fall back to a derived name only for legacy records (pre-isolation).
    linux_username = domain_obj.linux_username
    if not linux_username:
        # Legacy record: agent call omits linux_username param.
        # delete_domain validator requires it — skip agent call for legacy.
        logger.warning(
            "Legacy domain without linux_username: domain=%r — "
            "skipping agent delete, removing DB record only.",
            domain_obj.domain,
        )
    else:
        agent = AgentClient()
        try:
            await agent.call("nginx.delete_domain", {
                "domain":         domain_obj.domain,
                "linux_username": linux_username,
            })
        except (AgentError, RuntimeError, TimeoutError) as exc:
            raise _agent_http_error(exc, f"delete_domain({domain_obj.domain!r})")

    await db.delete(domain_obj)
    await db.commit()

    logger.info(
        "Domain deleted: domain=%r linux_username=%r user=%r",
        domain_obj.domain, linux_username, current_user.username,
    )


@router.post("/{domain_id}/suspend", status_code=status.HTTP_200_OK)
async def suspend_domain(
    domain_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Suspend a domain.

    Replaces the domain's nginx config with a 503 stub so the domain stops
    serving content.  The original config is preserved on disk so it can be
    restored by the unsuspend endpoint.  ACME challenge paths remain open so
    Let's Encrypt certificate renewals continue during suspension.
    """
    result = await db.execute(
        select(Domain).where(
            Domain.id == domain_id,
            Domain.user_id == current_user.id,
        )
    )
    domain_obj = result.scalar_one_or_none()
    if not domain_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found"
        )

    if domain_obj.status == "suspended":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Domain is already suspended"
        )

    linux_username = domain_obj.linux_username
    if not linux_username:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Cannot suspend a legacy domain without a system username.",
        )

    agent = AgentClient()
    try:
        await agent.call("nginx.suspend_domain", {
            "domain":         domain_obj.domain,
            "linux_username": linux_username,
        })
    except (AgentError, RuntimeError, TimeoutError) as exc:
        raise _agent_http_error(exc, f"suspend_domain({domain_obj.domain!r})")

    domain_obj.status = "suspended"
    await db.commit()
    await db.refresh(domain_obj)

    logger.info(
        "Domain suspended: domain=%r user=%r",
        domain_obj.domain, current_user.username,
    )
    return DomainResponse.model_validate(domain_obj)


@router.post("/{domain_id}/unsuspend", status_code=status.HTTP_200_OK)
async def unsuspend_domain(
    domain_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Unsuspend a previously suspended domain.

    Restores the preserved nginx config and reloads nginx so the domain
    resumes serving content.
    """
    result = await db.execute(
        select(Domain).where(
            Domain.id == domain_id,
            Domain.user_id == current_user.id,
        )
    )
    domain_obj = result.scalar_one_or_none()
    if not domain_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found"
        )

    if domain_obj.status != "suspended":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Domain is not suspended"
        )

    linux_username = domain_obj.linux_username
    if not linux_username:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Cannot unsuspend a legacy domain without a system username.",
        )

    agent = AgentClient()
    try:
        await agent.call("nginx.unsuspend_domain", {
            "domain":         domain_obj.domain,
            "linux_username": linux_username,
        })
    except (AgentError, RuntimeError, TimeoutError) as exc:
        raise _agent_http_error(exc, f"unsuspend_domain({domain_obj.domain!r})")

    domain_obj.status = "active"
    await db.commit()
    await db.refresh(domain_obj)

    logger.info(
        "Domain unsuspended: domain=%r user=%r",
        domain_obj.domain, current_user.username,
    )
    return DomainResponse.model_validate(domain_obj)


@router.post("/{domain_id}/rebuild", status_code=status.HTTP_200_OK)
async def rebuild_domain(
    domain_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Rebuild a domain's nginx config from current server state.

    SSL status is detected from on-disk certificate files — not from the
    database — so the result is always consistent.

    If the domain is currently suspended the rebuilt config is written to the
    preserved .disabled file only; the live 503 stub is left untouched and
    the domain status remains "suspended".  The updated config will become
    active on the next unsuspend call.
    """
    result = await db.execute(
        select(Domain).where(
            Domain.id == domain_id,
            Domain.user_id == current_user.id,
        )
    )
    domain_obj = result.scalar_one_or_none()
    if not domain_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found"
        )

    linux_username = domain_obj.linux_username
    if not linux_username:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Cannot rebuild a legacy domain without a system username.",
        )

    agent = AgentClient()
    try:
        agent_result = await agent.call("nginx.rebuild_domain", {
            "domain":         domain_obj.domain,
            "linux_username": linux_username,
        })
    except (AgentError, RuntimeError, TimeoutError) as exc:
        raise _agent_http_error(exc, f"rebuild_domain({domain_obj.domain!r})")

    # Sync ssl_enabled with what the agent detected on disk.
    ssl_active = agent_result.get("ssl_active", domain_obj.ssl_enabled)
    if domain_obj.ssl_enabled != ssl_active:
        domain_obj.ssl_enabled = ssl_active
        await db.commit()
        await db.refresh(domain_obj)

    logger.info(
        "Domain rebuilt: domain=%r user=%r ssl=%s reloaded=%s",
        domain_obj.domain, current_user.username,
        agent_result.get("ssl_active"), agent_result.get("reloaded"),
    )
    return {
        "detail":        "Domain config rebuilt",
        "domain":        domain_obj.domain,
        "ssl_enabled":   ssl_active,
        "reloaded":      agent_result.get("reloaded", False),
        "was_suspended": agent_result.get("was_suspended", False),
    }


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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found"
        )

    if domain_obj.ssl_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="SSL is already enabled"
        )

    # For the webroot challenge path we use the domain-specific webroot,
    # not the panel's ACME webroot, so certbot can verify without nginx changes.
    acme_webroot = "/var/www/letsencrypt"

    agent = AgentClient()
    try:
        await agent.call("ssl.issue", {
            "domain":  domain_obj.domain,
            "webroot": acme_webroot,
        })
    except (AgentError, RuntimeError, TimeoutError) as exc:
        raise _agent_http_error(exc, f"enable_ssl({domain_obj.domain!r})")

    domain_obj.ssl_enabled = True
    await db.commit()

    logger.info(
        "SSL enabled: domain=%r user=%r",
        domain_obj.domain, current_user.username,
    )
    return {"detail": "SSL enabled", "domain": domain_obj.domain}
