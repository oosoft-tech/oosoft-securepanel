from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.domain import Domain
from app.models.user import User
from app.services.nginx_manager import NginxManager
from app.services.ssl_manager import SSLManager
from app.services.dns_manager import DNSManager

router = APIRouter()


class CreateDomainRequest(BaseModel):
    domain: str
    php_version: str = "8.1"
    server_ip: str


class DomainResponse(BaseModel):
    id: int
    domain: str
    php_version: str
    ssl_enabled: bool
    document_root: str

    class Config:
        from_attributes = True


@router.get("/", response_model=list[DomainResponse])
async def list_domains(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Domain).where(Domain.user_id == current_user.id))
    return result.scalars().all()


@router.post("/", response_model=DomainResponse, status_code=status.HTTP_201_CREATED)
async def create_domain(
    request: CreateDomainRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.execute(select(Domain).where(Domain.domain == request.domain))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Domain already exists")

    nginx = NginxManager()
    dns = DNSManager()

    await nginx.create_vhost(current_user.username, request.domain, request.php_version)
    await nginx.create_phpfpm_pool(current_user.username, request.php_version)
    await dns.create_zone(request.domain, request.server_ip)

    domain = Domain(
        user_id=current_user.id,
        domain=request.domain,
        document_root=f"/home/{current_user.username}/public_html/{request.domain}",
        php_version=request.php_version,
    )
    db.add(domain)
    await db.commit()
    await db.refresh(domain)
    return domain


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain(
    domain_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Domain).where(Domain.id == domain_id, Domain.user_id == current_user.id)
    )
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    nginx = NginxManager()
    await nginx.delete_vhost(current_user.username, domain.domain)

    await db.delete(domain)
    await db.commit()


@router.post("/{domain_id}/ssl")
async def enable_ssl(
    domain_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Domain).where(Domain.id == domain_id, Domain.user_id == current_user.id)
    )
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    ssl = SSLManager()
    cert_result = await ssl.issue_certificate(current_user.username, domain.domain)

    nginx = NginxManager()
    await nginx.create_vhost(current_user.username, domain.domain, domain.php_version, ssl=True)

    domain.ssl_enabled = True
    await db.commit()
    return {"detail": "SSL enabled", "result": cert_result}
