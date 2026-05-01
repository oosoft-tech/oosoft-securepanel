from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os

from app.core.config import settings
from app.api.v1 import auth, domains, dns, email, databases, firewall, migration, monitoring, cron, ftp


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not os.path.exists("/run/securepanel/agent.sock"):
        raise RuntimeError("Privileged agent socket not found — is securepanel-agent running?")
    yield


app = FastAPI(
    title="Oosoft SecurePanel API",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth.router,       prefix="/api/v1/auth",       tags=["auth"])
app.include_router(domains.router,    prefix="/api/v1/domains",    tags=["domains"])
app.include_router(dns.router,        prefix="/api/v1/dns",        tags=["dns"])
app.include_router(email.router,      prefix="/api/v1/email",      tags=["email"])
app.include_router(databases.router,  prefix="/api/v1/databases",  tags=["databases"])
app.include_router(firewall.router,   prefix="/api/v1/firewall",   tags=["firewall"])
app.include_router(migration.router,  prefix="/api/v1/migration",  tags=["migration"])
app.include_router(monitoring.router, prefix="/api/v1/monitoring", tags=["monitoring"])
app.include_router(cron.router,       prefix="/api/v1/cron",       tags=["cron"])
app.include_router(ftp.router,        prefix="/api/v1/ftp",        tags=["ftp"])
