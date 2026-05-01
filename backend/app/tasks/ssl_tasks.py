import asyncio
import logging
from datetime import datetime, timezone, timedelta
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

RENEWAL_THRESHOLD_DAYS = 14


@celery_app.task(name="app.tasks.ssl_tasks.issue_certificate", bind=True, max_retries=3)
def issue_certificate(self, username: str, domain: str):
    try:
        from app.services.ssl_manager import SSLManager
        ssl = SSLManager()
        result = asyncio.run(ssl.issue_certificate(username, domain))
        logger.info(f"SSL issued for {domain}")
        return result
    except Exception as exc:
        logger.error(f"SSL issuance failed for {domain}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@celery_app.task(name="app.tasks.ssl_tasks.check_expiring_certs")
def check_expiring_certs():
    from app.services.ssl_manager import SSLManager
    from app.core.database import AsyncSessionLocal
    from app.models.domain import Domain
    import asyncio

    async def _check():
        ssl = SSLManager()
        threshold = datetime.now(timezone.utc) + timedelta(days=RENEWAL_THRESHOLD_DAYS)
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            result = await db.execute(
                select(Domain).where(
                    Domain.ssl_enabled == True,
                    Domain.ssl_expiry <= threshold,
                )
            )
            domains = result.scalars().all()
            for domain in domains:
                try:
                    await ssl.renew_certificate(domain.domain)
                    logger.info(f"SSL renewed for {domain.domain}")
                except Exception as e:
                    logger.error(f"SSL renewal failed for {domain.domain}: {e}")

    asyncio.run(_check())
