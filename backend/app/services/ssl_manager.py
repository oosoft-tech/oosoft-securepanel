import re
import logging
from datetime import datetime, timezone
from app.core.agent_client import AgentClient

logger = logging.getLogger(__name__)

DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


class SSLManager:
    def __init__(self):
        self.agent = AgentClient()

    def _validate_domain(self, domain: str) -> None:
        if not DOMAIN_PATTERN.fullmatch(domain):
            raise ValueError(f"Invalid domain: {domain}")

    async def issue_certificate(self, username: str, domain: str) -> dict:
        self._validate_domain(domain)
        webroot = f"/home/{username}/public_html"

        result = await self.agent.call("ssl.issue", {
            "domain": domain,
            "webroot": webroot,
        })
        logger.info(f"SSL certificate issued for domain={domain}")
        return result

    async def renew_certificate(self, domain: str) -> dict:
        self._validate_domain(domain)
        result = await self.agent.call("ssl.renew", {"domain": domain})
        logger.info(f"SSL certificate renewed for domain={domain}")
        return result

    async def get_expiry(self, domain: str) -> datetime | None:
        self._validate_domain(domain)
        result = await self.agent.call("ssl.get_expiry", {"domain": domain})
        expiry_str = result.get("expiry")
        if expiry_str:
            return datetime.fromisoformat(expiry_str)
        return None
