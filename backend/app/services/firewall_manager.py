import ipaddress
import logging
import re
from collections import Counter
from datetime import datetime, timezone

from app.core.agent_client import AgentClient

logger = logging.getLogger(__name__)

BRUTE_FORCE_THRESHOLD = 10


class FirewallManager:
    def __init__(self):
        self.agent = AgentClient()

    def _validate_ip(self, ip: str) -> str:
        try:
            parsed = ipaddress.ip_network(ip, strict=False)
            return str(parsed)
        except ValueError as e:
            raise ValueError(f"Invalid IP/CIDR: {ip}") from e

    async def block_ip(self, ip: str, reason: str = "", duration_hours: int = 24) -> dict:
        ip = self._validate_ip(ip)
        result = await self.agent.call("firewall.add_rule", {
            "ip": ip,
            "action": "DROP",
            "chain": "INPUT",
        })
        logger.warning(f"Blocked IP {ip}: {reason}")
        return result

    async def unblock_ip(self, rule_id: str) -> dict:
        if not re.fullmatch(r"^\d+$", rule_id):
            raise ValueError("Invalid rule ID")
        return await self.agent.call("firewall.delete_rule", {"rule_id": rule_id})

    async def list_rules(self) -> dict:
        return await self.agent.call("firewall.list_rules", {})

    async def detect_brute_force(self, log_lines: list[str]) -> list[str]:
        failed_pattern = re.compile(
            r"Failed (password|publickey) for .+ from (\d+\.\d+\.\d+\.\d+)"
        )
        ip_counts: Counter = Counter()
        for line in log_lines:
            match = failed_pattern.search(line)
            if match:
                ip_counts[match.group(2)] += 1
        return [ip for ip, count in ip_counts.items() if count > BRUTE_FORCE_THRESHOLD]

    async def auto_block_brute_force(self, log_path: str = "/var/log/auth.log") -> list[str]:
        try:
            with open(log_path) as f:
                lines = f.readlines()
        except FileNotFoundError:
            return []

        ips_to_block = await self.detect_brute_force(lines)
        blocked = []
        for ip in ips_to_block:
            try:
                await self.block_ip(ip, reason="auto: brute force detected")
                blocked.append(ip)
            except Exception as e:
                logger.error(f"Failed to block {ip}: {e}")
        return blocked
