import asyncio
import json
import logging
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger(__name__)


class ImunifyManager:
    async def _call(self, args: list[str]) -> dict:
        proc = await asyncio.create_subprocess_exec(
            "imunify360-agent", *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"imunify360-agent error: {stderr.decode()}")
        return json.loads(stdout.decode()) if stdout else {}

    async def scan_path(self, path: str) -> dict:
        safe_path = Path(path).resolve()
        if not str(safe_path).startswith("/home/"):
            raise ValueError(f"Can only scan paths under /home/: {path}")
        return await self._call(["malware", "on-demand", "start", "--path", str(safe_path)])

    async def get_malware_list(self, username: str | None = None) -> dict:
        args = ["malware", "infected", "list", "--json"]
        if username:
            args += ["--user", username]
        return await self._call(args)

    async def cleanup_malware(self, item_id: str) -> dict:
        return await self._call(["malware", "cleanup", "--id", item_id])

    async def whitelist_ip(self, ip: str) -> dict:
        return await self._call(["whitelist", "ip", "add", ip])

    async def get_incidents(self, limit: int = 50) -> dict:
        return await self._call(["incident", "list", "--json", "--limit", str(limit)])
