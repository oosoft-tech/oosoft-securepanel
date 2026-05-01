import logging
from app.core.agent_client import AgentClient

logger = logging.getLogger(__name__)


class CageFSManager:
    def __init__(self):
        self.agent = AgentClient()

    async def enable_user(self, username: str) -> None:
        await self.agent.call("cagefs.enable", {"username": username})
        logger.info(f"CageFS enabled for user={username}")

    async def disable_user(self, username: str) -> None:
        await self.agent.call("cagefs.disable", {"username": username})
        logger.warning(f"CageFS disabled for user={username}")

    async def update_skeleton(self) -> None:
        await self.agent.call("cagefs.update_skeleton", {})

    async def remount_user(self, username: str) -> None:
        await self.agent.call("cagefs.remount", {"username": username})
