import asyncio
import json
import logging

AGENT_SOCKET = "/run/securepanel/agent.sock"
logger = logging.getLogger(__name__)


class AgentClient:
    async def call(self, action: str, params: dict) -> dict:
        try:
            reader, writer = await asyncio.open_unix_connection(AGENT_SOCKET)
        except (FileNotFoundError, ConnectionRefusedError) as e:
            raise RuntimeError(f"Cannot connect to privileged agent: {e}") from e

        try:
            payload = json.dumps({"action": action, "params": params}).encode()
            writer.write(payload)
            await writer.drain()

            raw = await asyncio.wait_for(reader.read(65536), timeout=30.0)
            response = json.loads(raw.decode())

            if response.get("status") != "ok":
                raise RuntimeError(f"Agent error for action={action}: {response.get('message')}")

            logger.debug(f"Agent call ok: action={action}")
            return response.get("result", {})
        finally:
            writer.close()
            await writer.wait_closed()
