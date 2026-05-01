#!/usr/bin/env python3
"""
Oosoft SecurePanel Privileged Agent
Runs as root, exposes a Unix socket with a strict command allowlist.
All actions are logged before execution.
"""
import asyncio
import json
import os
import logging
import grp
from pathlib import Path

SOCKET_PATH = "/run/securepanel/agent.sock"
LOG_PATH = "/var/log/securepanel/agent.log"

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("agent")


def _get_gid(name: str) -> int:
    return grp.getgrnam(name).gr_gid


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    from validator import CommandValidator
    validator = CommandValidator()

    try:
        raw = await asyncio.wait_for(reader.read(65536), timeout=10.0)
        request = json.loads(raw.decode())

        action = request.get("action", "")
        params = request.get("params", {})

        if not validator.is_allowed(action, params):
            logger.warning(f"BLOCKED action={action} params={json.dumps(params)}")
            response = {"status": "error", "message": "Action not permitted"}
        else:
            logger.info(f"EXEC action={action} params={json.dumps(params)}")
            handler = validator.get_handler(action)
            result = await handler(params)
            response = {"status": "ok", "result": result}

    except asyncio.TimeoutError:
        logger.warning("Connection timed out")
        response = {"status": "error", "message": "Timeout"}
    except json.JSONDecodeError:
        logger.warning("Invalid JSON received")
        response = {"status": "error", "message": "Invalid JSON"}
    except Exception as e:
        logger.exception(f"Handler error: {e}")
        response = {"status": "error", "message": "Internal error"}
    finally:
        writer.write(json.dumps(response).encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()


async def main():
    socket_dir = Path(SOCKET_PATH).parent
    socket_dir.mkdir(parents=True, exist_ok=True)

    if Path(SOCKET_PATH).exists():
        Path(SOCKET_PATH).unlink()

    server = await asyncio.start_unix_server(handle_client, path=SOCKET_PATH)

    os.chmod(SOCKET_PATH, 0o660)
    try:
        gid = _get_gid("securepanel")
        os.chown(SOCKET_PATH, 0, gid)
    except KeyError:
        logger.warning("Group 'securepanel' not found; socket permissions may be insecure")

    logger.info("SecurePanel privileged agent started")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    if os.getuid() != 0:
        raise RuntimeError("Agent must run as root")
    asyncio.run(main())
