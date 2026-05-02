"""
CageFS handler.
All subprocess calls routed through utils.exec.run_command().
"""
import logging

from utils.exec import run_command, CommandError

logger = logging.getLogger(__name__)


async def enable(params: dict) -> dict:
    username = params["username"]

    try:
        await run_command(["cagefsctl", "--enable", username])
    except CommandError as exc:
        logger.error("cagefsctl --enable failed for username=%s rc=%d", username, exc.result.returncode)
        raise RuntimeError("Failed to enable CageFS") from exc

    logger.info("CageFS enabled: username=%s", username)
    return {"enabled": True, "username": username}


async def disable(params: dict) -> dict:
    username = params["username"]

    try:
        await run_command(["cagefsctl", "--disable", username])
    except CommandError as exc:
        logger.error("cagefsctl --disable failed for username=%s rc=%d", username, exc.result.returncode)
        raise RuntimeError("Failed to disable CageFS") from exc

    logger.warning("CageFS disabled: username=%s", username)
    return {"disabled": True, "username": username}


async def update_skeleton(params: dict) -> dict:
    try:
        await run_command(["cagefsctl", "--force-update"])
    except CommandError as exc:
        logger.error("cagefsctl --force-update failed rc=%d", exc.result.returncode)
        raise RuntimeError("Failed to update CageFS skeleton") from exc

    logger.info("CageFS skeleton updated")
    return {"updated": True}


async def remount(params: dict) -> dict:
    username = params["username"]

    try:
        await run_command(["cagefsctl", "--remount", username])
    except CommandError as exc:
        logger.error("cagefsctl --remount failed for username=%s rc=%d", username, exc.result.returncode)
        raise RuntimeError("Failed to remount CageFS") from exc

    logger.info("CageFS remounted: username=%s", username)
    return {"remounted": True}
