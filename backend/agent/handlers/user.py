"""
User management handler.
All subprocess calls routed through utils.exec.run_command().
"""
import logging
from pathlib import Path

from utils.exec import run_command, CommandError

logger = logging.getLogger(__name__)


async def create(params: dict) -> dict:
    username = params["username"]
    shell    = params.get("shell", "/bin/false")
    home_dir = f"/home/{username}"

    try:
        await run_command([
            "useradd",
            "-m", "-d", home_dir,
            "-s", shell,
            "-G", "securepanel_users",
            username,
        ])
    except CommandError as exc:
        # rc=9 means user already exists — allowed by the registry
        # Any other non-zero was already raised by run_command; re-raise clean
        raise RuntimeError("Failed to create system user") from exc

    home = Path(home_dir)
    home.chmod(0o711)

    public_html = home / "public_html"
    public_html.mkdir(exist_ok=True)
    public_html.chmod(0o755)

    logger.info("System user created: username=%s", username)
    return {"username": username, "home": home_dir}


async def delete(params: dict) -> dict:
    username = params["username"]

    try:
        await run_command(["userdel", "-r", username])
    except CommandError as exc:
        # rc=6 means user does not exist — treated as success by the registry
        raise RuntimeError("Failed to delete system user") from exc

    logger.info("System user deleted: username=%s", username)
    return {"deleted": True}


async def fix_ownership(params: dict) -> dict:
    username = params["username"]
    home_dir = f"/home/{username}"

    try:
        await run_command(["chown", "-R", f"{username}:{username}", home_dir])
    except CommandError as exc:
        logger.error("chown failed for username=%s rc=%d", username, exc.result.returncode)
        raise RuntimeError("Failed to fix file ownership") from exc

    logger.info("Ownership fixed: username=%s path=%s", username, home_dir)
    return {"fixed": True}
