import asyncio
import subprocess
from pathlib import Path


async def create(params: dict) -> dict:
    username = params["username"]
    shell = params.get("shell", "/bin/false")
    home_dir = f"/home/{username}"

    proc = await asyncio.create_subprocess_exec(
        "useradd",
        "-m", "-d", home_dir,
        "-s", shell,
        "-G", "securepanel_users",
        username,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode not in (0, 9):   # 9 = already exists
        raise RuntimeError(f"useradd failed: {stderr.decode()}")

    # Set directory permissions
    home = Path(home_dir)
    home.chmod(0o711)
    public_html = home / "public_html"
    public_html.mkdir(exist_ok=True)
    public_html.chmod(0o755)

    return {"username": username, "home": home_dir}


async def delete(params: dict) -> dict:
    username = params["username"]
    proc = await asyncio.create_subprocess_exec(
        "userdel", "-r", username,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode not in (0, 6):   # 6 = user doesn't exist
        raise RuntimeError(f"userdel failed: {stderr.decode()}")
    return {"deleted": True}


async def fix_ownership(params: dict) -> dict:
    username = params["username"]
    home_dir = f"/home/{username}"

    proc = await asyncio.create_subprocess_exec(
        "chown", "-R", f"{username}:{username}", home_dir,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"chown failed: {stderr.decode()}")
    return {"fixed": True}
