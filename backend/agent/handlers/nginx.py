import asyncio
from pathlib import Path

VHOST_DIR = Path("/etc/nginx/sites-enabled")
VHOST_DIR.mkdir(parents=True, exist_ok=True)


async def reload(params: dict) -> dict:
    proc = await asyncio.create_subprocess_exec(
        "nginx", "-t",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Nginx config test failed: {stderr.decode()}")

    proc = await asyncio.create_subprocess_exec("systemctl", "reload", "nginx")
    await proc.communicate()
    return {"reloaded": True}


async def write_vhost(params: dict) -> dict:
    username = params["username"]
    domain = params["domain"]
    config = params["config_content"]

    vhost_file = VHOST_DIR / f"{username}_{domain}.conf"
    vhost_file.write_text(config)
    vhost_file.chmod(0o644)
    return {"file": str(vhost_file)}


async def delete_vhost(params: dict) -> dict:
    username = params["username"]
    domain = params["domain"]
    vhost_file = VHOST_DIR / f"{username}_{domain}.conf"
    if vhost_file.exists():
        vhost_file.unlink()
    return {"deleted": True}
