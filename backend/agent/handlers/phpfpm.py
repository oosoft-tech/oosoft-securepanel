import asyncio
from pathlib import Path

PHPFPM_CONF_DIR = Path("/etc/php-fpm.d")


async def write_pool(params: dict) -> dict:
    username = params["username"]
    php_version = params["php_version"]
    config = params["config_content"]

    pool_file = PHPFPM_CONF_DIR / f"{username}.conf"
    pool_file.write_text(config)
    pool_file.chmod(0o640)
    return {"file": str(pool_file)}


async def reload(params: dict) -> dict:
    version = params["version"]
    service = f"php{version}-fpm"

    proc = await asyncio.create_subprocess_exec(
        "systemctl", "reload", service,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"php-fpm reload failed: {stderr.decode()}")
    return {"reloaded": True, "version": version}
