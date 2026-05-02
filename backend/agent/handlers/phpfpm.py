"""
PHP-FPM handler.
All subprocess calls routed through utils.exec.run_command().
"""
import logging
import re
from pathlib import Path

from utils.exec import run_command, CommandError

logger = logging.getLogger(__name__)

PHPFPM_CONF_DIR = Path("/etc/php-fpm.d")

# Pattern accepted for PHP versions — matches the registry in exec.py
_PHP_VERSION_RE = re.compile(r"^(7\.4|8\.[0-3])$")


async def write_pool(params: dict) -> dict:
    username    = params["username"]
    php_version = params["php_version"]
    config      = params["config_content"]

    # Extra guard: version already validated by allowlist, but double-check
    if not _PHP_VERSION_RE.fullmatch(php_version):
        raise ValueError(f"Invalid PHP version: {php_version!r}")

    pool_file = (PHPFPM_CONF_DIR / f"{username}.conf").resolve()
    if not str(pool_file).startswith(str(PHPFPM_CONF_DIR.resolve()) + "/"):
        raise ValueError("Path traversal detected in phpfpm.write_pool")

    pool_file.write_text(config, encoding="utf-8")
    pool_file.chmod(0o640)

    logger.info("PHP-FPM pool written: username=%s version=%s", username, php_version)
    return {"file": str(pool_file)}


async def reload(params: dict) -> dict:
    version = params["version"]

    if not _PHP_VERSION_RE.fullmatch(version):
        raise ValueError(f"Invalid PHP version: {version!r}")

    service = f"php{version}-fpm"

    try:
        await run_command(["systemctl", "reload", service])
    except CommandError as exc:
        logger.error(
            "systemctl reload %s failed rc=%d", service, exc.result.returncode
        )
        raise RuntimeError(f"PHP-FPM {version} reload failed") from exc

    logger.info("PHP-FPM reloaded: version=%s", version)
    return {"reloaded": True, "version": version}
