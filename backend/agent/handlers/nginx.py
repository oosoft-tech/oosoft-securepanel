"""
Nginx handler — privileged operations executed by the root agent.

All subprocess execution is delegated to utils.exec.run_command().
No asyncio.create_subprocess_exec() calls exist here.
"""
import logging
import re
from pathlib import Path
from string import Template

from utils.exec import run_command, CommandError

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

VHOST_DIR     = Path("/etc/nginx/conf.d")
WEBROOT_BASE  = Path("/var/www")
TEMPLATE_FILE = Path("/opt/oosoft-securepanel/nginx/templates/domain.conf.j2")

# Inline fallback template (string.Template — safe substitution only)
_INLINE_TEMPLATE = """\
server {
    listen 80;
    server_name $domain www.$domain;

    root /var/www/$domain;
    index index.html index.htm;

    access_log /var/log/nginx/${domain}_access.log;
    error_log  /var/log/nginx/${domain}_error.log;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location ~ /\\. { deny all; return 404; }
    location ~* (\\.env|wp-config\\.php|\\.git) { deny all; return 404; }

    location / { try_files $$uri $$uri/ =404; }

    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        default_type "text/plain";
    }

    client_max_body_size 64M;
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# Internal domain validation (defense-in-depth)
# ─────────────────────────────────────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _assert_safe_domain(domain: str) -> None:
    if not isinstance(domain, str) or not _DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"Domain failed agent-level validation: {domain!r}")
    if ".." in domain or "/" in domain or "\\" in domain or "\x00" in domain:
        raise ValueError(f"Domain contains forbidden characters: {domain!r}")


def _safe_vhost_path(domain: str) -> Path:
    path = (VHOST_DIR / f"{domain}.conf").resolve()
    if not str(path).startswith(str(VHOST_DIR.resolve()) + "/"):
        raise ValueError("Path traversal detected in vhost path construction")
    return path


def _safe_webroot_path(domain: str) -> Path:
    path = (WEBROOT_BASE / domain).resolve()
    if not str(path).startswith(str(WEBROOT_BASE.resolve()) + "/"):
        raise ValueError("Path traversal detected in webroot path construction")
    return path


# ─────────────────────────────────────────────────────────────────────────────
# Config rendering (no user input reaches string concatenation)
# ─────────────────────────────────────────────────────────────────────────────

def _render_config(domain: str) -> str:
    if TEMPLATE_FILE.exists():
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
            env = Environment(
                loader=FileSystemLoader(str(TEMPLATE_FILE.parent)),
                autoescape=select_autoescape(["conf", "j2"]),
            )
            return env.get_template(TEMPLATE_FILE.name).render(domain=domain)
        except Exception as exc:
            logger.warning("Jinja2 render failed (%s); using inline fallback", exc)

    return Template(_INLINE_TEMPLATE).safe_substitute(domain=domain)


# ─────────────────────────────────────────────────────────────────────────────
# Nginx primitives — all go through run_command()
# ─────────────────────────────────────────────────────────────────────────────

async def _nginx_test() -> None:
    """
    Run `nginx -t`.  Raises RuntimeError on failure.
    stderr detail is logged by run_command() internally; a generic message
    is raised so callers never forward nginx internals to the network layer.
    """
    try:
        await run_command(["nginx", "-t"])
    except CommandError as exc:
        logger.error("nginx -t failed (rc=%d)", exc.result.returncode)
        raise RuntimeError("Nginx configuration test failed") from exc


async def _nginx_reload() -> None:
    """Reload nginx via systemctl. Raises RuntimeError on failure."""
    try:
        await run_command(["systemctl", "reload", "nginx"])
    except CommandError as exc:
        logger.error("systemctl reload nginx failed (rc=%d)", exc.result.returncode)
        raise RuntimeError("Nginx reload failed") from exc


# ─────────────────────────────────────────────────────────────────────────────
# Public handlers
# ─────────────────────────────────────────────────────────────────────────────

async def reload(params: dict) -> dict:
    """Test nginx config then reload.  Kept for existing callers."""
    await _nginx_test()
    await _nginx_reload()
    return {"reloaded": True}


async def create_domain(params: dict) -> dict:
    """
    Provision a new static domain:
      1. Validate domain (defense-in-depth)
      2. Create webroot + index.html
      3. Render nginx config via template
      4. Write config file
      5. nginx -t  (roll back on failure)
      6. systemctl reload nginx
    """
    domain = params["domain"]
    _assert_safe_domain(domain)

    webroot    = _safe_webroot_path(domain)
    vhost_path = _safe_vhost_path(domain)

    # 1. Webroot
    webroot.mkdir(parents=True, exist_ok=True)
    webroot.chmod(0o755)

    # 2. Default index.html
    index_file = webroot / "index.html"
    if not index_file.exists():
        index_file.write_text(
            f"<!DOCTYPE html>\n<html lang='en'>\n"
            f"<head><meta charset='UTF-8'>"
            f"<title>Welcome to {domain}</title></head>\n"
            f"<body><h1>{domain} is live.</h1>"
            f"<p>Hosted on Oosoft SecurePanel.</p></body>\n</html>\n",
            encoding="utf-8",
        )
        index_file.chmod(0o644)
        logger.info("Created index.html for domain=%s", domain)

    # 3. Render config
    config_content = _render_config(domain)

    # 4. Write config
    vhost_path.write_text(config_content, encoding="utf-8")
    vhost_path.chmod(0o644)
    logger.info("Wrote nginx config: %s", vhost_path)

    # 5. Test — roll back on failure
    try:
        await _nginx_test()
    except RuntimeError:
        vhost_path.unlink(missing_ok=True)
        logger.error("Rolled back nginx config for domain=%s", domain)
        raise

    # 6. Reload
    await _nginx_reload()
    logger.info("Domain provisioned: domain=%s webroot=%s", domain, webroot)

    return {"webroot": str(webroot), "config": str(vhost_path), "domain": domain}


async def delete_domain(params: dict) -> dict:
    """Remove a domain's nginx config; remove webroot only if empty."""
    domain = params["domain"]
    _assert_safe_domain(domain)

    vhost_path = _safe_vhost_path(domain)
    webroot    = _safe_webroot_path(domain)

    config_removed = webroot_removed = False

    if vhost_path.exists():
        vhost_path.unlink()
        config_removed = True
        logger.info("Removed nginx config: %s", vhost_path)

    if config_removed:
        try:
            await _nginx_test()
            await _nginx_reload()
        except RuntimeError as exc:
            logger.error("Nginx reload failed after deleting domain=%s: %s", domain, exc)
            raise

    if webroot.exists() and not any(webroot.iterdir()):
        webroot.rmdir()
        webroot_removed = True
        logger.info("Removed empty webroot: %s", webroot)

    return {
        "domain": domain,
        "config_removed": config_removed,
        "webroot_removed": webroot_removed,
    }


async def write_vhost(params: dict) -> dict:
    """Write a pre-rendered vhost config (PHP/SSL flow)."""
    username = params["username"]
    domain   = params["domain"]
    config   = params["config_content"]

    _assert_safe_domain(domain)

    vhost_file = (VHOST_DIR / f"{username}_{domain}.conf").resolve()
    if not str(vhost_file).startswith(str(VHOST_DIR.resolve()) + "/"):
        raise ValueError("Path traversal detected in write_vhost")

    vhost_file.write_text(config, encoding="utf-8")
    vhost_file.chmod(0o644)
    return {"file": str(vhost_file)}


async def delete_vhost(params: dict) -> dict:
    """Remove a user-namespaced vhost config."""
    username = params["username"]
    domain   = params["domain"]

    _assert_safe_domain(domain)

    vhost_file = (VHOST_DIR / f"{username}_{domain}.conf").resolve()
    if not str(vhost_file).startswith(str(VHOST_DIR.resolve()) + "/"):
        raise ValueError("Path traversal detected in delete_vhost")

    if vhost_file.exists():
        vhost_file.unlink()
    return {"deleted": True}
