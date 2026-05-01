"""
Nginx handler — privileged operations executed by the root agent.

All functions receive pre-validated params from the allowlist validator.
A second layer of domain validation runs here (defense-in-depth).

NO shell=True anywhere. All subprocess calls use argument lists.
"""
import asyncio
import logging
import re
from pathlib import Path
from string import Template

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths — no configparser or env reads; agent is intentionally self-contained
# ---------------------------------------------------------------------------

VHOST_DIR      = Path("/etc/nginx/conf.d")
WEBROOT_BASE   = Path("/var/www")
TEMPLATE_FILE  = Path("/opt/oosoft-securepanel/nginx/templates/domain.conf.j2")

# Fallback inline template used when the file template is unavailable.
# Uses Python's string.Template (safe — $domain is substituted only from
# a controlled dict, never from user input directly).
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

# ---------------------------------------------------------------------------
# Internal validation (defense-in-depth — validator already ran this)
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _assert_safe_domain(domain: str) -> None:
    """
    Raise ValueError if domain does not match the strict pattern.
    Called inside every handler before any filesystem or subprocess operation.
    """
    if not isinstance(domain, str) or not _DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"Domain failed agent-level validation: {domain!r}")

    # Extra guard: ensure no path traversal characters survived
    if ".." in domain or "/" in domain or "\\" in domain or "\x00" in domain:
        raise ValueError(f"Domain contains forbidden characters: {domain!r}")


def _safe_vhost_path(domain: str) -> Path:
    """Return the nginx config path and assert it stays inside VHOST_DIR."""
    filename = f"{domain}.conf"
    # Filenames are validated by _assert_safe_domain, but re-check via resolve
    path = (VHOST_DIR / filename).resolve()
    if not str(path).startswith(str(VHOST_DIR.resolve())):
        raise ValueError("Path traversal detected in vhost path construction")
    return path


def _safe_webroot_path(domain: str) -> Path:
    """Return the webroot path and assert it stays inside WEBROOT_BASE."""
    path = (WEBROOT_BASE / domain).resolve()
    if not str(path).startswith(str(WEBROOT_BASE.resolve())):
        raise ValueError("Path traversal detected in webroot path construction")
    return path


# ---------------------------------------------------------------------------
# Nginx config rendering (safe — no user input reaches string concatenation)
# ---------------------------------------------------------------------------

def _render_config(domain: str) -> str:
    """
    Render nginx config for *domain*.

    Uses the file-based Jinja2 template when available; falls back to the
    inline Python string.Template. In both cases the domain value is
    substituted into a pre-defined structure — never concatenated raw.
    """
    if TEMPLATE_FILE.exists():
        # Avoid importing jinja2 at the top level — the agent is minimal.
        # jinja2 is available because it is in requirements.txt.
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
            env = Environment(
                loader=FileSystemLoader(str(TEMPLATE_FILE.parent)),
                autoescape=select_autoescape(["conf", "j2"]),
            )
            tmpl = env.get_template(TEMPLATE_FILE.name)
            return tmpl.render(domain=domain)
        except Exception as exc:
            logger.warning("Jinja2 template render failed (%s); using inline fallback", exc)

    # Inline fallback — string.Template substitutes $domain only from the
    # controlled mapping; $$ in the template becomes a literal $ in nginx config
    return Template(_INLINE_TEMPLATE).safe_substitute(domain=domain)


# ---------------------------------------------------------------------------
# Handler: nginx -t
# ---------------------------------------------------------------------------

async def _nginx_test() -> None:
    """Run `nginx -t` and raise RuntimeError on failure."""
    proc = await asyncio.create_subprocess_exec(
        "nginx", "-t",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        # Log the nginx error internally — do not pass it back to the caller
        logger.error("nginx -t failed: %s", stderr.decode(errors="replace"))
        raise RuntimeError("Nginx configuration test failed")


# ---------------------------------------------------------------------------
# Handler: nginx reload
# ---------------------------------------------------------------------------

async def _nginx_reload() -> None:
    """Reload nginx gracefully via systemctl."""
    proc = await asyncio.create_subprocess_exec(
        "systemctl", "reload", "nginx",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        logger.error("systemctl reload nginx failed: %s", stderr.decode(errors="replace"))
        raise RuntimeError("Nginx reload failed")


# ---------------------------------------------------------------------------
# Public handlers — called by the agent via validator.get_handler()
# ---------------------------------------------------------------------------

async def reload(params: dict) -> dict:
    """Validate nginx config then reload. Kept for existing callers."""
    await _nginx_test()
    await _nginx_reload()
    return {"reloaded": True}


async def create_domain(params: dict) -> dict:
    """
    Provision a new static domain:
      1. Validate domain (defense-in-depth)
      2. Create webroot directory with safe permissions
      3. Write a default index.html
      4. Render and write nginx config
      5. Test nginx config — abort and clean up on failure
      6. Reload nginx

    Returns {"webroot": str, "config": str} on success.
    """
    domain   = params["domain"]
    username = params.get("username", "")

    # Defense-in-depth: validate at the agent layer too
    _assert_safe_domain(domain)

    webroot     = _safe_webroot_path(domain)
    vhost_path  = _safe_vhost_path(domain)

    # -- 1. Create webroot directory -----------------------------------------
    webroot.mkdir(parents=True, exist_ok=True)
    webroot.chmod(0o755)

    # -- 2. Write default index.html -----------------------------------------
    index_file = webroot / "index.html"
    if not index_file.exists():
        index_file.write_text(
            f"<!DOCTYPE html>\n"
            f"<html lang='en'>\n"
            f"<head><meta charset='UTF-8'><title>Welcome to {domain}</title></head>\n"
            f"<body><h1>{domain} is live.</h1>"
            f"<p>This domain is hosted on Oosoft SecurePanel.</p></body>\n"
            f"</html>\n",
            encoding="utf-8",
        )
        index_file.chmod(0o644)
        logger.info("Created index.html for domain=%s", domain)

    # -- 3. Render nginx config -----------------------------------------------
    config_content = _render_config(domain)

    # -- 4. Write config to disk ---------------------------------------------
    vhost_path.write_text(config_content, encoding="utf-8")
    vhost_path.chmod(0o644)
    logger.info("Wrote nginx config: %s", vhost_path)

    # -- 5. Validate config — roll back on failure ----------------------------
    try:
        await _nginx_test()
    except RuntimeError:
        # Remove the bad config so nginx remains in a valid state
        vhost_path.unlink(missing_ok=True)
        logger.error("Rolled back nginx config for domain=%s after nginx -t failure", domain)
        raise

    # -- 6. Reload nginx ------------------------------------------------------
    await _nginx_reload()
    logger.info("Domain provisioned: domain=%s webroot=%s", domain, webroot)

    return {
        "webroot": str(webroot),
        "config":  str(vhost_path),
        "domain":  domain,
    }


async def delete_domain(params: dict) -> dict:
    """
    Remove a domain's nginx config and optionally its webroot.

    Webroot removal is intentionally conservative: it is only removed when
    it is empty after the config delete, to avoid accidental data loss.
    """
    domain = params["domain"]
    _assert_safe_domain(domain)

    vhost_path = _safe_vhost_path(domain)
    webroot    = _safe_webroot_path(domain)

    config_removed  = False
    webroot_removed = False

    if vhost_path.exists():
        vhost_path.unlink()
        config_removed = True
        logger.info("Removed nginx config: %s", vhost_path)

    # Only attempt reload if a config was actually removed
    if config_removed:
        try:
            await _nginx_test()
            await _nginx_reload()
        except RuntimeError as exc:
            logger.error("Nginx reload failed after removing domain=%s: %s", domain, exc)
            raise

    # Remove webroot only if it is now empty (no user data left)
    if webroot.exists() and not any(webroot.iterdir()):
        webroot.rmdir()
        webroot_removed = True
        logger.info("Removed empty webroot: %s", webroot)

    return {
        "domain":         domain,
        "config_removed": config_removed,
        "webroot_removed": webroot_removed,
    }


async def write_vhost(params: dict) -> dict:
    """Write a pre-rendered vhost config (used by the PHP/SSL flow)."""
    username = params["username"]
    domain   = params["domain"]
    config   = params["config_content"]

    _assert_safe_domain(domain)

    # For the PHP flow, store under a user-namespaced filename
    vhost_file = (VHOST_DIR / f"{username}_{domain}.conf").resolve()
    if not str(vhost_file).startswith(str(VHOST_DIR.resolve())):
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
    if not str(vhost_file).startswith(str(VHOST_DIR.resolve())):
        raise ValueError("Path traversal detected in delete_vhost")

    if vhost_file.exists():
        vhost_file.unlink()
    return {"deleted": True}
