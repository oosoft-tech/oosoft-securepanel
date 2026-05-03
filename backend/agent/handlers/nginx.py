"""
Nginx handler — privileged operations executed by the root agent.

All subprocess execution is delegated to utils.exec.run_command().
No asyncio.create_subprocess_exec() calls exist in this module.

create_domain() flow
─────────────────────
Phase 0 — User isolation (always, hard-fails on error):
  0. Validate linux_username (defense-in-depth)
  1. ensure_domain_user() — create/verify per-domain Linux user
  2. Validate domain
  3. Create /var/www/{domain} webroot
  4. Write default index.html
  5. chown -R {linux_username}:{linux_username} /var/www/{domain}
  6. Render HTTP-only nginx config
  7. Write config, nginx -t (rollback on failure), reload

Phase 1 — Best-effort SSL (never breaks domain creation):
  8. ssl-params.conf snippet present?
  9. DNS resolves?
 10. Domain re-validated before certbot
 11. ssl.provision_cert() — certbot --webroot
 12. Cert-file presence check
 13. Render HTTPS config, write, nginx -t
     • failure → rollback to HTTP config, reload
     • success → reload, ssl_enabled=True
"""
import asyncio
import logging
import os
import re
import shutil
import socket
from pathlib import Path
from string import Template

from utils.exec import run_command, CommandError

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

VHOST_DIR      = Path("/etc/nginx/conf.d")
WEBROOT_BASE   = Path("/var/www")
_TEMPLATE_DIR  = Path("/opt/oosoft-securepanel/nginx/templates")
TEMPLATE_FILE  = _TEMPLATE_DIR / "domain.conf.j2"
_SSL_TEMPLATE  = _TEMPLATE_DIR / "domain-ssl.conf.j2"

_LE_LIVE_DIR   = Path("/etc/letsencrypt/live")
_ACME_WEBROOT  = "/var/www/letsencrypt"
_SSL_SNIPPET   = "/etc/nginx/snippets/ssl-params.conf"

# ─────────────────────────────────────────────────────────────────────────────
# Inline fallback templates (string.Template — safe_substitute only)
#
# Escape rules:
#   $domain / ${domain}  →  substituted with the actual domain string
#   $$variable           →  written as $variable (nginx variable)
#   \\.                  →  Python literal \.  (nginx regex class)
# ─────────────────────────────────────────────────────────────────────────────

_INLINE_TEMPLATE_HTTP = """\
# /etc/nginx/conf.d/$domain.conf  —  HTTP only (Oosoft SecurePanel)
server {
    listen      80;
    listen      [::]:80;
    server_name $domain www.$domain;

    root  /var/www/$domain;
    index index.html index.htm;

    access_log /var/log/nginx/${domain}_access.log combined;
    error_log  /var/log/nginx/${domain}_error.log warn;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location ~ /\\. { deny all; return 404; }
    location ~* (\\.env|wp-config\\.php|\\.git) { deny all; return 404; }

    location / { try_files $$uri $$uri/ =404; }

    location /.well-known/acme-challenge/ {
        root         /var/www/letsencrypt;
        default_type "text/plain";
        try_files    $$uri =404;
    }

    client_max_body_size 64M;
}
"""

_INLINE_TEMPLATE_HTTPS = """\
# /etc/nginx/conf.d/$domain.conf  —  HTTPS (Oosoft SecurePanel)

server {
    listen      80;
    listen      [::]:80;
    server_name $domain www.$domain;

    location /.well-known/acme-challenge/ {
        root         /var/www/letsencrypt;
        default_type "text/plain";
        try_files    $$uri =404;
    }

    location / {
        return 301 https://$domain$$request_uri;
    }
}

server {
    listen      443 ssl;
    listen      [::]:443 ssl;
    http2       on;
    server_name $domain;

    ssl_certificate         /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key     /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/$domain/chain.pem;

    include /etc/nginx/snippets/ssl-params.conf;

    root  /var/www/$domain;
    index index.html index.htm;

    access_log /var/log/nginx/${domain}_access.log combined;
    error_log  /var/log/nginx/${domain}_error.log warn;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location ~ /\\. { deny all; return 404; }
    location ~* (\\.env|wp-config\\.php|\\.git) { deny all; return 404; }

    location / { try_files $$uri $$uri/ =404; }

    client_max_body_size 64M;
}
"""

_INLINE_TEMPLATE_SUSPENDED_HTTP = """\
# /etc/nginx/conf.d/$domain.conf  —  SUSPENDED (Oosoft SecurePanel)
server {
    listen      80;
    listen      [::]:80;
    server_name $domain www.$domain;

    # Keep ACME challenge open so Let's Encrypt renewals succeed while suspended.
    location /.well-known/acme-challenge/ {
        root         /var/www/letsencrypt;
        default_type "text/plain";
        try_files    $$uri =404;
    }

    location / { return 503; }
}
"""

# Appended to the HTTP stub when a cert already exists for the domain.
# Prevents HSTS-preloaded browsers from seeing a certificate error.
_INLINE_TEMPLATE_SUSPENDED_SSL = """\

server {
    listen      443 ssl;
    listen      [::]:443 ssl;
    http2       on;
    server_name $domain;

    ssl_certificate         /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key     /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/$domain/chain.pem;

    include /etc/nginx/snippets/ssl-params.conf;

    location / { return 503; }
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# Validation helpers (defense-in-depth — validator already checked these)
# ─────────────────────────────────────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

# Same pattern as validator.py's _RE_USERNAME / _RE_LINUX_USERNAME
_USERNAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


def _assert_safe_domain(domain: str) -> None:
    """Raise ValueError if *domain* fails agent-level validation."""
    if not isinstance(domain, str) or not _DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"Domain failed agent-level validation: {domain!r}")
    if ".." in domain or "/" in domain or "\\" in domain or "\x00" in domain:
        raise ValueError(f"Domain contains forbidden characters: {domain!r}")


def _assert_safe_username(username: str) -> None:
    """
    Raise ValueError if *username* fails agent-level validation.
    Called before any chown / useradd invocation — ensures no shell
    metacharacters can appear in a command argument even though
    run_command never uses shell=True.
    """
    if not isinstance(username, str) or not _USERNAME_RE.fullmatch(username):
        raise ValueError(f"Username failed agent-level validation: {username!r}")


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


def _safe_disabled_vhost_path(domain: str) -> Path:
    """Return the path to a domain's preserved (suspended) vhost config."""
    path = (VHOST_DIR / f"{domain}.conf.disabled").resolve()
    if not str(path).startswith(str(VHOST_DIR.resolve()) + "/"):
        raise ValueError("Path traversal detected in disabled-vhost path construction")
    return path


def _safe_backup_vhost_path(domain: str) -> Path:
    """Return a temporary backup path used by rebuild_domain for rollback."""
    path = (VHOST_DIR / f"{domain}.conf.bak").resolve()
    if not str(path).startswith(str(VHOST_DIR.resolve()) + "/"):
        raise ValueError("Path traversal detected in backup-vhost path construction")
    return path


# ─────────────────────────────────────────────────────────────────────────────
# Config rendering
# ─────────────────────────────────────────────────────────────────────────────

def _jinja_env(template_dir: Path):
    from jinja2 import Environment, FileSystemLoader
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=False,           # nginx configs are not HTML
        keep_trailing_newline=True,
    )


def _render_config(domain: str) -> str:
    """Render HTTP-only vhost config."""
    if TEMPLATE_FILE.exists():
        try:
            env = _jinja_env(TEMPLATE_FILE.parent)
            return env.get_template(TEMPLATE_FILE.name).render(domain=domain)
        except Exception as exc:
            logger.warning("Jinja2 HTTP render failed (%s); using inline fallback", exc)
    return Template(_INLINE_TEMPLATE_HTTP).safe_substitute(domain=domain)


def _render_https_config(domain: str) -> str:
    """Render HTTPS vhost config (HTTP redirect + TLS block)."""
    if _SSL_TEMPLATE.exists():
        try:
            env = _jinja_env(_SSL_TEMPLATE.parent)
            return env.get_template(_SSL_TEMPLATE.name).render(domain=domain)
        except Exception as exc:
            logger.warning("Jinja2 HTTPS render failed (%s); using inline fallback", exc)
    return Template(_INLINE_TEMPLATE_HTTPS).safe_substitute(domain=domain)


def _cert_exists(domain: str) -> bool:
    """Return True if a complete Let's Encrypt cert set exists for *domain*."""
    cert_dir = _LE_LIVE_DIR / domain
    return all(
        (cert_dir / fname).exists()
        for fname in ("fullchain.pem", "privkey.pem", "chain.pem")
    )


def _render_suspended_config(domain: str) -> str:
    """
    Render a 503-returning suspension stub.

    Always includes the HTTP block so ACME renewals survive suspension.
    Appends a HTTPS 503 block when a cert already exists, preventing
    HSTS-preloaded browsers from seeing a certificate error.
    """
    config = Template(_INLINE_TEMPLATE_SUSPENDED_HTTP).safe_substitute(domain=domain)
    if _cert_exists(domain):
        config += Template(_INLINE_TEMPLATE_SUSPENDED_SSL).safe_substitute(domain=domain)
    return config


# ─────────────────────────────────────────────────────────────────────────────
# DNS resolution check
# ─────────────────────────────────────────────────────────────────────────────

async def _dns_resolves(domain: str) -> tuple[bool, str | None]:
    """
    Check DNS resolution via socket.getaddrinfo() in a thread executor.
    Returns (resolves: bool, first_ip: str | None).
    """
    loop = asyncio.get_running_loop()
    try:
        results = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP),
            ),
            timeout=5.0,
        )
        if results:
            return True, results[0][4][0]
        return False, None
    except (socket.gaierror, OSError, asyncio.TimeoutError) as exc:
        logger.debug("DNS check failed for domain=%s: %s", domain, exc)
        return False, None


# ─────────────────────────────────────────────────────────────────────────────
# Nginx primitives
# ─────────────────────────────────────────────────────────────────────────────

async def _nginx_test() -> None:
    try:
        await run_command(["nginx", "-t"])
    except CommandError as exc:
        logger.error("nginx -t failed (rc=%d)", exc.result.returncode)
        raise RuntimeError("Nginx configuration test failed") from exc


async def _nginx_reload() -> None:
    try:
        await run_command(["systemctl", "reload", "nginx"])
    except CommandError as exc:
        logger.error("systemctl reload nginx failed (rc=%d)", exc.result.returncode)
        raise RuntimeError("Nginx reload failed") from exc


# ─────────────────────────────────────────────────────────────────────────────
# SSL provisioning helper
# ─────────────────────────────────────────────────────────────────────────────

async def _provision_ssl(domain: str) -> tuple[bool, str | None]:
    """
    Attempt cert issuance + HTTPS config deployment.
    Never raises — returns (success, error_message_or_None).
    """
    resolves, resolved_ip = await _dns_resolves(domain)
    if not resolves:
        logger.warning("SSL skipped: DNS does not resolve for domain=%s", domain)
        return False, "DNS does not resolve for domain — SSL skipped"

    logger.info("DNS OK for domain=%s ip=%s", domain, resolved_ip)

    try:
        _assert_safe_domain(domain)
    except ValueError as exc:
        logger.error("Domain re-validation failed before SSL: %s", exc)
        return False, "Domain validation failed before SSL request"

    try:
        from handlers.ssl import provision_cert
        email = os.environ.get("PANEL_ADMIN_EMAIL", "ssl-admin@localhost")
        await provision_cert(domain, _ACME_WEBROOT, email=email)
    except RuntimeError as exc:
        logger.error("SSL provisioning failed for domain=%s: %s", domain, exc)
        return False, "SSL certificate issuance failed"
    except Exception:
        logger.exception("Unexpected error during SSL provisioning domain=%s", domain)
        return False, "Unexpected error during SSL provisioning"

    cert_dir = _LE_LIVE_DIR / domain
    for fname in ("fullchain.pem", "privkey.pem", "chain.pem"):
        if not (cert_dir / fname).exists():
            logger.error("Cert file missing: %s/%s", cert_dir, fname)
            return False, f"Certificate file {fname} missing after issuance"

    return True, None


# ─────────────────────────────────────────────────────────────────────────────
# Public handlers
# ─────────────────────────────────────────────────────────────────────────────

async def reload(params: dict) -> dict:
    await _nginx_test()
    await _nginx_reload()
    return {"reloaded": True}


async def create_domain(params: dict) -> dict:
    """
    Full domain provisioning pipeline.

    Expected params
    ───────────────
    domain         : validated, lowercase domain string
    linux_username : per-domain isolation user (derived from domain by API layer)

    Returns
    ───────
    {
        domain         : str
        linux_username : str
        webroot        : str   — absolute path
        config         : str   — absolute path to active nginx config
        ssl_enabled    : bool
        ssl_error      : str | None
        uid            : int   — OS uid of the domain user
        gid            : int   — OS gid of the domain user
    }
    """
    domain         = params["domain"]
    linux_username = params["linux_username"]

    # ── Phase 0-a: validate both inputs (defense-in-depth) ───────────────────
    _assert_safe_domain(domain)
    _assert_safe_username(linux_username)

    # ── Phase 0-b: ensure per-domain isolation user exists ───────────────────
    # Hard failure — if we can't create the user we refuse to create the domain.
    try:
        from handlers.user import ensure_domain_user
        user_info = await ensure_domain_user(
            linux_username=linux_username,
            domain=domain,
        )
    except RuntimeError as exc:
        logger.error(
            "User isolation setup failed for domain=%s username=%s: %s",
            domain, linux_username, exc,
        )
        raise  # propagate: domain creation aborted

    uid = user_info["uid"]
    gid = user_info["gid"]

    # ── Phase 0-c: safe path construction ────────────────────────────────────
    webroot    = _safe_webroot_path(domain)
    vhost_path = _safe_vhost_path(domain)

    # ── Phase 1: webroot ──────────────────────────────────────────────────────
    webroot.mkdir(parents=True, exist_ok=True)
    # Permissions BEFORE chown — owner will be linux_username, nginx reads as other
    webroot.chmod(0o755)

    # ── Phase 2: default index.html ───────────────────────────────────────────
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
        logger.info("Created default index.html: domain=%s", domain)

    # ── Phase 3: transfer webroot ownership to isolation user ─────────────────
    # chown is safe: linux_username matches [a-z][a-z0-9_]{,31} — no metacharacters
    # The argument f"{u}:{u}" only contains [a-z0-9_:] — still safe without shell.
    try:
        await run_command([
            "chown", "-R",
            f"{linux_username}:{linux_username}",
            str(webroot),
        ])
        logger.info(
            "Webroot ownership set: path=%s owner=%s uid=%d gid=%d",
            webroot, linux_username, uid, gid,
        )
    except CommandError as exc:
        logger.error(
            "chown failed for domain=%s username=%s rc=%d",
            domain, linux_username, exc.result.returncode,
        )
        raise RuntimeError("Failed to set webroot ownership") from exc

    # ── Phase 4: render HTTP-only config ──────────────────────────────────────
    http_config = _render_config(domain)

    # ── Phase 5: write + test + reload (HTTP) ─────────────────────────────────
    vhost_path.write_text(http_config, encoding="utf-8")
    vhost_path.chmod(0o644)
    logger.info("Wrote HTTP nginx config: %s", vhost_path)

    try:
        await _nginx_test()
    except RuntimeError:
        vhost_path.unlink(missing_ok=True)
        logger.error("Rolled back nginx config: domain=%s", domain)
        raise   # hard-fail; domain never became reachable

    await _nginx_reload()
    logger.info("Domain live via HTTP: domain=%s webroot=%s owner=%s",
                domain, webroot, linux_username)

    # ── Phase 6: best-effort SSL ──────────────────────────────────────────────
    ssl_enabled = False
    ssl_error: str | None = None

    if not Path(_SSL_SNIPPET).exists():
        ssl_error = (
            f"ssl-params.conf not found at {_SSL_SNIPPET}. "
            "Run ssl-setup.sh, then re-issue the cert manually via ssl.issue."
        )
        logger.warning("SSL skipped for domain=%s: %s", domain, ssl_error)
    else:
        cert_ok, cert_err = await _provision_ssl(domain)

        if not cert_ok:
            ssl_error = cert_err
        else:
            https_config = _render_https_config(domain)
            vhost_path.write_text(https_config, encoding="utf-8")
            vhost_path.chmod(0o644)

            try:
                await _nginx_test()
            except RuntimeError as exc:
                logger.error(
                    "HTTPS nginx config failed for domain=%s — rolling back: %s",
                    domain, exc,
                )
                ssl_error = "HTTPS nginx config test failed after cert issuance"
                # Restore known-good HTTP config
                vhost_path.write_text(http_config, encoding="utf-8")
                try:
                    await _nginx_test()
                    await _nginx_reload()
                    logger.info("HTTP rollback succeeded: domain=%s", domain)
                except RuntimeError:
                    logger.critical(
                        "HTTP rollback FAILED for domain=%s — nginx may be broken!",
                        domain,
                    )
            else:
                await _nginx_reload()
                ssl_enabled = True
                logger.info("HTTPS active: domain=%s", domain)

    result = {
        "domain":         domain,
        "linux_username": linux_username,
        "webroot":        str(webroot),
        "config":         str(vhost_path),
        "ssl_enabled":    ssl_enabled,
        "ssl_error":      ssl_error,
        "uid":            uid,
        "gid":            gid,
    }
    logger.info("create_domain complete: %s", result)
    return result


async def delete_domain(params: dict) -> dict:
    """
    Remove a domain's nginx config(s) and webroot entirely.

    Handles both active and suspended states:
    - Removes {domain}.conf  (active config or suspension stub)
    - Removes {domain}.conf.disabled  (preserved config from suspend)
    - Removes /var/www/{domain}  (recursive, symlink-safe)
    """
    domain         = params["domain"]
    linux_username = params["linux_username"]

    _assert_safe_domain(domain)
    _assert_safe_username(linux_username)

    vhost_path    = _safe_vhost_path(domain)
    disabled_path = _safe_disabled_vhost_path(domain)
    webroot       = _safe_webroot_path(domain)

    config_removed = False

    # Remove active config (present whether domain is live or suspended)
    if vhost_path.exists():
        vhost_path.unlink()
        config_removed = True
        logger.info("Removed nginx config: %s", vhost_path)

    # Remove preserved config left by suspend_domain
    if disabled_path.exists():
        disabled_path.unlink()
        logger.info("Removed suspended nginx config: %s", disabled_path)

    if config_removed:
        try:
            await _nginx_test()
            await _nginx_reload()
        except RuntimeError as exc:
            logger.error("Nginx reload failed after delete domain=%s: %s", domain, exc)
            raise

    # Remove webroot — recursive, guards against symlink escape
    webroot_removed = False
    if webroot.is_symlink():
        webroot.unlink()
        webroot_removed = True
        logger.info("Removed webroot symlink: %s", webroot)
    elif webroot.exists():
        shutil.rmtree(str(webroot))
        webroot_removed = True
        logger.info("Removed webroot directory: %s", webroot)

    return {
        "domain":          domain,
        "linux_username":  linux_username,
        "config_removed":  config_removed,
        "webroot_removed": webroot_removed,
    }


async def suspend_domain(params: dict) -> dict:
    """
    Suspend a domain by swapping its nginx config for a 503 stub.

    The original config is preserved as {domain}.conf.disabled so it can be
    restored verbatim by unsuspend_domain, or replaced by rebuild_domain.

    The ACME challenge location remains open so Let's Encrypt renewals
    continue while the domain is suspended.  A HTTPS 503 block is also
    written when a cert exists, preventing HSTS-preloaded clients from
    encountering a certificate error.

    Rollback: if ``nginx -t`` rejects the stub, the original config is
    restored and no reload is performed.
    """
    domain         = params["domain"]
    linux_username = params["linux_username"]

    _assert_safe_domain(domain)
    _assert_safe_username(linux_username)

    vhost_path    = _safe_vhost_path(domain)
    disabled_path = _safe_disabled_vhost_path(domain)

    if not vhost_path.exists():
        if disabled_path.exists():
            raise RuntimeError(f"Domain {domain!r} is already suspended")
        raise RuntimeError(f"No nginx config found for domain {domain!r}")

    # Atomically preserve the active config before writing the stub.
    vhost_path.rename(disabled_path)
    logger.info("Preserved active config as: %s", disabled_path)

    stub = _render_suspended_config(domain)
    vhost_path.write_text(stub, encoding="utf-8")
    vhost_path.chmod(0o644)

    try:
        await _nginx_test()
    except RuntimeError as exc:
        # Rollback: remove the bad stub and restore the original config.
        vhost_path.unlink(missing_ok=True)
        disabled_path.rename(vhost_path)
        logger.error(
            "Suspension nginx test failed for domain=%s — rolled back: %s",
            domain, exc,
        )
        raise

    await _nginx_reload()
    logger.info("Domain suspended (503): domain=%s", domain)

    return {"domain": domain, "suspended": True}


async def unsuspend_domain(params: dict) -> dict:
    """
    Restore a suspended domain by reinstating its preserved nginx config.

    Reads {domain}.conf.disabled (written by suspend_domain), renames it
    back to {domain}.conf, and reloads nginx.  Rolls back if ``nginx -t``
    rejects the restored config.
    """
    domain         = params["domain"]
    linux_username = params["linux_username"]

    _assert_safe_domain(domain)
    _assert_safe_username(linux_username)

    vhost_path    = _safe_vhost_path(domain)
    disabled_path = _safe_disabled_vhost_path(domain)

    if not disabled_path.exists():
        raise RuntimeError(f"No suspended config found for domain {domain!r}")

    # Rename .disabled → .conf, atomically replacing the 503 stub.
    disabled_path.rename(vhost_path)
    logger.info("Restored config from: %s → %s", disabled_path, vhost_path)

    try:
        await _nginx_test()
    except RuntimeError as exc:
        # Rollback: rename .conf back to .disabled so domain stays suspended.
        vhost_path.rename(disabled_path)
        logger.error(
            "Unsuspend nginx test failed for domain=%s — rolled back: %s",
            domain, exc,
        )
        raise

    await _nginx_reload()
    logger.info("Domain unsuspended: domain=%s", domain)

    return {"domain": domain, "suspended": False}


async def rebuild_domain(params: dict) -> dict:
    """
    Regenerate a domain's nginx config from current state.

    SSL is detected from cert file existence (not from the database) so
    the result is always consistent with what is on disk.

    Suspended domains
    ─────────────────
    When the domain is suspended ({domain}.conf.disabled exists and
    {domain}.conf is the 503 stub), the rebuilt config is written only to
    the .disabled file.  The live 503 stub is left untouched and no reload
    is performed.  The domain will serve the updated config next time
    unsuspend_domain is called.

    Active domains
    ──────────────
    1. Back up the current config to {domain}.conf.bak.
    2. Write the new config.
    3. Run ``nginx -t``:
       - On failure: restore the backup and re-test/reload; raise.
       - On success: reload nginx; remove the backup.
    """
    domain         = params["domain"]
    linux_username = params["linux_username"]

    _assert_safe_domain(domain)
    _assert_safe_username(linux_username)

    vhost_path    = _safe_vhost_path(domain)
    disabled_path = _safe_disabled_vhost_path(domain)
    backup_path   = _safe_backup_vhost_path(domain)

    # A domain is considered suspended when the .disabled file exists AND
    # the active .conf file is present (it holds the 503 stub).  If only
    # .disabled exists and .conf is absent the state is inconsistent; we
    # still treat it as suspended to avoid an accidental live reload.
    is_suspended = disabled_path.exists()

    ssl_active = _cert_exists(domain)
    new_config  = _render_https_config(domain) if ssl_active else _render_config(domain)

    if is_suspended:
        # Overwrite the preserved config; leave the live 503 stub alone.
        disabled_path.write_text(new_config, encoding="utf-8")
        disabled_path.chmod(0o644)
        logger.info(
            "Rebuilt suspended config (not reloaded): domain=%s ssl=%s",
            domain, ssl_active,
        )
        return {
            "domain":        domain,
            "ssl_active":    ssl_active,
            "reloaded":      False,
            "was_suspended": True,
        }

    # Active domain — backup → write → test → reload (restore on failure).
    backup_written = False
    if vhost_path.exists():
        shutil.copy2(str(vhost_path), str(backup_path))
        backup_written = True

    vhost_path.write_text(new_config, encoding="utf-8")
    vhost_path.chmod(0o644)

    try:
        await _nginx_test()
    except RuntimeError as exc:
        if backup_written and backup_path.exists():
            shutil.copy2(str(backup_path), str(vhost_path))
            logger.error(
                "Rebuild nginx test failed for domain=%s — restored backup: %s",
                domain, exc,
            )
            try:
                await _nginx_test()
                await _nginx_reload()
            except RuntimeError:
                logger.critical(
                    "Backup config also failed nginx test for domain=%s — "
                    "manual intervention required!",
                    domain,
                )
        else:
            logger.error(
                "Rebuild nginx test failed for domain=%s (no backup): %s",
                domain, exc,
            )
        raise
    finally:
        backup_path.unlink(missing_ok=True)

    await _nginx_reload()
    logger.info("Rebuilt domain config: domain=%s ssl=%s", domain, ssl_active)

    return {
        "domain":        domain,
        "ssl_active":    ssl_active,
        "reloaded":      True,
        "was_suspended": False,
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
