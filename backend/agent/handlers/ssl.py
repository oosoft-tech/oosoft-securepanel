"""
SSL/TLS certificate handler (certbot + openssl).
All subprocess calls routed through utils.exec.run_command().

Public surface
──────────────
  provision_cert(domain, webroot, *, email=None)
      Low-level async function called DIRECTLY by other handlers
      (e.g. nginx.create_domain).  Does NOT go through the agent
      protocol — no validator or token check applies.

  issue(params)  /  renew(params)  /  get_expiry(params)
      Agent-protocol handlers; always called via the validator.
"""
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from utils.exec import run_command, CommandError

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_LE_LIVE_DIR = Path("/etc/letsencrypt/live")

# Post-renewal hook installed by ssl-setup.sh.
# Passed to certbot so every auto-renewal also reloads nginx.
_RENEWAL_HOOK = "/etc/letsencrypt/renewal-hooks/post/reload-nginx.sh"

# Fallback email when neither the caller nor the env provides one.
_DEFAULT_EMAIL = os.environ.get("PANEL_ADMIN_EMAIL", "ssl-admin@localhost")

# Matches "notAfter=Jan  1 00:00:00 2025 GMT"
_NOTAFTER_RE = re.compile(r"notAfter=(.+)")


# ─────────────────────────────────────────────────────────────────────────────
# Internal shared implementation
# ─────────────────────────────────────────────────────────────────────────────

async def provision_cert(
    domain: str,
    webroot: str,
    *,
    email: str | None = None,
) -> None:
    """
    Obtain a Let's Encrypt certificate via certbot --webroot.

    This function is the single point that calls certbot.  Both the
    agent-protocol ``ssl.issue`` handler and ``nginx.create_domain``
    (which calls it directly without going through the agent protocol)
    use this function so there is no duplicated certbot logic.

    Parameters
    ----------
    domain   : Apex domain to request a certificate for (e.g. "example.com").
               Only the apex is requested; www is a separate concern.
    webroot  : Directory served by nginx for ACME challenges
               (must be accessible at http://<domain>/.well-known/acme-challenge/).
    email    : Contact address for Let's Encrypt expiry notices.  Falls back
               to the PANEL_ADMIN_EMAIL env var, then "ssl-admin@localhost".

    Raises
    ------
    RuntimeError  on certbot failure or timeout.
    """
    _email = email or _DEFAULT_EMAIL

    # Verify the renewal hook exists so certbot doesn't log a warning about
    # a missing hook.  The hook is installed by ssl-setup.sh; if absent we
    # omit the --deploy-hook flag rather than hard-failing.
    hook_args: list[str] = []
    if Path(_RENEWAL_HOOK).exists():
        hook_args = ["--deploy-hook", _RENEWAL_HOOK]
    else:
        logger.warning(
            "Renewal hook not found at %s — nginx will NOT reload on renewal "
            "until ssl-setup.sh is run.  Continuing without --deploy-hook.",
            _RENEWAL_HOOK,
        )

    try:
        await run_command([
            "certbot", "certonly",
            "--webroot",
            "--webroot-path", webroot,
            "--domain",       domain,
            "--email",        _email,
            "--non-interactive",
            "--agree-tos",
            "--no-eff-email",
            # Use domain as the cert-name so renewal maps cleanly.
            "--cert-name",    domain,
            # Quiet: suppress output unless error or renewal.
            "--quiet",
            *hook_args,
        ])
    except CommandError as exc:
        logger.error(
            "certbot failed for domain=%s rc=%d",
            domain, exc.result.returncode,
        )
        raise RuntimeError(
            f"Certificate issuance failed for {domain}"
        ) from exc
    except TimeoutError as exc:
        logger.error("certbot timed out for domain=%s", domain)
        raise RuntimeError(
            f"Certificate issuance timed out for {domain}"
        ) from exc

    # Verify cert files are actually present — certbot can exit 0 when a cert
    # already exists and is not yet due for renewal (no files are written in
    # that case, but files should still exist from the prior run).
    cert_dir = _LE_LIVE_DIR / domain
    missing = [
        name for name in ("fullchain.pem", "privkey.pem", "chain.pem")
        if not (cert_dir / name).exists()
    ]
    if missing:
        raise RuntimeError(
            f"certbot exited 0 but cert files missing for {domain}: "
            + ", ".join(missing)
        )

    logger.info("Certificate ready: domain=%s cert_dir=%s", domain, cert_dir)


# ─────────────────────────────────────────────────────────────────────────────
# Agent-protocol handlers
# ─────────────────────────────────────────────────────────────────────────────

async def issue(params: dict) -> dict:
    """
    Agent-protocol handler for ssl.issue.
    Delegates to provision_cert() — no certbot logic lives here.
    """
    domain  = params["domain"]
    webroot = params["webroot"]
    email   = params.get("email")   # optional; validator does not declare it
                                    # but safe_substitute ignores extras

    try:
        await provision_cert(domain, webroot, email=email)
    except RuntimeError as exc:
        # Re-raise: agent protocol layer catches RuntimeError and returns error
        raise

    return {"issued": True, "domain": domain}


async def renew(params: dict) -> dict:
    domain = params["domain"]

    try:
        await run_command([
            "certbot", "renew",
            "--cert-name",     domain,
            "--non-interactive",
            "--quiet",
        ])
    except CommandError as exc:
        logger.error(
            "certbot renew failed for domain=%s rc=%d",
            domain, exc.result.returncode,
        )
        raise RuntimeError(f"SSL certificate renewal failed for {domain}") from exc

    logger.info("SSL certificate renewed: domain=%s", domain)
    return {"renewed": True, "domain": domain}


async def get_expiry(params: dict) -> dict:
    domain    = params["domain"]
    cert_path = _LE_LIVE_DIR / domain / "cert.pem"

    if not cert_path.exists():
        return {"expiry": None}

    try:
        result = await run_command([
            "openssl", "x509",
            "-enddate", "-noout",
            "-in", str(cert_path),
        ])
    except (CommandError, TimeoutError) as exc:
        logger.warning("openssl expiry check failed for domain=%s: %s", domain, exc)
        return {"expiry": None}

    # stdout: "notAfter=Jan  1 00:00:00 2025 GMT\n"
    match = _NOTAFTER_RE.search(result.stdout.strip())
    if not match:
        logger.warning("Unexpected openssl output for domain=%s", domain)
        return {"expiry": None}

    try:
        expiry_dt = datetime.strptime(match.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
        expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        return {"expiry": expiry_dt.isoformat()}
    except ValueError as exc:
        logger.warning("Cannot parse expiry date for domain=%s: %s", domain, exc)
        return {"expiry": None}
