"""
SSL/TLS certificate handler (certbot + openssl).
All subprocess calls routed through utils.exec.run_command().
The blocking subprocess.run() call for openssl is replaced with
an async run_command() call — no more thread-blocking in the event loop.
"""
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from utils.exec import run_command, CommandError

logger = logging.getLogger(__name__)

# Certbot stores certs here; used only for read operations (openssl -in)
_LE_LIVE_DIR = Path("/etc/letsencrypt/live")

# Pattern that matches the notAfter line openssl prints
_NOTAFTER_RE = re.compile(r"notAfter=(.+)")


async def issue(params: dict) -> dict:
    domain  = params["domain"]
    webroot = params["webroot"]

    try:
        await run_command([
            "certbot", "certonly",
            "--webroot", "-w", webroot,
            "-d", domain, "-d", f"www.{domain}",
            "--non-interactive", "--agree-tos",
            "--email", "ssl-admin@localhost",
        ])
    except CommandError as exc:
        logger.error("certbot issue failed for domain=%s rc=%d", domain, exc.result.returncode)
        raise RuntimeError(f"SSL certificate issuance failed for {domain}") from exc
    except TimeoutError as exc:
        logger.error("certbot issue timed out for domain=%s", domain)
        raise RuntimeError(f"SSL certificate issuance timed out for {domain}") from exc

    logger.info("SSL certificate issued: domain=%s", domain)
    return {"issued": True, "domain": domain}


async def renew(params: dict) -> dict:
    domain = params["domain"]

    try:
        await run_command([
            "certbot", "renew",
            "--cert-name", domain,
            "--non-interactive",
        ])
    except CommandError as exc:
        logger.error("certbot renew failed for domain=%s rc=%d", domain, exc.result.returncode)
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
