import asyncio
import subprocess
from datetime import datetime


async def issue(params: dict) -> dict:
    domain = params["domain"]
    webroot = params["webroot"]

    proc = await asyncio.create_subprocess_exec(
        "certbot", "certonly",
        "--webroot", "-w", webroot,
        "-d", domain, "-d", f"www.{domain}",
        "--non-interactive", "--agree-tos",
        "--email", "ssl-admin@localhost",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"certbot failed: {stderr.decode()}")
    return {"issued": True, "domain": domain}


async def renew(params: dict) -> dict:
    domain = params["domain"]
    proc = await asyncio.create_subprocess_exec(
        "certbot", "renew", "--cert-name", domain, "--non-interactive",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"certbot renew failed: {stderr.decode()}")
    return {"renewed": True, "domain": domain}


async def get_expiry(params: dict) -> dict:
    domain = params["domain"]
    cert_path = f"/etc/letsencrypt/live/{domain}/cert.pem"
    try:
        result = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", cert_path],
            capture_output=True, text=True, check=True
        )
        # Format: notAfter=Jan  1 00:00:00 2025 GMT
        date_str = result.stdout.strip().replace("notAfter=", "")
        expiry = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return {"expiry": expiry.isoformat()}
    except (FileNotFoundError, subprocess.CalledProcessError):
        return {"expiry": None}
