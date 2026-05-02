"""
User management handler — privileged operations executed by the root agent.

Two distinct concepts live here
────────────────────────────────
Panel accounts  (create / delete / fix_ownership)
    Regular hosting-panel users created when someone signs up.
    Home at /home/{username}, used for SFTP, crons, etc.

Domain isolation users  (ensure_domain_user)
    One per domain; named after the domain (example_com, my_site_org).
    Own the webroot at /var/www/{domain}.
    Prepared for PHP-FPM per-user pools and CageFS jailing.
    Called DIRECTLY by nginx.create_domain — not via agent protocol.

All subprocess calls are routed through utils.exec.run_command().
"""
import grp
import logging
import pwd
from pathlib import Path

from utils.exec import run_command, CommandError

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Shared constants
# ─────────────────────────────────────────────────────────────────────────────

# Group every hosting user belongs to (exists from install.sh)
_PANEL_GROUP = "securepanel_users"

# Shell assigned to all web-hosting system users — interactive login blocked
_NO_LOGIN_SHELL = "/bin/false"


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _lookup_user(username: str) -> tuple[int, int]:
    """
    Return (uid, gid) for *username*.  Raises RuntimeError if not found.
    Uses Python's pwd module — no subprocess required.
    """
    try:
        pw = pwd.getpwnam(username)
        return pw.pw_uid, pw.pw_gid
    except KeyError:
        raise RuntimeError(
            f"System user {username!r} does not exist after creation attempt"
        )


def _group_exists(group: str) -> bool:
    """Return True if *group* exists on the system."""
    try:
        grp.getgrnam(group)
        return True
    except KeyError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Domain isolation user  (called directly — NOT via agent protocol)
# ─────────────────────────────────────────────────────────────────────────────

async def ensure_domain_user(linux_username: str, domain: str) -> dict:
    """
    Idempotently provision the per-domain Linux isolation user.

    This function is called DIRECTLY by nginx.create_domain before any
    filesystem work is done.  It never goes through the agent protocol,
    so no validator / token overhead applies — but the caller (nginx handler)
    has already run _assert_safe_username() before calling us.

    What it does
    ────────────
    1. Create the system user with useradd (rc=9 = already exists → OK).
    2. Harden home directory permissions to 0711
       (owner enters freely; others need the full path — prevents casual
       enumeration of file names while still letting nginx traverse).
    3. Resolve and return the uid/gid so the caller can chown the webroot
       without an extra lookup.
    4. Attempt CageFS enrollment (best-effort — silently skipped when
       CloudLinux / CageFS is not installed).

    PHP-FPM preparation
    ─────────────────────
    The returned dict includes a ``php_socket_path`` key pointing at
    /run/php-fpm/{linux_username}.sock.  The caller writes the PHP-FPM
    pool config to activate it; no subprocess needed here.

    Parameters
    ──────────
    linux_username : pre-validated system username (matches [a-z][a-z0-9_]{,31})
    domain         : the domain this user is being created for (logging only)

    Returns
    ───────
    {
        "linux_username": str,
        "uid":            int,
        "gid":            int,
        "home_dir":       str,
        "php_socket_path": str,
        "created":        bool,   # True = new user; False = already existed
        "cagefs_enrolled": bool,
    }

    Raises
    ──────
    RuntimeError on hard failure (useradd non-recoverable exit code).
    """
    home_dir = f"/home/{linux_username}"

    # ── 1. Create user (idempotent) ───────────────────────────────────────────
    # useradd rc=9 (user already exists) is declared in exec.py allow_nonzero,
    # so run_command returns normally rather than raising CommandError.

    # Build the group arg only if the panel group exists; on a fresh machine
    # the group is created by install.sh, but defensive code is prudent.
    groups_args: list[str] = []
    if _group_exists(_PANEL_GROUP):
        groups_args = ["-G", _PANEL_GROUP]
    else:
        logger.warning(
            "Group %r not found — domain user %s will not be added to it",
            _PANEL_GROUP, linux_username,
        )

    result = await run_command([
        "useradd",
        "-m",                        # create home directory
        "-d", home_dir,              # explicit home path
        "-s", _NO_LOGIN_SHELL,       # no interactive login
        *groups_args,                # supplementary group (if exists)
        linux_username,
    ])

    created = result.returncode == 0
    if created:
        logger.info(
            "Created domain isolation user: username=%s domain=%s home=%s",
            linux_username, domain, home_dir,
        )
    else:
        # returncode == 9: user already exists (allowed by exec registry)
        logger.info(
            "Domain user already exists — skipping creation: username=%s",
            linux_username,
        )

    # ── 2. Harden home directory permissions ─────────────────────────────────
    # 0711: owner rwx | group --x | other --x
    # The sticky x for group/other allows traversal (cd) but not listing (ls).
    home = Path(home_dir)
    if home.exists():
        home.chmod(0o711)

    # ── 3. Resolve uid / gid ──────────────────────────────────────────────────
    uid, gid = _lookup_user(linux_username)

    # ── 4. CageFS enrollment (best-effort) ───────────────────────────────────
    cagefs_enrolled = False
    try:
        from handlers.cagefs import enable as _cagefs_enable
        await _cagefs_enable({"username": linux_username})
        cagefs_enrolled = True
        logger.info("CageFS enrolled: username=%s", linux_username)
    except Exception as exc:
        # cagefsctl is CloudLinux-specific; not present on every server.
        # Log at DEBUG so non-CloudLinux deployments aren't noisy.
        logger.debug(
            "CageFS enrollment skipped for username=%s (non-fatal): %s",
            linux_username, exc,
        )

    return {
        "linux_username":   linux_username,
        "uid":              uid,
        "gid":              gid,
        "home_dir":         home_dir,
        # Caller uses this path when writing the PHP-FPM pool config later.
        "php_socket_path":  f"/run/php-fpm/{linux_username}.sock",
        "created":          created,
        "cagefs_enrolled":  cagefs_enrolled,
    }


async def ensure_domain_user_handler(params: dict) -> dict:
    """
    Agent-protocol wrapper for ensure_domain_user.
    Allows the action to be called directly via the agent socket when needed
    (e.g. repair flows, admin CLI tools).
    """
    return await ensure_domain_user(
        linux_username=params["linux_username"],
        domain=params["domain"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Panel account management (existing handlers — unchanged semantics)
# ─────────────────────────────────────────────────────────────────────────────

async def create(params: dict) -> dict:
    """
    Create a panel hosting account (human login user).
    Different from ensure_domain_user: this is for the person who logs into
    the panel, not the per-domain isolation user.
    """
    username = params["username"]
    shell    = params.get("shell", _NO_LOGIN_SHELL)
    home_dir = f"/home/{username}"

    groups_args: list[str] = []
    if _group_exists(_PANEL_GROUP):
        groups_args = ["-G", _PANEL_GROUP]

    try:
        await run_command([
            "useradd",
            "-m", "-d", home_dir,
            "-s", shell,
            *groups_args,
            username,
        ])
    except CommandError as exc:
        # rc=9 is in allow_nonzero → never reaches here for "user exists".
        # Any other failure is a hard error.
        logger.error(
            "useradd failed for username=%s rc=%d", username, exc.result.returncode
        )
        raise RuntimeError("Failed to create system user") from exc

    home = Path(home_dir)
    home.chmod(0o711)

    public_html = home / "public_html"
    public_html.mkdir(exist_ok=True)
    public_html.chmod(0o755)

    logger.info("Panel account created: username=%s", username)
    return {"username": username, "home": home_dir}


async def delete(params: dict) -> dict:
    """Delete a panel hosting account and its home directory."""
    username = params["username"]

    try:
        await run_command(["userdel", "-r", username])
    except CommandError as exc:
        # rc=6 (user does not exist) is in allow_nonzero — safe to ignore.
        logger.error(
            "userdel failed for username=%s rc=%d", username, exc.result.returncode
        )
        raise RuntimeError("Failed to delete system user") from exc

    logger.info("Panel account deleted: username=%s", username)
    return {"deleted": True}


async def fix_ownership(params: dict) -> dict:
    """Recursively re-assign ownership of a panel account's home directory."""
    username = params["username"]
    home_dir = f"/home/{username}"

    try:
        await run_command(["chown", "-R", f"{username}:{username}", home_dir])
    except CommandError as exc:
        logger.error(
            "chown failed for username=%s rc=%d", username, exc.result.returncode
        )
        raise RuntimeError("Failed to fix file ownership") from exc

    logger.info("Ownership fixed: username=%s path=%s", username, home_dir)
    return {"fixed": True}
