"""
backend/app/utils/username.py
─────────────────────────────────────────────────────────────────────────────
Per-domain Linux username derivation and uniqueness enforcement.

Design goals
────────────
1. Deterministic   — the same domain always produces the same candidate name.
2. Collision-safe  — a suffix (_001…_999) is appended when the base clashes.
3. System-safe     — a comprehensive blocklist prevents any derived name from
                     landing on a real system account (root, nginx, etc.).
4. Injection-safe  — the output matches ^[a-z][a-z0-9_]{0,31}$ so it is safe
                     to pass directly to useradd / chown without quoting.

Typical derivations
───────────────────
  example.com             → example_com
  my-site.org             → my_site_org
  shop.example.com        → shop_example_com
  sub.sub.domain.co.uk    → sub_sub_domain_co_uk   (truncated at 28 chars)
  123numbers.net          → w123numbers_net         (prepend 'w' if no letter)
  xn--nxasmq6b.com        → xn__nxasmq6b_com
"""
import re

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Linux hard limit on username length.
_LINUX_MAX = 32

# Reserve 4 characters for the collision suffix (_001 … _999).
# The base name is therefore truncated to 28 characters.
_BASE_MAX = _LINUX_MAX - 4  # 28

# Compiled pattern that every generated username MUST match.
_RE_LINUX_USERNAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

# ─────────────────────────────────────────────────────────────────────────────
# System-level blocklist
#
# These names must NEVER be assigned to a web-hosting domain user.
# The list covers:
#   • Standard POSIX / Linux accounts
#   • Common service accounts (web servers, databases, mail, …)
#   • Panel-specific reserved names
#   • Attacker-bait names that look like service accounts
# ─────────────────────────────────────────────────────────────────────────────

RESERVED_SYSTEM_USERS: frozenset[str] = frozenset({
    # ── Core POSIX ────────────────────────────────────────────────────────────
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp",
    "mail", "news", "uucp", "proxy", "backup", "list", "irc",
    "gnats", "nobody", "syslog",
    # ── Debian / Ubuntu ───────────────────────────────────────────────────────
    "_apt", "ubuntu", "debian", "landscape", "pollinate",
    # ── RHEL / CentOS / CloudLinux ────────────────────────────────────────────
    "centos", "redhat", "cloudlinux", "adm", "tty", "disk",
    "kmem", "dialout", "fax", "voice", "cdrom", "floppy",
    "tape", "sudo", "audio", "dip", "www_data",
    # ── Web / proxy ───────────────────────────────────────────────────────────
    "www", "www_data", "nginx", "apache", "apache2", "httpd",
    "lighttpd", "caddy", "haproxy",
    # ── Database ─────────────────────────────────────────────────────────────
    "mysql", "mariadb", "postgres", "postgresql", "mongodb",
    "redis", "memcached", "elasticsearch", "cassandra", "couchdb",
    # ── Mail ─────────────────────────────────────────────────────────────────
    "postfix", "dovecot", "exim", "sendmail", "qmail",
    "postmaster", "hostmaster", "webmaster", "abuse",
    # ── Other services ────────────────────────────────────────────────────────
    "ftp", "sftp", "ssh", "sshd", "ftpuser",
    "ntp", "ntpd", "chrony", "bind", "named", "unbound",
    "vsftpd", "proftpd", "pure_ftpd",
    "rabbitmq", "kafka", "zookeeper",
    "nagios", "zabbix", "prometheus", "grafana", "influxdb",
    "docker", "podman", "lxd", "libvirt_qemu",
    "cups", "avahi", "messagebus", "dbus", "polkitd",
    "systemd_network", "systemd_resolve", "systemd_timesync",
    "uuidd", "at", "cron", "dnsmasq", "rtkit", "colord",
    # ── Panel-specific ────────────────────────────────────────────────────────
    "securepanel", "securepanel_users",
    "cpanel", "whm", "plesk", "directadmin", "ispconfig", "webmin",
    # ── Generic / attacker-bait ───────────────────────────────────────────────
    "admin", "administrator", "operator", "superuser", "su",
    "user", "guest", "anonymous", "test", "demo", "default",
    "support", "help", "info", "noreply", "no_reply",
    "web", "api", "static", "media", "cdn", "assets",
    "deploy", "deployment", "ci", "build", "release",
    "monitor", "monitoring", "health", "status", "metrics",
    "log", "logs", "logstash", "fluentd",
    "backup", "restore", "maintenance", "maint",
})


# ─────────────────────────────────────────────────────────────────────────────
# Core derivation logic
# ─────────────────────────────────────────────────────────────────────────────

def derive_username(domain: str) -> str:
    """
    Convert a domain name to a candidate Linux username.

    The transformation is purely mechanical — it never checks for collisions
    or blocklisted names.  Use ``generate_unique_username`` for that.

    Algorithm
    ─────────
    1. Lowercase the domain.
    2. Replace every character outside [a-z0-9] with a single underscore
       (dots, hyphens, plus any other punctuation that DNS normalization
       leaves in IDN labels become underscores).
    3. Collapse consecutive underscores into one.
    4. Strip leading / trailing underscores.
    5. If the result starts with a digit (or is empty), prepend 'w'
       ('w' for 'web'; keeps the name meaningful).
    6. Truncate to _BASE_MAX (28) characters.
    7. Strip a trailing underscore left by truncation.

    Examples
    ────────
    "example.com"          → "example_com"
    "my-site.org"          → "my_site_org"
    "shop.example.com"     → "shop_example_com"
    "123.io"               → "w123_io"
    "xn--nxasmq6b.com"     → "xn__nxasmq6b_com"
    "a" * 50 + ".com"      → first 28 chars of the normalised string
    """
    # Step 1 — normalise to lowercase
    cleaned = domain.lower()

    # Step 2 — keep only letters and digits; everything else → underscore
    cleaned = re.sub(r"[^a-z0-9]+", "_", cleaned)

    # Step 3 — collapse runs of underscores
    cleaned = re.sub(r"_+", "_", cleaned)

    # Step 4 — strip leading / trailing underscores
    cleaned = cleaned.strip("_")

    # Step 5 — ensure starts with a letter
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "w" + cleaned

    # Step 6-7 — truncate; clean any trailing underscore introduced by the cut
    cleaned = cleaned[:_BASE_MAX].rstrip("_")

    return cleaned


def generate_unique_username(
    domain: str,
    existing_usernames: set[str],
) -> str:
    """
    Return a Linux username derived from *domain* that is:
      • not in *existing_usernames* (DB collision check)
      • not in RESERVED_SYSTEM_USERS (OS collision check)

    Collision resolution
    ─────────────────────
    The base name is tried first.  On collision, zero-padded numeric suffixes
    are appended: _001, _002, …, _999.  If all 999 slots are occupied a
    ValueError is raised (this is astronomically unlikely in practice).

    Parameters
    ──────────
    domain            : raw domain string (will be passed through derive_username)
    existing_usernames: set of usernames already in the database

    Returns
    ───────
    A validated username string that matches ``_RE_LINUX_USERNAME``.

    Raises
    ──────
    ValueError — if the domain cannot produce a safe username after 999 tries.
    """
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("domain must be a non-empty string")

    blocked = RESERVED_SYSTEM_USERS | existing_usernames
    base    = derive_username(domain)

    # Try the plain base name first
    if base not in blocked:
        return base

    # Append numeric suffix until a free slot is found
    for counter in range(1, 1000):
        suffix    = f"_{counter:03d}"
        candidate = base[: _BASE_MAX - len(suffix)] + suffix
        # The truncation above may leave a trailing underscore before the suffix
        candidate = candidate.replace("__", "_")
        if candidate not in blocked:
            return candidate

    raise ValueError(
        f"Cannot derive a unique Linux username for domain {domain!r}: "
        "all 999 candidate names are already taken."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public validation
# ─────────────────────────────────────────────────────────────────────────────

def validate_linux_username(raw: str) -> str:
    """
    Validate a Linux username intended for domain isolation.

    This is the FastAPI-layer guard.  The privileged agent runs its own
    regex check as a second, independent layer of defense.

    Returns
    ───────
    The (already lowercase) username string on success.

    Raises
    ──────
    ValueError with a safe, non-leaking message on any failure.
    """
    if not isinstance(raw, str):
        raise ValueError("linux_username must be a string")

    username = raw.strip().lower()

    if not username:
        raise ValueError("linux_username must not be empty")

    if len(username) > _LINUX_MAX:
        raise ValueError(
            f"linux_username must not exceed {_LINUX_MAX} characters"
        )

    if not _RE_LINUX_USERNAME.fullmatch(username):
        raise ValueError(
            "linux_username must start with a lowercase letter and contain "
            "only lowercase letters, digits, and underscores"
        )

    if username in RESERVED_SYSTEM_USERS:
        raise ValueError(
            f"linux_username {username!r} conflicts with a reserved system name"
        )

    return username
