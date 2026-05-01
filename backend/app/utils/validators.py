"""
Domain and input validation utilities.

All validation is done with compiled regexes and explicit rules — no
external libraries required. Every function either returns a clean,
normalised value or raises ValueError with a safe (non-leaking) message.
"""
import re

# ---------------------------------------------------------------------------
# Compiled patterns — defined once at module load
# ---------------------------------------------------------------------------

# RFC 1123 label: 1-63 chars, alphanumeric or hyphen, cannot start/end with hyphen
_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"

# Full domain: one or more labels separated by dots, TLD at least 2 chars
_DOMAIN_RE = re.compile(
    r"^(?:" + _LABEL + r"\.)+" + r"[a-zA-Z]{2,63}$"
)

# Explicitly block patterns that should never appear in a domain string
# even if the regex above somehow passed them.
_DOMAIN_BLOCKLIST = re.compile(
    r"(\.\.|//|\\|@|%|&|\$|;|`|'|\"|\s|\x00)"
)

# Maximum allowed domain length (RFC 1035: 253 chars for full name)
_DOMAIN_MAX_LEN = 253

# Labels that are localhost-equivalent or reserved — reject them
_RESERVED_NAMES = frozenset({
    "localhost", "localdomain", "local", "internal",
    "example", "example.com", "example.org", "example.net",
    "test", "invalid", "broadcasthost",
})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_domain(raw: str) -> str:
    """
    Validate and normalise a domain name.

    Returns the lowercase domain string on success.
    Raises ValueError with a safe message on any failure.

    Defense-in-depth: this runs in both the FastAPI layer (user input)
    and inside the privileged agent handler (before filesystem ops).
    """
    if not isinstance(raw, str):
        raise ValueError("Domain must be a string")

    domain = raw.strip().lower()

    if not domain:
        raise ValueError("Domain must not be empty")

    if len(domain) > _DOMAIN_MAX_LEN:
        raise ValueError(f"Domain exceeds maximum length of {_DOMAIN_MAX_LEN} characters")

    # Reject any blocklisted characters/sequences before regex matching
    if _DOMAIN_BLOCKLIST.search(domain):
        raise ValueError("Domain contains invalid characters")

    if not _DOMAIN_RE.fullmatch(domain):
        raise ValueError("Domain does not match required format")

    # Reject reserved / test names
    if domain in _RESERVED_NAMES:
        raise ValueError("Domain name is reserved and cannot be used")

    # Reject individual labels that are too long (RFC 1123)
    for label in domain.split("."):
        if len(label) > 63:
            raise ValueError("Domain label exceeds 63 characters")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError("Domain labels must not start or end with a hyphen")

    return domain


def validate_username(raw: str) -> str:
    """
    Validate a system username.
    Returns the username on success, raises ValueError on failure.
    """
    if not isinstance(raw, str):
        raise ValueError("Username must be a string")

    username = raw.strip().lower()

    if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", username):
        raise ValueError("Invalid username format")

    return username
