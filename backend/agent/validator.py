"""
Agent command allowlist validator.

Every action the privileged agent may execute must be registered here with:
  - "params"     : list of accepted param keys (extras are rejected)
  - "validators" : per-field regex patterns (fullmatch required)

The validator is initialized once at agent startup (not per-request).
"""
import re
from typing import Callable

# ---------------------------------------------------------------------------
# Shared patterns — defined once, reused across entries
# ---------------------------------------------------------------------------

_RE_USERNAME  = r"^[a-z0-9_]{1,32}$"
_RE_DOMAIN    = r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
_RE_PHP_VER   = r"^(7\.4|8\.[0-3])$"
_RE_IP_CIDR   = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
_RE_FW_ACTION = r"^(ACCEPT|DROP|REJECT)$"
_RE_FW_CHAIN  = r"^(INPUT|OUTPUT|FORWARD)$"
_RE_RULE_ID   = r"^\d+$"
_RE_SHELL     = r"^/bin/(bash|sh|false|nologin)$"
_RE_WEBROOT   = r"^/home/[a-z0-9_]{1,32}/public_html$"

# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

ALLOWED_ACTIONS: dict[str, dict] = {

    # -- Domain (static site) provisioning ------------------------------------
    "nginx.create_domain": {
        "params": ["domain", "username"],
        "validators": {
            "domain":   _RE_DOMAIN,
            "username": _RE_USERNAME,
        },
        # Reject any extra keys — no undeclared params reach the handler
        "strict_params": True,
    },
    "nginx.delete_domain": {
        "params": ["domain", "username"],
        "validators": {
            "domain":   _RE_DOMAIN,
            "username": _RE_USERNAME,
        },
        "strict_params": True,
    },

    # -- Nginx config management (PHP/CMS flow) --------------------------------
    "nginx.reload": {
        "params": [],
        "validators": {},
    },
    "nginx.write_vhost": {
        "params": ["username", "domain", "config_content"],
        "validators": {
            "username": _RE_USERNAME,
            "domain":   _RE_DOMAIN,
            # config_content is large and validated structurally by the
            # nginx -t step in the handler; no regex here
        },
    },
    "nginx.delete_vhost": {
        "params": ["username", "domain"],
        "validators": {
            "username": _RE_USERNAME,
            "domain":   _RE_DOMAIN,
        },
        "strict_params": True,
    },

    # -- System user management -----------------------------------------------
    "user.create": {
        "params": ["username", "uid", "shell"],
        "validators": {
            "username": _RE_USERNAME,
            "shell":    _RE_SHELL,
        },
    },
    "user.delete": {
        "params": ["username"],
        "validators": {"username": _RE_USERNAME},
        "strict_params": True,
    },
    "user.fix_ownership": {
        "params": ["username"],
        "validators": {"username": _RE_USERNAME},
        "strict_params": True,
    },

    # -- CageFS ----------------------------------------------------------------
    "cagefs.enable": {
        "params": ["username"],
        "validators": {"username": _RE_USERNAME},
        "strict_params": True,
    },
    "cagefs.disable": {
        "params": ["username"],
        "validators": {"username": _RE_USERNAME},
        "strict_params": True,
    },
    "cagefs.update_skeleton": {"params": [], "validators": {}},
    "cagefs.remount": {
        "params": ["username"],
        "validators": {"username": _RE_USERNAME},
        "strict_params": True,
    },

    # -- Firewall --------------------------------------------------------------
    "firewall.add_rule": {
        "params": ["ip", "action", "chain"],
        "validators": {
            "ip":     _RE_IP_CIDR,
            "action": _RE_FW_ACTION,
            "chain":  _RE_FW_CHAIN,
        },
        "strict_params": True,
    },
    "firewall.delete_rule": {
        "params": ["rule_id"],
        "validators": {"rule_id": _RE_RULE_ID},
        "strict_params": True,
    },
    "firewall.list_rules":   {"params": [], "validators": {}},
    "firewall.load_ruleset": {"params": ["rules"], "validators": {}},

    # -- SSL / Certbot ---------------------------------------------------------
    "ssl.issue": {
        "params": ["domain", "webroot"],
        "validators": {
            "domain":  _RE_DOMAIN,
            "webroot": _RE_WEBROOT,
        },
        "strict_params": True,
    },
    "ssl.renew": {
        "params": ["domain"],
        "validators": {"domain": _RE_DOMAIN},
        "strict_params": True,
    },
    "ssl.get_expiry": {
        "params": ["domain"],
        "validators": {"domain": _RE_DOMAIN},
        "strict_params": True,
    },

    # -- PHP-FPM ---------------------------------------------------------------
    "phpfpm.write_pool": {
        "params": ["username", "php_version", "config_content"],
        "validators": {
            "username":    _RE_USERNAME,
            "php_version": _RE_PHP_VER,
        },
    },
    "phpfpm.reload": {
        "params": ["version"],
        "validators": {"version": _RE_PHP_VER},
        "strict_params": True,
    },
}


# ---------------------------------------------------------------------------
# Validator class
# ---------------------------------------------------------------------------

class CommandValidator:
    def __init__(self) -> None:
        from handlers import nginx, user, firewall, cagefs, ssl, phpfpm
        self._handlers: dict[str, Callable] = {
            # Domain
            "nginx.create_domain":   nginx.create_domain,
            "nginx.delete_domain":   nginx.delete_domain,
            # Nginx config
            "nginx.reload":          nginx.reload,
            "nginx.write_vhost":     nginx.write_vhost,
            "nginx.delete_vhost":    nginx.delete_vhost,
            # Users
            "user.create":           user.create,
            "user.delete":           user.delete,
            "user.fix_ownership":    user.fix_ownership,
            # CageFS
            "cagefs.enable":         cagefs.enable,
            "cagefs.disable":        cagefs.disable,
            "cagefs.update_skeleton": cagefs.update_skeleton,
            "cagefs.remount":        cagefs.remount,
            # Firewall
            "firewall.add_rule":     firewall.add_rule,
            "firewall.delete_rule":  firewall.delete_rule,
            "firewall.list_rules":   firewall.list_rules,
            "firewall.load_ruleset": firewall.load_ruleset,
            # SSL
            "ssl.issue":             ssl.issue,
            "ssl.renew":             ssl.renew,
            "ssl.get_expiry":        ssl.get_expiry,
            # PHP-FPM
            "phpfpm.write_pool":     phpfpm.write_pool,
            "phpfpm.reload":         phpfpm.reload,
        }

    def is_allowed(self, action: str, params: dict) -> bool:
        """
        Return True only if:
          1. action is in the allowlist
          2. all declared validators pass (fullmatch)
          3. when strict_params=True, no undeclared keys exist in params
        """
        if action not in ALLOWED_ACTIONS:
            return False

        spec = ALLOWED_ACTIONS[action]

        # Strict param check — reject extra keys when declared
        if spec.get("strict_params") and isinstance(params, dict):
            allowed_keys = set(spec.get("params", []))
            extra = set(params.keys()) - allowed_keys
            if extra:
                return False

        # Field-level regex validation
        for field, pattern in spec.get("validators", {}).items():
            value = params.get(field, "")
            if not re.fullmatch(pattern, str(value)):
                return False

        return True

    def get_handler(self, action: str) -> Callable:
        return self._handlers[action]
