import re
from typing import Callable, Awaitable

ALLOWED_ACTIONS: dict[str, dict] = {
    "nginx.reload": {"params": [], "validators": {}},
    "nginx.write_vhost": {
        "params": ["username", "domain", "config_content"],
        "validators": {
            "username": r"^[a-z0-9_]{1,32}$",
            "domain": r"^[a-z0-9.\-]{1,253}$",
        }
    },
    "nginx.delete_vhost": {
        "params": ["username", "domain"],
        "validators": {
            "username": r"^[a-z0-9_]{1,32}$",
            "domain": r"^[a-z0-9.\-]{1,253}$",
        }
    },
    "user.create": {
        "params": ["username", "uid", "shell"],
        "validators": {
            "username": r"^[a-z0-9_]{1,32}$",
            "shell": r"^/bin/(bash|sh|false|nologin)$",
        }
    },
    "user.delete": {
        "params": ["username"],
        "validators": {"username": r"^[a-z0-9_]{1,32}$"}
    },
    "user.fix_ownership": {
        "params": ["username"],
        "validators": {"username": r"^[a-z0-9_]{1,32}$"}
    },
    "cagefs.enable": {
        "params": ["username"],
        "validators": {"username": r"^[a-z0-9_]{1,32}$"}
    },
    "cagefs.disable": {
        "params": ["username"],
        "validators": {"username": r"^[a-z0-9_]{1,32}$"}
    },
    "cagefs.update_skeleton": {"params": [], "validators": {}},
    "cagefs.remount": {
        "params": ["username"],
        "validators": {"username": r"^[a-z0-9_]{1,32}$"}
    },
    "firewall.add_rule": {
        "params": ["ip", "action", "chain"],
        "validators": {
            "ip": r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$",
            "action": r"^(ACCEPT|DROP|REJECT)$",
            "chain": r"^(INPUT|OUTPUT|FORWARD)$",
        }
    },
    "firewall.delete_rule": {
        "params": ["rule_id"],
        "validators": {"rule_id": r"^\d+$"}
    },
    "firewall.list_rules": {"params": [], "validators": {}},
    "firewall.load_ruleset": {
        "params": ["rules"],
        "validators": {}
    },
    "ssl.issue": {
        "params": ["domain", "webroot"],
        "validators": {
            "domain": r"^[a-z0-9.\-]{1,253}$",
            "webroot": r"^/home/[a-z0-9_]{1,32}/public_html$",
        }
    },
    "ssl.renew": {
        "params": ["domain"],
        "validators": {"domain": r"^[a-z0-9.\-]{1,253}$"}
    },
    "ssl.get_expiry": {
        "params": ["domain"],
        "validators": {"domain": r"^[a-z0-9.\-]{1,253}$"}
    },
    "phpfpm.write_pool": {
        "params": ["username", "php_version", "config_content"],
        "validators": {
            "username": r"^[a-z0-9_]{1,32}$",
            "php_version": r"^(7\.4|8\.[0-3])$",
        }
    },
    "phpfpm.reload": {
        "params": ["version"],
        "validators": {"version": r"^(7\.4|8\.[0-3])$"}
    },
}


class CommandValidator:
    def __init__(self):
        from handlers import nginx, user, firewall, cagefs, ssl, phpfpm
        self._handlers: dict[str, Callable] = {
            "nginx.reload":        nginx.reload,
            "nginx.write_vhost":   nginx.write_vhost,
            "nginx.delete_vhost":  nginx.delete_vhost,
            "user.create":         user.create,
            "user.delete":         user.delete,
            "user.fix_ownership":  user.fix_ownership,
            "cagefs.enable":       cagefs.enable,
            "cagefs.disable":      cagefs.disable,
            "cagefs.update_skeleton": cagefs.update_skeleton,
            "cagefs.remount":      cagefs.remount,
            "firewall.add_rule":   firewall.add_rule,
            "firewall.delete_rule": firewall.delete_rule,
            "firewall.list_rules": firewall.list_rules,
            "firewall.load_ruleset": firewall.load_ruleset,
            "ssl.issue":           ssl.issue,
            "ssl.renew":           ssl.renew,
            "ssl.get_expiry":      ssl.get_expiry,
            "phpfpm.write_pool":   phpfpm.write_pool,
            "phpfpm.reload":       phpfpm.reload,
        }

    def is_allowed(self, action: str, params: dict) -> bool:
        if action not in ALLOWED_ACTIONS:
            return False
        spec = ALLOWED_ACTIONS[action]
        for field, pattern in spec.get("validators", {}).items():
            value = params.get(field, "")
            if not re.fullmatch(pattern, str(value)):
                return False
        return True

    def get_handler(self, action: str) -> Callable:
        return self._handlers[action]
