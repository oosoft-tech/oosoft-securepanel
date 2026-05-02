"""
Firewall handler (nftables).
All subprocess calls routed through utils.exec.run_command().
"""
import json
import logging

from utils.exec import run_command, CommandError

logger = logging.getLogger(__name__)


async def add_rule(params: dict) -> dict:
    ip     = params["ip"]
    action = params["action"]
    chain  = params["chain"]

    # nft set element syntax: "{ 1.2.3.4 }"
    # Each token is a separate list element — NO shell interpolation possible
    try:
        await run_command([
            "nft", "add", "element",
            "inet", "securepanel", "blocklist",
            "{", ip, "}",
        ])
    except CommandError as exc:
        logger.error("nft add_rule failed rc=%d", exc.result.returncode)
        raise RuntimeError("Failed to add firewall rule") from exc

    logger.info("Firewall rule added: ip=%s action=%s chain=%s", ip, action, chain)
    return {"ip": ip, "action": action, "added": True}


async def delete_rule(params: dict) -> dict:
    rule_id = params["rule_id"]

    try:
        await run_command([
            "nft", "delete", "rule",
            "inet", "securepanel", "input_filter",
            "handle", rule_id,
        ])
    except CommandError as exc:
        logger.error("nft delete_rule failed rc=%d", exc.result.returncode)
        raise RuntimeError("Failed to delete firewall rule") from exc

    logger.info("Firewall rule deleted: rule_id=%s", rule_id)
    return {"deleted": True, "rule_id": rule_id}


async def list_rules(params: dict) -> dict:
    try:
        result = await run_command([
            "nft", "-j", "list", "table", "inet", "securepanel",
        ])
    except CommandError as exc:
        logger.error("nft list_rules failed rc=%d", exc.result.returncode)
        raise RuntimeError("Failed to list firewall rules") from exc

    try:
        rules = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        logger.error("nft output is not valid JSON: %s", exc)
        raise RuntimeError("Failed to parse firewall rules") from exc

    return {"rules": rules}


async def load_ruleset(params: dict) -> dict:
    rules = params["rules"]

    try:
        await run_command(
            ["nft", "-f", "-"],
            stdin_data=rules.encode("utf-8"),
        )
    except CommandError as exc:
        logger.error("nft load_ruleset failed rc=%d", exc.result.returncode)
        raise RuntimeError("Failed to load nftables ruleset") from exc

    logger.info("nftables ruleset loaded successfully")
    return {"loaded": True}
