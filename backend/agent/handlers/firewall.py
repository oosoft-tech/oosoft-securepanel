import asyncio
import json


async def add_rule(params: dict) -> dict:
    ip = params["ip"]
    action = params["action"]
    chain = params["chain"]

    proc = await asyncio.create_subprocess_exec(
        "nft", "add", "element", "inet", "securepanel", "blocklist",
        f"{{ {ip} }}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"nft error: {stderr.decode()}")
    return {"ip": ip, "action": action, "added": True}


async def delete_rule(params: dict) -> dict:
    rule_id = params["rule_id"]
    proc = await asyncio.create_subprocess_exec(
        "nft", "delete", "rule", "inet", "securepanel", "input_filter",
        "handle", rule_id,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"nft delete error: {stderr.decode()}")
    return {"deleted": True, "rule_id": rule_id}


async def list_rules(params: dict) -> dict:
    proc = await asyncio.create_subprocess_exec(
        "nft", "-j", "list", "table", "inet", "securepanel",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"nft list error: {stderr.decode()}")
    return {"rules": json.loads(stdout.decode())}


async def load_ruleset(params: dict) -> dict:
    rules = params["rules"]
    proc = await asyncio.create_subprocess_exec(
        "nft", "-f", "-",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate(input=rules.encode())
    if proc.returncode != 0:
        raise RuntimeError(f"nft ruleset load error: {stderr.decode()}")
    return {"loaded": True}
