import asyncio


async def enable(params: dict) -> dict:
    username = params["username"]
    proc = await asyncio.create_subprocess_exec(
        "cagefsctl", "--enable", username,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"cagefsctl enable failed: {stderr.decode()}")
    return {"enabled": True, "username": username}


async def disable(params: dict) -> dict:
    username = params["username"]
    proc = await asyncio.create_subprocess_exec(
        "cagefsctl", "--disable", username,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"cagefsctl disable failed: {stderr.decode()}")
    return {"disabled": True, "username": username}


async def update_skeleton(params: dict) -> dict:
    proc = await asyncio.create_subprocess_exec(
        "cagefsctl", "--force-update",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    return {"updated": True}


async def remount(params: dict) -> dict:
    username = params["username"]
    proc = await asyncio.create_subprocess_exec(
        "cagefsctl", "--remount", username,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"cagefsctl remount failed: {stderr.decode()}")
    return {"remounted": True}
