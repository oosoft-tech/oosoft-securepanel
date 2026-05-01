from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.dependencies import require_admin
from app.services.firewall_manager import FirewallManager
from app.ai.firewall_advisor import FirewallAdvisor

router = APIRouter()


class BlockIPRequest(BaseModel):
    ip: str
    reason: str = ""
    duration_hours: int = 24


class UnblockRequest(BaseModel):
    rule_id: str


@router.get("/rules")
async def list_rules(admin=Depends(require_admin)):
    fw = FirewallManager()
    return await fw.list_rules()


@router.post("/block")
async def block_ip(request: BlockIPRequest, admin=Depends(require_admin)):
    fw = FirewallManager()
    try:
        result = await fw.block_ip(request.ip, request.reason, request.duration_hours)
        return {"detail": f"Blocked {request.ip}", "result": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/rules/{rule_id}")
async def unblock_rule(rule_id: str, admin=Depends(require_admin)):
    fw = FirewallManager()
    try:
        result = await fw.unblock_ip(rule_id)
        return {"detail": "Rule deleted", "result": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/auto-detect")
async def auto_detect_brute_force(admin=Depends(require_admin)):
    fw = FirewallManager()
    blocked = await fw.auto_block_brute_force()
    return {"blocked": blocked, "count": len(blocked)}


@router.get("/suggestions")
async def get_firewall_suggestions(admin=Depends(require_admin)):
    advisor = FirewallAdvisor()
    try:
        with open("/var/log/nginx/access.log") as f:
            access_lines = f.readlines()[-5000:]
        with open("/var/log/auth.log") as f:
            auth_lines = f.readlines()[-5000:]
    except FileNotFoundError:
        access_lines, auth_lines = [], []

    suggestions = advisor.analyze(access_lines, auth_lines)
    return {
        "suggestions": [
            {
                "ip": s.ip,
                "reason": s.reason,
                "confidence": s.confidence,
                "rule_type": s.rule_type,
            }
            for s in suggestions
        ]
    }
