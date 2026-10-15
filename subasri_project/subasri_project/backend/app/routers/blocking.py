from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from app.blocking.engine import blocking_engine
from app.schemas import BlockedIPOut, BlockIPRequest
from app.security import get_current_user
from app.websocket.manager import manager

router = APIRouter(tags=["blocking"])

@router.get("/blocked-ips", response_model=List[BlockedIPOut])
def get_blocked_ips(_user=Depends(get_current_user)):
    return blocking_engine.list_blocked_ips()

@router.post("/blocked-ips", response_model=BlockedIPOut)
async def block_ip_endpoint(payload: BlockIPRequest, user=Depends(get_current_user)):
    res = blocking_engine.block_ip(
        ip_address=payload.ip_address,
        reason=payload.reason or "Manual administrative block",
        attack_type=payload.attack_type or "manual",
        blocked_by=f"admin ({user.email})"
    )
    if not res:
        raise HTTPException(status_code=400, detail="Invalid IP or failed to block IP")

    # Broadcast real-time WebSocket event to all dashboard clients
    await manager.broadcast("ip_blocked", res)
    return res

@router.delete("/blocked-ips/{ip_address}")
async def unblock_ip_endpoint(ip_address: str, _user=Depends(get_current_user)):
    success = blocking_engine.unblock_ip(ip_address)
    if not success:
        raise HTTPException(status_code=404, detail="IP address not found or not active in blocklist")

    await manager.broadcast("ip_unblocked", {"ip_address": ip_address})
    return {"status": "unblocked", "ip_address": ip_address}
