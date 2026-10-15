from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.websocket.manager import manager

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Client doesn't need to send anything; keep the connection open
            # and drain any pings so the socket doesn't get closed as idle.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
