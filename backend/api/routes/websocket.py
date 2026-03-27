from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from core.websocket_manager import manager

router = APIRouter()


@router.websocket("/stream")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo for ping/pong keepalive
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
