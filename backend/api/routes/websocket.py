from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from loguru import logger

from core.security import verify_dashboard_token
from core.websocket_manager import manager

router = APIRouter()


@router.websocket("/stream")
async def websocket_endpoint(websocket: WebSocket):
    # Browsers can't set custom headers on WebSocket connections, so the
    # dashboard key is passed as a query parameter (over TLS only).
    if not verify_dashboard_token(websocket.query_params.get("token")):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)
