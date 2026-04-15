from fastapi import WebSocket
from typing import List
import json
from loguru import logger


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WS client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(f"WS client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, data: dict):
        if not self.active_connections:
            return
        message = json.dumps(data)
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                dead.append(connection)
        for conn in dead:
            self.active_connections.remove(conn)

    async def send_personal(self, websocket: WebSocket, data: dict):
        await websocket.send_text(json.dumps(data))


manager = ConnectionManager()
