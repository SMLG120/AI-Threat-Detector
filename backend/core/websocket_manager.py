"""
WebSocket connection manager.

Each API worker process holds only its own sockets, so events are published to
Redis and every worker relays them to its local clients. This keeps the
dashboard consistent when running multiple gunicorn workers / replicas.
"""
import asyncio
import json
from typing import Set

from fastapi import WebSocket
from loguru import logger

from core.redis_client import EVENTS_CHANNEL, MODELS_CHANNEL, redis_client


class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WS client connected. Local total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(f"WS client disconnected. Local total: {len(self.active_connections)}")

    async def broadcast(self, data: dict):
        """Publish an event to all workers (and therefore all connected clients)."""
        try:
            await redis_client.publish(EVENTS_CHANNEL, data)
        except Exception as e:
            logger.error(f"Failed to publish WS event: {e}")

    async def _send_local(self, message: str):
        dead = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception:
                dead.append(connection)
        for conn in dead:
            self.active_connections.discard(conn)

    async def send_personal(self, websocket: WebSocket, data: dict):
        await websocket.send_text(json.dumps(data))


manager = ConnectionManager()


async def run_pubsub_listener(on_models_updated):
    """
    Long-running task (one per worker): relay dashboard events to local sockets
    and trigger model reloads. Reconnects automatically if Redis drops.
    """
    while True:
        pubsub = redis_client.pubsub()
        try:
            await pubsub.subscribe(EVENTS_CHANNEL, MODELS_CHANNEL)
            async for msg in pubsub.listen():
                if msg.get("type") != "message":
                    continue
                if msg["channel"] == EVENTS_CHANNEL:
                    await manager._send_local(msg["data"])
                elif msg["channel"] == MODELS_CHANNEL:
                    await on_models_updated()
        except asyncio.CancelledError:
            await pubsub.aclose()
            raise
        except Exception as e:
            logger.error(f"Pub/sub listener error, reconnecting in 2s: {e}")
            await asyncio.sleep(2)
        finally:
            try:
                await pubsub.aclose()
            except Exception:
                pass
