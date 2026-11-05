import json

import redis.asyncio as aioredis
from loguru import logger

from core.config import settings

# Pub/sub channels
EVENTS_CHANNEL = "aiwaf:events"          # dashboard events, fanned out to every API worker
MODELS_CHANNEL = "aiwaf:models_updated"  # tells API workers to reload models from disk


class RedisClient:
    def __init__(self):
        self.client: aioredis.Redis | None = None

    async def connect(self):
        self.client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            health_check_interval=30,
        )
        await self.client.ping()
        logger.info("Redis connection established")

    async def disconnect(self):
        if self.client:
            await self.client.aclose()

    async def ping(self) -> bool:
        try:
            return bool(self.client and await self.client.ping())
        except Exception:
            return False

    async def publish(self, channel: str, data: dict):
        await self.client.publish(channel, json.dumps(data))

    def pubsub(self):
        return self.client.pubsub()

    async def get(self, key: str):
        return await self.client.get(key)

    async def set(self, key: str, value: str, ex: int | None = None):
        await self.client.set(key, value, ex=ex)

    async def incr(self, key: str):
        return await self.client.incr(key)

    async def expire(self, key: str, seconds: int):
        await self.client.expire(key, seconds)


redis_client = RedisClient()
