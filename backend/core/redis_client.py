import redis.asyncio as aioredis
from core.config import settings
from loguru import logger
import json


class RedisClient:
    def __init__(self):
        self.client: aioredis.Redis | None = None

    async def connect(self):
        self.client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        await self.client.ping()
        logger.info("Redis connection established")

    async def disconnect(self):
        if self.client:
            await self.client.aclose()

    async def publish(self, channel: str, data: dict):
        await self.client.publish(channel, json.dumps(data))

    async def lpush(self, key: str, value: str):
        await self.client.lpush(key, value)

    async def brpop(self, key: str, timeout: int = 1):
        return await self.client.brpop(key, timeout=timeout)

    async def get(self, key: str):
        return await self.client.get(key)

    async def set(self, key: str, value: str, ex: int = None):
        await self.client.set(key, value, ex=ex)

    async def incr(self, key: str):
        return await self.client.incr(key)

    async def expire(self, key: str, seconds: int):
        await self.client.expire(key, seconds)


redis_client = RedisClient()
