"""
Authentication and rate limiting.

Two API keys:
  - INGEST_API_KEY    → log shippers (POST /api/logs/ingest only)
  - DASHBOARD_API_KEY → dashboard / operators (read endpoints, retrain, labeling, WebSocket)
"""
import secrets
import time

from fastapi import Header, HTTPException, Request, status
from loguru import logger

from core.config import settings
from core.redis_client import redis_client


def _matches(provided: str | None, expected: str) -> bool:
    if not provided:
        return False
    return secrets.compare_digest(provided.encode(), expected.encode())


def verify_dashboard_token(token: str | None) -> bool:
    return _matches(token, settings.DASHBOARD_API_KEY)


async def require_dashboard_key(x_api_key: str | None = Header(default=None)):
    if not verify_dashboard_token(x_api_key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key")


async def require_ingest_key(x_api_key: str | None = Header(default=None)):
    if not _matches(x_api_key, settings.INGEST_API_KEY):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key")


def _client_ip(request: Request) -> str:
    # Uvicorn's proxy-headers support (FORWARDED_ALLOW_IPS) already resolves
    # X-Forwarded-For from the trusted reverse proxy into request.client.
    return request.client.host if request.client else "unknown"


async def _check_rate(bucket: str, request: Request, limit: int):
    window = int(time.time() // 60)
    key = f"ratelimit:{bucket}:{_client_ip(request)}:{window}"
    try:
        count = await redis_client.incr(key)
        if count == 1:
            await redis_client.expire(key, 70)
    except Exception as e:  # fail open if Redis is briefly unavailable
        logger.warning(f"Rate limiter unavailable: {e}")
        return
    if count > limit:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Rate limit exceeded",
            headers={"Retry-After": "60"},
        )


async def rate_limit(request: Request):
    await _check_rate("api", request, settings.RATE_LIMIT_PER_MINUTE)


async def ingest_rate_limit(request: Request):
    await _check_rate("ingest", request, settings.INGEST_RATE_LIMIT_PER_MINUTE)
