import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from loguru import logger
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.redis_client import redis_client
from core.security import rate_limit, require_dashboard_key
from db.models import RequestLog

router = APIRouter(dependencies=[Depends(require_dashboard_key), Depends(rate_limit)])

STATS_CACHE_KEY = "cache:dashboard:stats"
STATS_CACHE_TTL = 10  # seconds — many dashboards polling share one DB query


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    try:
        cached = await redis_client.get(STATS_CACHE_KEY)
        if cached:
            return json.loads(cached)
    except Exception as e:
        logger.warning(f"Stats cache read failed: {e}")

    last_24h = datetime.now(timezone.utc) - timedelta(hours=24)

    # One table scan instead of five separate COUNT queries
    row = (
        await db.execute(
            select(
                func.count(),
                func.count().filter(RequestLog.is_malicious),
                func.count().filter(RequestLog.timestamp >= last_24h),
                func.avg(RequestLog.threat_score),
                func.sum(case((RequestLog.threat_level == "HIGH", 1), else_=0)),
            ).select_from(RequestLog)
        )
    ).one()
    total, malicious, recent, avg_score, high_threats = row

    # Attack type distribution (most recent 500 malicious requests)
    result = await db.execute(
        select(RequestLog.attack_types)
        .where(RequestLog.is_malicious)
        .order_by(RequestLog.timestamp.desc())
        .limit(500)
    )
    attack_counts: dict = {}
    for types in result.scalars():
        for attack in types or []:
            attack_counts[attack] = attack_counts.get(attack, 0) + 1

    stats = {
        "total_requests": total or 0,
        "malicious_count": malicious or 0,
        "requests_24h": recent or 0,
        "avg_threat_score": round(float(avg_score or 0), 4),
        "high_threat_count": int(high_threats or 0),
        "block_rate": round((malicious or 0) / max(total or 1, 1) * 100, 2),
        "attack_distribution": attack_counts,
    }

    try:
        await redis_client.set(STATS_CACHE_KEY, json.dumps(stats), ex=STATS_CACHE_TTL)
    except Exception as e:
        logger.warning(f"Stats cache write failed: {e}")
    return stats
