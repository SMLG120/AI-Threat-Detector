from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from db.models import RequestLog, Alert
from core.database import get_db
from datetime import datetime, timedelta

router = APIRouter()


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)

    total = await db.scalar(select(func.count()).select_from(RequestLog))
    malicious = await db.scalar(
        select(func.count()).select_from(RequestLog).where(RequestLog.is_malicious == True)
    )
    recent = await db.scalar(
        select(func.count()).select_from(RequestLog).where(RequestLog.timestamp >= last_24h)
    )
    avg_score = await db.scalar(select(func.avg(RequestLog.threat_score)).select_from(RequestLog))
    high_threats = await db.scalar(
        select(func.count()).select_from(RequestLog).where(RequestLog.threat_level == "HIGH")
    )

    # Attack type distribution
    result = await db.execute(
        select(RequestLog.attack_types).where(RequestLog.is_malicious == True).limit(500)
    )
    attack_counts: dict = {}
    for row in result.scalars():
        if row:
            for attack in row:
                attack_counts[attack] = attack_counts.get(attack, 0) + 1

    return {
        "total_requests": total or 0,
        "malicious_count": malicious or 0,
        "requests_24h": recent or 0,
        "avg_threat_score": round(float(avg_score or 0), 4),
        "high_threat_count": high_threats or 0,
        "block_rate": round((malicious or 0) / max(total or 1, 1) * 100, 2),
        "attack_distribution": attack_counts,
    }
