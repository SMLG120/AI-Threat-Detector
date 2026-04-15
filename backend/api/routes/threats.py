from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from db.models import Alert
from core.database import get_db

router = APIRouter()


@router.get("/alerts")
async def get_alerts(limit: int = 20, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Alert).order_by(desc(Alert.timestamp)).limit(limit)
    )
    alerts = result.scalars().all()
    return {
        "alerts": [
            {
                "id": str(a.id),
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "ip_address": a.ip_address,
                "threat_level": a.threat_level,
                "threat_score": a.threat_score,
                "attack_types": a.attack_types or [],
                "message": a.message,
                "acknowledged": a.acknowledged,
            }
            for a in alerts
        ]
    }
