from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import get_db
from core.security import rate_limit, require_dashboard_key
from db.models import Alert

router = APIRouter(dependencies=[Depends(require_dashboard_key), Depends(rate_limit)])


@router.get("/alerts")
async def get_alerts(
    limit: int = Query(20, ge=1, le=settings.MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
):
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
