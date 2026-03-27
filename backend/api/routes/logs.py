"""
Log ingestion API — accepts HTTP request logs and runs detection.
"""
from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from typing import Optional, List
from loguru import logger
from datetime import datetime, timezone

from core.database import get_db, AsyncSessionLocal
from core.websocket_manager import manager
from pipeline.feature_extractor import RawRequest
from pipeline.detector import analyze_request
from db.models import RequestLog, Alert

router = APIRouter()


class LogIngestRequest(BaseModel):
    ip_address: str
    method: str
    url: str
    user_agent: Optional[str] = ""
    referer: Optional[str] = ""
    request_body: Optional[str] = ""
    status_code: Optional[int] = 200
    response_size: Optional[int] = 0
    headers: Optional[dict] = {}


class LogResponse(BaseModel):
    id: str
    threat_score: float
    threat_level: str
    is_malicious: bool
    attack_types: List[str]


@router.post("/ingest", response_model=LogResponse)
async def ingest_log(
    payload: LogIngestRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Ingest a single HTTP log entry and run detection."""
    raw = RawRequest(**payload.model_dump())
    result = await analyze_request(raw)

    now = datetime.now(timezone.utc)

    log_entry = RequestLog(
        ip_address=payload.ip_address,
        method=payload.method,
        url=payload.url,
        path=payload.url.split("?")[0],
        query_string=payload.url.split("?")[1] if "?" in payload.url else "",
        user_agent=payload.user_agent,
        referer=payload.referer,
        status_code=payload.status_code,
        response_size=payload.response_size,
        request_body=payload.request_body,
        headers=payload.headers,
        threat_score=result.threat_score,
        threat_level=result.threat_level,
        is_malicious=result.is_malicious,
        attack_types=result.attack_types,
        rule_score=result.rule_score,
        isolation_forest_score=result.isolation_forest_score,
        random_forest_score=result.random_forest_score,
        autoencoder_score=result.autoencoder_score,
        features=result.features,
    )

    db.add(log_entry)
    await db.commit()
    await db.refresh(log_entry)

    ts = log_entry.timestamp or now
    ts.isoformat()
    log_id = str(log_entry.id)

    ws_payload = {
        "type": "new_request",
        "data": {
            "id": log_id,
            "timestamp": ts.isoformat(),
            "ip_address": payload.ip_address,
            "method": payload.method,
            "url": payload.url[:120],
            "threat_score": result.threat_score,
            "threat_level": result.threat_level,
            "is_malicious": result.is_malicious,
            "attack_types": result.attack_types,
        },
    }
    background_tasks.add_task(manager.broadcast, ws_payload)

    # Background alert uses its OWN session — never reuse the request session
    if result.is_malicious:
        background_tasks.add_task(
            _create_alert_background,
            log_id,
            payload.ip_address,
            result.threat_level,
            result.threat_score,
            result.attack_types,
        )

    return LogResponse(
        id=log_id,
        threat_score=result.threat_score,
        threat_level=result.threat_level,
        is_malicious=result.is_malicious,
        attack_types=result.attack_types,
    )


async def _create_alert_background(
    log_id: str,
    ip_address: str,
    threat_level: str,
    threat_score: float,
    attack_types: list,
):
    """Background task with its own fresh DB session."""
    try:
        import uuid
        async with AsyncSessionLocal() as db:
            alert = Alert(
                log_id=uuid.UUID(log_id),
                ip_address=ip_address,
                threat_level=threat_level,
                threat_score=threat_score,
                attack_types=attack_types,
                message=f"Threat detected: {', '.join(attack_types)} from {ip_address}",
            )
            db.add(alert)
            await db.commit()

        await manager.broadcast({
            "type": "alert",
            "data": {
                "ip_address": ip_address,
                "threat_level": threat_level,
                "threat_score": threat_score,
                "attack_types": attack_types,
            },
        })
    except Exception as e:
        logger.error(f"Failed to create alert: {e}")


@router.get("/")
async def list_logs(
    page: int = 1,
    limit: int = 50,
    threat_level: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(RequestLog).order_by(desc(RequestLog.timestamp))
    if threat_level:
        query = query.where(RequestLog.threat_level == threat_level.upper())
    query = query.offset((page - 1) * limit).limit(limit)
    result = await db.execute(query)
    logs = result.scalars().all()
    return {"logs": [_serialize_log(l) for l in logs]}


def _serialize_log(log: RequestLog) -> dict:
    return {
        "id": str(log.id),
        "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        "ip_address": log.ip_address,
        "method": log.method,
        "url": log.url,
        "threat_score": log.threat_score,
        "threat_level": log.threat_level,
        "is_malicious": log.is_malicious,
        "attack_types": log.attack_types or [],
        "rule_score": log.rule_score,
        "random_forest_score": log.random_forest_score,
        "isolation_forest_score": log.isolation_forest_score,
    }