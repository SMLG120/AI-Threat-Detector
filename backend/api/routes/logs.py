"""
Log ingestion API — accepts HTTP request logs and runs detection.
"""
import uuid
from datetime import datetime, timezone
from typing import List, Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import get_db
from core.security import (
    ingest_rate_limit,
    rate_limit,
    require_dashboard_key,
    require_ingest_key,
)
from core.websocket_manager import manager
from db.models import Alert, RequestLog
from pipeline.detector import analyze_request
from pipeline.feature_extractor import RawRequest

router = APIRouter()

MAX_HEADERS = 100
MAX_HEADER_VALUE = 8192


class LogIngestRequest(BaseModel):
    ip_address: str = Field(max_length=45)
    method: str = Field(max_length=10)
    url: str = Field(max_length=8192)
    user_agent: Optional[str] = Field(default="", max_length=2048)
    referer: Optional[str] = Field(default="", max_length=8192)
    request_body: Optional[str] = Field(default="", max_length=65536)
    status_code: Optional[int] = Field(default=200, ge=100, le=599)
    response_size: Optional[int] = Field(default=0, ge=0)
    headers: Optional[dict] = Field(default_factory=dict)

    @field_validator("headers")
    @classmethod
    def _limit_headers(cls, v: Optional[dict]) -> dict:
        v = v or {}
        if len(v) > MAX_HEADERS:
            raise ValueError(f"At most {MAX_HEADERS} headers allowed")
        for k, val in v.items():
            if len(str(k)) > 256 or len(str(val)) > MAX_HEADER_VALUE:
                raise ValueError("Header name/value too long")
        return v


class LogResponse(BaseModel):
    id: str
    threat_score: float
    threat_level: str
    is_malicious: bool
    attack_types: List[str]


class LabelRequest(BaseModel):
    is_malicious: bool


@router.post(
    "/ingest",
    response_model=LogResponse,
    dependencies=[Depends(require_ingest_key), Depends(ingest_rate_limit)],
)
async def ingest_log(
    payload: LogIngestRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Ingest a single HTTP log entry and run detection."""
    raw = RawRequest(**payload.model_dump())
    result = await analyze_request(raw)

    log_id = uuid.uuid4()
    log_entry = RequestLog(
        id=log_id,
        ip_address=payload.ip_address,
        method=payload.method,
        url=payload.url,
        path=payload.url.split("?")[0],
        query_string=payload.url.split("?", 1)[1] if "?" in payload.url else "",
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

    # Alert is written in the same transaction — no orphaned/lost alerts.
    # Flush first so the request_logs row exists before the FK'd alert insert.
    if result.is_malicious:
        await db.flush()
        db.add(
            Alert(
                log_id=log_id,
                ip_address=payload.ip_address,
                threat_level=result.threat_level,
                threat_score=result.threat_score,
                attack_types=result.attack_types,
                message=f"Threat detected: {', '.join(result.attack_types) or 'anomaly'} "
                        f"from {payload.ip_address}",
            )
        )

    await db.commit()

    ts = datetime.now(timezone.utc).isoformat()
    background_tasks.add_task(
        manager.broadcast,
        {
            "type": "new_request",
            "data": {
                "id": str(log_id),
                "timestamp": ts,
                "ip_address": payload.ip_address,
                "method": payload.method,
                "url": payload.url[:120],
                "threat_score": result.threat_score,
                "threat_level": result.threat_level,
                "is_malicious": result.is_malicious,
                "attack_types": result.attack_types,
            },
        },
    )
    if result.is_malicious:
        background_tasks.add_task(
            manager.broadcast,
            {
                "type": "alert",
                "data": {
                    "ip_address": payload.ip_address,
                    "threat_level": result.threat_level,
                    "threat_score": result.threat_score,
                    "attack_types": result.attack_types,
                },
            },
        )

    return LogResponse(
        id=str(log_id),
        threat_score=result.threat_score,
        threat_level=result.threat_level,
        is_malicious=result.is_malicious,
        attack_types=result.attack_types,
    )


@router.get("/", dependencies=[Depends(require_dashboard_key), Depends(rate_limit)])
async def list_logs(
    page: int = Query(1, ge=1, le=10000),
    limit: int = Query(50, ge=1, le=settings.MAX_PAGE_SIZE),
    threat_level: Optional[Literal["LOW", "MEDIUM", "HIGH", "low", "medium", "high"]] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(RequestLog).order_by(desc(RequestLog.timestamp))
    if threat_level:
        query = query.where(RequestLog.threat_level == threat_level.upper())
    query = query.offset((page - 1) * limit).limit(limit)
    result = await db.execute(query)
    logs = result.scalars().all()
    return {"logs": [_serialize_log(log_item) for log_item in logs]}


@router.patch(
    "/{log_id}/label",
    dependencies=[Depends(require_dashboard_key), Depends(rate_limit)],
)
async def label_log(log_id: uuid.UUID, body: LabelRequest, db: AsyncSession = Depends(get_db)):
    """Record a human-verified label (confirm attack / mark false positive) for retraining."""
    log = await db.get(RequestLog, log_id)
    if log is None:
        raise HTTPException(404, "Log not found")
    log.verified_label = body.is_malicious
    log.labeled_at = datetime.now(timezone.utc)
    await db.commit()
    return {"id": str(log_id), "verified_label": log.verified_label}


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
        "verified_label": log.verified_label,
    }
