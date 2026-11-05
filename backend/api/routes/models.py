from fastapi import APIRouter, Depends
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import rate_limit, require_dashboard_key
from db.models import ModelMetadata
from ml.model_manager import model_manager

router = APIRouter(dependencies=[Depends(require_dashboard_key), Depends(rate_limit)])


@router.post("/retrain")
async def retrain_models():
    """Queue a retraining job on the Celery worker (uses human-verified labels only)."""
    from tasks.retrain import retrain_models as retrain_task

    job = retrain_task.delay()
    return {"status": "retraining_queued", "task_id": job.id}


@router.get("/status")
async def model_status(db: AsyncSession = Depends(get_db)):
    latest = (
        await db.execute(
            select(ModelMetadata)
            .where(ModelMetadata.is_active)
            .order_by(desc(ModelMetadata.trained_at))
            .limit(1)
        )
    ).scalar_one_or_none()
    return {
        "models_ready": model_manager.is_ready,
        "loaded_version": model_manager.version,
        "models": ["isolation_forest", "random_forest"],
        "latest_training": (
            {
                "version": latest.version,
                "trained_at": latest.trained_at.isoformat() if latest.trained_at else None,
                "accuracy": latest.accuracy,
                "samples_used": latest.samples_used,
                "metrics": latest.model_metadata,
            }
            if latest
            else None
        ),
    }
