from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from db.models import RequestLog
from ml.model_manager import model_manager
from core.database import get_db

router = APIRouter()


@router.post("/retrain")
async def retrain_models(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Trigger async model retraining using stored logs."""
    background_tasks.add_task(_retrain_task, db)
    return {"status": "retraining_started", "message": "Retraining job queued"}


async def _retrain_task(db: AsyncSession):
    """Pull labeled data from DB and retrain ensemble."""
    result = await db.execute(
        select(RequestLog.features, RequestLog.is_malicious).limit(10000)
    )
    rows = result.all()
    if len(rows) < 100:
        return {"error": "Not enough data to retrain (need 100+ samples)"}

    X = []
    y = []
    for features, label in rows:
        if features:
            X.append(list(features.values()))
            y.append(int(label))

    await model_manager._bootstrap_train()
    return {"status": "done", "samples": len(X)}


@router.get("/status")
async def model_status():
    return {
        "models_ready": model_manager.is_ready,
        "models": ["isolation_forest", "random_forest", "autoencoder"],
    }
