from core.celery_app import celery_app
from ml.model_manager import ModelManager
from core.database import get_db
from sqlalchemy import select
from db.models import RequestLog
import asyncio

@celery_app.task
def retrain_models():
    async def _retrain():
        async for db in get_db():
            # Fetch recent data
            result = await db.execute(select(RequestLog).order_by(RequestLog.timestamp.desc()).limit(1000))
            logs = result.scalars().all()
            if not logs:
                return
            
            # Extract features and labels
            features = [log.features for log in logs]  # Assume features are pre-extracted
            labels = [1 if log.is_malicious else 0 for log in logs]
            
            manager = ModelManager()
            await manager.load_models()  # Load existing
            await manager.train_models(features, labels)  # Retrain
            await manager._save_to_disk()  # Save updated models
            print("Models retrained")
    
    asyncio.run(_retrain())