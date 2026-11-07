"""
Celery tasks for async log processing.
Optional path for bulk/offline analysis: enqueue with
    celery_app.send_task("tasks.detection.process_log", args=[log_dict])
The real-time path is POST /api/logs/ingest.
"""
from loguru import logger

from core.celery_app import celery_app
from ml.model_manager import model_manager
from pipeline.detector import analyze_request_sync
from pipeline.feature_extractor import RawRequest


@celery_app.task(name="tasks.detection.process_log", bind=True, max_retries=3)
def process_log_task(self, log_data: dict) -> dict:
    """Run the full detection pipeline for one raw log entry."""
    try:
        if not model_manager.is_ready:
            model_manager.load_models(bootstrap_if_missing=False)
        result = analyze_request_sync(RawRequest(**log_data))
        return {
            "threat_score": result.threat_score,
            "threat_level": result.threat_level,
            "is_malicious": result.is_malicious,
            "attack_types": result.attack_types,
            "rule_score": result.rule_score,
            "isolation_forest_score": result.isolation_forest_score,
            "random_forest_score": result.random_forest_score,
        }
    except Exception as exc:
        logger.error(f"Detection task failed: {exc}")
        raise self.retry(exc=exc, countdown=2**self.request.retries)
