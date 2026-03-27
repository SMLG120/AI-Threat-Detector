"""
Celery tasks for async log processing.
Used by the worker container to process logs from the Redis queue.
"""
import asyncio
from core.celery_app import celery_app
from pipeline.feature_extractor import RawRequest
from pipeline.detector import analyze_request
from loguru import logger


@celery_app.task(name="tasks.detection.process_log", bind=True, max_retries=3)
def process_log_task(self, log_data: dict) -> dict:
    """
    Process a raw log entry asynchronously.
    Runs the full detection pipeline and returns results.
    """
    try:
        raw = RawRequest(**log_data)
        result = asyncio.get_event_loop().run_until_complete(analyze_request(raw))
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
