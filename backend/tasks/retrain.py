"""
Model retraining task.

Trains ONLY on human-verified labels (RequestLog.verified_label). Training on
the model's own predictions would create a feedback loop that amplifies errors
and lets an attacker poison the model by flooding it with traffic.

A new model is promoted only if it beats the quality bar on a held-out set of
real, verified traffic and isn't worse than the currently deployed model.
"""
import asyncio
import json
from datetime import datetime, timezone

import numpy as np
import redis
from loguru import logger
from sqlalchemy import select

from core.celery_app import celery_app
from core.config import settings
from core.database import make_task_session_factory
from core.redis_client import MODELS_CHANNEL
from db.models import ModelMetadata, RequestLog
from ml.model_manager import ModelManager, fit_bundle, generate_synthetic_data, score_bundle
from pipeline.feature_extractor import features_dict_to_array

MAX_SAMPLES = 50_000
LOCK_KEY = "lock:retrain"


async def _load_verified_samples(session_factory):
    async with session_factory() as db:
        result = await db.execute(
            select(RequestLog.features, RequestLog.verified_label)
            .where(RequestLog.verified_label.is_not(None))
            .order_by(RequestLog.labeled_at.desc())
            .limit(MAX_SAMPLES)
        )
        rows = result.all()

    X, y = [], []
    for features, label in rows:
        if not features:
            continue
        try:
            X.append(features_dict_to_array(features))
            y.append(int(label))
        except (KeyError, TypeError, ValueError):
            continue  # stored with an older feature set
    return np.array(X), np.array(y)


async def _record_metadata(session_factory, version: str, metrics: dict, n_samples: int):
    async with session_factory() as db:
        await db.execute(
            ModelMetadata.__table__.update().values(is_active=False)
        )
        db.add(
            ModelMetadata(
                model_name="ensemble",
                version=version,
                trained_at=datetime.now(timezone.utc),
                accuracy=metrics.get("accuracy"),
                samples_used=n_samples,
                is_active=True,
                model_metadata=metrics,
            )
        )
        await db.commit()


def _evaluate(bundle, X, y) -> dict:
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

    pred = (score_bundle(bundle, X) >= 0.5).astype(int)
    return {
        "accuracy": round(float(accuracy_score(y, pred)), 4),
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
    }


async def _retrain() -> dict:
    from sklearn.model_selection import train_test_split

    engine, session_factory = make_task_session_factory()
    try:
        X, y = await _load_verified_samples(session_factory)
        n = len(y)
        if n < settings.RETRAIN_MIN_VERIFIED_SAMPLES or len(set(y.tolist())) < 2:
            msg = (
                f"Skipping retrain: {n} verified samples "
                f"(need {settings.RETRAIN_MIN_VERIFIED_SAMPLES}+ with both classes)"
            )
            logger.info(msg)
            return {"status": "skipped", "reason": msg}

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=42
        )

        # Augment the real training data with the synthetic baseline so rare
        # attack classes aren't forgotten. Evaluation uses real data only.
        X_syn, y_syn = generate_synthetic_data()
        X_fit = np.vstack([X_train, X_syn])
        y_fit = np.concatenate([y_train, y_syn])

        version = datetime.now(timezone.utc).strftime("v%Y%m%d-%H%M%S")
        candidate = fit_bundle(X_fit, y_fit, version=version)
        metrics = _evaluate(candidate, X_test, y_test)
        metrics.update({"train_samples": int(len(y_train)), "test_samples": int(len(y_test))})

        current = ModelManager()
        current_f1 = None
        if current.load_models(bootstrap_if_missing=False):
            current_f1 = _evaluate(current.bundle, X_test, y_test)["f1"]
        metrics["previous_f1"] = current_f1

        if metrics["f1"] < settings.RETRAIN_MIN_F1:
            logger.warning(f"Candidate {version} rejected: F1 {metrics['f1']} < {settings.RETRAIN_MIN_F1}")
            return {"status": "rejected", "metrics": metrics}
        if current_f1 is not None and metrics["f1"] < current_f1 - 0.01:
            logger.warning(f"Candidate {version} rejected: F1 {metrics['f1']} worse than current {current_f1}")
            return {"status": "rejected", "metrics": metrics}

        candidate.metrics = metrics
        current.save(candidate)
        await _record_metadata(session_factory, version, metrics, n)

        # Tell every API worker to hot-reload the new bundle
        r = redis.Redis.from_url(settings.REDIS_URL)
        try:
            r.publish(MODELS_CHANNEL, json.dumps({"version": version}))
        finally:
            r.close()

        logger.info(f"Promoted model {version}: {metrics}")
        return {"status": "promoted", "version": version, "metrics": metrics}
    finally:
        await engine.dispose()


@celery_app.task(name="tasks.retrain.retrain_models")
def retrain_models():
    # Prevent overlapping runs (beat + manual trigger)
    r = redis.Redis.from_url(settings.REDIS_URL)
    lock = r.lock(LOCK_KEY, timeout=3600, blocking=False)
    if not lock.acquire(blocking=False):
        return {"status": "skipped", "reason": "retrain already running"}
    try:
        return asyncio.run(_retrain())
    finally:
        try:
            lock.release()
        except Exception:
            pass
        r.close()
