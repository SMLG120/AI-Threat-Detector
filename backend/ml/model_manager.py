"""
ML Model Manager
Loads the trained sklearn ensemble and runs inference.

All models (scaler + isolation forest + random forest) live in a single bundle
file that is replaced atomically, so a reader can never observe a half-written
or mismatched set of models.

SECURITY: the bundle is a pickle — loading it executes code. The model volume
must only be writable by the trainer (init job / Celery worker); the API mounts
it read-only.
"""
import os
import pickle
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

import numpy as np
from loguru import logger

from core.config import settings
from pipeline.feature_extractor import FEATURE_NAMES

BUNDLE_FILE = "ensemble.pkl"


@dataclass
class ModelBundle:
    scaler: object
    isolation_forest: object
    random_forest: object
    version: str
    trained_at: str
    feature_names: list
    metrics: dict


def generate_synthetic_data(seed: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    """Synthetic feature vectors used to bootstrap the models before real labels exist."""
    rng = np.random.default_rng(seed)
    n_benign, n_malicious = 5000, 1500
    n_features = len(FEATURE_NAMES)

    benign = np.clip(rng.normal(0.1, 0.05, (n_benign, n_features)), 0, 1)
    benign[:, 10:15] = np.abs(rng.normal(0.01, 0.01, (n_benign, 5)))  # attack pattern cols

    malicious = np.clip(rng.normal(0.15, 0.1, (n_malicious, n_features)), 0, 1)
    malicious[:, 10:15] = rng.uniform(0.4, 1.0, (n_malicious, 5))  # high pattern scores
    malicious[:, 7:10] = rng.uniform(0.5, 1.0, (n_malicious, 3))   # high entropy
    malicious[:, 0] = rng.uniform(0.3, 1.0, n_malicious)           # long URLs

    X = np.vstack([benign, malicious])
    y = np.array([0] * n_benign + [1] * n_malicious)
    return X, y


def fit_bundle(X: np.ndarray, y: np.ndarray, version: str, metrics: Optional[dict] = None) -> ModelBundle:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Isolation Forest models "normal" traffic, so fit it on benign samples only
    benign = X_scaled[y == 0] if (y == 0).any() else X_scaled
    iso = IsolationForest(contamination=0.05, n_estimators=200, random_state=42)
    iso.fit(benign)

    rf = RandomForestClassifier(
        n_estimators=200, max_depth=12, random_state=42, class_weight="balanced", n_jobs=-1
    )
    rf.fit(X_scaled, y)

    return ModelBundle(
        scaler=scaler,
        isolation_forest=iso,
        random_forest=rf,
        version=version,
        trained_at=datetime.now(timezone.utc).isoformat(),
        feature_names=list(FEATURE_NAMES),
        metrics=metrics or {},
    )


def score_bundle(bundle: ModelBundle, X: np.ndarray) -> np.ndarray:
    """Random-forest malicious probability for a batch."""
    proba = bundle.random_forest.predict_proba(bundle.scaler.transform(X))
    return proba[:, 1] if proba.shape[1] > 1 else np.zeros(len(X))


class ModelManager:
    def __init__(self, model_dir: Optional[str] = None):
        self.model_dir = Path(model_dir or settings.MODEL_DIR)
        self._bundle: Optional[ModelBundle] = None

    @property
    def bundle_path(self) -> Path:
        return self.model_dir / BUNDLE_FILE

    @property
    def is_ready(self) -> bool:
        return self._bundle is not None

    @property
    def version(self) -> Optional[str]:
        return self._bundle.version if self._bundle else None

    @property
    def bundle(self) -> Optional[ModelBundle]:
        return self._bundle

    # ── Loading ───────────────────────────────────────────────────────────────
    def load_models(self, bootstrap_if_missing: bool = True) -> bool:
        """Load the bundle from disk. If missing, optionally bootstrap in memory."""
        try:
            if self.bundle_path.exists():
                self._bundle = self._read_bundle()
                logger.info(f"Models loaded from disk (version {self._bundle.version})")
                return True
            if bootstrap_if_missing:
                logger.warning("Model bundle not found — bootstrapping with synthetic data")
                self.bootstrap(save=False)
                return True
            logger.error(f"Model bundle not found at {self.bundle_path}")
        except Exception as e:
            logger.exception(f"Model loading failed: {e}")
        return False

    def reload(self) -> bool:
        """Hot-swap to the latest bundle on disk; keeps the current one on failure."""
        try:
            new_bundle = self._read_bundle()
        except Exception as e:
            logger.error(f"Model reload failed, keeping version {self.version}: {e}")
            return False
        self._bundle = new_bundle  # single reference assignment → atomic for readers
        logger.info(f"Models reloaded (version {new_bundle.version})")
        return True

    def _read_bundle(self) -> ModelBundle:
        with open(self.bundle_path, "rb") as f:
            bundle = pickle.load(f)  # noqa: S301 — trusted, read-only volume
        if bundle.feature_names != list(FEATURE_NAMES):
            raise ValueError("Model bundle feature set does not match the current extractor")
        return bundle

    # ── Training / saving ─────────────────────────────────────────────────────
    def bootstrap(self, save: bool = True) -> ModelBundle:
        X, y = generate_synthetic_data()
        bundle = fit_bundle(X, y, version="bootstrap", metrics={"source": "synthetic"})
        self._bundle = bundle
        if save:
            self.save(bundle)
        logger.info(f"Bootstrap training complete — {len(X)} synthetic samples")
        return bundle

    def save(self, bundle: ModelBundle):
        """Atomic write: temp file in the same dir, then os.replace()."""
        self.model_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.model_dir, prefix=".ensemble-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                pickle.dump(bundle, f)
            os.replace(tmp, self.bundle_path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        self._bundle = bundle
        logger.info(f"Model bundle saved (version {bundle.version})")

    # ── Inference ─────────────────────────────────────────────────────────────
    def predict(self, features: np.ndarray) -> dict:
        bundle = self._bundle  # take one reference so a concurrent reload can't mix models
        if bundle is None:
            return {"isolation_forest": 0.0, "random_forest": 0.0, "autoencoder": 0.0}

        features_scaled = bundle.scaler.transform(features.reshape(1, -1))

        # score_samples: more negative = more anomalous → map roughly to [0, 1]
        if_raw = bundle.isolation_forest.score_samples(features_scaled)[0]
        if_score = float(np.clip((-if_raw - 0.05) / 0.5, 0, 1))

        rf_proba = bundle.random_forest.predict_proba(features_scaled)[0]
        rf_score = float(rf_proba[1]) if len(rf_proba) > 1 else 0.0

        return {
            "isolation_forest": round(if_score, 4),
            "random_forest": round(rf_score, 4),
            "autoencoder": 0.0,  # Not implemented — AUTOENCODER_WEIGHT defaults to 0
        }


model_manager = ModelManager()
