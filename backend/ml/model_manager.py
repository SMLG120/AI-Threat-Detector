"""
ML Model Manager
Loads trained models (ONNX / sklearn) and runs ensemble inference.
Falls back to synthetic bootstrapping if models don't exist yet.
"""
import os
import pickle
import numpy as np
from pathlib import Path
from loguru import logger
from typing import Tuple

from core.config import settings


class ModelManager:
    def __init__(self):
        self.model_dir = Path(settings.MODEL_DIR)
        self.isolation_forest = None
        self.random_forest = None
        self.autoencoder = None
        self.scaler = None
        self._ready = False

    async def load_models(self):
        """Load all models from disk, or bootstrap with synthetic training."""
        try:
            if self._all_models_exist():
                self._load_from_disk()
            else:
                logger.warning("Models not found — bootstrapping with synthetic data...")
                await self._bootstrap_train()
            self._ready = True
            logger.info("✅ ML ensemble ready")
        except Exception as e:
            logger.error(f"Model loading failed: {e}")
            self._ready = False

    def _all_models_exist(self) -> bool:
        required = ["scaler.pkl", "isolation_forest.pkl", "random_forest.pkl"]
        return all((self.model_dir / f).exists() for f in required)

    def _load_from_disk(self):
        with open(self.model_dir / "scaler.pkl", "rb") as f:
            self.scaler = pickle.load(f)
        with open(self.model_dir / "isolation_forest.pkl", "rb") as f:
            self.isolation_forest = pickle.load(f)
        with open(self.model_dir / "random_forest.pkl", "rb") as f:
            self.random_forest = pickle.load(f)
        logger.info("Models loaded from disk")

    def _save_to_disk(self):
        self.model_dir.mkdir(parents=True, exist_ok=True)
        with open(self.model_dir / "scaler.pkl", "wb") as f:
            pickle.dump(self.scaler, f)
        with open(self.model_dir / "isolation_forest.pkl", "wb") as f:
            pickle.dump(self.isolation_forest, f)
        with open(self.model_dir / "random_forest.pkl", "wb") as f:
            pickle.dump(self.random_forest, f)
        logger.info("Models saved to disk")

    async def _bootstrap_train(self):
        """Generate synthetic data and train initial models."""
        from sklearn.preprocessing import StandardScaler
        from sklearn.ensemble import IsolationForest, RandomForestClassifier

        X_benign, X_malicious = self._generate_synthetic_data()
        X = np.vstack([X_benign, X_malicious])
        y = np.array([0] * len(X_benign) + [1] * len(X_malicious))

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.isolation_forest = IsolationForest(
            contamination=0.15,
            n_estimators=200,
            random_state=42,
        )
        self.isolation_forest.fit(X_scaled)

        self.random_forest = RandomForestClassifier(
            n_estimators=200,
            max_depth=8,
            random_state=42,
            class_weight="balanced",
        )
        self.random_forest.fit(X_scaled, y)

        self._save_to_disk()
        logger.info(
            f"Bootstrap training complete — {len(X_benign)} benign, "
            f"{len(X_malicious)} malicious samples"
        )

    async def train_models(self, features: list, labels: list):
        """Retrain models with new data."""
        from sklearn.preprocessing import StandardScaler
        from sklearn.ensemble import IsolationForest, RandomForestClassifier

        X = np.array(features)
        y = np.array(labels)

        if self.scaler is None:
            self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        if self.isolation_forest is None:
            self.isolation_forest = IsolationForest(contamination=0.15, n_estimators=200, random_state=42)
        self.isolation_forest.fit(X_scaled)

        if self.random_forest is None:
            self.random_forest = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42, class_weight="balanced")
        self.random_forest.fit(X_scaled, y)

        self._save_to_disk()
        logger.info("Models retrained with new data")

    def _generate_synthetic_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic feature vectors for initial training."""
        np.random.seed(42)
        n_benign = 5000
        n_malicious = 1500
        n_features = 29  # must match FeatureVector field count

        # Benign: low entropy, low pattern scores, normal URLs
        benign = np.random.normal(0.1, 0.05, (n_benign, n_features))
        benign = np.clip(benign, 0, 1)
        # Set attack pattern cols (10-14) to near-zero for benign
        benign[:, 10:15] = np.abs(np.random.normal(0.01, 0.01, (n_benign, 5)))

        # Malicious: elevated entropy, elevated pattern scores
        malicious = np.random.normal(0.15, 0.1, (n_malicious, n_features))
        malicious = np.clip(malicious, 0, 1)
        # High attack pattern scores
        malicious[:, 10:15] = np.random.uniform(0.4, 1.0, (n_malicious, 5))
        # High entropy
        malicious[:, 7:10] = np.random.uniform(0.5, 1.0, (n_malicious, 3))
        # Long URLs
        malicious[:, 0] = np.random.uniform(0.3, 1.0, n_malicious)

        return benign, malicious

    def predict(self, features: np.ndarray) -> dict:
        """
        Run ensemble inference on a feature vector.
        Returns individual model scores + combined score.
        """
        if not self._ready:
            return {"isolation_forest": 0.0, "random_forest": 0.0, "autoencoder": 0.0}

        features_2d = features.reshape(1, -1)
        features_scaled = self.scaler.transform(features_2d)

        # Isolation Forest: -1 = anomaly, 1 = normal → convert to [0,1]
        if_score_raw = self.isolation_forest.score_samples(features_scaled)[0]
        # score_samples returns negative values; more negative = more anomalous
        # Normalize to [0,1] roughly: typical range is [-0.5, 0.5]
        if_score = float(np.clip((-if_score_raw - 0.05) / 0.5, 0, 1))

        # Random Forest: probability of class 1 (malicious)
        rf_proba = self.random_forest.predict_proba(features_scaled)[0]
        rf_score = float(rf_proba[1]) if len(rf_proba) > 1 else 0.0

        return {
            "isolation_forest": round(if_score, 4),
            "random_forest": round(rf_score, 4),
            "autoencoder": 0.0,  # Placeholder — wire PyTorch model here
        }

    @property
    def is_ready(self) -> bool:
        return self._ready


model_manager = ModelManager()
