from typing import List

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    ENVIRONMENT: str = "production"  # "production" | "development"

    # ── Infrastructure (required — no insecure defaults) ──────────────────────
    DATABASE_URL: str
    REDIS_URL: str
    MODEL_DIR: str = "./models"
    LOG_DIR: str = "./logs"

    # ── Auth ──────────────────────────────────────────────────────────────────
    # Key used by log shippers to POST /api/logs/ingest
    INGEST_API_KEY: str = Field(min_length=32)
    # Key used by the dashboard / operators for read + admin endpoints
    DASHBOARD_API_KEY: str = Field(min_length=32)

    # ── HTTP ──────────────────────────────────────────────────────────────────
    # Comma-separated list of allowed browser origins. Empty = no CORS (same-origin only).
    CORS_ORIGINS: str = ""
    ENABLE_DOCS: bool = False
    RATE_LIMIT_PER_MINUTE: int = 600          # dashboard/read endpoints, per client IP
    INGEST_RATE_LIMIT_PER_MINUTE: int = 12000  # ingest endpoint, per client IP
    MAX_PAGE_SIZE: int = 200

    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_JSON: bool = True
    LOG_LEVEL: str = "INFO"

    # ── Data retention ────────────────────────────────────────────────────────
    RETENTION_DAYS: int = 30

    # ── Retraining ────────────────────────────────────────────────────────────
    RETRAIN_INTERVAL_HOURS: int = 6
    RETRAIN_MIN_VERIFIED_SAMPLES: int = 200
    # A retrained model is only promoted if its holdout F1 is at least this
    RETRAIN_MIN_F1: float = 0.80

    # ── Detection thresholds ──────────────────────────────────────────────────
    THREAT_SCORE_LOW: float = 0.3
    THREAT_SCORE_MEDIUM: float = 0.6
    THREAT_SCORE_HIGH: float = 0.85

    # ── Ensemble weights (must sum to 1.0) ────────────────────────────────────
    # The autoencoder is not implemented yet, so its weight defaults to 0.
    RULE_WEIGHT: float = 0.45
    ISOLATION_FOREST_WEIGHT: float = 0.20
    RANDOM_FOREST_WEIGHT: float = 0.35
    AUTOENCODER_WEIGHT: float = 0.0

    # ── WebSocket ─────────────────────────────────────────────────────────────
    WS_HEARTBEAT_INTERVAL: int = 30

    @field_validator("ENVIRONMENT")
    @classmethod
    def _check_env(cls, v: str) -> str:
        if v not in {"production", "development"}:
            raise ValueError("ENVIRONMENT must be 'production' or 'development'")
        return v

    @model_validator(mode="after")
    def _check_weights(self):
        total = (
            self.RULE_WEIGHT
            + self.ISOLATION_FOREST_WEIGHT
            + self.RANDOM_FOREST_WEIGHT
            + self.AUTOENCODER_WEIGHT
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Ensemble weights must sum to 1.0 (got {total})")
        if self.INGEST_API_KEY == self.DASHBOARD_API_KEY:
            raise ValueError("INGEST_API_KEY and DASHBOARD_API_KEY must be different")
        return self

    @property
    def cors_origins(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


settings = Settings()
