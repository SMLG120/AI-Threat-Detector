from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://aiwaf:aiwaf_secret@localhost:5432/aiwaf"
    REDIS_URL: str = "redis://localhost:6379/0"
    MODEL_DIR: str = "./models"
    LOG_DIR: str = "./logs"

    # Detection thresholds
    THREAT_SCORE_LOW: float = 0.3
    THREAT_SCORE_MEDIUM: float = 0.6
    THREAT_SCORE_HIGH: float = 0.85

    # Model weights for ensemble
    RULE_WEIGHT: float = 0.45
    ISOLATION_FOREST_WEIGHT: float = 0.20
    RANDOM_FOREST_WEIGHT: float = 0.25
    AUTOENCODER_WEIGHT: float = 0.10

    # WebSocket
    WS_HEARTBEAT_INTERVAL: int = 30

    class Config:
        env_file = ".env"


settings = Settings()
