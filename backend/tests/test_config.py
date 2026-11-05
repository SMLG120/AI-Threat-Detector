import pytest
from pydantic import ValidationError

from core.config import Settings

BASE = dict(
    DATABASE_URL="postgresql+asyncpg://u:p@h/db",
    REDIS_URL="redis://h:6379/0",
    INGEST_API_KEY="a" * 32,
    DASHBOARD_API_KEY="b" * 32,
)


def test_valid_settings():
    s = Settings(**BASE, CORS_ORIGINS="https://a.com, https://b.com")
    assert s.cors_origins == ["https://a.com", "https://b.com"]


def test_weights_must_sum_to_one():
    with pytest.raises(ValidationError):
        Settings(**BASE, RULE_WEIGHT=0.9)


def test_short_api_key_rejected():
    with pytest.raises(ValidationError):
        Settings(**{**BASE, "INGEST_API_KEY": "short"})


def test_keys_must_differ():
    with pytest.raises(ValidationError):
        Settings(**{**BASE, "DASHBOARD_API_KEY": "a" * 32})
