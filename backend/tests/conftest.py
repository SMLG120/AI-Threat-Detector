import os
import sys
from pathlib import Path

# Settings are required (no insecure defaults), so provide test values
# before any application module is imported.
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("INGEST_API_KEY", "i" * 40)
os.environ.setdefault("DASHBOARD_API_KEY", "d" * 40)
os.environ.setdefault("LOG_JSON", "false")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

INGEST_KEY = os.environ["INGEST_API_KEY"]
DASHBOARD_KEY = os.environ["DASHBOARD_API_KEY"]
