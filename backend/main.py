"""
AI-WAF: Real-time AI-powered Web Application Firewall
Main application entry point
"""
import asyncio
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from api.routes import dashboard, logs, models, threats, websocket
from core.config import settings
from core.database import engine
from core.metrics import setup_metrics
from core.redis_client import redis_client
from core.websocket_manager import run_pubsub_listener
from ml.model_manager import model_manager

# ── Logging ───────────────────────────────────────────────────────────────────
logger.remove()
logger.add(sys.stdout, level=settings.LOG_LEVEL, serialize=settings.LOG_JSON)

APP_VERSION = "1.1.0"


async def _reload_models():
    await run_in_threadpool(model_manager.reload)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting AI-WAF backend ({settings.ENVIRONMENT})")

    await redis_client.connect()

    # Models are trained by the init job / worker; fall back to an in-memory
    # bootstrap so the API still serves if the bundle is missing.
    await run_in_threadpool(model_manager.load_models, True)

    listener = asyncio.create_task(run_pubsub_listener(_reload_models))
    try:
        yield
    finally:
        listener.cancel()
        try:
            await listener
        except (asyncio.CancelledError, Exception):
            pass
        await redis_client.disconnect()
        await engine.dispose()
        logger.info("AI-WAF backend shut down")


app = FastAPI(
    title="AI-WAF API",
    description="AI-powered real-time threat detection engine for web traffic",
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if settings.ENABLE_DOCS else None,
    redoc_url="/redoc" if settings.ENABLE_DOCS else None,
    openapi_url="/openapi.json" if settings.ENABLE_DOCS else None,
)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,  # auth is via X-API-Key header, not cookies
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Content-Type", "X-API-Key"],
    )

setup_metrics(app)

# Routers (auth dependencies are declared on each router/route)
app.include_router(logs.router, prefix="/api/logs", tags=["logs"])
app.include_router(threats.router, prefix="/api/threats", tags=["threats"])
app.include_router(models.router, prefix="/api/models", tags=["models"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(websocket.router, prefix="/ws", tags=["websocket"])


@app.get("/health")
async def health():
    """Liveness: the process is up and serving."""
    return {"status": "ok", "version": APP_VERSION}


@app.get("/ready")
async def ready():
    """Readiness: dependencies reachable and models loaded."""
    checks = {"database": False, "redis": False, "models": model_manager.is_ready}
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception as e:
        logger.warning(f"Readiness: database check failed: {e}")
    checks["redis"] = await redis_client.ping()

    ok = all(checks.values())
    return JSONResponse(
        status_code=200 if ok else 503,
        content={"status": "ready" if ok else "not_ready", "checks": checks,
                 "model_version": model_manager.version},
    )
