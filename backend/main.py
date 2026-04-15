"""
AI-WAF: Real-time AI-powered Web Application Firewall
Main application entry point
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from core.database import init_db
from core.redis_client import redis_client
from api.routes import logs, threats, models, websocket, dashboard
from ml.model_manager import model_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    logger.info("🚀 Starting AI-WAF backend...")

    # Init DB
    await init_db()
    logger.info("✅ Database initialized")

    # Connect Redis
    await redis_client.connect()
    logger.info("✅ Redis connected")

    # Load ML models
    await model_manager.load_models()
    logger.info("✅ ML models loaded")

    yield

    # Cleanup
    await redis_client.disconnect()
    logger.info("👋 AI-WAF backend shutting down")


app = FastAPI(
    title="AI-WAF API",
    description="AI-powered real-time threat detection engine for web traffic",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(logs.router, prefix="/api/logs", tags=["logs"])
app.include_router(threats.router, prefix="/api/threats", tags=["threats"])
app.include_router(models.router, prefix="/api/models", tags=["models"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(websocket.router, prefix="/ws", tags=["websocket"])


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
