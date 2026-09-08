import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.router import api_router
from app.config import settings
from app.database import get_db
from app.services.scheduler import (
    get_scheduler_status,
    setup_scheduler,
    shutdown_scheduler,
    start_scheduler,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Lifespan context manager for application startup and shutdown events."""
    logger.info("Starting %s (v%s)...", settings.PROJECT_NAME, settings.VERSION)

    # Startup: Initialize and launch APScheduler background worker
    scheduler = setup_scheduler()
    if settings.TAILSCALE_POLL_ENABLED:
        start_scheduler(scheduler)
        logger.info(
            "APScheduler initialized with Tailscale polling interval of %d minutes (MagicDNS SSL monitor enabled: %s).",
            settings.TAILSCALE_POLL_INTERVAL_MINUTES,
            getattr(settings, "MAGICDNS_SSL_MONITOR_ENABLED", True),
        )
    else:
        logger.info("Tailscale background polling is disabled by configuration.")

    app.state.scheduler = scheduler

    yield

    # Shutdown: Graceful cleanup of background tasks
    logger.info("Shutting down %s background services...", settings.PROJECT_NAME)
    active_scheduler = getattr(app.state, "scheduler", None)
    if active_scheduler is not None:
        shutdown_scheduler(active_scheduler)
    logger.info("Shutdown completed successfully.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="GridPulse: Tailscale Device & Fleet Telemetry API",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers
app.include_router(api_router)


@app.post("/webhooks/tailscale", tags=["Webhooks"], include_in_schema=False)
async def root_tailscale_webhook_listener(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Direct alias for /api/v1/webhooks/tailscale."""
    from app.api.v1.router import v1_tailscale_webhook_listener
    return await v1_tailscale_webhook_listener(request=request, db=db)


@app.get("/", tags=["Root"])
async def root():
    """Root status endpoint."""
    return {
        "message": "Welcome to GridPulse API",
        "version": settings.VERSION,
        "docs_url": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health_check(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Comprehensive health check verifying application, database, and background scheduler connectivity."""

    try:
        result = await db.execute(text("SELECT 1"))
        db_healthy = result.scalar() == 1
        db_status = "connected" if db_healthy else "unexpected_result"
    except Exception as exc:
        db_status = f"unhealthy: {str(exc)}"

    scheduler_instance = (
        getattr(request.app.state, "scheduler", None)
        if request is not None
        else getattr(app.state, "scheduler", None)
    )
    scheduler_info = get_scheduler_status(scheduler_instance)
    scheduler_ok = (
        not settings.TAILSCALE_POLL_ENABLED
        or scheduler_instance is None
        or scheduler_info["running"]
    )

    overall_status = "ok" if (db_status == "connected" and scheduler_ok) else "degraded"

    return {
        "status": overall_status,
        "database": db_status,
        "scheduler": scheduler_info,
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
    }

