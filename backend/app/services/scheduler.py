from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.config import settings
from app.services.poller import poll_tailscale_devices
from app.tasks.ssl_monitor import MAGICDNS_SSL_JOB_ID, monitor_magicdns_certificates

logger = logging.getLogger(__name__)

# Global or canonical job IDs for periodic background workers
TAILSCALE_POLL_JOB_ID = "poll_tailscale_devices"



def setup_scheduler(
    poll_interval_minutes: Optional[int] = None,
    poll_on_startup: Optional[bool] = None,
) -> AsyncIOScheduler:
    """Instantiates and configures the AsyncIOScheduler for background tasks.

    Uses `AsyncIOScheduler` to execute asynchronous coroutine jobs directly on
    the running `asyncio` event loop without blocking or spawning unnecessary threads.

    Args:
        poll_interval_minutes: Polling interval in minutes. Defaults to
            `settings.TAILSCALE_POLL_INTERVAL_MINUTES`.
        poll_on_startup: Whether to trigger an initial poll run immediately upon startup.
            Defaults to `settings.TAILSCALE_POLL_ON_STARTUP`.

    Returns:
        Configured, unstarted `AsyncIOScheduler` instance.
    """
    interval = (
        poll_interval_minutes
        if poll_interval_minutes is not None
        else settings.TAILSCALE_POLL_INTERVAL_MINUTES
    )
    run_on_startup = (
        poll_on_startup
        if poll_on_startup is not None
        else settings.TAILSCALE_POLL_ON_STARTUP
    )

    scheduler = AsyncIOScheduler(
        timezone=timezone.utc,
        job_defaults={
            "coalesce": True,
            "max_instances": 1,
            "misfire_grace_time": 60,
        },
    )

    trigger = IntervalTrigger(minutes=interval, timezone=timezone.utc)
    job_kwargs: Dict[str, Any] = {
        "trigger": trigger,
        "id": TAILSCALE_POLL_JOB_ID,
        "name": f"Poll Tailscale Fleet Devices Telemetry (every {interval}m)",
        "replace_existing": True,
        "max_instances": 1,
        "coalesce": True,
        "misfire_grace_time": 60,
    }

    if run_on_startup:
        job_kwargs["next_run_time"] = datetime.now(timezone.utc)

    scheduler.add_job(poll_tailscale_devices, **job_kwargs)
    logger.debug(
        "Configured background job '%s' with %d-minute interval trigger (run_on_startup=%s).",
        TAILSCALE_POLL_JOB_ID,
        interval,
        run_on_startup,
    )

    if getattr(settings, "MAGICDNS_SSL_MONITOR_ENABLED", True):
        ssl_interval = getattr(settings, "MAGICDNS_SSL_POLL_INTERVAL_MINUTES", 60)
        ssl_trigger = IntervalTrigger(minutes=ssl_interval, timezone=timezone.utc)
        ssl_job_kwargs: Dict[str, Any] = {
            "trigger": ssl_trigger,
            "id": MAGICDNS_SSL_JOB_ID,
            "name": f"Monitor MagicDNS TLS/SSL Certificates (every {ssl_interval}m)",
            "replace_existing": True,
            "max_instances": 1,
            "coalesce": True,
            "misfire_grace_time": 60,
        }
        if run_on_startup:
            ssl_job_kwargs["next_run_time"] = datetime.now(timezone.utc)

        scheduler.add_job(monitor_magicdns_certificates, **ssl_job_kwargs)
        logger.debug(
            "Configured background job '%s' with %d-minute interval trigger (run_on_startup=%s).",
            MAGICDNS_SSL_JOB_ID,
            ssl_interval,
            run_on_startup,
        )

    return scheduler



def start_scheduler(scheduler: AsyncIOScheduler) -> None:
    """Starts the AsyncIOScheduler if not already running.

    Args:
        scheduler: The `AsyncIOScheduler` instance to start.
    """
    if not scheduler.running:
        logger.info("Starting APScheduler background task worker...")
        scheduler.start()
        logger.info("APScheduler background task worker started successfully.")
    else:
        logger.debug("APScheduler background task worker is already running.")


def shutdown_scheduler(
    scheduler: Optional[AsyncIOScheduler],
    wait: bool = False,
) -> None:
    """Gracefully shuts down the AsyncIOScheduler instance.

    Args:
        scheduler: The `AsyncIOScheduler` instance to stop.
        wait: If True, blocks until currently running jobs complete.
            Defaults to False for fast asynchronous server termination.
    """
    if scheduler is not None and scheduler.running:
        logger.info("Shutting down APScheduler background task worker...")
        try:
            scheduler.shutdown(wait=wait)
            logger.info("APScheduler background task worker shut down successfully.")
        except Exception as exc:
            logger.warning("Error encountered during APScheduler shutdown: %s", exc)


def get_scheduler_status(
    scheduler: Optional[AsyncIOScheduler],
) -> Dict[str, Any]:
    """Inspects and returns current status and jobs of the scheduler.

    Args:
        scheduler: The `AsyncIOScheduler` instance to inspect.

    Returns:
        Dictionary containing running status and job details.
    """
    if scheduler is None:
        return {
            "status": "not_initialized",
            "running": False,
            "interval_minutes": settings.TAILSCALE_POLL_INTERVAL_MINUTES,
            "jobs": [],
        }

    job_list = []
    if scheduler.running:
        for job in scheduler.get_jobs():
            job_list.append(
                {
                    "id": job.id,
                    "name": job.name,
                    "next_run_time": (
                        job.next_run_time.isoformat()
                        if getattr(job, "next_run_time", None)
                        else None
                    ),
                    "trigger": str(job.trigger),
                }
            )

    return {
        "status": "running" if scheduler.running else "stopped",
        "running": scheduler.running,
        "interval_minutes": settings.TAILSCALE_POLL_INTERVAL_MINUTES,
        "jobs": job_list,
    }
