from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from httpx import ASGITransport, AsyncClient
import pytest

from app.config import settings
from app.main import app, lifespan
from app.schemas.tailscale import TailscaleDevice, TailscaleDevicesResponse
from app.services.poller import poll_tailscale_devices
from app.services.scheduler import (
    MAGICDNS_SSL_JOB_ID,
    TAILSCALE_POLL_JOB_ID,
    get_scheduler_status,
    setup_scheduler,
    shutdown_scheduler,
    start_scheduler,
)
from app.services.tailscale_client import TailscaleAuthError, TailscaleClient


@pytest.mark.asyncio
async def test_setup_scheduler_defaults():
    """Verifies setup_scheduler applies 10-minute interval and default job settings."""
    scheduler = setup_scheduler()

    assert isinstance(scheduler, AsyncIOScheduler)
    assert scheduler.timezone == timezone.utc

    # Verify job defaults configured on scheduler
    assert scheduler._job_defaults["max_instances"] == 1
    assert scheduler._job_defaults["coalesce"] is True

    # Retrieve configured job
    job = scheduler.get_job(TAILSCALE_POLL_JOB_ID)
    assert job is not None
    assert job.id == TAILSCALE_POLL_JOB_ID
    assert "10m" in job.name
    assert isinstance(job.trigger, IntervalTrigger)
    assert job.trigger.interval.total_seconds() == 600  # 10 minutes = 600 seconds

    # Verify job parameters when set on job instance
    if hasattr(job, "max_instances"):
        assert job.max_instances == 1
    if hasattr(job, "coalesce"):
        assert job.coalesce is True


@pytest.mark.asyncio
async def test_setup_scheduler_custom_interval_and_startup():
    """Verifies setup_scheduler with custom interval and poll_on_startup."""
    scheduler = setup_scheduler(poll_interval_minutes=5, poll_on_startup=True)

    job = scheduler.get_job(TAILSCALE_POLL_JOB_ID)
    assert job is not None
    assert isinstance(job.trigger, IntervalTrigger)
    assert job.trigger.interval.total_seconds() == 300  # 5 minutes

    # When poll_on_startup=True, next_run_time is set
    assert job.next_run_time is not None
    # Verify next run is set to approximately now
    diff = abs((job.next_run_time - datetime.now(timezone.utc)).total_seconds())
    assert diff < 5


@pytest.mark.asyncio
async def test_scheduler_lifecycle():
    """Tests start_scheduler and shutdown_scheduler methods."""
    scheduler = setup_scheduler()
    assert not scheduler.running

    start_scheduler(scheduler)
    assert scheduler.running

    # Idempotent start call
    start_scheduler(scheduler)
    assert scheduler.running

    # Shutdown
    shutdown_scheduler(scheduler, wait=False)
    # Yield control to the event loop so APScheduler shutdown callback processes
    await asyncio.sleep(0.02)
    assert not scheduler.running


@pytest.mark.asyncio
async def test_shutdown_scheduler_safe_on_none_and_not_running():
    """Ensures shutdown_scheduler does not raise errors on None or stopped schedulers."""
    shutdown_scheduler(None)

    scheduler = setup_scheduler()
    shutdown_scheduler(scheduler)  # Not yet started


def test_get_scheduler_status_none():
    """Tests get_scheduler_status when scheduler is uninitialized (None)."""
    status = get_scheduler_status(None)
    assert status["status"] == "not_initialized"
    assert status["running"] is False
    assert status["jobs"] == []


@pytest.mark.asyncio
async def test_get_scheduler_status_running():
    """Tests get_scheduler_status when scheduler is actively running."""
    scheduler = setup_scheduler(poll_interval_minutes=10)
    start_scheduler(scheduler)

    status = get_scheduler_status(scheduler)
    assert status["status"] == "running"
    assert status["running"] is True
    assert status["interval_minutes"] == 10
    assert len(status["jobs"]) == 2
    job_ids = [job["id"] for job in status["jobs"]]
    assert TAILSCALE_POLL_JOB_ID in job_ids
    assert MAGICDNS_SSL_JOB_ID in job_ids

    shutdown_scheduler(scheduler, wait=False)
    await asyncio.sleep(0.02)


@pytest.mark.asyncio
async def test_fastapi_lifespan_starts_and_stops_scheduler():
    """Tests that the FastAPI lifespan context manager starts and stops APScheduler."""
    async with lifespan(app):
        # Startup event ran
        scheduler = getattr(app.state, "scheduler", None)
        assert scheduler is not None
        assert scheduler.running is True

        job = scheduler.get_job(TAILSCALE_POLL_JOB_ID)
        assert job is not None

    # After lifespan exit (shutdown)
    await asyncio.sleep(0.02)
    assert not scheduler.running


@pytest.mark.asyncio
async def test_fastapi_lifespan_polling_disabled(monkeypatch):
    """Tests that lifespan respects TAILSCALE_POLL_ENABLED=False."""
    monkeypatch.setattr(settings, "TAILSCALE_POLL_ENABLED", False)

    async with lifespan(app):
        scheduler = getattr(app.state, "scheduler", None)
        assert scheduler is not None
        # Scheduler should not be started when disabled
        assert not scheduler.running


@pytest.mark.asyncio
async def test_health_check_reports_scheduler_status():
    """Tests /health endpoint includes scheduler status."""
    async with lifespan(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert "scheduler" in data
            assert data["scheduler"]["status"] == "running"
            assert data["scheduler"]["running"] is True


@pytest.mark.asyncio
async def test_api_v1_scheduler_status_endpoint():
    """Tests /api/v1/scheduler/status returns detailed scheduler job state."""
    async with lifespan(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/scheduler/status")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "running"
            assert data["running"] is True
            assert len(data["jobs"]) == 2
            job_ids = [job["id"] for job in data["jobs"]]
            assert TAILSCALE_POLL_JOB_ID in job_ids
            assert MAGICDNS_SSL_JOB_ID in job_ids


@pytest.mark.asyncio
async def test_poll_tailscale_devices_skipped_when_no_api_key(monkeypatch):
    """Verifies poll_tailscale_devices skips execution when no API key is configured."""
    monkeypatch.setattr(settings, "TAILSCALE_API_KEY", "")
    result = await poll_tailscale_devices()
    assert result["status"] == "skipped"
    assert result["reason"] == "Tailscale API credentials not configured"
    assert result["devices_polled"] == 0


@pytest.mark.asyncio
async def test_poll_tailscale_devices_auth_error():
    """Verifies poll_tailscale_devices handles Tailscale authentication errors gracefully."""
    mock_client = MagicMock(spec=TailscaleClient)
    mock_client.is_configured = True
    mock_client.tailnet = "test-tailnet"
    mock_client.get_devices = AsyncMock(
        side_effect=TailscaleAuthError("Invalid API key", status_code=401)
    )

    result = await poll_tailscale_devices(client=mock_client)
    assert result["status"] == "error"
    assert result["reason"] == "authentication_failed"
    assert "Invalid API key" in result["error"]
    assert result["devices_polled"] == 0


@pytest.mark.asyncio
async def test_poll_tailscale_devices_success_with_mocked_db():
    """Verifies poll_tailscale_devices fetches devices and commits to database."""
    raw_device = {
        "id": "node-1001",
        "nodeId": "n1001CNTRL",
        "name": "worker-01.example.org.beta.tailscale.net",
        "hostname": "worker-01",
        "user": "test@example.org",
        "os": "linux",
        "clientVersion": "1.56.0",
        "addresses": ["100.64.0.1"],
        "authorized": True,
        "isExternal": False,
        "keyExpiryDisabled": True,
        "lastSeen": "2026-09-08T14:50:00Z",
        "created": "2026-01-01T00:00:00Z",
    }
    device = TailscaleDevice.model_validate(raw_device)
    response = TailscaleDevicesResponse(devices=[device])

    mock_client = MagicMock(spec=TailscaleClient)
    mock_client.is_configured = True
    mock_client.tailnet = "test-tailnet"
    mock_client.get_devices = AsyncMock(return_value=response)

    mock_session = AsyncMock()
    mock_execute_result = MagicMock()
    mock_execute_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_execute_result)
    mock_session.add = MagicMock()
    mock_session.flush = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.rollback = AsyncMock()

    class MockSessionFactory:
        def __call__(self):
            return self

        async def __aenter__(self):
            return mock_session

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            return None

    result = await poll_tailscale_devices(
        session_factory=MockSessionFactory(),
        client=mock_client,
    )
    assert result["status"] == "success"
    assert result["devices_polled"] == 1
    assert result["nodes_created"] == 1
    assert result["nodes_updated"] == 0
    assert result["node_states_recorded"] == 1
    mock_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_api_v1_tailscale_sync_endpoint():
    """Tests POST /api/v1/tailscale/sync manually triggers background sync."""
    with patch("app.api.v1.router.poll_tailscale_devices", new_callable=AsyncMock) as mock_poll:
        mock_poll.return_value = {
            "status": "success",
            "devices_polled": 5,
            "nodes_created": 2,
            "nodes_updated": 3,
            "node_states_recorded": 5,
        }
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/v1/tailscale/sync")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["devices_polled"] == 5
