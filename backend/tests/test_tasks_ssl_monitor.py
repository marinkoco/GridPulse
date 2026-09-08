from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from unittest.mock import AsyncMock, MagicMock, patch

from httpx import AsyncClient, Response
import pytest

from app.models.enums import SSLCertificateStatus
from app.models.node import Node
from app.tasks.ssl_monitor import (
    MAGICDNS_SSL_JOB_ID,
    check_ssl_certificates,
    extract_magicdns_domain,
    monitor_magicdns_certificates,
    parse_tls_certificate_info,
    probe_domain_ssl,
    run_magicdns_ssl_monitor,
    run_ssl_monitor,
)
from app.services.scheduler import setup_scheduler


def make_test_node(
    node_id: str = "node-1",
    hostname: str = "web-node",
    name: str = "web-node.example.ts.net",
    tailnet: str = "example.ts.net",
) -> Node:
    return Node(
        id=node_id,
        node_id=f"tailscale-{node_id}",
        hostname=hostname,
        name=name,
        user="ops@example.com",
        tailnet=tailnet,
        os="linux",
        client_version="1.60.0",
        is_online=True,
        key_expiry_disabled=True,
        telemetry_metadata={},
    )


@pytest.mark.asyncio
async def test_ssl_monitor_task_exports():
    """Verify task module exposes expected interfaces and job ID."""
    assert callable(check_ssl_certificates)
    assert callable(monitor_magicdns_certificates)
    assert callable(run_magicdns_ssl_monitor)
    assert callable(run_ssl_monitor)
    assert callable(probe_domain_ssl)
    assert MAGICDNS_SSL_JOB_ID == "monitor_magicdns_certificates"


@pytest.mark.asyncio
async def test_ssl_monitor_logs_parsed_expiration_date(caplog):
    """Test that parsing TLS certs and probing logs the expiration date at INFO level."""
    caplog.set_level(logging.INFO)

    raw_cert = {
        "subject": ((("commonName", "test-node.example.ts.net"),),),
        "issuer": ((("commonName", "Tailscale Test CA"),),),
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Dec 31 23:59:59 2026 GMT",
        "subjectAltName": (("DNS", "test-node.example.ts.net"),),
    }

    mock_ssl_obj = MagicMock()
    mock_ssl_obj.getpeercert.return_value = raw_cert
    mock_ssl_obj.version.return_value = "TLSv1.3"
    mock_ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    mock_writer = MagicMock()
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_reader = MagicMock()

    mock_http = AsyncMock(spec=AsyncClient)
    mock_http.get.return_value = Response(status_code=200, request=MagicMock())

    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
        mock_connect.return_value = (mock_reader, mock_writer)

        result = await probe_domain_ssl(
            domain="test-node.example.ts.net",
            http_client=mock_http,
        )

        assert result["is_reachable"] is True
        assert result["expires_at"] == "2026-12-31T23:59:59+00:00"
        assert result["status"] == SSLCertificateStatus.VALID.value

        # Verify that parsed expiration date was logged
        matching_logs = [
            rec.message
            for rec in caplog.records
            if "2026-12-31T23:59:59+00:00" in rec.message and "expiration date" in rec.message.lower()
        ]
        assert len(matching_logs) > 0


@pytest.mark.asyncio
async def test_check_ssl_certificates_background_task_run(caplog):
    """Test check_ssl_certificates executes on fleet nodes and updates telemetry."""
    caplog.set_level(logging.INFO)

    node = make_test_node(node_id="n-ssl-1", hostname="alpha", name="alpha.corp.ts.net")

    # Mock DB session
    mock_session = AsyncMock()
    mock_execute_result = MagicMock()
    mock_execute_result.scalars.return_value.all.return_value = [node]
    mock_session.execute.return_value = mock_execute_result
    mock_session.commit = AsyncMock()

    mock_session_maker = MagicMock()
    mock_session_maker.return_value.__aenter__.return_value = mock_session
    mock_session_maker.return_value.__aexit__.return_value = AsyncMock()

    mock_probe_result = {
        "domain": "alpha.corp.ts.net",
        "port": 443,
        "is_reachable": True,
        "http_reachable": True,
        "http_status_code": 200,
        "response_time_ms": 25.5,
        "tls_version": "TLSv1.3",
        "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        "certificate": {
            "expires_at": "2026-11-15T12:00:00+00:00",
            "status": "valid",
        },
        "expires_at": "2026-11-15T12:00:00+00:00",
        "remaining_days": 68.0,
        "countdown_human": "68 days remaining",
        "is_expired": False,
        "is_expiring_soon": False,
        "status": "valid",
        "error": None,
        "error_type": None,
        "checked_at": "2026-09-08T12:00:00+00:00",
    }

    with patch("app.services.magicdns_ssl.probe_domain_ssl", new_callable=AsyncMock) as mock_probe:
        mock_probe.return_value = mock_probe_result

        summary = await check_ssl_certificates(
            session_factory=mock_session_maker,
            log_events=False,
        )

        assert summary["status"] == "completed"
        assert summary["total_nodes_checked"] == 1
        assert summary["valid_count"] == 1
        assert summary["expired_count"] == 0

        # Check node telemetry updated
        assert "magicdns_ssl" in node.telemetry_metadata
        assert node.telemetry_metadata["magicdns_ssl"]["expires_at"] == "2026-11-15T12:00:00+00:00"

        # Check logs output parsed certificate expiration date
        log_msgs = [rec.message for rec in caplog.records]
        assert any("2026-11-15T12:00:00+00:00" in msg for msg in log_msgs)


@pytest.mark.asyncio
async def test_scheduler_registers_magicdns_ssl_monitor_task():
    """Tests that APScheduler registers the SSL monitor task under MAGICDNS_SSL_JOB_ID."""
    scheduler = setup_scheduler(poll_interval_minutes=15)
    jobs = scheduler.get_jobs()
    job_ids = [j.id for j in jobs]
    assert MAGICDNS_SSL_JOB_ID in job_ids

    ssl_job = scheduler.get_job(MAGICDNS_SSL_JOB_ID)
    assert ssl_job is not None
    assert ssl_job.func == monitor_magicdns_certificates
