from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.main import app
from app.models.audit_log import AuditLog
from app.models.enums import AuditEventType, AuditSeverity, ComplianceStatus, EventCategory
from app.models.node import Node
from app.models.node_state import NodeState
from app.schemas.tailscale import TailscaleDevice
from app.services.poller import sync_tailscale_devices
from app.services.version_monitor import (
    calculate_key_expiry_countdown,
    evaluate_node_security_posture,
    evaluate_version_drift,
    format_countdown_human,
    get_fleet_key_expiry_overview,
    get_fleet_version_drift_overview,
    get_node_security_posture,
    parse_node_ts_version,
    parse_semver_tuple,
)


# ---------------------------------------------------------------------------
# Semver & Version Drift Unit Tests
# ---------------------------------------------------------------------------


def test_parse_semver_tuple_valid():
    """Verifies parse_semver_tuple handles standard and decorated semver strings."""
    assert parse_semver_tuple("1.60.0") == (1, 60, 0)
    assert parse_semver_tuple("v1.58.2") == (1, 58, 2)
    assert parse_semver_tuple("V2.1.0") == (2, 1, 0)
    assert parse_semver_tuple("1.56.0-t1234abcd") == (1, 56, 0)
    assert parse_semver_tuple("1.56.0+build999") == (1, 56, 0)
    assert parse_semver_tuple("1.56.0~preview") == (1, 56, 0)
    assert parse_semver_tuple("1.54") == (1, 54, 0)
    assert parse_semver_tuple("2") == (2, 0, 0)


def test_parse_semver_tuple_invalid():
    """Verifies parse_semver_tuple returns None for unparseable version strings."""
    assert parse_semver_tuple("invalid") is None
    assert parse_semver_tuple("") is None
    assert parse_semver_tuple(None) is None
    assert parse_semver_tuple("v") is None
    assert parse_semver_tuple("not.a.version") is None
    assert parse_semver_tuple("1.xx") is None
    assert parse_semver_tuple("1.2.yy") is None


def test_parse_node_ts_version_attribute_priority():
    """Verifies parse_node_ts_version respects extraction priority."""
    # 1. From device.attributes['node:tsVersion']
    d1 = TailscaleDevice.model_validate(
        {
            "id": "1",
            "name": "d1",
            "hostname": "d1",
            "os": "linux",
            "attributes": {"node:tsVersion": "1.58.0"},
            "clientVersion": "1.50.0",
        }
    )
    assert parse_node_ts_version(d1) == "1.58.0"

    # 2. From device.attributes['node:ts_version']
    d2 = TailscaleDevice.model_validate(
        {
            "id": "2",
            "name": "d2",
            "hostname": "d2",
            "os": "linux",
            "attributes": {"node:ts_version": "1.56.1"},
        }
    )
    assert parse_node_ts_version(d2) == "1.56.1"

    # 3. From device.tags 'node:tsVersion:<version>'
    d3 = TailscaleDevice.model_validate(
        {
            "id": "3",
            "name": "d3",
            "hostname": "d3",
            "os": "linux",
            "tags": ["tag:server", "node:tsVersion:1.54.2"],
            "clientVersion": "1.50.0",
        }
    )
    assert parse_node_ts_version(d3) == "1.54.2"

    # 4. From clientVersion
    d4 = TailscaleDevice.model_validate(
        {
            "id": "4",
            "name": "d4",
            "hostname": "d4",
            "os": "linux",
            "clientVersion": "1.60.0",
        }
    )
    assert parse_node_ts_version(d4) == "1.60.0"

    # 5. From clientConnectivity runningVersion
    d5 = TailscaleDevice.model_validate(
        {
            "id": "5",
            "name": "d5",
            "hostname": "d5",
            "os": "linux",
            "clientConnectivity": {
                "clientVersion": {"runningVersion": "1.60.2"}
            },
        }
    )
    assert parse_node_ts_version(d5) == "1.60.2"


def test_evaluate_version_drift_stable_and_ahead():
    """Verifies evaluate_version_drift when current is identical or ahead of stable."""
    # Exactly stable
    res_stable = evaluate_version_drift("1.60.0", stable_version="1.60.0")
    assert res_stable["is_stable"] is True
    assert res_stable["is_behind"] is False
    assert res_stable["is_ahead"] is False
    assert res_stable["drift_type"] == "none"
    assert res_stable["is_vulnerable"] is False
    assert res_stable["vulnerability_severity"] == "none"

    # Ahead of stable (e.g. beta / preview)
    res_ahead = evaluate_version_drift("1.62.0", stable_version="1.60.0")
    assert res_ahead["is_stable"] is False
    assert res_ahead["is_behind"] is False
    assert res_ahead["is_ahead"] is True
    assert res_ahead["drift_type"] == "ahead"
    assert res_ahead["is_vulnerable"] is False
    assert res_ahead["vulnerability_severity"] == "none"


def test_evaluate_version_drift_behind_categories():
    """Verifies evaluate_version_drift correctly classifies patch, minor, and major drift severity."""
    # Patch behind -> low severity
    res_patch = evaluate_version_drift("1.60.0", stable_version="1.60.2")
    assert res_patch["is_behind"] is True
    assert res_patch["drift_type"] == "patch"
    assert res_patch["patch_behind"] == 2
    assert res_patch["major_behind"] == 0
    assert res_patch["minor_behind"] == 0
    assert res_patch["vulnerability_severity"] == "low"
    assert res_patch["is_vulnerable"] is True

    # 1 minor behind -> medium severity
    res_med = evaluate_version_drift("1.58.0", stable_version="1.60.0")
    assert res_med["is_behind"] is True
    assert res_med["drift_type"] == "minor"
    assert res_med["minor_behind"] == 2
    assert res_med["vulnerability_severity"] == "medium"
    assert res_med["is_vulnerable"] is True

    # >=3 minor behind -> high severity
    res_high = evaluate_version_drift("1.54.0", stable_version="1.60.0")
    assert res_high["is_behind"] is True
    assert res_high["drift_type"] == "minor"
    assert res_high["minor_behind"] == 6
    assert res_high["vulnerability_severity"] == "high"
    assert res_high["is_vulnerable"] is True

    # Major behind -> critical severity
    res_crit = evaluate_version_drift("0.99.0", stable_version="1.60.0")
    assert res_crit["is_behind"] is True
    assert res_crit["drift_type"] == "major"
    assert res_crit["major_behind"] == 1
    assert res_crit["vulnerability_severity"] == "critical"
    assert res_crit["is_vulnerable"] is True

    # Unknown or unparseable version -> high severity
    res_unk = evaluate_version_drift("not-a-valid-ver", stable_version="1.60.0")
    assert res_unk["is_valid"] is False
    assert res_unk["is_vulnerable"] is True
    assert res_unk["drift_type"] == "unknown"
    assert res_unk["vulnerability_severity"] == "high"


# ---------------------------------------------------------------------------
# Key Expiry Countdown Unit Tests
# ---------------------------------------------------------------------------


def test_format_countdown_human():
    """Verifies format_countdown_human converts remaining seconds to human string."""
    assert format_countdown_human(20) == "< 1m"
    assert format_countdown_human(120) == "2m"
    assert format_countdown_human(3665) == "1h 1m"
    assert format_countdown_human(7200) == "2h"
    assert format_countdown_human(90000) == "1d 1h"
    assert format_countdown_human(1209600) == "14d"


def test_calculate_key_expiry_countdown_disabled_and_none():
    """Verifies calculate_key_expiry_countdown handles disabled expiry and missing dates."""
    res_dis = calculate_key_expiry_countdown(
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        key_expiry_disabled=True,
    )
    assert res_dis["status"] == "disabled"
    assert res_dis["key_expiry_disabled"] is True
    assert res_dis["is_expired"] is False
    assert res_dis["is_expiring_soon"] is False
    assert res_dis["countdown_human"] == "Key expiry disabled"
    assert res_dis["severity"] == "info"

    res_none = calculate_key_expiry_countdown(expires_at=None, key_expiry_disabled=False)
    assert res_none["status"] == "unknown"
    assert res_none["is_expired"] is False
    assert res_none["countdown_human"] == "No expiry configured"


def test_calculate_key_expiry_countdown_thresholds():
    """Verifies calculate_key_expiry_countdown flags expired, critical, warning, and valid keys."""
    now = datetime.now(timezone.utc)

    # 1. Expired 2 hours ago
    past = now - timedelta(hours=2)
    res_exp = calculate_key_expiry_countdown(expires_at=past, now=now)
    assert res_exp["status"] == "expired"
    assert res_exp["is_expired"] is True
    assert res_exp["is_expiring_soon"] is False
    assert res_exp["severity"] == "critical"
    assert "Expired 2h ago" in res_exp["countdown_human"]

    # 2. Critical: expires in 2 days (<= critical threshold of 3 days)
    crit_exp = now + timedelta(days=2)
    res_crit = calculate_key_expiry_countdown(
        expires_at=crit_exp, warning_days=14, critical_days=3, now=now
    )
    assert res_crit["status"] == "critical"
    assert res_crit["is_expired"] is False
    assert res_crit["is_expiring_soon"] is True
    assert res_crit["severity"] == "critical"
    assert res_crit["remaining_days"] == 2.0
    assert "2d" in res_crit["countdown_human"]

    # 3. Expiring soon: expires in 10 days (<= warning threshold of 14 days)
    warn_exp = now + timedelta(days=10)
    res_warn = calculate_key_expiry_countdown(
        expires_at=warn_exp, warning_days=14, critical_days=3, now=now
    )
    assert res_warn["status"] == "expiring_soon"
    assert res_warn["is_expired"] is False
    assert res_warn["is_expiring_soon"] is True
    assert res_warn["severity"] == "warning"

    # 4. Valid: expires in 30 days (> 14 days)
    valid_exp = now + timedelta(days=30)
    res_val = calculate_key_expiry_countdown(
        expires_at=valid_exp, warning_days=14, critical_days=3, now=now
    )
    assert res_val["status"] == "valid"
    assert res_val["is_expired"] is False
    assert res_val["is_expiring_soon"] is False
    assert res_val["severity"] == "info"

    # 5. String ISO format support
    iso_str = (now + timedelta(days=5)).isoformat()
    res_iso = calculate_key_expiry_countdown(expires_at=iso_str, now=now)
    assert res_iso["is_expiring_soon"] is True


# ---------------------------------------------------------------------------
# Node Security Posture Evaluation Tests
# ---------------------------------------------------------------------------


def test_evaluate_node_security_posture_compliant():
    """Verifies evaluate_node_security_posture marks a device compliant when keys and version are healthy."""
    device = TailscaleDevice.model_validate(
        {
            "id": "node-clean",
            "name": "clean.net",
            "hostname": "clean-box",
            "os": "linux",
            "clientVersion": "1.60.0",
            "keyExpiryDisabled": True,
            "updateAvailable": False,
        }
    )
    posture = evaluate_node_security_posture(device=device, stable_version="1.60.0")
    assert posture["is_compliant"] is True
    assert posture["compliance_status"] == ComplianceStatus.COMPLIANT.value
    assert len(posture["vulnerabilities"]) == 0
    assert posture["version_drift"]["is_vulnerable"] is False
    assert posture["key_expiry"]["status"] == "disabled"


def test_evaluate_node_security_posture_non_compliant_and_warning():
    """Verifies non-compliant status on expired key or major drift, and warning status on upcoming expiry."""
    # Non-compliant due to expired key
    past = datetime.now(timezone.utc) - timedelta(days=1)
    device_expired = TailscaleDevice.model_validate(
        {
            "id": "node-bad-key",
            "name": "expired.net",
            "hostname": "expired-box",
            "os": "linux",
            "clientVersion": "1.60.0",
            "keyExpiry": past,
            "keyExpiryDisabled": False,
        }
    )
    posture_exp = evaluate_node_security_posture(device=device_expired, stable_version="1.60.0")
    assert posture_exp["is_compliant"] is False
    assert posture_exp["compliance_status"] == ComplianceStatus.NON_COMPLIANT.value
    assert any(v["type"] == "key_expired" for v in posture_exp["vulnerabilities"])

    # Non-compliant due to major version drift
    device_old = TailscaleDevice.model_validate(
        {
            "id": "node-old-major",
            "name": "old.net",
            "hostname": "old-box",
            "os": "linux",
            "clientVersion": "0.98.0",
            "keyExpiryDisabled": True,
        }
    )
    posture_old = evaluate_node_security_posture(device=device_old, stable_version="1.60.0")
    assert posture_old["is_compliant"] is False
    assert posture_old["compliance_status"] == ComplianceStatus.NON_COMPLIANT.value
    assert any(v["type"] == "version_drift" for v in posture_old["vulnerabilities"])

    # Warning status due to key expiring soon and minor drift
    device_warn = TailscaleDevice.model_validate(
        {
            "id": "node-warn",
            "name": "warn.net",
            "hostname": "warn-box",
            "os": "linux",
            "attributes": {"node:tsVersion": "1.58.0"},
            "keyExpiry": datetime.now(timezone.utc) + timedelta(days=5),
            "keyExpiryDisabled": False,
            "updateAvailable": True,
        }
    )
    posture_warn = evaluate_node_security_posture(device=device_warn, stable_version="1.60.0")
    assert posture_warn["is_compliant"] is True
    assert posture_warn["compliance_status"] == ComplianceStatus.WARNING.value
    assert len(posture_warn["vulnerabilities"]) >= 2


# ---------------------------------------------------------------------------
# Database Synchronization with Security Posture Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_tailscale_devices_records_security_posture_and_drift_warning():
    """Verifies sync_tailscale_devices stores security posture in NodeState and logs VERSION_DRIFT_WARNING."""
    device = TailscaleDevice.model_validate(
        {
            "id": "node-drift-01",
            "nodeId": "nDriftCNTRL",
            "name": "drift.net",
            "hostname": "drift-node",
            "os": "linux",
            "clientVersion": "1.54.0",  # 6 minor versions behind stable 1.60.0 -> high severity
            "online": True,
            "keyExpiryDisabled": True,
        }
    )

    added_objects = []
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = None  # New node
    mock_session.execute.return_value = mock_exec_result
    mock_session.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
    mock_session.flush = AsyncMock()

    created, updated, states = await sync_tailscale_devices([device], mock_session)
    assert created == 1
    assert states == 1

    # Verify Node ORM has security_posture in telemetry_metadata
    created_node = next(obj for obj in added_objects if isinstance(obj, Node))
    assert "security_posture" in created_node.telemetry_metadata
    posture_meta = created_node.telemetry_metadata["security_posture"]
    assert posture_meta["node_ts_version"] == "1.54.0"
    assert posture_meta["version_drift"]["drift_type"] == "minor"
    assert posture_meta["version_drift"]["is_vulnerable"] is True

    # Verify NodeState ORM snapshot contains posture checks
    created_state = next(obj for obj in added_objects if isinstance(obj, NodeState))
    assert created_state.compliance_status == ComplianceStatus.WARNING.value
    assert created_state.posture_checks["node_ts_version"] == "1.54.0"
    assert created_state.posture_checks["version_drift"]["is_vulnerable"] is True

    # Verify VERSION_DRIFT_WARNING audit log
    audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
    drift_event = next(
        (a for a in audit_logs if a.event_type == AuditEventType.VERSION_DRIFT_WARNING.value), None
    )
    assert drift_event is not None
    assert drift_event.severity == AuditSeverity.HIGH.value
    assert drift_event.details["drift_type"] == "minor"
    assert drift_event.details["versions_behind"] == 6


@pytest.mark.asyncio
async def test_sync_tailscale_devices_logs_key_expiry_warning():
    """Verifies sync_tailscale_devices logs KEY_EXPIRY_WARNING when key is expiring soon."""
    now = datetime.now(timezone.utc)
    exp_dt = now + timedelta(days=2)  # Critical threshold (<= 3 days)

    device = TailscaleDevice.model_validate(
        {
            "id": "node-expiring-01",
            "nodeId": "nExpCNTRL",
            "name": "expiring.net",
            "hostname": "expiring-node",
            "os": "linux",
            "clientVersion": "1.60.0",
            "keyExpiry": exp_dt,
            "keyExpiryDisabled": False,
            "online": True,
        }
    )

    added_objects = []
    mock_session = AsyncMock()
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = None  # New node
    mock_session.execute = AsyncMock(return_value=mock_exec_result)
    mock_session.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
    mock_session.flush = AsyncMock()

    created, updated, states = await sync_tailscale_devices([device], mock_session)
    assert created == 1

    audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
    expiry_event = next(
        (a for a in audit_logs if a.event_type == AuditEventType.KEY_EXPIRY_WARNING.value), None
    )
    assert expiry_event is not None
    assert expiry_event.severity == AuditSeverity.CRITICAL.value
    assert expiry_event.details["status"] == "critical"
    assert ("2d" in expiry_event.details["countdown_human"] or "1d" in expiry_event.details["countdown_human"])


# ---------------------------------------------------------------------------
# Fleet Security Aggregation Services Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_fleet_version_drift_overview():
    """Verifies get_fleet_version_drift_overview aggregates fleet version metrics."""
    nodes = [
        Node(id="1", hostname="srv1", os="linux", client_version="1.60.0", is_online=True),
        Node(id="2", hostname="srv2", os="linux", client_version="1.58.0", is_online=True),
        Node(id="3", hostname="srv3", os="linux", client_version="1.54.0", is_online=False),
        Node(id="4", hostname="srv4", os="linux", client_version="0.99.0", is_online=True),
        Node(id="5", hostname="srv5", os="macos", client_version="1.62.0", is_online=True),
    ]

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = nodes
    mock_session.execute.return_value = mock_result

    data = await get_fleet_version_drift_overview(mock_session, stable_version="1.60.0")
    assert data["total_nodes"] == 5
    assert data["stable_nodes"] == 2  # srv1 (stable) + srv5 (ahead)
    assert data["outdated_nodes"] == 3  # srv2, srv3, srv4
    assert data["vulnerable_nodes"] == 3
    assert data["vulnerability_rate_percentage"] == 60.0
    assert data["drift_breakdown"]["critical"] == 1  # 0.99.0
    assert data["drift_breakdown"]["high"] == 1  # 1.54.0
    assert data["drift_breakdown"]["medium"] == 1  # 1.58.0
    assert len(data["nodes"]) == 5


@pytest.mark.asyncio
async def test_get_fleet_key_expiry_overview():
    """Verifies get_fleet_key_expiry_overview categorizes and sorts nodes by expiry urgency."""
    now = datetime.now(timezone.utc)
    nodes = [
        Node(id="1", hostname="valid-node", expires_at=now + timedelta(days=60), key_expiry_disabled=False),
        Node(id="2", hostname="crit-node", expires_at=now + timedelta(days=1), key_expiry_disabled=False),
        Node(id="3", hostname="expired-node", expires_at=now - timedelta(days=2), key_expiry_disabled=False),
        Node(id="4", hostname="disabled-node", expires_at=None, key_expiry_disabled=True),
    ]

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = nodes
    mock_session.execute.return_value = mock_result

    data = await get_fleet_key_expiry_overview(mock_session, warning_days=14, critical_days=3)
    assert data["total_nodes"] == 4
    assert data["valid_keys"] == 1
    assert data["expiring_soon_keys"] == 1
    assert data["expired_keys"] == 1
    assert data["disabled_expiry_keys"] == 1

    # Verify expired and critical nodes appear first in sorted list
    nodes_res = data["nodes"]
    assert nodes_res[0]["hostname"] == "expired-node"
    assert nodes_res[0]["is_expired"] is True
    assert nodes_res[1]["hostname"] == "crit-node"
    assert nodes_res[1]["is_expiring_soon"] is True


@pytest.mark.asyncio
async def test_get_node_security_posture():
    """Verifies get_node_security_posture returns posture details and handles not found."""
    node = Node(
        id="target-node-id",
        node_id="nTargetCNTRL",
        hostname="target-server",
        name="target-server.net",
        os="linux",
        os_version="Ubuntu 22.04",
        client_version="1.58.0",
        is_online=True,
        key_expiry_disabled=True,
        update_available=False,
    )
    latest_state = NodeState(
        id="state-001",
        node_id="target-node-id",
        is_online=True,
        recorded_at=datetime.now(timezone.utc),
    )

    mock_session = AsyncMock()
    node_result = MagicMock()
    node_result.scalar_one_or_none.return_value = node

    state_result = MagicMock()
    state_result.scalar_one_or_none.return_value = latest_state

    mock_session.execute.side_effect = [node_result, state_result]

    res = await get_node_security_posture(mock_session, "target-node-id", stable_version="1.60.0")
    assert res["id"] == "target-node-id"
    assert res["hostname"] == "target-server"
    assert res["node_ts_version"] == "1.58.0"
    assert res["version_drift"]["drift_type"] == "minor"
    assert res["key_expiry"]["status"] == "disabled"
    assert res["compliance_status"] == ComplianceStatus.WARNING.value
    assert res["latest_state_recorded_at"] is not None

    # Test not found
    mock_session.execute.side_effect = None
    mock_not_found = MagicMock()
    mock_not_found.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_not_found

    res_404 = await get_node_security_posture(mock_session, "missing-node")
    assert res_404["error"] == "node_not_found"


# ---------------------------------------------------------------------------
# API Endpoints Integration Tests (Step 8 Routes)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_v1_fleet_version_drift_endpoint():
    """Tests GET /api/v1/fleet/version-drift endpoint."""
    with patch("app.api.v1.router.get_fleet_version_drift_overview", new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = {
            "stable_version": "1.60.0",
            "total_nodes": 10,
            "stable_nodes": 7,
            "outdated_nodes": 3,
            "vulnerable_nodes": 3,
            "vulnerability_rate_percentage": 30.0,
            "drift_breakdown": {"critical": 0, "high": 1, "medium": 2, "low": 0, "none": 7, "unknown": 0},
            "version_distribution": {"1.60.0": 7, "1.58.0": 2, "1.54.0": 1},
            "nodes": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/fleet/version-drift")
            assert response.status_code == 200
            data = response.json()
            assert data["stable_version"] == "1.60.0"
            assert data["vulnerable_nodes"] == 3
            assert data["vulnerability_rate_percentage"] == 30.0


@pytest.mark.asyncio
async def test_api_v1_fleet_key_expiry_endpoint():
    """Tests GET /api/v1/fleet/key-expiry endpoint."""
    with patch("app.api.v1.router.get_fleet_key_expiry_overview", new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = {
            "warning_threshold_days": 14,
            "critical_threshold_days": 3,
            "total_nodes": 5,
            "valid_keys": 3,
            "expiring_soon_keys": 1,
            "expired_keys": 1,
            "disabled_expiry_keys": 0,
            "unknown_keys": 0,
            "nodes": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/fleet/key-expiry")
            assert response.status_code == 200
            data = response.json()
            assert data["total_nodes"] == 5
            assert data["expired_keys"] == 1
            assert data["expiring_soon_keys"] == 1


@pytest.mark.asyncio
async def test_api_v1_node_security_posture_endpoint():
    """Tests GET /api/v1/fleet/nodes/{node_id}/security and /posture endpoints."""
    with patch("app.api.v1.router.get_node_security_posture", new_callable=AsyncMock) as mock_fn:
        # Success case
        mock_fn.return_value = {
            "id": "node-123",
            "hostname": "test-box",
            "node_ts_version": "1.60.0",
            "is_compliant": True,
            "compliance_status": "compliant",
            "version_drift": {"is_vulnerable": False},
            "key_expiry": {"status": "disabled"},
            "vulnerabilities": [],
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # /security route
            resp1 = await client.get("/api/v1/fleet/nodes/node-123/security")
            assert resp1.status_code == 200
            assert resp1.json()["hostname"] == "test-box"

            # /posture route alias
            resp2 = await client.get("/api/v1/fleet/nodes/node-123/posture")
            assert resp2.status_code == 200
            assert resp2.json()["compliance_status"] == "compliant"

            # 404 case
            mock_fn.return_value = {"error": "node_not_found", "node_id": "nonexistent"}
            resp_404 = await client.get("/api/v1/fleet/nodes/nonexistent/security")
            assert resp_404.status_code == 404
            assert "Node 'nonexistent' not found" in resp_404.json()["detail"]


def test_parse_node_ts_version_case_insensitivity_and_whitespace():
    """Verifies parse_node_ts_version handles case variations in attributes and stripped tags."""
    # Lowercase attribute key 'node:tsversion'
    d_lower = TailscaleDevice.model_validate(
        {
            "id": "d-lower",
            "name": "d-lower",
            "hostname": "d-lower",
            "os": "linux",
            "attributes": {"node:tsversion": "  1.58.1  "},
        }
    )
    assert parse_node_ts_version(d_lower) == "1.58.1"

    # CamelCase attribute key 'tsVersion'
    d_camel = TailscaleDevice.model_validate(
        {
            "id": "d-camel",
            "name": "d-camel",
            "hostname": "d-camel",
            "os": "linux",
            "attributes": {"tsVersion": "1.60.2"},
        }
    )
    assert parse_node_ts_version(d_camel) == "1.60.2"

    # Whitespace in tags
    d_tag_ws = TailscaleDevice.model_validate(
        {
            "id": "d-tag-ws",
            "name": "d-tag-ws",
            "hostname": "d-tag-ws",
            "os": "linux",
            "tags": ["node:tsversion: 1.54.0 "],
        }
    )
    assert parse_node_ts_version(d_tag_ws) == "1.54.0"


def test_calculate_key_expiry_countdown_naive_and_custom_thresholds():
    """Verifies calculate_key_expiry_countdown handles naive datetimes and custom threshold arguments."""
    now_naive = datetime(2026, 9, 8, 12, 0, 0)
    exp_naive = datetime(2026, 9, 14, 12, 0, 0)  # 6 days remaining

    # With default thresholds (warning=14, critical=3): 6 days is warning
    res_default = calculate_key_expiry_countdown(
        expires_at=exp_naive, warning_days=14, critical_days=3, now=now_naive
    )
    assert res_default["status"] == "expiring_soon"
    assert res_default["severity"] == "warning"
    assert res_default["remaining_days"] == 6.0

    # With custom critical threshold (critical=7): 6 days is critical
    res_custom = calculate_key_expiry_countdown(
        expires_at=exp_naive, warning_days=30, critical_days=7, now=now_naive
    )
    assert res_custom["status"] == "critical"
    assert res_custom["severity"] == "critical"


@pytest.mark.asyncio
async def test_get_node_security_posture_by_tailscale_node_id():
    """Verifies get_node_security_posture resolves nodes by Tailscale node_id when different from primary id."""
    node = Node(
        id="uuid-internal-12345",
        node_id="nTailscaleCNTRL",
        hostname="cntrl-server",
        name="cntrl-server.net",
        os="linux",
        client_version="1.60.0",
        is_online=True,
        key_expiry_disabled=True,
    )
    mock_session = AsyncMock()
    node_result = MagicMock()
    node_result.scalar_one_or_none.return_value = node

    state_result = MagicMock()
    state_result.scalar_one_or_none.return_value = None

    mock_session.execute.side_effect = [node_result, state_result]

    res = await get_node_security_posture(mock_session, "nTailscaleCNTRL")
    assert res["id"] == "uuid-internal-12345"
    assert res["node_id"] == "nTailscaleCNTRL"
    assert res["hostname"] == "cntrl-server"
    assert res["is_compliant"] is True


@pytest.mark.asyncio
async def test_api_v1_fleet_version_drift_query_params():
    """Tests GET /api/v1/fleet/version-drift propagates tailnet and stable_version query parameters."""
    with patch("app.api.v1.router.get_fleet_version_drift_overview", new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = {
            "stable_version": "1.62.0",
            "total_nodes": 1,
            "stable_nodes": 1,
            "outdated_nodes": 0,
            "vulnerable_nodes": 0,
            "vulnerability_rate_percentage": 0.0,
            "drift_breakdown": {"none": 1},
            "version_distribution": {"1.62.0": 1},
            "nodes": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/api/v1/fleet/version-drift?tailnet=example.org&stable_version=1.62.0"
            )
            assert response.status_code == 200
            assert response.json()["stable_version"] == "1.62.0"
            mock_fn.assert_called_once()
            _, kwargs = mock_fn.call_args
            assert kwargs["tailnet"] == "example.org"
            assert kwargs["stable_version"] == "1.62.0"


@pytest.mark.asyncio
async def test_api_v1_fleet_key_expiry_query_params():
    """Tests GET /api/v1/fleet/key-expiry propagates warning_days and critical_days query parameters."""
    with patch("app.api.v1.router.get_fleet_key_expiry_overview", new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = {
            "warning_threshold_days": 30,
            "critical_threshold_days": 7,
            "total_nodes": 1,
            "valid_keys": 1,
            "expiring_soon_keys": 0,
            "expired_keys": 0,
            "disabled_expiry_keys": 0,
            "unknown_keys": 0,
            "nodes": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/fleet/key-expiry?warning_days=30&critical_days=7")
            assert response.status_code == 200
            assert response.json()["warning_threshold_days"] == 30
            mock_fn.assert_called_once()
            _, kwargs = mock_fn.call_args
            assert kwargs["warning_days"] == 30
            assert kwargs["critical_days"] == 7

