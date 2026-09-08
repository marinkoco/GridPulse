from __future__ import annotations

from datetime import datetime, timezone
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
from app.services.posture import (
    DEFAULT_EXEMPT_POSTURE_TAGS,
    POSTURE_AUTO_UPDATE_ATTR,
    POSTURE_STATE_ENCRYPTED_ATTR,
    audit_node_device_posture,
    get_fleet_non_compliant_endpoints,
    get_fleet_posture_compliance_overview,
    get_node_posture_compliance_audit,
    is_device_posture_exempt,
    parse_node_auto_update,
    parse_node_state_encrypted,
    parse_posture_boolean,
)


def make_device(
    device_id: str = "d1",
    hostname: str = "host1",
    os: str = "linux",
    attributes: dict | None = None,
    tags: list[str] | None = None,
    online: bool = True,
) -> TailscaleDevice:
    """Helper to construct valid TailscaleDevice instances for testing."""
    return TailscaleDevice.model_validate(
        {
            "id": device_id,
            "nodeId": f"nodeId-{device_id}",
            "name": f"{hostname}.example.net",
            "hostname": hostname,
            "os": os,
            "attributes": attributes or {},
            "tags": tags or [],
            "online": online,
            "keyExpiryDisabled": True,
        }
    )


# ---------------------------------------------------------------------------
# Posture Attribute Parsing Tests
# ---------------------------------------------------------------------------


def test_parse_posture_boolean():
    """Verifies parse_posture_boolean handles various boolean representations correctly."""
    # Direct booleans
    assert parse_posture_boolean(True) is True
    assert parse_posture_boolean(False) is False

    # Numbers
    assert parse_posture_boolean(1) is True
    assert parse_posture_boolean(0) is False

    # Strings
    assert parse_posture_boolean("true") is True
    assert parse_posture_boolean("True") is True
    assert parse_posture_boolean("1") is True
    assert parse_posture_boolean("yes") is True
    assert parse_posture_boolean("enabled") is True
    assert parse_posture_boolean("on") is True

    assert parse_posture_boolean("false") is False
    assert parse_posture_boolean("False") is False
    assert parse_posture_boolean("0") is False
    assert parse_posture_boolean("no") is False
    assert parse_posture_boolean("disabled") is False
    assert parse_posture_boolean("off") is False

    # None and unparseable
    assert parse_posture_boolean(None) is None
    assert parse_posture_boolean("") is None
    assert parse_posture_boolean("unknown") is None
    assert parse_posture_boolean("invalid_value") is None


def test_parse_node_auto_update():
    """Verifies parse_node_auto_update extracts auto-update attribute from attributes and tags."""
    # From attributes with standardized key
    dev1 = make_device("d1", attributes={POSTURE_AUTO_UPDATE_ATTR: True})
    assert parse_node_auto_update(dev1) is True

    dev2 = make_device("d2", attributes={POSTURE_AUTO_UPDATE_ATTR: "false"})
    assert parse_node_auto_update(dev2) is False

    # From attributes with alias key
    dev3 = make_device("d3", attributes={"auto_update": "enabled"})
    assert parse_node_auto_update(dev3) is True

    dev4 = make_device("d4", attributes={"ts_auto_update": 0})
    assert parse_node_auto_update(dev4) is False

    # From tags
    dev5 = make_device("d5", tags=["tag:server", "node:tsautoupdate:true"])
    assert parse_node_auto_update(dev5) is True

    dev6 = make_device("d6", tags=["node:tsautoupdate:false"])
    assert parse_node_auto_update(dev6) is False

    dev7 = make_device("d7", tags=["tag:auto-update"])
    assert parse_node_auto_update(dev7) is True

    dev8 = make_device("d8", tags=["tag:no-auto-update"])
    assert parse_node_auto_update(dev8) is False

    # Unknown
    dev9 = make_device("d9", tags=["tag:worker"])
    assert parse_node_auto_update(dev9) is None


def test_parse_node_state_encrypted():
    """Verifies parse_node_state_encrypted extracts state encryption from attributes and tags."""
    # From attributes with standardized key
    dev1 = make_device("d1", attributes={POSTURE_STATE_ENCRYPTED_ATTR: True})
    assert parse_node_state_encrypted(dev1) is True

    dev2 = make_device("d2", attributes={POSTURE_STATE_ENCRYPTED_ATTR: "false"})
    assert parse_node_state_encrypted(dev2) is False

    # From attributes with alias key
    dev3 = make_device("d3", attributes={"disk_encrypted": True})
    assert parse_node_state_encrypted(dev3) is True

    dev4 = make_device("d4", attributes={"state_encrypted": "disabled"})
    assert parse_node_state_encrypted(dev4) is False

    # From tags
    dev5 = make_device("d5", tags=["node:tsstateencrypted:true"])
    assert parse_node_state_encrypted(dev5) is True

    dev6 = make_device("d6", tags=["node:tsstateencrypted:false"])
    assert parse_node_state_encrypted(dev6) is False

    dev7 = make_device("d7", tags=["tag:state-encrypted"])
    assert parse_node_state_encrypted(dev7) is True

    dev8 = make_device("d8", tags=["tag:unencrypted-state"])
    assert parse_node_state_encrypted(dev8) is False

    # Unknown
    dev9 = make_device("d9", tags=["tag:linux"])
    assert parse_node_state_encrypted(dev9) is None


# ---------------------------------------------------------------------------
# Exemption Checking Tests
# ---------------------------------------------------------------------------


def test_is_device_posture_exempt():
    """Verifies is_device_posture_exempt detects exemption tags and explicit attributes."""
    # Exemption by standard tag
    dev1 = make_device("d1", tags=["tag:posture-exempt", "tag:dev"])
    is_ex, reason = is_device_posture_exempt(dev1)
    assert is_ex is True
    assert "tag:posture-exempt" in reason

    dev2 = make_device("d2", tags=["tag:compliance-exempt"])
    is_ex, reason = is_device_posture_exempt(dev2)
    assert is_ex is True
    assert "tag:compliance-exempt" in reason

    # Exemption by attribute
    dev3 = make_device("d3", attributes={"posture_exempt": True})
    is_ex, reason = is_device_posture_exempt(dev3)
    assert is_ex is True
    assert "posture_exempt" in reason

    # Custom exemption tags parameter
    dev4 = make_device("d4", tags=["tag:special-bypass"])
    is_ex_custom, _ = is_device_posture_exempt(dev4, exempt_tags=["tag:special-bypass"])
    assert is_ex_custom is True

    # Not exempt
    dev5 = make_device("d5", tags=["tag:prod", "tag:server"])
    is_ex_none, reason_none = is_device_posture_exempt(dev5)
    assert is_ex_none is False
    assert reason_none is None


# ---------------------------------------------------------------------------
# Device Posture Auditor Logic Tests
# ---------------------------------------------------------------------------


def test_audit_node_device_posture_compliant():
    """Verifies fully compliant device with both auto-update and encryption enabled."""
    device = make_device(
        device_id="node-comp-01",
        hostname="macbook-prod",
        os="macOS",
        attributes={
            POSTURE_AUTO_UPDATE_ATTR: True,
            POSTURE_STATE_ENCRYPTED_ATTR: True,
        },
    )

    report = audit_node_device_posture(device=device)
    assert report["is_compliant"] is True
    assert report["compliance_status"] == ComplianceStatus.COMPLIANT.value
    assert report["ts_auto_update"] is True
    assert report["ts_state_encrypted"] is True
    assert report["violations_count"] == 0
    assert len(report["alerts"]) == 0


def test_audit_node_device_posture_auto_update_disabled():
    """Verifies violation and alert when node:tsAutoUpdate is False."""
    device = make_device(
        device_id="node-no-update-01",
        hostname="linux-stale",
        os="linux",
        attributes={
            POSTURE_AUTO_UPDATE_ATTR: False,
            POSTURE_STATE_ENCRYPTED_ATTR: True,
        },
    )

    report = audit_node_device_posture(device=device)
    assert report["is_compliant"] is False
    assert report["compliance_status"] == ComplianceStatus.NON_COMPLIANT.value
    assert report["ts_auto_update"] is False
    assert report["violations_count"] == 1
    assert report["violations"][0]["attribute"] == POSTURE_AUTO_UPDATE_ATTR
    assert report["violations"][0]["severity"] == AuditSeverity.HIGH.value

    assert len(report["alerts"]) == 1
    alert = report["alerts"][0]
    assert alert["type"] == "auto_update_disabled"
    assert alert["event_type"] == AuditEventType.AUTO_UPDATE_DISABLED.value
    assert alert["event_category"] == EventCategory.POSTURE.value
    assert alert["severity"] == AuditSeverity.HIGH.value
    assert "Automatic updates disabled" in alert["title"]


def test_audit_node_device_posture_state_unencrypted():
    """Verifies violation and alert when node:tsStateEncrypted is False."""
    device = make_device(
        device_id="node-unenc-01",
        hostname="win-unencrypted",
        os="windows",
        attributes={
            POSTURE_AUTO_UPDATE_ATTR: True,
            POSTURE_STATE_ENCRYPTED_ATTR: False,
        },
    )

    report = audit_node_device_posture(device=device)
    assert report["is_compliant"] is False
    assert report["compliance_status"] == ComplianceStatus.NON_COMPLIANT.value
    assert report["ts_state_encrypted"] is False
    assert report["violations_count"] == 1
    assert report["violations"][0]["attribute"] == POSTURE_STATE_ENCRYPTED_ATTR
    assert report["violations"][0]["severity"] == AuditSeverity.CRITICAL.value

    assert len(report["alerts"]) == 1
    alert = report["alerts"][0]
    assert alert["type"] == "state_unencrypted"
    assert alert["event_type"] == AuditEventType.STATE_UNENCRYPTED.value
    assert alert["event_category"] == EventCategory.POSTURE.value
    assert alert["severity"] == AuditSeverity.CRITICAL.value
    assert "unencrypted" in alert["title"].lower()


def test_audit_node_device_posture_both_disabled():
    """Verifies multiple violations and alerts when both attributes are False."""
    device = make_device(
        device_id="node-both-bad",
        hostname="rogue-laptop",
        os="linux",
        attributes={
            POSTURE_AUTO_UPDATE_ATTR: False,
            POSTURE_STATE_ENCRYPTED_ATTR: False,
        },
    )

    report = audit_node_device_posture(device=device)
    assert report["is_compliant"] is False
    assert report["compliance_status"] == ComplianceStatus.NON_COMPLIANT.value
    assert report["violations_count"] == 2
    assert len(report["alerts"]) == 2

    event_types = {a["event_type"] for a in report["alerts"]}
    assert AuditEventType.AUTO_UPDATE_DISABLED.value in event_types
    assert AuditEventType.STATE_UNENCRYPTED.value in event_types


def test_audit_node_device_posture_exempt_device():
    """Verifies exempt device does not trigger violations or non-compliant alerts."""
    device = make_device(
        device_id="node-exempt-01",
        hostname="lab-tester",
        os="linux",
        tags=["tag:posture-exempt"],
        attributes={
            POSTURE_AUTO_UPDATE_ATTR: False,
            POSTURE_STATE_ENCRYPTED_ATTR: False,
        },
    )

    report = audit_node_device_posture(device=device)
    assert report["is_compliant"] is True
    assert report["is_exempt"] is True
    assert report["compliance_status"] == ComplianceStatus.EXEMPT.value
    assert report["violations_count"] == 0
    assert len(report["alerts"]) == 0


def test_audit_node_device_posture_compliance_restoration_alert():
    """Verifies POSTURE_COMPLIANT alert when an existing non-compliant node becomes compliant."""
    existing = Node(
        id="node-restored-01",
        hostname="restored-host",
        telemetry_metadata={
            "device_posture": {
                "compliance_status": ComplianceStatus.NON_COMPLIANT.value,
                "is_compliant": False,
                "ts_auto_update": False,
                "ts_state_encrypted": False,
            }
        },
    )

    device = make_device(
        device_id="node-restored-01",
        hostname="restored-host",
        os="linux",
        attributes={
            POSTURE_AUTO_UPDATE_ATTR: True,
            POSTURE_STATE_ENCRYPTED_ATTR: True,
        },
    )

    report = audit_node_device_posture(device=device, existing_node=existing)
    assert report["is_compliant"] is True
    assert report["compliance_status"] == ComplianceStatus.COMPLIANT.value
    assert report["state_changes"]["compliance_changed"] is True
    assert report["state_changes"]["previous_compliance_status"] == ComplianceStatus.NON_COMPLIANT.value

    # Verify restoration alert
    restored_alert = next((a for a in report["alerts"] if a["type"] == "posture_compliant"), None)
    assert restored_alert is not None
    assert restored_alert["event_type"] == AuditEventType.POSTURE_COMPLIANT.value
    assert restored_alert["severity"] == AuditSeverity.INFO.value


# ---------------------------------------------------------------------------
# Poller Integration & Alert Triggering Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_tailscale_devices_triggers_posture_alerts_and_persists_state():
    """Verifies sync_tailscale_devices audits posture, persists state to telemetry_metadata, and triggers alerts."""
    device = TailscaleDevice.model_validate(
        {
            "id": "node-posture-test-01",
            "nodeId": "nPosture01",
            "name": "audit-laptop.net",
            "hostname": "audit-laptop",
            "os": "macOS",
            "tags": ["tag:workstation"],
            "attributes": {
                POSTURE_AUTO_UPDATE_ATTR: False,
                POSTURE_STATE_ENCRYPTED_ATTR: False,
            },
            "online": True,
            "keyExpiryDisabled": True,
        }
    )

    added_objects = []
    mock_session = AsyncMock()
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = None  # New node
    mock_session.execute.return_value = mock_exec_result
    mock_session.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
    mock_session.flush = AsyncMock()

    created, updated, states = await sync_tailscale_devices([device], mock_session)
    assert created == 1
    assert states == 1

    # 1. Verify telemetry_metadata contains device_posture report
    created_node = next(obj for obj in added_objects if isinstance(obj, Node))
    meta = created_node.telemetry_metadata
    assert "device_posture" in meta
    posture_meta = meta["device_posture"]
    assert posture_meta["ts_auto_update"] is False
    assert posture_meta["ts_state_encrypted"] is False
    assert posture_meta["is_compliant"] is False
    assert posture_meta["compliance_status"] == ComplianceStatus.NON_COMPLIANT.value
    assert meta["ts_auto_update"] is False
    assert meta["ts_state_encrypted"] is False

    # Node model properties
    assert created_node.ts_auto_update is False
    assert created_node.ts_state_encrypted is False
    assert created_node.is_posture_compliant is False

    # 2. Verify NodeState snapshot records posture
    created_state = next(obj for obj in added_objects if isinstance(obj, NodeState))
    assert created_state.compliance_status == ComplianceStatus.NON_COMPLIANT.value
    assert created_state.is_compliant is False
    assert created_state.disk_encryption_enabled is False
    assert "device_posture" in created_state.posture_checks
    assert created_state.posture_checks["ts_auto_update"] is False
    assert created_state.posture_checks["ts_state_encrypted"] is False
    assert "device_posture" in created_state.telemetry_data

    # 3. Verify AuditLog records were inserted for both violations
    audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
    auto_update_log = next(
        (a for a in audit_logs if a.event_type == AuditEventType.AUTO_UPDATE_DISABLED.value),
        None,
    )
    assert auto_update_log is not None
    assert auto_update_log.severity == AuditSeverity.HIGH.value
    assert auto_update_log.event_category == EventCategory.POSTURE.value
    assert "Automatic updates disabled" in auto_update_log.action
    assert auto_update_log.details["attribute"] == POSTURE_AUTO_UPDATE_ATTR

    state_unenc_log = next(
        (a for a in audit_logs if a.event_type == AuditEventType.STATE_UNENCRYPTED.value),
        None,
    )
    assert state_unenc_log is not None
    assert state_unenc_log.severity == AuditSeverity.CRITICAL.value
    assert state_unenc_log.event_category == EventCategory.POSTURE.value
    assert "unencrypted" in state_unenc_log.action.lower()
    assert state_unenc_log.details["attribute"] == POSTURE_STATE_ENCRYPTED_ATTR


@pytest.mark.asyncio
async def test_sync_tailscale_devices_existing_node_posture_update():
    """Verifies sync_tailscale_devices updates existing node telemetry_metadata and triggers compliant alert on remediation."""
    existing_node = Node(
        id="node-posture-test-02",
        node_id="nPosture02",
        name="server-02.net",
        hostname="server-02",
        os="linux",
        is_online=True,
        telemetry_metadata={
            "uptime_info": {"last_state_change": datetime.now(timezone.utc).isoformat()},
            "device_posture": {
                "compliance_status": ComplianceStatus.NON_COMPLIANT.value,
                "is_compliant": False,
                "ts_auto_update": False,
                "ts_state_encrypted": False,
            },
        },
    )

    device = TailscaleDevice.model_validate(
        {
            "id": "node-posture-test-02",
            "nodeId": "nPosture02",
            "name": "server-02.net",
            "hostname": "server-02",
            "os": "linux",
            "attributes": {
                POSTURE_AUTO_UPDATE_ATTR: True,
                POSTURE_STATE_ENCRYPTED_ATTR: True,
            },
            "online": True,
            "keyExpiryDisabled": True,
        }
    )

    added_objects = []
    mock_session = AsyncMock()
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = existing_node
    mock_session.execute.return_value = mock_exec_result
    mock_session.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
    mock_session.flush = AsyncMock()

    created, updated, states = await sync_tailscale_devices([device], mock_session)
    assert created == 0
    assert updated == 1
    assert states == 1

    # Verify existing node telemetry_metadata updated
    meta = existing_node.telemetry_metadata
    assert meta["device_posture"]["is_compliant"] is True
    assert meta["device_posture"]["compliance_status"] == ComplianceStatus.COMPLIANT.value
    assert meta["ts_auto_update"] is True
    assert meta["ts_state_encrypted"] is True

    # Verify restoration audit log inserted
    audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
    restored_log = next(
        (a for a in audit_logs if a.event_type == AuditEventType.POSTURE_COMPLIANT.value),
        None,
    )
    assert restored_log is not None
    assert restored_log.event_category == EventCategory.POSTURE.value
    assert restored_log.severity == AuditSeverity.INFO.value
    assert "compliance restored" in restored_log.action.lower()


# ---------------------------------------------------------------------------
# Fleet Aggregation Service Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_fleet_posture_compliance_overview():
    """Verifies get_fleet_posture_compliance_overview computes metrics, breakdowns, and flagged devices."""
    node1 = Node(
        id="n1",
        node_id="nid-1",
        hostname="node-compliant",
        os="macos",
        telemetry_metadata={
            "device_posture": {
                "is_compliant": True,
                "compliance_status": ComplianceStatus.COMPLIANT.value,
                "ts_auto_update": True,
                "ts_state_encrypted": True,
                "violations": [],
            }
        },
    )
    node2 = Node(
        id="n2",
        node_id="nid-2",
        hostname="node-bad-update",
        os="linux",
        telemetry_metadata={
            "device_posture": {
                "is_compliant": False,
                "compliance_status": ComplianceStatus.NON_COMPLIANT.value,
                "ts_auto_update": False,
                "ts_state_encrypted": True,
                "violations": [{"attribute": POSTURE_AUTO_UPDATE_ATTR}],
            }
        },
    )
    node3 = Node(
        id="n3",
        node_id="nid-3",
        hostname="node-exempt",
        os="linux",
        telemetry_metadata={
            "device_posture": {
                "is_compliant": True,
                "compliance_status": ComplianceStatus.EXEMPT.value,
                "is_exempt": True,
                "ts_auto_update": False,
                "ts_state_encrypted": False,
                "violations": [],
            }
        },
    )

    mock_session = AsyncMock()
    mock_res = MagicMock()
    mock_res.scalars.return_value.all.return_value = [node1, node2, node3]
    mock_session.execute.return_value = mock_res

    overview = await get_fleet_posture_compliance_overview(session=mock_session)
    assert overview["total_endpoints"] == 3
    assert overview["compliant_endpoints"] == 2  # n1 + n3 (exempt counts as compliant)
    assert overview["non_compliant_endpoints"] == 1
    assert overview["exempt_endpoints"] == 1
    assert overview["compliance_rate_percent"] == 66.67

    assert overview["auto_update_summary"]["enabled_count"] == 1
    assert overview["auto_update_summary"]["disabled_count"] == 2
    assert overview["state_encrypted_summary"]["encrypted_count"] == 2
    assert overview["state_encrypted_summary"]["unencrypted_count"] == 1

    # Flagged endpoints: node2
    assert len(overview["flagged_endpoints"]) == 1
    assert overview["flagged_endpoints"][0]["hostname"] == "node-bad-update"


@pytest.mark.asyncio
async def test_get_fleet_non_compliant_endpoints_filters():
    """Verifies get_fleet_non_compliant_endpoints filters by violation category."""
    with patch(
        "app.services.posture.get_fleet_posture_compliance_overview", new_callable=AsyncMock
    ) as mock_overview:
        mock_overview.return_value = {
            "flagged_endpoints": [
                {
                    "hostname": "box-auto-update",
                    "ts_auto_update": False,
                    "ts_state_encrypted": True,
                },
                {
                    "hostname": "box-disk-unenc",
                    "ts_auto_update": True,
                    "ts_state_encrypted": False,
                },
            ]
        }

        mock_session = AsyncMock()

        # All filter
        res_all = await get_fleet_non_compliant_endpoints(mock_session, violation_filter="all")
        assert res_all["total_non_compliant"] == 2

        # Auto-update filter
        res_auto = await get_fleet_non_compliant_endpoints(mock_session, violation_filter="auto_update")
        assert res_auto["total_non_compliant"] == 1
        assert res_auto["endpoints"][0]["hostname"] == "box-auto-update"

        # State encrypted filter
        res_enc = await get_fleet_non_compliant_endpoints(mock_session, violation_filter="state_encrypted")
        assert res_enc["total_non_compliant"] == 1
        assert res_enc["endpoints"][0]["hostname"] == "box-disk-unenc"


@pytest.mark.asyncio
async def test_get_node_posture_compliance_audit():
    """Verifies get_node_posture_compliance_audit retrieves node posture and historical snapshots."""
    node = Node(
        id="node-deep-01",
        node_id="nDeep01",
        hostname="deep-audit-host",
        name="deep-audit-host.net",
        user="admin@example.com",
        os="windows",
        telemetry_metadata={
            "device_posture": {
                "is_compliant": False,
                "compliance_status": ComplianceStatus.NON_COMPLIANT.value,
                "ts_auto_update": True,
                "ts_state_encrypted": False,
                "violations": [{"attribute": POSTURE_STATE_ENCRYPTED_ATTR}],
            }
        },
    )

    state1 = NodeState(
        id="s1",
        node_id=node.id,
        recorded_at=datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc),
        is_compliant=False,
        compliance_status=ComplianceStatus.NON_COMPLIANT.value,
        disk_encryption_enabled=False,
        posture_checks={"ts_auto_update": True, "ts_state_encrypted": False},
    )

    mock_session = AsyncMock()
    mock_node_res = MagicMock()
    mock_node_res.scalar_one_or_none.return_value = node

    mock_state_res = MagicMock()
    mock_state_res.scalars.return_value.all.return_value = [state1]

    mock_session.execute = AsyncMock(side_effect=[mock_node_res, mock_state_res])

    result = await get_node_posture_compliance_audit(mock_session, "node-deep-01")
    assert result["hostname"] == "deep-audit-host"
    assert result["ts_auto_update"] is True
    assert result["ts_state_encrypted"] is False
    assert result["compliance_status"] == ComplianceStatus.NON_COMPLIANT.value
    assert result["history_count"] == 1
    assert result["history"][0]["state_id"] == "s1"

    # Test not found
    mock_session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: None))
    not_found = await get_node_posture_compliance_audit(mock_session, "nonexistent")
    assert not_found == {"error": "node_not_found", "node_id": "nonexistent"}


# ---------------------------------------------------------------------------
# API Endpoints Integration Tests (Step 10 Routes)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_v1_fleet_posture_overview_endpoints():
    """Tests GET /api/v1/fleet/posture and /api/v1/fleet/compliance endpoints."""
    with patch(
        "app.api.v1.router.get_fleet_posture_compliance_overview", new_callable=AsyncMock
    ) as mock_overview:
        mock_overview.return_value = {
            "total_endpoints": 15,
            "compliant_endpoints": 12,
            "non_compliant_endpoints": 3,
            "compliance_rate_percent": 80.0,
            "auto_update_summary": {"enabled_count": 14, "compliance_percent": 93.33},
            "state_encrypted_summary": {"encrypted_count": 13, "compliance_percent": 86.67},
            "flagged_endpoints_count": 3,
            "flagged_endpoints": [],
            "audited_at": datetime.now(timezone.utc).isoformat(),
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp1 = await client.get("/api/v1/fleet/posture")
            assert resp1.status_code == 200
            data1 = resp1.json()
            assert data1["total_endpoints"] == 15
            assert data1["compliance_rate_percent"] == 80.0

            resp2 = await client.get("/api/v1/fleet/compliance")
            assert resp2.status_code == 200
            assert resp2.json()["compliant_endpoints"] == 12


@pytest.mark.asyncio
async def test_api_v1_fleet_non_compliant_endpoints_route():
    """Tests GET /api/v1/fleet/posture/non-compliant HTTP endpoint."""
    with patch(
        "app.api.v1.router.get_fleet_non_compliant_endpoints", new_callable=AsyncMock
    ) as mock_fn:
        mock_fn.return_value = {
            "total_non_compliant": 1,
            "violation_filter": "auto_update",
            "endpoints": [
                {
                    "hostname": "legacy-box",
                    "ts_auto_update": False,
                    "violations": [{"attribute": POSTURE_AUTO_UPDATE_ATTR}],
                }
            ],
            "audited_at": datetime.now(timezone.utc).isoformat(),
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/fleet/posture/non-compliant?violation_filter=auto_update")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_non_compliant"] == 1
            assert data["endpoints"][0]["hostname"] == "legacy-box"


@pytest.mark.asyncio
async def test_api_v1_node_posture_compliance_audit_endpoint():
    """Tests GET /api/v1/fleet/nodes/{node_id}/compliance and 404 handling."""
    with patch(
        "app.api.v1.router.get_node_posture_compliance_audit", new_callable=AsyncMock
    ) as mock_fn:
        mock_fn.return_value = {
            "id": "node-target-01",
            "hostname": "target-box",
            "is_compliant": False,
            "compliance_status": "non_compliant",
            "ts_auto_update": True,
            "ts_state_encrypted": False,
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/fleet/nodes/node-target-01/compliance")
            assert resp.status_code == 200
            data = resp.json()
            assert data["hostname"] == "target-box"
            assert data["ts_state_encrypted"] is False

            # Test 404 on missing node
            mock_fn.return_value = {"error": "node_not_found", "node_id": "nonexistent"}
            resp_404 = await client.get("/api/v1/fleet/nodes/nonexistent/compliance")
            assert resp_404.status_code == 404
            assert "Node 'nonexistent' not found" in resp_404.json()["detail"]
