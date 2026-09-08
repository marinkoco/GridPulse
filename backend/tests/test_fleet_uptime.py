from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.audit_log import AuditLog
from app.models.enums import AuditEventType, AuditSeverity, EventCategory
from app.models.node import Node
from app.models.node_state import NodeState
from app.schemas.tailscale import TailscaleDevice, TailscaleDevicesResponse
from app.services.fleet import (
    calculate_duration_seconds,
    categorize_os_device,
    evaluate_node_state_changes,
    format_duration_human,
    get_fleet_os_distribution,
    get_fleet_uptime_overview,
    get_node_uptime_history,
    normalize_os,
    parse_node_os_attributes,
)
from app.services.poller import sync_tailscale_devices


# ---------------------------------------------------------------------------
# OS Normalization and Categorization Tests
# ---------------------------------------------------------------------------


def test_normalize_os():
    """Verifies normalize_os maps various vendor/kernel strings to canonical families."""
    assert normalize_os("Linux") == "linux"
    assert normalize_os("ubuntu") == "linux"
    assert normalize_os("Debian") == "linux"
    assert normalize_os("Darwin") == "macos"
    assert normalize_os("macOS") == "macos"
    assert normalize_os("Windows") == "windows"
    assert normalize_os("win32") == "windows"
    assert normalize_os("iOS") == "ios"
    assert normalize_os("iPhone") == "ios"
    assert normalize_os("android") == "android"
    assert normalize_os("FreeBSD") == "bsd"
    assert normalize_os("openbsd") == "bsd"
    assert normalize_os("") == "other"
    assert normalize_os(None) == "other"
    assert normalize_os("Solaris") == "other"


def test_categorize_os_device():
    """Verifies categorize_os_device accurately identifies node roles."""
    assert categorize_os_device("linux", tags=["tag:server"]) == "server"
    assert categorize_os_device("linux", tags=["tag:prod"]) == "server"
    assert categorize_os_device("macos", tags=["tag:workstation"]) == "workstation"
    assert categorize_os_device("windows", tags=["tag:desktop"]) == "workstation"
    assert categorize_os_device("linux", tags=["tag:embedded"]) == "embedded"
    assert categorize_os_device("ios", tags=[]) == "mobile"
    assert categorize_os_device("android", tags=[]) == "mobile"
    assert categorize_os_device("linux", tags=[]) == "server"
    assert categorize_os_device("macos", tags=[]) == "workstation"
    assert categorize_os_device("windows", tags=[]) == "workstation"
    assert categorize_os_device("other", tags=[]) == "unknown"


def test_parse_node_os_attributes_direct_os():
    """Verifies parse_node_os_attributes extracts OS information from standard device payload."""
    device = TailscaleDevice.model_validate(
        {
            "id": "node-1",
            "name": "srv.example.net",
            "hostname": "srv-prod-01",
            "os": "linux",
            "osVersion": "Ubuntu 22.04.3 LTS",
            "tags": ["tag:server"],
        }
    )
    result = parse_node_os_attributes(device)
    assert result["os_family"] == "linux"
    assert result["raw_os"] == "linux"
    assert result["os_version"] == "Ubuntu 22.04.3 LTS"
    assert result["node_os"] == "linux"
    assert result["os_category"] == "server"
    assert "Ubuntu 22.04.3 LTS" in result["display_name"]


def test_parse_node_os_attributes_from_node_os_attribute():
    """Verifies parse_node_os_attributes detects node:os attribute in attributes or posture tags."""
    # From attributes dict
    device1 = TailscaleDevice.model_validate(
        {
            "id": "node-2",
            "name": "mac.example.net",
            "hostname": "mac-dev-01",
            "os": "darwin",
            "attributes": {"node:os": "macos"},
            "tags": ["tag:workstation"],
        }
    )
    assert device1.get_node_os_attribute() == "macos"
    parsed1 = parse_node_os_attributes(device1)
    assert parsed1["os_family"] == "macos"
    assert parsed1["node_os"] == "macos"
    assert parsed1["os_category"] == "workstation"

    # From node:os: tag prefix
    device2 = TailscaleDevice.model_validate(
        {
            "id": "node-3",
            "name": "win.example.net",
            "hostname": "win-user-01",
            "os": "windows",
            "tags": ["node:os:windows"],
        }
    )
    assert device2.get_node_os_attribute() == "windows"
    parsed2 = parse_node_os_attributes(device2)
    assert parsed2["os_family"] == "windows"
    assert parsed2["node_os"] == "windows"


# ---------------------------------------------------------------------------
# Online Status Parsing & Uptime Duration Tests
# ---------------------------------------------------------------------------


def test_tailscale_device_check_is_online_explicit():
    """Verifies check_is_online prioritizes explicit online and connectedToControl flags."""
    # Explicit online=True overrides stale timestamp
    old_time = datetime.now(timezone.utc) - timedelta(hours=2)
    d1 = TailscaleDevice.model_validate(
        {"id": "1", "name": "d1", "hostname": "d1", "os": "linux", "online": True, "lastSeen": old_time}
    )
    assert d1.check_is_online() is True

    # Explicit online=False overrides recent timestamp
    recent_time = datetime.now(timezone.utc) - timedelta(seconds=10)
    d2 = TailscaleDevice.model_validate(
        {"id": "2", "name": "d2", "hostname": "d2", "os": "linux", "online": False, "lastSeen": recent_time}
    )
    assert d2.check_is_online() is False

    # connectedToControl=True
    d3 = TailscaleDevice.model_validate(
        {"id": "3", "name": "d3", "hostname": "d3", "os": "linux", "connectedToControl": True}
    )
    assert d3.check_is_online() is True


def test_tailscale_device_check_is_online_last_seen_threshold():
    """Verifies check_is_online falls back to last_seen within threshold."""
    now = datetime.now(timezone.utc)

    # 60 seconds ago -> online (within default 300s)
    d1 = TailscaleDevice.model_validate(
        {"id": "1", "name": "d1", "hostname": "d1", "os": "linux", "lastSeen": now - timedelta(seconds=60)}
    )
    assert d1.check_is_online() is True

    # 400 seconds ago -> offline (exceeds default 300s)
    d2 = TailscaleDevice.model_validate(
        {"id": "2", "name": "d2", "hostname": "d2", "os": "linux", "lastSeen": now - timedelta(seconds=400)}
    )
    assert d2.check_is_online() is False

    # last_seen is None -> offline
    d3 = TailscaleDevice.model_validate(
        {"id": "3", "name": "d3", "hostname": "d3", "os": "linux", "lastSeen": None}
    )
    assert d3.check_is_online() is False


def test_format_duration_human():
    """Verifies duration in seconds converts to human-readable time strings."""
    assert format_duration_human(30) == "< 1m"
    assert format_duration_human(90) == "1m 30s"
    assert format_duration_human(120) == "2m"
    assert format_duration_human(3665) == "1h 1m"
    assert format_duration_human(7200) == "2h"
    assert format_duration_human(90000) == "1d 1h"
    assert format_duration_human(172800) == "2d"


def test_calculate_duration_seconds():
    """Verifies timezone-aware duration calculation."""
    now = datetime.now(timezone.utc)
    earlier = now - timedelta(minutes=15)
    assert abs(calculate_duration_seconds(earlier, now) - 900.0) < 1.0
    assert calculate_duration_seconds(None) == 0.0


# ---------------------------------------------------------------------------
# State Change Detection Tests
# ---------------------------------------------------------------------------


def test_evaluate_node_state_changes_online_transition():
    """Verifies evaluate_node_state_changes detects online to offline transition."""
    node = Node(
        id="node-101",
        hostname="web-app-01",
        os="linux",
        os_version="Ubuntu 22.04",
        is_online=True,
        last_seen=datetime.now(timezone.utc) - timedelta(hours=1),
        telemetry_metadata={
            "uptime_info": {
                "last_state_change": (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            }
        },
    )
    # Incoming device is offline
    device = TailscaleDevice.model_validate(
        {
            "id": "node-101",
            "name": "web.net",
            "hostname": "web-app-01",
            "os": "linux",
            "osVersion": "Ubuntu 22.04",
            "online": False,
        }
    )
    changes = evaluate_node_state_changes(node, device)
    assert changes["is_online_changed"] is True
    assert changes["was_online"] is True
    assert changes["now_online"] is False
    assert changes["duration_seconds"] > 80000  # approximately 24h
    assert "1d" in changes["duration_human"]
    assert changes["is_os_changed"] is False


def test_evaluate_node_state_changes_os_upgrade():
    """Verifies evaluate_node_state_changes detects OS version update."""
    node = Node(
        id="node-102",
        hostname="db-primary",
        os="linux",
        os_version="Debian 11",
        is_online=True,
        last_seen=datetime.now(timezone.utc),
    )
    device = TailscaleDevice.model_validate(
        {
            "id": "node-102",
            "name": "db.net",
            "hostname": "db-primary",
            "os": "linux",
            "osVersion": "Debian 12",
            "online": True,
        }
    )
    changes = evaluate_node_state_changes(node, device)
    assert changes["is_online_changed"] is False
    assert changes["is_os_changed"] is True
    assert changes["was_os_version"] == "Debian 11"
    assert changes["new_os_version"] == "Debian 12"


def test_evaluate_node_state_changes_client_version_upgrade():
    """Verifies evaluate_node_state_changes detects client version updates."""
    node = Node(
        id="node-103",
        hostname="worker-01",
        os="linux",
        client_version="1.54.0",
        is_online=True,
        last_seen=datetime.now(timezone.utc),
    )
    device = TailscaleDevice.model_validate(
        {
            "id": "node-103",
            "name": "worker.net",
            "hostname": "worker-01",
            "os": "linux",
            "clientVersion": "1.56.0",
            "online": True,
        }
    )
    changes = evaluate_node_state_changes(node, device)
    assert changes["is_client_changed"] is True
    assert changes["was_client_version"] == "1.54.0"
    assert changes["new_client_version"] == "1.56.0"


# ---------------------------------------------------------------------------
# Database Synchronization & State Change Logging Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_tailscale_devices_logs_offline_transition():
    """Verifies sync_tailscale_devices creates NODE_OFFLINE audit log on transition."""
    existing_node = Node(
        id="node-100",
        node_id="n100CNTRL",
        hostname="server-01",
        name="server-01.tailnet.net",
        os="linux",
        os_version="Ubuntu 22.04",
        is_online=True,
        last_seen=datetime.now(timezone.utc) - timedelta(hours=3),
        telemetry_metadata={
            "uptime_info": {
                "last_state_change": (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
            }
        },
    )

    device = TailscaleDevice.model_validate(
        {
            "id": "node-100",
            "nodeId": "n100CNTRL",
            "name": "server-01.tailnet.net",
            "hostname": "server-01",
            "os": "linux",
            "osVersion": "Ubuntu 22.04",
            "online": False,
            "addresses": ["100.64.0.5"],
            "lastSeen": datetime.now(timezone.utc) - timedelta(hours=3),
        }
    )

    added_objects = []
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = existing_node
    mock_session.execute.return_value = mock_exec_result
    mock_session.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
    mock_session.flush = AsyncMock()

    created, updated, states = await sync_tailscale_devices([device], mock_session)
    assert created == 0
    assert updated == 1
    assert states == 1
    assert existing_node.is_online is False

    # Check AuditLog entries
    audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
    offline_event = next(
        (a for a in audit_logs if a.event_type == AuditEventType.NODE_OFFLINE.value), None
    )
    assert offline_event is not None
    assert offline_event.severity == AuditSeverity.WARNING.value
    assert offline_event.event_category == EventCategory.DEVICE.value
    assert offline_event.actor == "system/apscheduler"
    assert offline_event.details["previous_state"] == "online"
    assert offline_event.details["new_state"] == "offline"
    assert offline_event.details["transition_type"] == "online_to_offline"
    assert "5h" in offline_event.details["duration_human"]


@pytest.mark.asyncio
async def test_sync_tailscale_devices_logs_os_changed():
    """Verifies sync_tailscale_devices creates NODE_OS_CHANGED audit log when OS upgrades."""
    existing_node = Node(
        id="node-200",
        node_id="n200CNTRL",
        hostname="macbook-dev",
        name="macbook-dev.tailnet.net",
        os="macos",
        os_version="13.6 Ventura",
        is_online=True,
        last_seen=datetime.now(timezone.utc),
    )

    device = TailscaleDevice.model_validate(
        {
            "id": "node-200",
            "nodeId": "n200CNTRL",
            "name": "macbook-dev.tailnet.net",
            "hostname": "macbook-dev",
            "os": "macOS",
            "osVersion": "14.4 Sonoma",
            "online": True,
            "addresses": ["100.64.0.20"],
        }
    )

    added_objects = []
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = existing_node
    mock_session.execute.return_value = mock_exec_result
    mock_session.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
    mock_session.flush = AsyncMock()

    created, updated, states = await sync_tailscale_devices([device], mock_session)
    assert updated == 1
    assert existing_node.os_version == "14.4 Sonoma"

    audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
    os_event = next(
        (a for a in audit_logs if a.event_type == AuditEventType.NODE_OS_CHANGED.value), None
    )
    assert os_event is not None
    assert os_event.details["previous_os_version"] == "13.6 Ventura"
    assert os_event.details["new_os_version"] == "14.4 Sonoma"


@pytest.mark.asyncio
async def test_sync_tailscale_devices_logs_online_transition():
    """Verifies sync_tailscale_devices creates NODE_ONLINE audit log when an offline node comes online."""
    existing_node = Node(
        id="node-201",
        node_id="n201CNTRL",
        hostname="backup-srv",
        name="backup-srv.tailnet.net",
        os="linux",
        os_version="Ubuntu 22.04",
        is_online=False,
        last_seen=datetime.now(timezone.utc) - timedelta(days=2),
        telemetry_metadata={
            "uptime_info": {
                "last_state_change": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
                "state_change_count": 3,
            }
        },
    )

    device = TailscaleDevice.model_validate(
        {
            "id": "node-201",
            "nodeId": "n201CNTRL",
            "name": "backup-srv.tailnet.net",
            "hostname": "backup-srv",
            "os": "linux",
            "osVersion": "Ubuntu 22.04",
            "online": True,
            "addresses": ["100.64.0.21"],
            "lastSeen": datetime.now(timezone.utc),
        }
    )

    added_objects = []
    mock_session = AsyncMock()
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = existing_node
    mock_session.execute = AsyncMock(return_value=mock_exec_result)
    mock_session.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
    mock_session.flush = AsyncMock()

    created, updated, states = await sync_tailscale_devices([device], mock_session)
    assert updated == 1
    assert existing_node.is_online is True

    audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
    online_event = next(
        (a for a in audit_logs if a.event_type == AuditEventType.NODE_ONLINE.value), None
    )
    assert online_event is not None
    assert online_event.severity == AuditSeverity.INFO.value
    assert online_event.details["previous_state"] == "offline"
    assert online_event.details["new_state"] == "online"
    assert online_event.details["transition_type"] == "offline_to_online"
    assert "2d" in online_event.details["duration_human"]


@pytest.mark.asyncio
async def test_sync_tailscale_devices_logs_client_updated():
    """Verifies sync_tailscale_devices creates NODE_CLIENT_UPDATED audit log when client version changes."""
    existing_node = Node(
        id="node-202",
        node_id="n202CNTRL",
        hostname="ci-runner",
        name="ci-runner.tailnet.net",
        os="linux",
        client_version="1.54.0",
        is_online=True,
        last_seen=datetime.now(timezone.utc),
    )

    device = TailscaleDevice.model_validate(
        {
            "id": "node-202",
            "nodeId": "n202CNTRL",
            "name": "ci-runner.tailnet.net",
            "hostname": "ci-runner",
            "os": "linux",
            "clientVersion": "1.58.2",
            "online": True,
            "addresses": ["100.64.0.22"],
        }
    )

    added_objects = []
    mock_session = AsyncMock()
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = existing_node
    mock_session.execute = AsyncMock(return_value=mock_exec_result)
    mock_session.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
    mock_session.flush = AsyncMock()

    created, updated, states = await sync_tailscale_devices([device], mock_session)
    assert updated == 1
    assert existing_node.client_version == "1.58.2"

    audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
    client_event = next(
        (a for a in audit_logs if a.event_type == AuditEventType.NODE_CLIENT_UPDATED.value), None
    )
    assert client_event is not None
    assert client_event.details["previous_client_version"] == "1.54.0"
    assert client_event.details["new_client_version"] == "1.58.2"


@pytest.mark.asyncio
async def test_sync_tailscale_devices_new_node_registration():
    """Verifies newly discovered node creates NODE_CREATED audit log and NodeState snapshot."""
    device = TailscaleDevice.model_validate(
        {
            "id": "node-new-300",
            "nodeId": "n300CNTRL",
            "name": "db-cluster-01.tailnet.net",
            "hostname": "db-cluster-01",
            "os": "Linux",
            "osVersion": "Debian 12",
            "clientVersion": "1.56.0",
            "addresses": ["100.64.0.99"],
            "online": True,
            "tags": ["tag:server", "tag:prod"],
        }
    )

    added_objects = []
    mock_session = AsyncMock()
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_exec_result)
    mock_session.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
    mock_session.flush = AsyncMock()

    created, updated, states = await sync_tailscale_devices([device], mock_session)
    assert created == 1
    assert updated == 0
    assert states == 1

    # Verify Node ORM created with canonical OS
    created_node = next(obj for obj in added_objects if isinstance(obj, Node))
    assert created_node.os == "linux"
    assert created_node.is_online is True
    assert created_node.telemetry_metadata["os_attributes"]["os_category"] == "server"

    # Verify NodeState snapshot
    created_state = next(obj for obj in added_objects if isinstance(obj, NodeState))
    assert created_state.is_online is True
    assert created_state.telemetry_data["os_family"] == "linux"
    assert created_state.telemetry_data["os_category"] == "server"

    # Verify audit log
    audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
    creation_event = next(
        (a for a in audit_logs if a.event_type == AuditEventType.NODE_CREATED.value), None
    )
    assert creation_event is not None
    assert creation_event.details["os"] == "linux"
    assert creation_event.details["raw_os"] == "Linux"


# ---------------------------------------------------------------------------
# Fleet Analytics Functions Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_fleet_os_distribution():
    """Verifies get_fleet_os_distribution aggregates OS families and version distributions."""
    nodes = [
        Node(id="1", hostname="srv1", os="linux", os_version="Ubuntu 22.04", is_online=True, tags=["tag:server"]),
        Node(id="2", hostname="srv2", os="linux", os_version="Ubuntu 24.04", is_online=True, tags=["tag:server"]),
        Node(id="3", hostname="srv3", os="linux", os_version="Ubuntu 22.04", is_online=False, tags=["tag:server"]),
        Node(id="4", hostname="mac1", os="macos", os_version="14.4", is_online=True, tags=["tag:workstation"]),
        Node(id="5", hostname="win1", os="windows", os_version="11 Pro", is_online=False, tags=["tag:workstation"]),
    ]

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = nodes
    mock_session.execute.return_value = mock_result

    data = await get_fleet_os_distribution(mock_session)
    assert data["total_devices"] == 5
    assert data["online_devices"] == 3
    assert data["offline_devices"] == 2
    assert data["fleet_uptime_percentage"] == 60.0

    # OS Breakdown
    assert "linux" in data["by_os"]
    assert data["by_os"]["linux"]["count"] == 3
    assert data["by_os"]["linux"]["online"] == 2
    assert data["by_os"]["linux"]["offline"] == 1
    assert data["by_os"]["linux"]["versions"]["Ubuntu 22.04"] == 2
    assert data["by_os"]["linux"]["versions"]["Ubuntu 24.04"] == 1

    assert "macos" in data["by_os"]
    assert data["by_os"]["macos"]["count"] == 1
    assert data["by_os"]["macos"]["online"] == 1

    # Categories
    assert data["by_category"]["server"] == 3
    assert data["by_category"]["workstation"] == 2


@pytest.mark.asyncio
async def test_get_fleet_uptime_overview():
    """Verifies get_fleet_uptime_overview outputs fleet-wide uptime streaks."""
    now = datetime.now(timezone.utc)
    nodes = [
        Node(
            id="1",
            hostname="prod-api",
            os="linux",
            is_online=True,
            last_seen=now,
            telemetry_metadata={
                "uptime_info": {"last_state_change": (now - timedelta(days=10)).isoformat()}
            },
        ),
        Node(
            id="2",
            hostname="dev-box",
            os="linux",
            is_online=False,
            last_seen=now - timedelta(hours=4),
            telemetry_metadata={
                "uptime_info": {"last_state_change": (now - timedelta(hours=4)).isoformat()}
            },
        ),
    ]

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = nodes
    mock_session.execute.return_value = mock_result

    data = await get_fleet_uptime_overview(mock_session)
    assert data["total_nodes"] == 2
    assert data["online_nodes"] == 1
    assert data["offline_nodes"] == 1
    assert data["fleet_uptime_percentage"] == 50.0

    nodes_list = data["nodes"]
    assert len(nodes_list) == 2
    prod_node = next(n for n in nodes_list if n["hostname"] == "prod-api")
    assert prod_node["is_online"] is True
    assert "10d" in prod_node["streak_duration_human"]


@pytest.mark.asyncio
async def test_get_node_uptime_history():
    """Verifies get_node_uptime_history computes historical uptime ratio from snapshots."""
    node = Node(id="node-77", hostname="bastion-host", os="linux", is_online=True)
    states = [
        NodeState(id="s1", node_id="node-77", is_online=True, recorded_at=datetime.now(timezone.utc)),
        NodeState(id="s2", node_id="node-77", is_online=True, recorded_at=datetime.now(timezone.utc)),
        NodeState(id="s3", node_id="node-77", is_online=False, recorded_at=datetime.now(timezone.utc)),
        NodeState(id="s4", node_id="node-77", is_online=True, recorded_at=datetime.now(timezone.utc)),
    ]

    mock_session = AsyncMock()
    node_result = MagicMock()
    node_result.scalar_one_or_none.return_value = node

    state_result = MagicMock()
    state_result.scalars.return_value.all.return_value = states

    mock_session.execute.side_effect = [node_result, state_result]

    history = await get_node_uptime_history(mock_session, "node-77")
    assert history["node_id"] == "node-77"
    assert history["total_snapshots_evaluated"] == 4
    assert history["online_snapshots"] == 3
    assert history["uptime_percentage"] == 75.0
    assert len(history["history"]) == 4


# ---------------------------------------------------------------------------
# API Endpoints Integration Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_v1_fleet_os_distribution_endpoint():
    """Tests GET /api/v1/fleet/os-distribution route returns 200 with schema."""
    with patch("app.api.v1.router.get_fleet_os_distribution", new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = {
            "total_devices": 10,
            "online_devices": 8,
            "offline_devices": 2,
            "fleet_uptime_percentage": 80.0,
            "by_os": {
                "linux": {"count": 6, "online": 5, "offline": 1, "percentage": 60.0},
                "macos": {"count": 4, "online": 3, "offline": 1, "percentage": 40.0},
            },
            "by_category": {"server": 6, "workstation": 4},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/fleet/os-distribution")
            assert response.status_code == 200
            data = response.json()
            assert data["total_devices"] == 10
            assert "linux" in data["by_os"]
            assert data["fleet_uptime_percentage"] == 80.0


@pytest.mark.asyncio
async def test_api_v1_fleet_uptime_endpoint():
    """Tests GET /api/v1/fleet/uptime route returns 200 with node streaks."""
    with patch("app.api.v1.router.get_fleet_uptime_overview", new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = {
            "total_nodes": 2,
            "online_nodes": 2,
            "offline_nodes": 0,
            "fleet_uptime_percentage": 100.0,
            "nodes": [
                {
                    "id": "node-1",
                    "hostname": "core-gw",
                    "os": "linux",
                    "is_online": True,
                    "streak_duration_human": "5d 2h",
                }
            ],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/fleet/uptime")
            assert response.status_code == 200
            data = response.json()
            assert data["total_nodes"] == 2
            assert len(data["nodes"]) == 1
            assert data["nodes"][0]["streak_duration_human"] == "5d 2h"


@pytest.mark.asyncio
async def test_api_v1_node_uptime_history_endpoint():
    """Tests GET /api/v1/fleet/nodes/{node_id}/uptime for 200 and 404 responses."""
    with patch("app.api.v1.router.get_node_uptime_history", new_callable=AsyncMock) as mock_fn:
        # Success case
        mock_fn.return_value = {
            "node_id": "node-1",
            "hostname": "test-box",
            "os": "linux",
            "is_online": True,
            "total_snapshots_evaluated": 10,
            "online_snapshots": 10,
            "uptime_percentage": 100.0,
            "history": [],
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/fleet/nodes/node-1/uptime")
            assert resp.status_code == 200
            assert resp.json()["uptime_percentage"] == 100.0

            # Not found case
            mock_fn.return_value = {"error": "node_not_found", "node_id": "nonexistent"}
            resp_404 = await client.get("/api/v1/fleet/nodes/nonexistent/uptime")
            assert resp_404.status_code == 404
            assert "Node 'nonexistent' not found" in resp_404.json()["detail"]
