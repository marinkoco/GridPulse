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
from app.services.geolocation import (
    COUNTRY_COORDINATES,
    POSTURE_IP_COUNTRY_ATTR,
    POSTURE_IP_PUBLIC_ADDRESS_ATTR,
    audit_node_geolocation,
    calculate_travel_speed,
    create_location_snapshot,
    detect_impossible_travel,
    format_time_delta_human,
    get_country_coordinates,
    get_fleet_geolocation_overview,
    get_fleet_impossible_travel_events,
    get_node_geolocation_audit,
    haversine_distance,
    normalize_country_code,
    parse_node_country,
    parse_node_public_address,
)
from app.services.poller import sync_tailscale_devices


def make_device(
    device_id: str = "d-geo-1",
    hostname: str = "geo-host-1",
    os: str = "linux",
    attributes: dict | None = None,
    tags: list[str] | None = None,
    endpoints: list[str] | None = None,
    online: bool = True,
) -> TailscaleDevice:
    """Helper to construct valid TailscaleDevice instances for geolocation testing."""
    payload = {
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
    if endpoints:
        payload["clientConnectivity"] = {"endpoints": endpoints}
    return TailscaleDevice.model_validate(payload)


# ---------------------------------------------------------------------------
# Country Normalization & Geospatial Helper Tests
# ---------------------------------------------------------------------------


def test_normalize_country_code():
    """Verifies country code normalization across ISO-2, ISO-3, full names, and aliases."""
    assert normalize_country_code("US") == "US"
    assert normalize_country_code("us") == "US"
    assert normalize_country_code("USA") == "US"
    assert normalize_country_code("united states") == "US"
    assert normalize_country_code("United States") == "US"

    assert normalize_country_code("DE") == "DE"
    assert normalize_country_code("de") == "DE"
    assert normalize_country_code("Germany") == "DE"
    assert normalize_country_code("deutschland") == "DE"

    assert normalize_country_code("uk") == "GB"
    assert normalize_country_code("United Kingdom") == "GB"
    assert normalize_country_code("gbr") == "GB"

    assert normalize_country_code("Japan") == "JP"
    assert normalize_country_code("jpn") == "JP"

    assert normalize_country_code(None) is None
    assert normalize_country_code("") is None
    assert normalize_country_code("   ") is None
    assert normalize_country_code("XX") == "XX"


def test_get_country_coordinates():
    """Verifies retrieval of country centroids and names."""
    us_coords = get_country_coordinates("US")
    assert us_coords is not None
    assert round(us_coords[0], 1) == 37.1
    assert us_coords[2] == "United States"

    de_coords = get_country_coordinates("germany")
    assert de_coords is not None
    assert de_coords[2] == "Germany"

    assert get_country_coordinates(None) is None
    assert get_country_coordinates("NonexistentCountry123") is None


def test_haversine_distance():
    """Verifies great-circle distance calculation between geographic coordinates."""
    us_coords = COUNTRY_COORDINATES["US"]
    de_coords = COUNTRY_COORDINATES["DE"]
    dist = haversine_distance(us_coords[0], us_coords[1], de_coords[0], de_coords[1])
    assert 7000 < dist < 8500

    zero_dist = haversine_distance(us_coords[0], us_coords[1], us_coords[0], us_coords[1])
    assert zero_dist == 0.0


def test_calculate_travel_speed():
    """Verifies speed calculation and edge cases."""
    assert calculate_travel_speed(800.0, 3600.0) == 800.0
    assert calculate_travel_speed(400.0, 1800.0) == 800.0
    assert calculate_travel_speed(500.0, 0.0) == float("inf")
    assert calculate_travel_speed(0.0, 0.0) == 0.0


def test_format_time_delta_human():
    """Verifies formatting of durations into concise strings."""
    assert format_time_delta_human(45) == "45s"
    assert format_time_delta_human(125) == "2m 5s"
    assert format_time_delta_human(3665) == "1h 1m"
    assert format_time_delta_human(90000) == "1d 1h"


# ---------------------------------------------------------------------------
# Posture Attribute Parsing Tests
# ---------------------------------------------------------------------------


def test_parse_node_country():
    """Verifies parsing of ip:country attribute from device attributes and tags."""
    dev1 = make_device("d1", attributes={POSTURE_IP_COUNTRY_ATTR: "US"})
    assert parse_node_country(dev1) == "US"

    dev2 = make_device("d2", attributes={"ip_country": "Germany"})
    assert parse_node_country(dev2) == "DE"

    dev3 = make_device("d3", tags=["ip:country:FR"])
    assert parse_node_country(dev3) == "FR"

    dev4 = make_device("d4", tags=["tag:country:JP"])
    assert parse_node_country(dev4) == "JP"

    dev5 = make_device("d5")
    assert parse_node_country(dev5) is None


def test_parse_node_public_address():
    """Verifies parsing of ip:publicAddress attribute from attributes, tags, and endpoints."""
    dev1 = make_device("d1", attributes={POSTURE_IP_PUBLIC_ADDRESS_ATTR: "198.51.100.25"})
    assert parse_node_public_address(dev1) == "198.51.100.25"

    dev2 = make_device("d2", attributes={"public_ip": "203.0.113.50"})
    assert parse_node_public_address(dev2) == "203.0.113.50"

    dev3 = make_device("d3", tags=["ip:publicaddress:198.51.100.99"])
    assert parse_node_public_address(dev3) == "198.51.100.99"

    dev4 = make_device("d4", endpoints=["198.51.100.12:41641", "192.168.1.5:41641"])
    assert parse_node_public_address(dev4) == "198.51.100.12"

    dev5 = make_device("d5", endpoints=["10.0.0.5:41641", "192.168.1.1:41641"])
    assert parse_node_public_address(dev5) is None


# ---------------------------------------------------------------------------
# Impossible Travel Detection Logic Tests
# ---------------------------------------------------------------------------


def test_detect_impossible_travel_same_location():
    """Verifies that identical locations do not trigger impossible travel."""
    now = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)
    t0 = now - timedelta(hours=1)

    loc0 = create_location_snapshot("US", "198.51.100.1", t0)
    loc1 = create_location_snapshot("US", "198.51.100.1", now)

    result = detect_impossible_travel(loc1, loc0)
    assert result["is_impossible_travel"] is False
    assert result["distance_km"] == 0.0
    assert result["speed_kmh"] == 0.0


def test_detect_impossible_travel_normal_speed():
    """Verifies that normal travel velocity does not trigger impossible travel."""
    now = datetime(2026, 9, 8, 20, 0, tzinfo=timezone.utc)
    t0 = now - timedelta(hours=12)

    loc0 = create_location_snapshot("US", "198.51.100.1", t0)
    loc1 = create_location_snapshot("DE", "203.0.113.1", now)

    result = detect_impossible_travel(loc1, loc0, max_speed_kmh=800.0)
    assert result["is_impossible_travel"] is False
    assert result["speed_kmh"] < 800.0


def test_detect_impossible_travel_supersonic_speed():
    """Verifies that impossible travel is triggered when velocity exceeds threshold."""
    now = datetime(2026, 9, 8, 12, 10, tzinfo=timezone.utc)
    t0 = now - timedelta(minutes=10)

    loc0 = create_location_snapshot("US", "198.51.100.1", t0)
    loc1 = create_location_snapshot("JP", "203.0.113.5", now)

    result = detect_impossible_travel(loc1, loc0, max_speed_kmh=800.0)
    assert result["is_impossible_travel"] is True
    assert result["severity"] == AuditSeverity.CRITICAL.value
    assert result["speed_kmh"] > 10000.0
    assert "impossible speed" in result["reason"].lower()


def test_detect_impossible_travel_instantaneous_country_jump():
    """Verifies that an instant country transition (< 60s) triggers impossible travel."""
    now = datetime(2026, 9, 8, 12, 0, 30, tzinfo=timezone.utc)
    t0 = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)

    # With high min_distance_km, speed rule is bypassed and instantaneous country rule triggers
    loc0 = create_location_snapshot("US", "198.51.100.1", t0)
    loc1 = create_location_snapshot("CA", "198.51.100.2", now)

    result = detect_impossible_travel(loc1, loc0, min_distance_km=5000.0, min_time_seconds=60.0)
    assert result["is_impossible_travel"] is True
    assert result["severity"] == AuditSeverity.CRITICAL.value
    assert "instantaneous" in result["reason"].lower()


# ---------------------------------------------------------------------------
# Geolocation Auditor Unit Tests
# ---------------------------------------------------------------------------


def test_audit_node_geolocation_new_node():
    """Verifies audit_node_geolocation on a newly registered endpoint without history."""
    now = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)
    dev = make_device(
        "d-new",
        attributes={
            POSTURE_IP_COUNTRY_ATTR: "DE",
            POSTURE_IP_PUBLIC_ADDRESS_ATTR: "198.51.100.42",
        },
    )

    result = audit_node_geolocation(device=dev, existing_node=None, now=now)
    assert result["is_compliant"] is True
    assert result["compliance_status"] == ComplianceStatus.COMPLIANT.value
    assert result["is_impossible_travel"] is False
    assert result["country"] == "DE"
    assert result["country_name"] == "Germany"
    assert result["public_address"] == "198.51.100.42"
    assert len(result["alerts"]) == 0
    assert len(result["location_history"]) == 1
    assert result["location_history"][0]["country"] == "DE"


def test_audit_node_geolocation_impossible_travel_alert():
    """Verifies audit_node_geolocation generates alert and flags non-compliance on anomaly."""
    now = datetime(2026, 9, 8, 12, 5, tzinfo=timezone.utc)
    t0 = now - timedelta(minutes=5)

    existing_node = Node(
        id="node-geo-alert-1",
        node_id="nGeoAlert1",
        hostname="traveling-box",
        name="traveling-box.net",
        telemetry_metadata={
            "geolocation": {
                "country": "US",
                "country_name": "United States",
                "public_address": "198.51.100.1",
                "latitude": 37.0902,
                "longitude": -95.7129,
                "audited_at": t0.isoformat(),
                "current_location": {
                    "country": "US",
                    "country_name": "United States",
                    "public_address": "198.51.100.1",
                    "latitude": 37.0902,
                    "longitude": -95.7129,
                    "recorded_at": t0.isoformat(),
                },
                "location_history": [
                    {
                        "country": "US",
                        "public_address": "198.51.100.1",
                        "recorded_at": t0.isoformat(),
                    }
                ],
            }
        },
    )

    dev = make_device(
        "node-geo-alert-1",
        hostname="traveling-box",
        attributes={
            POSTURE_IP_COUNTRY_ATTR: "JP",
            POSTURE_IP_PUBLIC_ADDRESS_ATTR: "203.0.113.100",
        },
    )

    result = audit_node_geolocation(device=dev, existing_node=existing_node, now=now)
    assert result["is_compliant"] is False
    assert result["compliance_status"] == ComplianceStatus.NON_COMPLIANT.value
    assert result["is_impossible_travel"] is True
    assert result["country"] == "JP"
    assert result["previous_country"] == "US"
    assert result["distance_km"] > 9000.0

    assert len(result["alerts"]) == 1
    alert = result["alerts"][0]
    assert alert["event_type"] == AuditEventType.IMPOSSIBLE_TRAVEL.value
    assert alert["event_category"] == EventCategory.SECURITY.value
    assert alert["severity"] == AuditSeverity.CRITICAL.value
    assert "Impossible travel" in alert["title"]
    assert alert["details"]["from_country"] == "US"
    assert alert["details"]["to_country"] == "JP"
    assert alert["details"]["from_ip"] == "198.51.100.1"
    assert alert["details"]["to_ip"] == "203.0.113.100"

    assert len(result["location_history"]) == 2
    assert result["location_history"][0]["country"] == "JP"
    assert result["location_history"][1]["country"] == "US"


# ---------------------------------------------------------------------------
# Poller Pipeline Integration Tests (Step 11 Core Fix Verification)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_tailscale_devices_creates_node_with_geolocation():
    """Verifies that newly registered nodes persist geolocation data in telemetry_metadata and NodeState."""
    device = make_device(
        "node-geo-new-01",
        hostname="geo-new-device",
        attributes={
            POSTURE_IP_COUNTRY_ATTR: "GB",
            POSTURE_IP_PUBLIC_ADDRESS_ATTR: "198.51.100.77",
            "node:tsAutoUpdate": True,
            "node:tsStateEncrypted": True,
        },
        online=True,
    )

    added_objects = []
    mock_session = AsyncMock()
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_exec_result
    mock_session.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
    mock_session.flush = AsyncMock()

    created, updated, states = await sync_tailscale_devices([device], mock_session)
    assert created == 1
    assert updated == 0
    assert states == 1

    created_node = next(obj for obj in added_objects if isinstance(obj, Node))
    meta = created_node.telemetry_metadata
    assert "geolocation" in meta
    geo_meta = meta["geolocation"]
    assert geo_meta["country"] == "GB"
    assert geo_meta["country_name"] == "United Kingdom"
    assert geo_meta["public_address"] == "198.51.100.77"
    assert geo_meta["is_impossible_travel"] is False

    assert created_node.country == "GB"
    assert created_node.public_address == "198.51.100.77"
    assert created_node.geolocation["country"] == "GB"

    created_state = next(obj for obj in added_objects if isinstance(obj, NodeState))
    assert "geolocation" in created_state.telemetry_data
    assert created_state.telemetry_data["country"] == "GB"
    assert created_state.telemetry_data["public_address"] == "198.51.100.77"
    assert "geolocation" in created_state.posture_checks
    assert created_state.posture_checks["country"] == "GB"


@pytest.mark.asyncio
async def test_sync_tailscale_devices_triggers_impossible_travel_alert():
    """CRITICAL TEST: Verifies poller calls audit_node_geolocation, logs impossible travel AuditLog, and persists state."""
    eval_t0 = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    eval_t1 = datetime(2026, 9, 8, 12, 2, 0, tzinfo=timezone.utc)

    existing_node = Node(
        id="node-traveler-01",
        node_id="nTraveler01",
        hostname="traveling-laptop",
        name="traveling-laptop.net",
        os="macos",
        is_online=True,
        telemetry_metadata={
            "uptime_info": {"last_state_change": eval_t0.isoformat()},
            "security_posture": {"is_compliant": True, "compliance_status": "compliant"},
            "network_routing": {"is_compliant": True, "compliance_status": "compliant", "exposed_routes": [], "is_advertising_exit_node": False},
            "device_posture": {"is_compliant": True, "compliance_status": "compliant", "ts_auto_update": True, "ts_state_encrypted": True},
            "geolocation": {
                "country": "US",
                "country_name": "United States",
                "public_address": "198.51.100.10",
                "latitude": 37.0902,
                "longitude": -95.7129,
                "audited_at": eval_t0.isoformat(),
                "current_location": {
                    "country": "US",
                    "country_name": "United States",
                    "public_address": "198.51.100.10",
                    "latitude": 37.0902,
                    "longitude": -95.7129,
                    "recorded_at": eval_t0.isoformat(),
                },
                "location_history": [
                    {
                        "country": "US",
                        "public_address": "198.51.100.10",
                        "recorded_at": eval_t0.isoformat(),
                    }
                ],
            },
        },
    )

    device = make_device(
        "node-traveler-01",
        hostname="traveling-laptop",
        os="macos",
        attributes={
            POSTURE_IP_COUNTRY_ATTR: "DE",
            POSTURE_IP_PUBLIC_ADDRESS_ATTR: "203.0.113.88",
            "node:tsAutoUpdate": True,
            "node:tsStateEncrypted": True,
        },
        online=True,
    )

    added_objects = []
    mock_session = AsyncMock()
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = existing_node
    mock_session.execute.return_value = mock_exec_result
    mock_session.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
    mock_session.flush = AsyncMock()

    with patch("app.services.poller.datetime") as mock_dt:
        mock_dt.now.return_value = eval_t1
        mock_dt.fromisoformat = datetime.fromisoformat

        created, updated, states = await sync_tailscale_devices([device], mock_session)

    assert created == 0
    assert updated == 1
    assert states == 1

    audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
    impossible_travel_log = next(
        (a for a in audit_logs if a.event_type == AuditEventType.IMPOSSIBLE_TRAVEL.value),
        None,
    )
    assert impossible_travel_log is not None, "AuditLog for IMPOSSIBLE_TRAVEL must be inserted into database!"
    assert impossible_travel_log.node_id == existing_node.id
    assert impossible_travel_log.severity == AuditSeverity.CRITICAL.value
    assert impossible_travel_log.event_category == EventCategory.SECURITY.value
    assert "Impossible travel detected" in impossible_travel_log.action
    assert "United States (198.51.100.10)" in impossible_travel_log.message
    assert "Current location: Germany (203.0.113.88)" in impossible_travel_log.message

    details = impossible_travel_log.details
    assert details["hostname"] == "traveling-laptop"
    assert details["from_country"] == "US"
    assert details["to_country"] == "DE"
    assert details["from_ip"] == "198.51.100.10"
    assert details["to_ip"] == "203.0.113.88"
    assert details["distance_km"] > 7000.0
    assert details["speed_kmh"] > 100000.0

    meta = existing_node.telemetry_metadata
    assert "geolocation" in meta
    geo = meta["geolocation"]
    assert geo["is_impossible_travel"] is True
    assert geo["country"] == "DE"
    assert geo["public_address"] == "203.0.113.88"
    assert len(geo["location_history"]) == 2
    assert geo["location_history"][0]["country"] == "DE"
    assert geo["location_history"][1]["country"] == "US"

    state_snap = next(obj for obj in added_objects if isinstance(obj, NodeState))
    assert state_snap.is_compliant is False
    assert state_snap.compliance_status == ComplianceStatus.NON_COMPLIANT.value
    assert state_snap.posture_checks["geolocation"]["is_impossible_travel"] is True


# ---------------------------------------------------------------------------
# Fleet Aggregation Service Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_fleet_geolocation_overview():
    """Verifies get_fleet_geolocation_overview computes country distribution and impossible travel counts."""
    node1 = Node(
        id="n1",
        hostname="node-us-1",
        telemetry_metadata={
            "geolocation": {
                "country": "US",
                "public_address": "198.51.100.1",
                "is_impossible_travel": False,
            }
        },
    )
    node2 = Node(
        id="n2",
        hostname="node-us-2",
        telemetry_metadata={
            "geolocation": {
                "country": "US",
                "public_address": "198.51.100.2",
                "is_impossible_travel": False,
            }
        },
    )
    node3 = Node(
        id="n3",
        hostname="node-jp-flagged",
        telemetry_metadata={
            "geolocation": {
                "country": "JP",
                "country_name": "Japan",
                "public_address": "203.0.113.9",
                "is_impossible_travel": True,
                "distance_km": 10100.0,
                "speed_kmh": 20000.0,
                "anomaly_reason": "Impossible travel across Pacific",
            }
        },
    )

    mock_session = AsyncMock()
    mock_node_res = MagicMock()
    mock_node_res.scalars.return_value.all.return_value = [node1, node2, node3]

    mock_audit_res = MagicMock()
    mock_audit_res.scalars.return_value.all.return_value = [MagicMock(id="audit-1")]

    mock_session.execute = AsyncMock(side_effect=[mock_node_res, mock_audit_res])

    overview = await get_fleet_geolocation_overview(session=mock_session)
    assert overview["total_endpoints"] == 3
    assert overview["endpoints_with_geolocation"] == 3
    assert overview["unique_countries_count"] == 2
    assert overview["country_distribution"]["US"] == 2
    assert overview["country_distribution"]["JP"] == 1

    assert len(overview["country_breakdown"]) == 2
    assert overview["country_breakdown"][0]["country_code"] == "US"
    assert overview["country_breakdown"][0]["endpoint_count"] == 2

    assert overview["flagged_endpoints_count"] == 1
    assert overview["flagged_endpoints"][0]["hostname"] == "node-jp-flagged"
    assert overview["impossible_travel_events_count"] == 1


@pytest.mark.asyncio
async def test_get_fleet_impossible_travel_events():
    """Verifies get_fleet_impossible_travel_events retrieves structured travel logs."""
    log1 = AuditLog(
        id="log-geo-01",
        node_id="n1",
        event_type=AuditEventType.IMPOSSIBLE_TRAVEL.value,
        severity=AuditSeverity.CRITICAL.value,
        action="Impossible travel detected",
        actor="system/apscheduler",
        message="Travel alert msg",
        details={
            "hostname": "box-traveler",
            "from_country": "US",
            "to_country": "DE",
            "from_ip": "198.51.100.1",
            "to_ip": "203.0.113.1",
            "distance_km": 7800.0,
            "speed_kmh": 15000.0,
            "time_delta_human": "30m",
        },
        created_at=datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc),
    )

    mock_session = AsyncMock()
    mock_res = MagicMock()
    mock_res.scalars.return_value.all.return_value = [log1]
    mock_session.execute.return_value = mock_res

    res = await get_fleet_impossible_travel_events(mock_session, limit=20)
    assert res["total_events"] == 1
    event = res["events"][0]
    assert event["id"] == "log-geo-01"
    assert event["hostname"] == "box-traveler"
    assert event["from_country"] == "US"
    assert event["to_country"] == "DE"
    assert event["speed_kmh"] == 15000.0


@pytest.mark.asyncio
async def test_get_node_geolocation_audit():
    """Verifies get_node_geolocation_audit returns complete node geolocation and event history."""
    node = Node(
        id="node-deep-geo-01",
        node_id="nDeepGeo01",
        hostname="deep-geo-host",
        name="deep-geo-host.net",
        user="dev@example.com",
        os="linux",
        is_online=True,
        telemetry_metadata={
            "geolocation": {
                "country": "FR",
                "country_name": "France",
                "public_address": "198.51.100.55",
                "is_impossible_travel": False,
                "location_history": [{"country": "FR", "public_address": "198.51.100.55"}],
            }
        },
    )

    mock_session = AsyncMock()
    mock_node_res = MagicMock()
    mock_node_res.scalar_one_or_none.return_value = node

    mock_log_res = MagicMock()
    mock_log_res.scalars.return_value.all.return_value = []

    mock_session.execute = AsyncMock(side_effect=[mock_node_res, mock_log_res])

    result = await get_node_geolocation_audit(mock_session, "node-deep-geo-01")
    assert result["hostname"] == "deep-geo-host"
    assert result["country"] == "FR"
    assert result["country_name"] == "France"
    assert result["public_address"] == "198.51.100.55"
    assert result["is_impossible_travel"] is False
    assert len(result["location_history"]) == 1

    mock_session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: None))
    not_found = await get_node_geolocation_audit(mock_session, "nonexistent-node")
    assert not_found == {"error": "node_not_found", "node_id": "nonexistent-node"}


# ---------------------------------------------------------------------------
# API Endpoints Integration Tests (Step 11 Routes)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_v1_fleet_geolocation_overview_endpoints():
    """Tests GET /api/v1/fleet/geolocation and alias routes."""
    with patch(
        "app.api.v1.router.get_fleet_geolocation_overview", new_callable=AsyncMock
    ) as mock_overview:
        mock_overview.return_value = {
            "total_endpoints": 10,
            "endpoints_with_geolocation": 9,
            "unique_countries_count": 3,
            "country_distribution": {"US": 5, "DE": 3, "GB": 1},
            "impossible_travel_events_count": 1,
            "flagged_endpoints_count": 1,
            "flagged_endpoints": [],
            "audited_at": datetime.now(timezone.utc).isoformat(),
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp1 = await client.get("/api/v1/fleet/geolocation")
            assert resp1.status_code == 200
            data1 = resp1.json()
            assert data1["total_endpoints"] == 10
            assert data1["unique_countries_count"] == 3

            resp2 = await client.get("/api/v1/fleet/geo")
            assert resp2.status_code == 200
            assert resp2.json()["total_endpoints"] == 10


@pytest.mark.asyncio
async def test_api_v1_fleet_impossible_travel_events_endpoint():
    """Tests GET /api/v1/fleet/geolocation/impossible-travel HTTP endpoint."""
    with patch(
        "app.api.v1.router.get_fleet_impossible_travel_events", new_callable=AsyncMock
    ) as mock_fn:
        mock_fn.return_value = {
            "total_events": 1,
            "events": [
                {
                    "id": "log-001",
                    "hostname": "hacked-laptop",
                    "from_country": "US",
                    "to_country": "RU",
                    "speed_kmh": 45000.0,
                }
            ],
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/fleet/geolocation/impossible-travel?limit=10")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_events"] == 1
            assert data["events"][0]["hostname"] == "hacked-laptop"


@pytest.mark.asyncio
async def test_api_v1_node_geolocation_audit_endpoint():
    """Tests GET /api/v1/fleet/nodes/{node_id}/geolocation and 404 handling."""
    with patch(
        "app.api.v1.router.get_node_geolocation_audit", new_callable=AsyncMock
    ) as mock_fn:
        mock_fn.return_value = {
            "id": "node-geo-target-01",
            "hostname": "target-geo-box",
            "country": "JP",
            "public_address": "203.0.113.1",
            "is_impossible_travel": True,
            "anomaly_reason": "Supersonic speed across continent",
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/fleet/nodes/node-geo-target-01/geolocation")
            assert resp.status_code == 200
            data = resp.json()
            assert data["hostname"] == "target-geo-box"
            assert data["country"] == "JP"
            assert data["is_impossible_travel"] is True

            mock_fn.return_value = {"error": "node_not_found", "node_id": "nonexistent"}
            resp_404 = await client.get("/api/v1/fleet/nodes/nonexistent/geolocation")
            assert resp_404.status_code == 404
            assert "Node 'nonexistent' not found" in resp_404.json()["detail"]
