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
from app.services.network_auditor import (
    EXIT_NODE_ROUTES,
    audit_node_network_routing,
    classify_route,
    evaluate_derp_connectivity,
    get_fleet_derp_overview,
    get_fleet_network_routing_overview,
    get_node_network_routing_audit,
    is_exit_node_authorized,
    is_exit_node_route,
    is_valid_cidr,
    parse_node_exposed_routes,
)
from app.services.poller import sync_tailscale_devices


# ---------------------------------------------------------------------------
# Route Classification & CIDR Validation Tests
# ---------------------------------------------------------------------------


def test_is_exit_node_route():
    """Verifies is_exit_node_route detects IPv4 and IPv6 default exit routes."""
    assert is_exit_node_route("0.0.0.0/0") is True
    assert is_exit_node_route("::/0") is True
    assert is_exit_node_route("  0.0.0.0/0  ") is True
    assert is_exit_node_route("10.0.0.0/8") is False
    assert is_exit_node_route("192.168.1.0/24") is False
    assert is_exit_node_route("") is False
    assert is_exit_node_route(None) is False


def test_is_valid_cidr():
    """Verifies is_valid_cidr distinguishes valid IPv4/IPv6 CIDRs from invalid inputs."""
    assert is_valid_cidr("192.168.1.0/24") is True
    assert is_valid_cidr("10.0.0.0/8") is True
    assert is_valid_cidr("0.0.0.0/0") is True
    assert is_valid_cidr("::/0") is True
    assert is_valid_cidr("2001:db8::/32") is True
    assert is_valid_cidr("fd7a:115c:a1e0::/48") is True

    assert is_valid_cidr("999.999.999.999/24") is False
    assert is_valid_cidr("invalid-cidr") is False
    assert is_valid_cidr("") is False
    assert is_valid_cidr(None) is False


def test_classify_route():
    """Verifies classify_route categorizes exit nodes, private subnets, and public subnets."""
    # Exit node IPv4
    r_exit4 = classify_route("0.0.0.0/0")
    assert r_exit4["is_valid"] is True
    assert r_exit4["is_exit_node"] is True
    assert r_exit4["category"] == "exit_node"
    assert r_exit4["ip_version"] == 4

    # Exit node IPv6
    r_exit6 = classify_route("::/0")
    assert r_exit6["is_valid"] is True
    assert r_exit6["is_exit_node"] is True
    assert r_exit6["category"] == "exit_node"
    assert r_exit6["ip_version"] == 6

    # Private subnet RFC 1918
    r_priv = classify_route("10.100.0.0/16")
    assert r_priv["is_valid"] is True
    assert r_priv["is_exit_node"] is False
    assert r_priv["category"] == "private_subnet"
    assert r_priv["is_private"] is True

    # Public subnet
    r_pub = classify_route("1.1.1.0/24")
    assert r_pub["is_valid"] is True
    assert r_pub["is_exit_node"] is False
    assert r_pub["category"] == "public_subnet"
    assert r_pub["is_private"] is False

    # Invalid route
    r_inv = classify_route("bad-network/33")
    assert r_inv["is_valid"] is False
    assert r_inv["category"] == "invalid"


def test_parse_node_exposed_routes():
    """Verifies parse_node_exposed_routes extracts routes from device exposedRoutes, attributes, and tags."""
    # From top-level exposedRoutes
    d1 = TailscaleDevice.model_validate(
        {
            "id": "dev-1",
            "name": "gw-01",
            "hostname": "gw-01",
            "os": "linux",
            "exposedRoutes": ["0.0.0.0/0", "192.168.1.0/24"],
        }
    )
    res1 = parse_node_exposed_routes(d1)
    assert res1["is_advertising_exit_node"] is True
    assert "0.0.0.0/0" in res1["exit_node_routes"]
    assert "192.168.1.0/24" in res1["subnet_routes"]
    assert res1["total_routes_count"] == 2

    # From device attributes
    d2 = TailscaleDevice.model_validate(
        {
            "id": "dev-2",
            "name": "srv-01",
            "hostname": "srv-01",
            "os": "linux",
            "attributes": {"exposedRoutes": ["10.0.0.0/8", "172.16.0.0/12"]},
        }
    )
    res2 = parse_node_exposed_routes(d2)
    assert res2["is_advertising_exit_node"] is False
    assert len(res2["subnet_routes"]) == 2

    # From device tags
    d3 = TailscaleDevice.model_validate(
        {
            "id": "dev-3",
            "name": "tag-node",
            "hostname": "tag-node",
            "os": "linux",
            "tags": ["tag:server", "route:10.50.0.0/16"],
        }
    )
    res3 = parse_node_exposed_routes(d3)
    assert "10.50.0.0/16" in res3["subnet_routes"]


# ---------------------------------------------------------------------------
# Exit Node Authorization Tests
# ---------------------------------------------------------------------------


def test_is_exit_node_authorized_with_tags():
    """Verifies authorization when node has approved exit node tags."""
    device = TailscaleDevice.model_validate(
        {
            "id": "dev-exit-1",
            "name": "gw-exit",
            "hostname": "gateway-node",
            "os": "linux",
            "tags": ["tag:exit-node", "tag:server"],
            "exposedRoutes": ["0.0.0.0/0"],
        }
    )
    authorized, reason = is_exit_node_authorized(device)
    assert authorized is True
    assert "tag:exit-node" in reason


def test_is_exit_node_authorized_with_hostname_whitelist():
    """Verifies authorization when node matches approved hostname whitelist."""
    device = TailscaleDevice.model_validate(
        {
            "id": "dev-exit-2",
            "name": "approved-vpn",
            "hostname": "approved-vpn-01",
            "os": "linux",
            "tags": [],
            "exposedRoutes": ["0.0.0.0/0"],
        }
    )
    authorized, reason = is_exit_node_authorized(
        device, authorized_hostnames=["approved-vpn-01"]
    )
    assert authorized is True
    assert "approved-vpn-01" in reason


def test_is_exit_node_unauthorized():
    """Verifies unauthorized exit node advertisement is rejected."""
    device = TailscaleDevice.model_validate(
        {
            "id": "dev-rogue-1",
            "name": "rogue-laptop",
            "hostname": "rogue-user-laptop",
            "os": "macos",
            "tags": ["tag:workstation"],
            "exposedRoutes": ["0.0.0.0/0"],
        }
    )
    authorized, reason = is_exit_node_authorized(device)
    assert authorized is False
    assert "not authorized" in reason


def test_is_exit_node_authorized_when_allow_untagged():
    """Verifies allow_untagged policy permits exit nodes without tags."""
    device = TailscaleDevice.model_validate(
        {
            "id": "dev-untagged",
            "name": "generic-node",
            "hostname": "generic-node",
            "os": "linux",
            "tags": [],
            "exposedRoutes": ["0.0.0.0/0"],
        }
    )
    authorized, reason = is_exit_node_authorized(device, allow_untagged=True)
    assert authorized is True
    assert "allow_untagged_exit_nodes=True" in reason


# ---------------------------------------------------------------------------
# DERP Connectivity & Fallback Tests
# ---------------------------------------------------------------------------


def test_evaluate_derp_connectivity_direct():
    """Verifies evaluate_derp_connectivity recognizes direct peer-to-peer connection."""
    device = TailscaleDevice.model_validate(
        {
            "id": "dev-direct",
            "name": "srv.net",
            "hostname": "direct-server",
            "os": "linux",
            "online": True,
            "clientConnectivity": {
                "endpoints": ["198.51.100.1:41641", "203.0.113.5:41641"],
                "derp": "fra",
                "latency": {"fra": {"latencyMs": 25.0, "preferred": True}},
            },
        }
    )
    res = evaluate_derp_connectivity(device)
    assert res["is_online"] is True
    assert res["connection_type"] == "direct"
    assert res["is_derp_fallback"] is False
    assert res["endpoints_count"] == 2
    assert res["derp_region"] == "fra"


def test_evaluate_derp_connectivity_fallback():
    """Verifies evaluate_derp_connectivity detects DERP fallback when direct endpoints are empty."""
    device = TailscaleDevice.model_validate(
        {
            "id": "dev-relay",
            "name": "srv.net",
            "hostname": "relayed-server",
            "os": "linux",
            "online": True,
            "clientConnectivity": {
                "endpoints": [],
                "derp": "fra",
                "latency": {"fra": {"latencyMs": 85.0, "preferred": True}},
            },
        }
    )
    res = evaluate_derp_connectivity(device)
    assert res["is_online"] is True
    assert res["connection_type"] == "derp_fallback"
    assert res["is_derp_fallback"] is True
    assert "NAT traversal / firewall" in res["fallback_reason"]


def test_evaluate_derp_connectivity_non_preferred_relay():
    """Verifies evaluate_derp_connectivity flags routing via non-preferred DERP region."""
    device = TailscaleDevice.model_validate(
        {
            "id": "dev-nonpref",
            "name": "srv.net",
            "hostname": "distant-relay",
            "os": "linux",
            "online": True,
            "clientConnectivity": {
                "endpoints": ["10.0.0.1:41641"],
                "derp": "syd",
                "latency": {
                    "fra": {"latencyMs": 20.0, "preferred": True},
                    "syd": {"latencyMs": 350.0, "preferred": False},
                },
            },
        }
    )
    res = evaluate_derp_connectivity(device)
    assert res["is_using_non_preferred_derp"] is True
    assert res["is_derp_fallback"] is True
    assert res["preferred_derp"] == "fra"


# ---------------------------------------------------------------------------
# Node Network Routing Auditor (audit_node_network_routing) Tests
# ---------------------------------------------------------------------------


def test_audit_node_network_routing_unauthorized_exit():
    """Verifies audit_node_network_routing flags unauthorized exit nodes and generates structured alert."""
    device = TailscaleDevice.model_validate(
        {
            "id": "node-unauth-exit",
            "name": "rogue-gateway.net",
            "hostname": "rogue-gateway",
            "os": "linux",
            "tags": ["tag:server"],
            "exposedRoutes": ["0.0.0.0/0", "10.0.0.0/16"],
            "online": True,
        }
    )
    report = audit_node_network_routing(device)
    assert report["is_advertising_exit_node"] is True
    assert report["exit_node_audit"]["is_unauthorized_exit_node"] is True
    assert report["compliance_status"] == ComplianceStatus.NON_COMPLIANT.value
    assert report["is_compliant"] is False

    # Check alert structure
    assert len(report["alerts"]) >= 1
    exit_alert = next((a for a in report["alerts"] if a["type"] == "unauthorized_exit_node"), None)
    assert exit_alert is not None
    assert exit_alert["severity"] == AuditSeverity.HIGH.value
    assert exit_alert["event_type"] == AuditEventType.UNAUTHORIZED_EXIT_NODE.value
    assert exit_alert["event_category"] == EventCategory.NETWORK.value
    assert "rogue-gateway" in exit_alert["title"]


def test_audit_node_network_routing_state_transitions():
    """Verifies audit_node_network_routing detects transitions from direct to DERP fallback."""
    existing_node = Node(
        id="node-state-trans",
        hostname="app-worker",
        is_online=True,
        telemetry_metadata={
            "network_routing": {
                "exposed_routes": [],
                "derp_info": {"is_derp_fallback": False, "derp_region": "fra"},
                "exit_node_audit": {"is_unauthorized_exit_node": False},
            }
        },
    )

    incoming_device = TailscaleDevice.model_validate(
        {
            "id": "node-state-trans",
            "name": "app-worker.net",
            "hostname": "app-worker",
            "os": "linux",
            "online": True,
            "clientConnectivity": {
                "endpoints": [],
                "derp": "fra",
            },
        }
    )

    report = audit_node_network_routing(incoming_device, existing_node=existing_node)
    assert report["derp_info"]["is_derp_fallback"] is True
    assert report["state_changes"]["is_new_derp_fallback"] is True

    fallback_alert = next((a for a in report["alerts"] if a["type"] == "derp_fallback"), None)
    assert fallback_alert is not None
    assert fallback_alert["event_type"] == AuditEventType.DERP_FALLBACK.value
    assert fallback_alert["severity"] == AuditSeverity.WARNING.value


# ---------------------------------------------------------------------------
# Poller Integration & Alert Triggering Database Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_tailscale_devices_triggers_unauthorized_exit_node_alert():
    """Verifies sync_tailscale_devices persists network_routing to telemetry_metadata and creates AuditLog for unauthorized exit node."""
    device = TailscaleDevice.model_validate(
        {
            "id": "node-exit-rogue-01",
            "nodeId": "nExitCNTRL",
            "name": "rogue-gw.net",
            "hostname": "rogue-gw",
            "os": "linux",
            "tags": ["tag:server"],
            "exposedRoutes": ["0.0.0.0/0", "192.168.1.0/24"],
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

    # 1. Verify telemetry_metadata contains network_routing report
    created_node = next(obj for obj in added_objects if isinstance(obj, Node))
    assert "network_routing" in created_node.telemetry_metadata
    routing_meta = created_node.telemetry_metadata["network_routing"]
    assert routing_meta["is_advertising_exit_node"] is True
    assert routing_meta["exit_node_audit"]["is_unauthorized_exit_node"] is True
    assert "0.0.0.0/0" in created_node.telemetry_metadata["exposed_routes"]
    assert created_node.telemetry_metadata["is_exit_node"] is True

    # 2. Verify NodeState snapshot records routing
    created_state = next(obj for obj in added_objects if isinstance(obj, NodeState))
    assert created_state.compliance_status == ComplianceStatus.NON_COMPLIANT.value
    assert created_state.is_compliant is False
    assert "network_routing" in created_state.posture_checks
    assert "network_routing" in created_state.telemetry_data

    # 3. Verify AuditLog record was inserted for the unauthorized exit node alert
    audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
    exit_log = next(
        (a for a in audit_logs if a.event_type == AuditEventType.UNAUTHORIZED_EXIT_NODE.value),
        None,
    )
    assert exit_log is not None
    assert exit_log.severity == AuditSeverity.HIGH.value
    assert exit_log.event_category == EventCategory.NETWORK.value
    assert "Unauthorized exit node" in exit_log.action
    assert "0.0.0.0/0" in exit_log.details["exit_node_routes"]


@pytest.mark.asyncio
async def test_sync_tailscale_devices_triggers_derp_fallback_alert():
    """Verifies sync_tailscale_devices creates DERP_FALLBACK AuditLog on new fallback transition."""
    existing_node = Node(
        id="node-relay-02",
        node_id="nRelayCNTRL",
        hostname="relay-candidate",
        name="relay-candidate.net",
        os="linux",
        is_online=True,
        telemetry_metadata={
            "uptime_info": {"last_state_change": datetime.now(timezone.utc).isoformat()},
            "network_routing": {
                "derp_info": {"is_derp_fallback": False, "derp_region": "fra"},
                "exit_node_audit": {"is_unauthorized_exit_node": False},
            },
        },
    )

    device = TailscaleDevice.model_validate(
        {
            "id": "node-relay-02",
            "nodeId": "nRelayCNTRL",
            "name": "relay-candidate.net",
            "hostname": "relay-candidate",
            "os": "linux",
            "online": True,
            "clientConnectivity": {
                "endpoints": [],
                "derp": "fra",
            },
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
    assert updated == 1

    # Verify AuditLog created for DERP fallback
    audit_logs = [obj for obj in added_objects if isinstance(obj, AuditLog)]
    fallback_log = next(
        (a for a in audit_logs if a.event_type == AuditEventType.DERP_FALLBACK.value), None
    )
    assert fallback_log is not None
    assert fallback_log.severity == AuditSeverity.WARNING.value
    assert fallback_log.event_category == EventCategory.NETWORK.value
    assert fallback_log.details["derp_region"] == "fra"


# ---------------------------------------------------------------------------
# Fleet Aggregation Services Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_fleet_network_routing_overview():
    """Verifies get_fleet_network_routing_overview compiles subnets, exit nodes, and alerts."""
    nodes = [
        Node(
            id="n1",
            hostname="gw-prod",
            os="linux",
            is_online=True,
            telemetry_metadata={
                "network_routing": {
                    "exposed_routes": ["0.0.0.0/0", "10.10.0.0/16"],
                    "exit_node_audit": {
                        "is_advertising_exit_node": True,
                        "is_unauthorized_exit_node": False,
                    },
                    "derp_info": {"is_derp_fallback": False, "derp_region": "fra"},
                }
            },
        ),
        Node(
            id="n2",
            hostname="rogue-box",
            os="linux",
            is_online=True,
            telemetry_metadata={
                "network_routing": {
                    "exposed_routes": ["0.0.0.0/0"],
                    "exit_node_audit": {
                        "is_advertising_exit_node": True,
                        "is_unauthorized_exit_node": True,
                        "exit_routes": ["0.0.0.0/0"],
                    },
                    "derp_info": {"is_derp_fallback": True, "derp_region": "ord"},
                }
            },
        ),
    ]

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = nodes
    mock_session.execute.return_value = mock_result

    data = await get_fleet_network_routing_overview(mock_session)
    assert data["total_devices"] == 2
    assert data["exit_nodes_count"] == 2
    assert data["authorized_exit_nodes_count"] == 1
    assert data["unauthorized_exit_nodes_count"] == 1
    assert len(data["unauthorized_alerts"]) == 1
    assert data["unauthorized_alerts"][0]["hostname"] == "rogue-box"
    assert "10.10.0.0/16" in data["subnets_catalog"]


@pytest.mark.asyncio
async def test_get_fleet_derp_overview():
    """Verifies get_fleet_derp_overview calculates region distribution and fallback rate."""
    nodes = [
        Node(
            id="n1",
            hostname="srv-fra",
            is_online=True,
            telemetry_metadata={
                "network_routing": {
                    "derp_info": {"derp_region": "fra", "is_derp_fallback": False, "latency_ms": 25.0}
                }
            },
        ),
        Node(
            id="n2",
            hostname="srv-ord-fallback",
            is_online=True,
            telemetry_metadata={
                "network_routing": {
                    "derp_info": {"derp_region": "ord", "is_derp_fallback": True, "latency_ms": 110.0}
                }
            },
        ),
    ]

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = nodes
    mock_session.execute.return_value = mock_result

    data = await get_fleet_derp_overview(mock_session)
    assert data["total_devices"] == 2
    assert data["online_devices"] == 2
    assert data["derp_fallback_devices"] == 1
    assert data["fleet_fallback_rate_percentage"] == 50.0
    assert len(data["regions"]) == 2


@pytest.mark.asyncio
async def test_get_node_network_routing_audit():
    """Verifies get_node_network_routing_audit retrieves node details and handles not found."""
    node = Node(
        id="target-node-99",
        node_id="n99CNTRL",
        hostname="audit-target",
        name="audit-target.net",
        os="linux",
        is_online=True,
        telemetry_metadata={
            "network_routing": {
                "exposed_routes": ["10.0.0.0/8"],
                "is_advertising_exit_node": False,
            }
        },
    )

    mock_session = AsyncMock()
    mock_res = MagicMock()
    mock_res.scalar_one_or_none.return_value = node
    mock_session.execute.return_value = mock_res

    res = await get_node_network_routing_audit(mock_session, "target-node-99")
    assert res["id"] == "target-node-99"
    assert res["hostname"] == "audit-target"
    assert "10.0.0.0/8" in res["exposed_routes"]

    # Not found case
    mock_res.scalar_one_or_none.return_value = None
    res_404 = await get_node_network_routing_audit(mock_session, "nonexistent-node")
    assert res_404["error"] == "node_not_found"


# ---------------------------------------------------------------------------
# API Endpoints Integration Tests (Step 9 Routes)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_v1_fleet_network_routing_endpoint():
    """Tests GET /api/v1/fleet/routes and /api/v1/fleet/network-routing HTTP endpoints."""
    with patch(
        "app.api.v1.router.get_fleet_network_routing_overview", new_callable=AsyncMock
    ) as mock_fn:
        mock_fn.return_value = {
            "total_devices": 10,
            "devices_advertising_routes": 3,
            "exit_nodes_count": 2,
            "authorized_exit_nodes_count": 1,
            "unauthorized_exit_nodes_count": 1,
            "derp_fallback_count": 2,
            "unauthorized_alerts": [{"hostname": "rogue-box", "severity": "high"}],
            "subnets_catalog": {"10.0.0.0/8": [{"hostname": "gw-01"}]},
            "nodes": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp1 = await client.get("/api/v1/fleet/routes")
            assert resp1.status_code == 200
            data1 = resp1.json()
            assert data1["total_devices"] == 10
            assert data1["unauthorized_exit_nodes_count"] == 1

            resp2 = await client.get("/api/v1/fleet/network-routing")
            assert resp2.status_code == 200
            assert resp2.json()["exit_nodes_count"] == 2


@pytest.mark.asyncio
async def test_api_v1_fleet_derp_endpoint():
    """Tests GET /api/v1/fleet/derp and /api/v1/fleet/derp-overview endpoints."""
    with patch("app.api.v1.router.get_fleet_derp_overview", new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = {
            "total_devices": 5,
            "online_devices": 4,
            "derp_fallback_devices": 1,
            "fleet_fallback_rate_percentage": 25.0,
            "regions_count": 2,
            "regions": [{"region": "fra", "node_count": 3, "average_latency_ms": 22.5}],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/fleet/derp")
            assert resp.status_code == 200
            data = resp.json()
            assert data["derp_fallback_devices"] == 1
            assert data["fleet_fallback_rate_percentage"] == 25.0


@pytest.mark.asyncio
async def test_api_v1_node_network_routing_audit_endpoint():
    """Tests GET /api/v1/fleet/nodes/{node_id}/routes and 404 behavior."""
    with patch(
        "app.api.v1.router.get_node_network_routing_audit", new_callable=AsyncMock
    ) as mock_fn:
        mock_fn.return_value = {
            "id": "node-101",
            "hostname": "test-gw",
            "is_advertising_exit_node": True,
            "exit_node_audit": {"is_authorized": True},
            "derp_info": {"is_derp_fallback": False},
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/fleet/nodes/node-101/routes")
            assert resp.status_code == 200
            assert resp.json()["hostname"] == "test-gw"

            mock_fn.return_value = {"error": "node_not_found", "node_id": "nonexistent"}
            resp_404 = await client.get("/api/v1/fleet/nodes/nonexistent/routes")
            assert resp_404.status_code == 404
            assert "Node 'nonexistent' not found" in resp_404.json()["detail"]
