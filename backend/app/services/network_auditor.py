from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.enums import (
    AuditSeverity,
    AuditEventType,
    ComplianceStatus,
    EventCategory,
)
from app.models.node import Node
from app.models.node_state import NodeState
from app.schemas.tailscale import TailscaleDevice

logger = logging.getLogger(__name__)

# Standard CIDRs for default exit node route advertisements in Tailscale
EXIT_NODE_ROUTES: Set[str] = {"0.0.0.0/0", "::/0"}

# Default tags that grant authorization to advertise exit node routes
DEFAULT_AUTHORIZED_EXIT_TAGS: Set[str] = {
    "tag:exit-node",
    "tag:exitnode",
    "tag:gateway",
    "tag:authorized-exit-node",
    "tag:vpn",
}


def is_exit_node_route(route: Optional[str]) -> bool:
    """Determines whether a CIDR route string represents a default exit node route.

    Exit nodes in Tailscale advertise the default route (0.0.0.0/0 for IPv4 or ::/0 for IPv6).

    Args:
        route: CIDR route string (e.g., '0.0.0.0/0', '::/0', '10.0.0.0/24').

    Returns:
        True if the route is a default exit node route, False otherwise.
    """
    if not route:
        return False
    return route.strip() in EXIT_NODE_ROUTES


def is_valid_cidr(cidr: Optional[str]) -> bool:
    """Validates whether a string is a valid IPv4 or IPv6 CIDR network notation.

    Args:
        cidr: String representing an IP prefix (e.g. '192.168.1.0/24', '10.0.0.0/8').

    Returns:
        True if valid IP network, False otherwise.
    """
    if not cidr:
        return False
    try:
        ipaddress.ip_network(cidr.strip(), strict=False)
        return True
    except (ValueError, TypeError):
        return False


def classify_route(route_str: str) -> Dict[str, Any]:
    """Classifies a route string into network metadata, family, and category.

    Categories:
    - 'exit_node': Default route ('0.0.0.0/0' or '::/0')
    - 'private_subnet': RFC 1918 or IPv6 ULA/link-local private network
    - 'public_subnet': Publicly routable IP subnet
    - 'invalid': Malformed CIDR notation

    Args:
        route_str: Raw route string.

    Returns:
        Dictionary containing parsed route metadata.
    """
    cleaned = route_str.strip()
    if is_exit_node_route(cleaned):
        is_v4 = "." in cleaned
        return {
            "route": cleaned,
            "is_valid": True,
            "is_exit_node": True,
            "category": "exit_node",
            "ip_version": 4 if is_v4 else 6,
            "is_private": False,
            "is_global": True,
            "network_address": "0.0.0.0" if is_v4 else "::",
            "prefixlen": 0,
            "description": f"Default IPv{4 if is_v4 else 6} exit node route",
        }

    try:
        net = ipaddress.ip_network(cleaned, strict=False)
        is_priv = net.is_private
        is_glob = net.is_global
        category = "private_subnet" if is_priv else "public_subnet"
        return {
            "route": cleaned,
            "is_valid": True,
            "is_exit_node": False,
            "category": category,
            "ip_version": net.version,
            "is_private": is_priv,
            "is_global": is_glob,
            "network_address": str(net.network_address),
            "prefixlen": net.prefixlen,
            "description": (
                f"Private IPv{net.version} subnet ({cleaned})"
                if is_priv
                else f"Public IPv{net.version} subnet ({cleaned})"
            ),
        }
    except (ValueError, TypeError):
        return {
            "route": cleaned,
            "is_valid": False,
            "is_exit_node": False,
            "category": "invalid",
            "ip_version": 0,
            "is_private": False,
            "is_global": False,
            "network_address": "",
            "prefixlen": 0,
            "description": f"Malformed or invalid CIDR route '{cleaned}'",
        }


def parse_node_exposed_routes(device: TailscaleDevice) -> Dict[str, Any]:
    """Extracts, validates, and parses the exposedRoutes field and attributes from a TailscaleDevice.

    Extracts:
    1. `exposed_routes`: list of raw advertised route strings
    2. `exit_node_routes`: list of default exit routes (e.g. ['0.0.0.0/0'])
    3. `subnet_routes`: list of non-exit subnet routes (e.g. ['10.0.0.0/24'])
    4. `classified_routes`: detailed list of parsed route objects

    Args:
        device: The validated TailscaleDevice schema instance.

    Returns:
        Dictionary containing route parsing results.
    """
    raw_routes = device.get_exposed_routes()
    exit_node_routes: List[str] = []
    subnet_routes: List[str] = []
    classified_routes: List[Dict[str, Any]] = []
    has_invalid_routes = False

    for r in raw_routes:
        cls_info = classify_route(r)
        classified_routes.append(cls_info)
        if not cls_info["is_valid"]:
            has_invalid_routes = True
            continue

        if cls_info["is_exit_node"]:
            exit_node_routes.append(cls_info["route"])
        else:
            subnet_routes.append(cls_info["route"])

    return {
        "exposed_routes": raw_routes,
        "exit_node_routes": exit_node_routes,
        "subnet_routes": subnet_routes,
        "is_advertising_exit_node": len(exit_node_routes) > 0,
        "total_routes_count": len(raw_routes),
        "exit_routes_count": len(exit_node_routes),
        "subnet_routes_count": len(subnet_routes),
        "has_invalid_routes": has_invalid_routes,
        "classified_routes": classified_routes,
    }


def is_exit_node_authorized(
    device: TailscaleDevice,
    authorized_tags: Optional[List[str]] = None,
    authorized_hostnames: Optional[List[str]] = None,
    allow_untagged: Optional[bool] = None,
) -> Tuple[bool, str]:
    """Evaluates whether a device is authorized to advertise exit node routes.

    A node is authorized if:
    1. `allow_untagged` or `settings.ALLOW_UNTAGGED_EXIT_NODES` is explicitly True.
    2. Device has an approved exit node tag (e.g., 'tag:exit-node', 'tag:gateway').
    3. Device hostname or device ID matches `authorized_hostnames` whitelist.
    4. Device attributes explicitly contain `authorized_exit_node: True`.

    Args:
        device: The validated TailscaleDevice instance.
        authorized_tags: Optional list of approved exit node tags.
        authorized_hostnames: Optional list of approved hostnames or device IDs.
        allow_untagged: Optional flag to permit untagged exit nodes.

    Returns:
        Tuple of `(is_authorized: bool, reason: str)`.
    """
    # Check global untagged allowance policy
    allow_untagged_eff = (
        allow_untagged
        if allow_untagged is not None
        else settings.ALLOW_UNTAGGED_EXIT_NODES
    )
    if allow_untagged_eff:
        return True, "Authorized by fleet-wide policy: allow_untagged_exit_nodes=True"

    # Check tags
    tags_pool = authorized_tags or settings.AUTHORIZED_EXIT_NODE_TAGS or list(DEFAULT_AUTHORIZED_EXIT_TAGS)
    target_tags = {t.strip().lower() for t in tags_pool}
    device_tags = {t.strip().lower() for t in (device.tags or [])}

    matching_tags = target_tags.intersection(device_tags)
    if matching_tags:
        matched = sorted(list(matching_tags))[0]
        return True, f"Authorized by assigned tag '{matched}'"

    # Check hostname / node ID whitelist
    approved_hosts = {
        h.strip().lower()
        for h in (authorized_hostnames or settings.AUTHORIZED_EXIT_NODE_HOSTNAMES or [])
    }
    dev_hostname = (device.hostname or "").strip().lower()
    dev_name = (device.name or "").strip().lower()
    dev_id = (device.id or "").strip().lower()
    dev_node_id = (device.node_id or "").strip().lower()

    if (
        dev_hostname in approved_hosts
        or dev_name in approved_hosts
        or dev_id in approved_hosts
        or dev_node_id in approved_hosts
    ):
        return True, f"Authorized by hostname/ID whitelist: '{device.hostname}'"

    # Check device attributes
    if device.attributes:
        for k, v in device.attributes.items():
            k_lower = k.lower().replace(":", "_").replace("-", "_")
            if (
                k_lower in ("authorized_exit_node", "exit_node_authorized", "is_exit_node_approved")
                and bool(v)
            ):
                return True, f"Authorized by explicit device attribute '{k}'"

    # Unauthorized: failed all checks
    tags_list_str = ", ".join(sorted(target_tags))
    return (
        False,
        f"Device '{device.hostname}' is not authorized to advertise exit nodes. "
        f"Missing required tags ({tags_list_str}) and not listed in authorized hostnames.",
    )


def evaluate_derp_connectivity(
    device: TailscaleDevice,
    latency_threshold_ms: Optional[float] = None,
) -> Dict[str, Any]:
    """Audits DERP connection status, relay usage, direct endpoints, and fallbacks.

    In Tailscale mesh networking:
    - Direct connection: Node has discovered direct UDP peer endpoints (`endpoints`).
    - DERP fallback: When direct UDP connectivity is blocked by firewalls or symmetric NAT,
      Tailscale routes all traffic through a DERP relay server.
    - Non-preferred fallback: When traffic is routed via a distant/secondary DERP relay
      instead of the geographically optimal preferred relay.

    Args:
        device: The validated TailscaleDevice instance.
        latency_threshold_ms: Milliseconds threshold to flag high-latency relay connections.

    Returns:
        Dictionary containing DERP connectivity classification, fallback flags, and latency analysis.
    """
    is_online = device.check_is_online()
    endpoints = device.endpoints
    endpoints_count = len(endpoints)
    has_direct_endpoints = endpoints_count > 0
    derp_region = device.derp_region
    latency_ms = device.latency_ms

    threshold = (
        latency_threshold_ms
        if latency_threshold_ms is not None
        else settings.DERP_LATENCY_THRESHOLD_MS
    )

    # Determine preferred DERP from client_connectivity latency map
    preferred_derp: Optional[str] = None
    if device.client_connectivity and device.client_connectivity.latency:
        for reg, reg_data in device.client_connectivity.latency.items():
            if isinstance(reg_data, dict) and reg_data.get("preferred"):
                preferred_derp = reg
                break
        if not preferred_derp:
            # Lowest latency region
            valid_latencies = [
                (reg, float(d["latencyMs"]))
                for reg, d in device.client_connectivity.latency.items()
                if isinstance(d, dict) and "latencyMs" in d and d["latencyMs"] is not None
            ]
            if valid_latencies:
                preferred_derp = min(valid_latencies, key=lambda x: x[1])[0]

    is_using_non_preferred_derp = bool(
        preferred_derp and derp_region and preferred_derp.lower() != derp_region.lower()
    )

    # Detect DERP fallback:
    # 1. Device is online, connected via DERP, but has 0 direct UDP endpoints (all traffic relayed)
    # 2. Or device attributes explicitly declare relay fallback
    is_derp_fallback = False
    fallback_reason = "Normal direct connectivity"

    if not is_online:
        connection_type = "offline"
        fallback_reason = "Device is offline"
    elif not derp_region and not has_direct_endpoints:
        connection_type = "unknown"
        fallback_reason = "No connectivity telemetry reported"
    elif not has_direct_endpoints and derp_region:
        is_derp_fallback = True
        connection_type = "derp_fallback"
        fallback_reason = (
            f"Relaying all traffic via DERP '{derp_region}' (0 direct UDP endpoints discovered; "
            f"NAT traversal / firewall UDP block likely)"
        )
    elif is_using_non_preferred_derp:
        is_derp_fallback = True
        connection_type = "derp_fallback"
        fallback_reason = (
            f"Routing via secondary DERP relay '{derp_region}' instead of preferred '{preferred_derp}'"
        )
    else:
        connection_type = "direct"
        fallback_reason = (
            f"Direct peer-to-peer connection active with {endpoints_count} endpoint(s); "
            f"DERP '{derp_region or 'unknown'}' available as control relay"
        )

    # Explicit attribute override (for testing or simulated telemetry)
    if device.attributes:
        if device.attributes.get("derp_fallback") is True or device.attributes.get("is_derp_fallback") is True:
            is_derp_fallback = True
            connection_type = "derp_fallback"
            fallback_reason = "Explicit DERP fallback indicated in device attributes"

    is_latency_spike = bool(latency_ms is not None and latency_ms > threshold)

    return {
        "is_online": is_online,
        "derp_region": derp_region,
        "preferred_derp": preferred_derp,
        "is_using_non_preferred_derp": is_using_non_preferred_derp,
        "endpoints": endpoints,
        "endpoints_count": endpoints_count,
        "has_direct_endpoints": has_direct_endpoints,
        "is_derp_fallback": is_derp_fallback,
        "connection_type": connection_type,
        "latency_ms": latency_ms,
        "latency_threshold_ms": threshold,
        "is_latency_spike": is_latency_spike,
        "fallback_reason": fallback_reason,
    }


def audit_node_network_routing(
    device: TailscaleDevice,
    existing_node: Optional[Node] = None,
    authorized_tags: Optional[List[str]] = None,
    authorized_hostnames: Optional[List[str]] = None,
    allow_untagged: Optional[bool] = None,
    latency_threshold_ms: Optional[float] = None,
) -> Dict[str, Any]:
    """Comprehensive network routing audit for a single device node.

    Audits:
    1. `exposedRoutes` field and subnet route classification.
    2. Exit node advertisement authorization (`0.0.0.0/0`, `::/0`).
    3. DERP connection fallbacks, relay degradation, and latency spikes.
    4. Route and DERP state transitions compared to the existing database record.

    Args:
        device: The validated TailscaleDevice instance.
        existing_node: Optional existing Node database model for state change comparison.
        authorized_tags: Approved exit node tags.
        authorized_hostnames: Approved exit node hostnames/IDs.
        allow_untagged: Whether untagged exit nodes are permitted.
        latency_threshold_ms: Threshold in ms for DERP latency alerts.

    Returns:
        Structured audit report including compliance outcomes, detected alerts, and state diffs.
    """
    # 1. Parse exposed routes
    routes_info = parse_node_exposed_routes(device)
    is_advertising_exit = routes_info["is_advertising_exit_node"]
    exit_routes = routes_info["exit_node_routes"]
    subnet_routes = routes_info["subnet_routes"]

    # 2. Audit Exit Node Authorization
    if is_advertising_exit:
        is_authorized, auth_reason = is_exit_node_authorized(
            device=device,
            authorized_tags=authorized_tags,
            authorized_hostnames=authorized_hostnames,
            allow_untagged=allow_untagged,
        )
        is_unauthorized_exit = not is_authorized
    else:
        is_authorized = True
        auth_reason = "Device does not advertise exit node routes"
        is_unauthorized_exit = False

    # 3. Audit DERP connectivity and fallbacks
    derp_info = evaluate_derp_connectivity(
        device=device,
        latency_threshold_ms=latency_threshold_ms,
    )

    # 4. Compare against existing Node record to detect state changes
    prev_metadata = (existing_node.telemetry_metadata or {}) if existing_node else {}
    prev_routing = prev_metadata.get("network_routing", {})
    prev_routes = prev_metadata.get("exposed_routes") or prev_routing.get("exposed_routes") or []
    prev_unauth_exit = prev_routing.get("exit_node_audit", {}).get("is_unauthorized_exit_node", False)
    prev_derp_fallback = prev_routing.get("derp_info", {}).get("is_derp_fallback", False)
    prev_derp_region = (
        prev_metadata.get("derp_region")
        or prev_routing.get("derp_info", {}).get("derp_region")
        or (
            existing_node.states[0].derp_region
            if existing_node and "states" in existing_node.__dict__ and existing_node.states
            else None
        )
    )

    # State transition flags
    is_new_unauthorized_exit = is_unauthorized_exit and not prev_unauth_exit
    is_new_derp_fallback = derp_info["is_derp_fallback"] and not prev_derp_fallback
    derp_changed = bool(
        prev_derp_region
        and derp_info["derp_region"]
        and prev_derp_region.lower() != derp_info["derp_region"].lower()
    )
    current_routes_set = set(routes_info["exposed_routes"])
    prev_routes_set = set(prev_routes)
    routes_changed = bool(existing_node is not None and current_routes_set != prev_routes_set)

    # 5. Determine Compliance & Posture Outcome
    if is_unauthorized_exit:
        compliance_status = ComplianceStatus.NON_COMPLIANT.value
        is_compliant = False
        posture_severity = AuditSeverity.HIGH.value
    elif derp_info["is_derp_fallback"] and derp_info["is_latency_spike"]:
        compliance_status = ComplianceStatus.WARNING.value
        is_compliant = True
        posture_severity = AuditSeverity.WARNING.value
    elif routes_info["has_invalid_routes"]:
        compliance_status = ComplianceStatus.WARNING.value
        is_compliant = True
        posture_severity = AuditSeverity.LOW.value
    else:
        compliance_status = ComplianceStatus.COMPLIANT.value
        is_compliant = True
        posture_severity = AuditSeverity.INFO.value

    # 6. Structured Alerts
    alerts: List[Dict[str, Any]] = []

    if is_unauthorized_exit:
        alerts.append(
            {
                "type": "unauthorized_exit_node",
                "severity": AuditSeverity.HIGH.value,
                "title": f"Unauthorized exit node advertised by '{device.hostname}'",
                "message": (
                    f"Device '{device.hostname}' is advertising unauthorized exit node route(s): "
                    f"{', '.join(exit_routes)}. {auth_reason}"
                ),
                "event_type": AuditEventType.UNAUTHORIZED_EXIT_NODE.value,
                "event_category": EventCategory.NETWORK.value,
                "details": {
                    "hostname": device.hostname,
                    "exit_node_routes": exit_routes,
                    "all_exposed_routes": routes_info["exposed_routes"],
                    "tags": device.tags,
                    "authorization_reason": auth_reason,
                    "is_authorized": False,
                },
            }
        )

    if is_new_derp_fallback:
        alerts.append(
            {
                "type": "derp_fallback",
                "severity": AuditSeverity.WARNING.value,
                "title": f"DERP relay connection fallback on '{device.hostname}'",
                "message": (
                    f"Device '{device.hostname}' fell back to DERP relay '{derp_info['derp_region']}'. "
                    f"{derp_info['fallback_reason']}"
                ),
                "event_type": AuditEventType.DERP_FALLBACK.value,
                "event_category": EventCategory.NETWORK.value,
                "details": {
                    "hostname": device.hostname,
                    "derp_region": derp_info["derp_region"],
                    "preferred_derp": derp_info["preferred_derp"],
                    "latency_ms": derp_info["latency_ms"],
                    "endpoints_count": derp_info["endpoints_count"],
                    "connection_type": derp_info["connection_type"],
                },
            }
        )

    return {
        "hostname": device.hostname,
        "exposed_routes": routes_info["exposed_routes"],
        "exit_node_routes": exit_routes,
        "subnet_routes": subnet_routes,
        "is_advertising_exit_node": is_advertising_exit,
        "routes_info": routes_info,
        "exit_node_audit": {
            "is_advertising_exit_node": is_advertising_exit,
            "is_authorized": is_authorized,
            "authorization_reason": auth_reason,
            "is_unauthorized_exit_node": is_unauthorized_exit,
            "exit_routes": exit_routes,
            "severity": AuditSeverity.HIGH.value if is_unauthorized_exit else "none",
        },
        "derp_info": derp_info,
        "state_changes": {
            "is_new_unauthorized_exit_node": is_new_unauthorized_exit,
            "is_new_derp_fallback": is_new_derp_fallback,
            "derp_changed": derp_changed,
            "previous_derp": prev_derp_region,
            "new_derp": derp_info["derp_region"],
            "routes_changed": routes_changed,
            "previous_routes": prev_routes,
            "new_routes": routes_info["exposed_routes"],
        },
        "is_compliant": is_compliant,
        "compliance_status": compliance_status,
        "posture_severity": posture_severity,
        "alerts": alerts,
        "audited_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Fleet-wide Aggregation Queries (Async Database Operations)
# ---------------------------------------------------------------------------


async def get_fleet_network_routing_overview(
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Dict[str, Any]:
    """Aggregates fleet-wide exposedRoutes, exit nodes, unauthorized alerts, and DERP fallbacks.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet domain to filter by.

    Returns:
        Dictionary containing fleet routing overview, catalog of subnets, exit nodes, and alerts.
    """
    stmt = select(Node).order_by(Node.hostname.asc())
    if tailnet:
        stmt = stmt.where(Node.tailnet == tailnet)

    result = await session.execute(stmt)
    nodes = list(result.scalars().all())

    total_devices = len(nodes)
    devices_advertising_routes = 0
    exit_nodes_count = 0
    authorized_exit_nodes_count = 0
    unauthorized_exit_nodes_count = 0
    derp_fallback_count = 0
    direct_connection_count = 0

    unauthorized_alerts: List[Dict[str, Any]] = []
    derp_fallback_nodes: List[Dict[str, Any]] = []
    subnets_catalog: Dict[str, List[Dict[str, str]]] = {}
    derp_region_counts: Dict[str, int] = {}
    nodes_summary: List[Dict[str, Any]] = []

    for node in nodes:
        meta = node.telemetry_metadata or {}
        routing_audit = meta.get("network_routing") or {}
        exposed_routes = meta.get("exposed_routes") or routing_audit.get("exposed_routes") or []
        exit_audit = routing_audit.get("exit_node_audit", {})
        derp_info = routing_audit.get("derp_info", {})

        is_exit = exit_audit.get("is_advertising_exit_node", any(r in ("0.0.0.0/0", "::/0") for r in exposed_routes))
        is_unauth = exit_audit.get("is_unauthorized_exit_node", False)
        is_fallback = derp_info.get("is_derp_fallback", False)
        conn_type = derp_info.get("connection_type", "direct" if node.endpoints else "derp_fallback")
        derp_reg = (
            derp_info.get("derp_region")
            or (node.states[0].derp_region if "states" in node.__dict__ and node.states else None)
            or "unknown"
        )

        if exposed_routes:
            devices_advertising_routes += 1

        if is_exit:
            exit_nodes_count += 1
            if is_unauth:
                unauthorized_exit_nodes_count += 1
                unauthorized_alerts.append(
                    {
                        "node_id": node.id,
                        "hostname": node.hostname,
                        "exit_routes": exit_audit.get("exit_routes", ["0.0.0.0/0"]),
                        "tags": node.tags,
                        "authorization_reason": exit_audit.get("authorization_reason", "Unauthorized advertisement"),
                        "severity": AuditSeverity.HIGH.value,
                    }
                )
            else:
                authorized_exit_nodes_count += 1

        if is_fallback or conn_type == "derp_fallback":
            derp_fallback_count += 1
            derp_fallback_nodes.append(
                {
                    "node_id": node.id,
                    "hostname": node.hostname,
                    "derp_region": derp_reg,
                    "latency_ms": derp_info.get("latency_ms"),
                    "fallback_reason": derp_info.get("fallback_reason", "No direct endpoints"),
                }
            )
        elif node.is_online:
            direct_connection_count += 1

        if derp_reg:
            derp_region_counts[derp_reg] = derp_region_counts.get(derp_reg, 0) + 1

        # Catalog subnet routes
        for r in exposed_routes:
            if not is_exit_node_route(r):
                if r not in subnets_catalog:
                    subnets_catalog[r] = []
                subnets_catalog[r].append({"node_id": node.id, "hostname": node.hostname})

        nodes_summary.append(
            {
                "id": node.id,
                "node_id": node.node_id,
                "hostname": node.hostname,
                "name": node.name,
                "is_online": node.is_online,
                "exposed_routes": exposed_routes,
                "is_exit_node": is_exit,
                "is_unauthorized_exit_node": is_unauth,
                "connection_type": conn_type,
                "derp_region": derp_reg,
                "endpoints_count": len(node.endpoints or []),
            }
        )

    return {
        "total_devices": total_devices,
        "devices_advertising_routes": devices_advertising_routes,
        "exit_nodes_count": exit_nodes_count,
        "authorized_exit_nodes_count": authorized_exit_nodes_count,
        "unauthorized_exit_nodes_count": unauthorized_exit_nodes_count,
        "derp_fallback_count": derp_fallback_count,
        "direct_connection_count": direct_connection_count,
        "unauthorized_alerts": unauthorized_alerts,
        "derp_fallback_nodes": derp_fallback_nodes,
        "subnets_catalog": subnets_catalog,
        "unique_subnets_count": len(subnets_catalog),
        "derp_region_distribution": derp_region_counts,
        "nodes": nodes_summary,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def get_fleet_derp_overview(
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Dict[str, Any]:
    """Aggregates fleet-wide DERP relay distribution, fallback rates, and region performance.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet domain filter.

    Returns:
        Dictionary containing DERP region breakdown, fallback percentage, and nodes list.
    """
    stmt = select(Node).order_by(Node.hostname.asc())
    if tailnet:
        stmt = stmt.where(Node.tailnet == tailnet)

    result = await session.execute(stmt)
    nodes = list(result.scalars().all())

    total_devices = len(nodes)
    online_devices = sum(1 for n in nodes if n.is_online)
    derp_regions: Dict[str, Dict[str, Any]] = {}
    fallback_count = 0

    for node in nodes:
        meta = node.telemetry_metadata or {}
        routing_audit = meta.get("network_routing", {})
        derp_info = routing_audit.get("derp_info", {})
        derp_reg = (
            derp_info.get("derp_region")
            or (node.states[0].derp_region if "states" in node.__dict__ and node.states else None)
            or "unknown"
        )
        is_fallback = derp_info.get("is_derp_fallback", False)
        lat = derp_info.get("latency_ms")

        if is_fallback:
            fallback_count += 1

        if derp_reg not in derp_regions:
            derp_regions[derp_reg] = {
                "region": derp_reg,
                "node_count": 0,
                "online_count": 0,
                "fallback_count": 0,
                "latencies": [],
            }

        entry = derp_regions[derp_reg]
        entry["node_count"] += 1
        if node.is_online:
            entry["online_count"] += 1
        if is_fallback:
            entry["fallback_count"] += 1
        if lat is not None:
            entry["latencies"].append(lat)

    # Compute averages per DERP region
    region_stats: List[Dict[str, Any]] = []
    for reg, data in sorted(derp_regions.items(), key=lambda x: x[1]["node_count"], reverse=True):
        lats = data.pop("latencies")
        avg_lat = round(sum(lats) / len(lats), 2) if lats else None
        min_lat = round(min(lats), 2) if lats else None
        max_lat = round(max(lats), 2) if lats else None
        region_stats.append(
            {
                **data,
                "average_latency_ms": avg_lat,
                "min_latency_ms": min_lat,
                "max_latency_ms": max_lat,
            }
        )

    fallback_rate = (
        round((fallback_count / online_devices) * 100.0, 2)
        if online_devices > 0
        else 0.0
    )

    return {
        "total_devices": total_devices,
        "online_devices": online_devices,
        "derp_fallback_devices": fallback_count,
        "fleet_fallback_rate_percentage": fallback_rate,
        "regions_count": len(region_stats),
        "regions": region_stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def get_node_network_routing_audit(
    session: AsyncSession,
    node_id: str,
) -> Dict[str, Any]:
    """Retrieves deep network routing audit and DERP telemetry for a specific node.

    Args:
        session: Active SQLAlchemy AsyncSession.
        node_id: Primary UUID or Tailscale stable nodeId.

    Returns:
        Dictionary containing route audit, authorization status, and DERP details.
    """
    stmt = select(Node).where((Node.id == node_id) | (Node.node_id == node_id))
    result = await session.execute(stmt)
    node = result.scalar_one_or_none()

    if node is None:
        return {"error": "node_not_found", "node_id": node_id}

    meta = node.telemetry_metadata or {}
    routing_audit = meta.get("network_routing")

    # If already cached in metadata, return enriched version
    if routing_audit:
        return {
            "id": node.id,
            "node_id": node.node_id,
            "hostname": node.hostname,
            "name": node.name,
            "is_online": node.is_online,
            "addresses": node.addresses,
            "tags": node.tags,
            **routing_audit,
        }

    # Otherwise reconstruct from device fields
    dev_payload = {
        "id": node.id,
        "nodeId": node.node_id,
        "name": node.name,
        "hostname": node.hostname,
        "os": node.os,
        "osVersion": node.os_version,
        "clientVersion": node.client_version,
        "addresses": node.addresses,
        "tags": node.tags,
        "authorized": node.authorized,
        "isOnline": node.is_online,
        "exposedRoutes": meta.get("exposed_routes", []),
    }
    dummy_device = TailscaleDevice.model_validate(dev_payload)
    fresh_audit = audit_node_network_routing(dummy_device, existing_node=node)

    return {
        "id": node.id,
        "node_id": node.node_id,
        "hostname": node.hostname,
        "name": node.name,
        "is_online": node.is_online,
        "addresses": node.addresses,
        "tags": node.tags,
        **fresh_audit,
    }
