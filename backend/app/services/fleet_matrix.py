from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import SSLCertificateStatus, TailnetLockStatus
from app.models.node import Node
from app.schemas.fleet_matrix import (
    FleetMatrixColumn,
    FleetMatrixCrossTabulation,
    FleetMatrixResponse,
    NodeMatrixItem,
)
from app.services.fleet import (
    calculate_duration_seconds,
    categorize_os_device,
    format_duration_human,
    normalize_os,
)

logger = logging.getLogger(__name__)

DEFAULT_FLEET_MATRIX_COLUMNS: List[FleetMatrixColumn] = [
    FleetMatrixColumn(key="hostname", label="Hostname", category="Identity", type="string", sortable=True, filterable=True),
    FleetMatrixColumn(key="name", label="Device Name", category="Identity", type="string", sortable=True, filterable=True),
    FleetMatrixColumn(key="user", label="Owner / User", category="Identity", type="string", sortable=True, filterable=True),
    FleetMatrixColumn(key="os", label="Operating System", category="System", type="string", sortable=True, filterable=True),
    FleetMatrixColumn(key="os_version", label="OS Version", category="System", type="string", sortable=True, filterable=True),
    FleetMatrixColumn(key="client_version", label="Tailscale Version", category="System", type="string", sortable=True, filterable=True),
    FleetMatrixColumn(key="category", label="Device Category", category="System", type="string", sortable=True, filterable=True),
    FleetMatrixColumn(key="is_online", label="Status", category="Status", type="boolean", sortable=True, filterable=True),
    FleetMatrixColumn(key="last_seen", label="Last Seen", category="Status", type="datetime", sortable=True, filterable=True),
    FleetMatrixColumn(key="streak_duration_human", label="Uptime Streak", category="Status", type="string", sortable=False, filterable=False),
    FleetMatrixColumn(key="is_compliant", label="Posture Compliant", category="Security", type="boolean", sortable=True, filterable=True),
    FleetMatrixColumn(key="compliance_status", label="Compliance Status", category="Security", type="status", sortable=True, filterable=True),
    FleetMatrixColumn(key="key_expiry_status", label="Key Expiry", category="Security", type="status", sortable=True, filterable=True),
    FleetMatrixColumn(key="days_until_key_expiry", label="Days To Expiry", category="Security", type="number", sortable=True, filterable=True),
    FleetMatrixColumn(key="is_exit_node", label="Exit Node", category="Network", type="boolean", sortable=True, filterable=True),
    FleetMatrixColumn(key="derp_region", label="DERP Region", category="Network", type="string", sortable=True, filterable=True),
    FleetMatrixColumn(key="latency_ms", label="Latency (ms)", category="Network", type="number", sortable=True, filterable=True),
    FleetMatrixColumn(key="country", label="Country", category="Geolocation", type="string", sortable=True, filterable=True),
    FleetMatrixColumn(key="is_impossible_travel", label="Geo Anomaly", category="Geolocation", type="boolean", sortable=True, filterable=True),
    FleetMatrixColumn(key="tailnet_lock_status", label="Tailnet Lock", category="Tailnet Lock", type="status", sortable=True, filterable=True),
    FleetMatrixColumn(key="is_quarantined", label="Quarantined", category="Tailnet Lock", type="boolean", sortable=True, filterable=True),
    FleetMatrixColumn(key="ssl_cert_status", label="TLS Certificate", category="MagicDNS", type="status", sortable=True, filterable=True),
    FleetMatrixColumn(key="health_status", label="Health Rating", category="Health", type="status", sortable=True, filterable=True),
    FleetMatrixColumn(key="health_score", label="Health Score", category="Health", type="number", sortable=True, filterable=True),
]


def evaluate_node_matrix_item(node: Node, now: Optional[datetime] = None) -> NodeMatrixItem:
    """Transforms a Node database entity into a full multidimensional NodeMatrixItem."""
    eval_now = now or datetime.now(timezone.utc)
    meta = node.telemetry_metadata or {}
    os_family = normalize_os(node.os)
    category = categorize_os_device(os_family, tags=node.tags, hostname=node.hostname)

    # Uptime streak calculation
    uptime_info = meta.get("uptime_info", {})
    last_change_iso = uptime_info.get("last_state_change")
    if last_change_iso:
        try:
            change_dt = datetime.fromisoformat(last_change_iso)
            streak_secs = calculate_duration_seconds(change_dt, eval_now)
        except Exception:
            streak_secs = calculate_duration_seconds(node.last_seen, eval_now)
    else:
        streak_secs = calculate_duration_seconds(node.last_seen, eval_now)

    streak_human = format_duration_human(streak_secs)

    # Posture compliance details
    posture_meta = meta.get("device_posture", {})
    is_compliant = node.is_posture_compliant
    compliance_status = posture_meta.get(
        "compliance_status", "compliant" if is_compliant else "non_compliant"
    )
    violations = posture_meta.get("violations", [])

    # Key expiry details
    key_info = meta.get("key_expiry", {})
    days_left: Optional[float] = key_info.get("days_remaining")
    if days_left is None and node.expires_at:
        days_left = max(0.0, calculate_duration_seconds(eval_now, node.expires_at) / 86400.0)

    if node.key_expiry_disabled:
        key_status = "disabled"
    elif key_info.get("status"):
        key_status = str(key_info.get("status")).lower()
    elif node.expires_at:
        exp_utc = node.expires_at if node.expires_at.tzinfo else node.expires_at.replace(tzinfo=timezone.utc)
        if exp_utc < eval_now:
            key_status = "expired"
        elif days_left is not None and days_left <= 7:
            key_status = "critical"
        elif days_left is not None and days_left <= 30:
            key_status = "warning"
        else:
            key_status = "healthy"
    else:
        key_status = "healthy"

    # Network routing & DERP
    derp_region = meta.get("derp_region") or meta.get("derp")
    latency_ms = meta.get("latency_ms") or meta.get("preferred_latency_ms")

    # Tailnet Lock status
    lock_meta = meta.get("tailnet_lock", {})
    lock_status = lock_meta.get("lock_status", node.tailnet_lock_status)

    # Geolocation details & impossible travel anomaly
    geo_meta = meta.get("geolocation", {})
    country_name = geo_meta.get("country_name")
    is_impossible_travel = bool(geo_meta.get("is_impossible_travel", False))
    geo_anomaly_reason = geo_meta.get("anomaly_reason")

    # Health score evaluation
    score = 100.0
    if not node.is_online:
        score -= 20.0
    if not is_compliant:
        score -= 25.0
    if key_status == "expired":
        score -= 30.0
    elif key_status == "critical":
        score -= 15.0
    elif key_status == "warning":
        score -= 5.0
    if node.is_locked_out or node.is_quarantined:
        score -= 40.0
    if is_impossible_travel:
        score -= 20.0
    if node.is_ssl_cert_expired:
        score -= 20.0
    elif node.is_ssl_cert_expiring:
        score -= 5.0
    if node.update_available:
        score -= 5.0
    if latency_ms and latency_ms > 200.0:
        score -= 5.0

    score = round(max(0.0, min(100.0, score)), 1)

    if node.is_locked_out or key_status == "expired" or is_impossible_travel or score < 50.0:
        health_status = "critical"
    elif score < 85.0 or not node.is_online or not is_compliant or node.is_ssl_cert_expiring:
        health_status = "warning"
    else:
        health_status = "healthy"

    return NodeMatrixItem(
        id=node.id,
        node_id=node.node_id,
        name=node.name,
        hostname=node.hostname,
        user=node.user,
        tailnet=node.tailnet,
        addresses=node.addresses or [],
        tags=node.tags or [],
        os=os_family,
        os_raw=node.os,
        os_version=node.os_version,
        client_version=node.client_version,
        category=category,
        is_online=node.is_online,
        last_seen=node.last_seen.isoformat() if node.last_seen else None,
        streak_duration_seconds=streak_secs,
        streak_duration_human=streak_human,
        is_compliant=is_compliant,
        compliance_status=compliance_status,
        violations=violations,
        update_available=node.update_available,
        key_expiry_disabled=node.key_expiry_disabled,
        expires_at=node.expires_at.isoformat() if node.expires_at else None,
        key_expiry_status=key_status,
        days_until_key_expiry=round(days_left, 1) if days_left is not None else None,
        is_exit_node=node.is_exit_node,
        exposed_routes=node.exposed_routes,
        derp_region=derp_region,
        latency_ms=round(latency_ms, 2) if latency_ms is not None else None,
        country=node.country,
        public_address=node.public_address,
        country_name=country_name,
        is_impossible_travel=is_impossible_travel,
        geo_anomaly_reason=geo_anomaly_reason,
        tailnet_lock_status=lock_status,
        is_locked_out=node.is_locked_out,
        is_quarantined=node.is_quarantined,
        is_signing_node=node.is_signing_node,
        magicdns_domain=node.magicdns_domain,
        ssl_cert_status=node.ssl_cert_status,
        ssl_cert_expires_at=node.ssl_cert_expires_at,
        is_ssl_cert_expiring=node.is_ssl_cert_expiring,
        is_ssl_cert_expired=node.is_ssl_cert_expired,
        health_status=health_status,
        health_score=score,
    )


def compute_cross_tabulation(items: List[NodeMatrixItem]) -> FleetMatrixCrossTabulation:
    """Generates 2D cross-tabulation summaries across OS, status, compliance, and category."""
    os_by_status: Dict[str, Dict[str, int]] = {}
    os_by_compliance: Dict[str, Dict[str, int]] = {}
    category_by_status: Dict[str, Dict[str, int]] = {}

    for item in items:
        # OS by status
        if item.os not in os_by_status:
            os_by_status[item.os] = {"online": 0, "offline": 0}
        if item.is_online:
            os_by_status[item.os]["online"] += 1
        else:
            os_by_status[item.os]["offline"] += 1

        # OS by compliance
        if item.os not in os_by_compliance:
            os_by_compliance[item.os] = {"compliant": 0, "non_compliant": 0}
        if item.is_compliant:
            os_by_compliance[item.os]["compliant"] += 1
        else:
            os_by_compliance[item.os]["non_compliant"] += 1

        # Category by status
        if item.category not in category_by_status:
            category_by_status[item.category] = {"online": 0, "offline": 0}
        if item.is_online:
            category_by_status[item.category]["online"] += 1
        else:
            category_by_status[item.category]["offline"] += 1

    return FleetMatrixCrossTabulation(
        os_by_status=os_by_status,
        os_by_compliance=os_by_compliance,
        category_by_status=category_by_status,
    )


async def get_fleet_matrix(
    session: AsyncSession,
    tailnet: Optional[str] = None,
    status: Optional[str] = None,
    os: Optional[str] = None,
    compliance: Optional[str] = None,
    category: Optional[str] = None,
    locked_out: Optional[bool] = None,
    quarantined: Optional[bool] = None,
    geo_anomaly: Optional[bool] = None,
    exit_node: Optional[bool] = None,
    q: Optional[str] = None,
    sort_by: str = "hostname",
    order: str = "asc",
    limit: int = 50,
    offset: int = 0,
) -> FleetMatrixResponse:
    """Queries the fleet database, filters nodes across all telemetry dimensions, sorts, paginates,

    and returns a FleetMatrixResponse with columns, cross-tabulations, and node matrix rows.
    """
    stmt = select(Node)
    if tailnet:
        stmt = stmt.where(Node.tailnet == tailnet)

    result = await session.execute(stmt)
    all_nodes = list(result.scalars().all())
    total_devices = len(all_nodes)

    now = datetime.now(timezone.utc)
    all_matrix_items = [evaluate_node_matrix_item(node, now=now) for node in all_nodes]

    # Compute global cross-tabulation across the target tailnet before filters
    cross_tabulation = compute_cross_tabulation(all_matrix_items)

    # Apply in-memory filters
    filtered_items: List[NodeMatrixItem] = []
    q_lower = q.strip().lower() if q else None
    os_lower = os.strip().lower() if os else None
    status_lower = status.strip().lower() if status else None
    compliance_lower = compliance.strip().lower() if compliance else None
    category_lower = category.strip().lower() if category else None

    for item in all_matrix_items:
        # Status filter ('online', 'offline')
        if status_lower in ("online", "true", "1"):
            if not item.is_online:
                continue
        elif status_lower in ("offline", "false", "0"):
            if item.is_online:
                continue

        # OS filter
        if os_lower and item.os != os_lower and (item.os_raw or "").lower() != os_lower:
            continue

        # Compliance filter ('compliant', 'non_compliant')
        if compliance_lower in ("compliant", "true"):
            if not item.is_compliant:
                continue
        elif compliance_lower in ("non_compliant", "false", "uncompliant"):
            if item.is_compliant:
                continue

        # Category filter
        if category_lower and item.category != category_lower:
            continue

        # Locked out filter
        if locked_out is not None and item.is_locked_out != locked_out:
            continue

        # Quarantined filter
        if quarantined is not None and item.is_quarantined != quarantined:
            continue

        # Geolocation anomaly filter
        if geo_anomaly is not None and item.is_impossible_travel != geo_anomaly:
            continue

        # Exit node filter
        if exit_node is not None and item.is_exit_node != exit_node:
            continue

        # Text search query (q)
        if q_lower:
            matches_hostname = q_lower in item.hostname.lower()
            matches_name = q_lower in item.name.lower()
            matches_user = bool(item.user and q_lower in item.user.lower())
            matches_ip = any(q_lower in ip.lower() for ip in item.addresses)
            matches_tag = any(q_lower in tag.lower() for tag in item.tags)
            if not (matches_hostname or matches_name or matches_user or matches_ip or matches_tag):
                continue

        filtered_items.append(item)

    filtered_count = len(filtered_items)

    # Sorting
    reverse = (order.lower() == "desc")
    sort_key = sort_by.lower()

    def get_sort_value(m: NodeMatrixItem) -> Any:
        if sort_key == "hostname":
            return m.hostname.lower()
        if sort_key == "name":
            return m.name.lower()
        if sort_key == "os":
            return m.os
        if sort_key == "client_version":
            return m.client_version or ""
        if sort_key == "last_seen":
            return m.last_seen or ""
        if sort_key == "latency_ms":
            return (m.latency_ms if m.latency_ms is not None else 999999.0)
        if sort_key == "health_score":
            return m.health_score
        if sort_key == "health_status":
            return m.health_status
        if sort_key == "is_online":
            return m.is_online
        if sort_key == "is_compliant":
            return m.is_compliant
        if sort_key in ("is_impossible_travel", "geo_anomaly"):
            return m.is_impossible_travel
        if sort_key in ("is_quarantined", "quarantined"):
            return m.is_quarantined
        if sort_key == "tailnet_lock_status":
            return m.tailnet_lock_status
        if sort_key == "days_until_key_expiry":
            return (m.days_until_key_expiry if m.days_until_key_expiry is not None else 999999.0)
        return m.hostname.lower()

    filtered_items.sort(key=get_sort_value, reverse=reverse)

    # Pagination
    paginated_items = filtered_items[offset : offset + limit]
    has_more = (offset + limit) < filtered_count

    return FleetMatrixResponse(
        total_devices=total_devices,
        filtered_devices=filtered_count,
        limit=limit,
        offset=offset,
        has_more=has_more,
        columns=DEFAULT_FLEET_MATRIX_COLUMNS,
        cross_tabulation=cross_tabulation,
        matrix=paginated_items,
        timestamp=now.isoformat(),
    )


async def get_fleet_matrix_summary(
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Dict[str, Any]:
    """Generates a lightweight matrix summary containing cross-tabulations and category statistics."""
    stmt = select(Node)
    if tailnet:
        stmt = stmt.where(Node.tailnet == tailnet)

    result = await session.execute(stmt)
    nodes = list(result.scalars().all())

    now = datetime.now(timezone.utc)
    items = [evaluate_node_matrix_item(n, now=now) for n in nodes]
    cross = compute_cross_tabulation(items)

    return {
        "total_devices": len(items),
        "online_devices": sum(1 for i in items if i.is_online),
        "offline_devices": sum(1 for i in items if not i.is_online),
        "cross_tabulation": cross.model_dump(),
        "columns": [c.model_dump() for c in DEFAULT_FLEET_MATRIX_COLUMNS],
        "timestamp": now.isoformat(),
    }
