from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.node import Node
from app.models.node_state import NodeState
from app.schemas.tailscale import TailscaleDevice

logger = logging.getLogger(__name__)

# Canonical OS families supported across the fleet
SUPPORTED_OS_FAMILIES = {
    "linux",
    "macos",
    "windows",
    "ios",
    "android",
    "bsd",
    "other",
}

# Normalization lookup table for OS variants reported by Tailscale daemon or posture attributes
OS_MAPPING = {
    "darwin": "macos",
    "macos": "macos",
    "mac_os": "macos",
    "mac": "macos",
    "apple": "macos",
    "linux": "linux",
    "ubuntu": "linux",
    "debian": "linux",
    "centos": "linux",
    "rhel": "linux",
    "fedora": "linux",
    "arch": "linux",
    "alpine": "linux",
    "suse": "linux",
    "windows": "windows",
    "win": "windows",
    "win32": "windows",
    "win64": "windows",
    "windows_nt": "windows",
    "ios": "ios",
    "iphone": "ios",
    "ipad": "ios",
    "ipados": "ios",
    "android": "android",
    "freebsd": "bsd",
    "openbsd": "bsd",
    "netbsd": "bsd",
    "dragonfly": "bsd",
}


def normalize_os(raw_os: Optional[str]) -> str:
    """Normalizes an OS string into a canonical OS family identifier.

    Args:
        raw_os: Raw operating system name (e.g., 'macOS', 'darwin', 'Linux', 'windows').

    Returns:
        Canonical OS family: 'linux', 'macos', 'windows', 'ios', 'android', 'bsd', or 'other'.
    """
    if not raw_os:
        return "other"
    cleaned = raw_os.strip().lower()
    return OS_MAPPING.get(cleaned, cleaned if cleaned in SUPPORTED_OS_FAMILIES else "other")


def categorize_os_device(
    os_family: str,
    tags: Optional[List[str]] = None,
    hostname: Optional[str] = None,
) -> str:
    """Classifies a node role/category based on OS family and assigned tags.

    Args:
        os_family: Normalized OS family string.
        tags: Optional list of Tailscale tags assigned to the node.
        hostname: Optional hostname for pattern-based inference.

    Returns:
        One of 'server', 'workstation', 'mobile', 'embedded', or 'unknown'.
    """
    tag_set = {t.lower() for t in (tags or [])}

    if any(t in tag_set for t in ("tag:server", "tag:prod", "tag:stage", "tag:ci", "tag:database")):
        return "server"
    if any(t in tag_set for t in ("tag:workstation", "tag:desktop", "tag:dev")):
        return "workstation"
    if any(t in tag_set for t in ("tag:mobile", "tag:phone")):
        return "mobile"
    if any(t in tag_set for t in ("tag:embedded", "tag:iot", "tag:router")):
        return "embedded"

    if os_family in ("ios", "android"):
        return "mobile"
    if os_family in ("linux", "bsd"):
        return "server"
    if os_family in ("macos", "windows"):
        return "workstation"

    return "unknown"


def parse_node_os_attributes(device: TailscaleDevice) -> Dict[str, Any]:
    """Parses node:os and system telemetry attributes from a TailscaleDevice payload.

    Args:
        device: The validated TailscaleDevice schema instance.

    Returns:
        Dictionary containing normalized OS family, raw OS, version, node:os posture attribute,
        device category, and friendly display string.
    """
    node_os_attr = device.get_node_os_attribute()
    raw_os = device.os or (node_os_attr if node_os_attr else "unknown")
    os_family = normalize_os(raw_os)
    os_version = device.os_version
    category = categorize_os_device(os_family, tags=device.tags, hostname=device.hostname)

    if os_version:
        display_name = f"{os_family.capitalize()} ({os_version})"
    else:
        display_name = os_family.capitalize()

    return {
        "os_family": os_family,
        "raw_os": raw_os,
        "os_version": os_version,
        "node_os": node_os_attr or os_family,
        "os_category": category,
        "display_name": display_name,
    }


def calculate_duration_seconds(
    start: Optional[datetime],
    end: Optional[datetime] = None,
) -> float:
    """Calculates duration in seconds between two timestamps with timezone safety.

    Args:
        start: Starting datetime.
        end: Ending datetime (defaults to current UTC time).

    Returns:
        Duration in seconds as a float, or 0.0 if start is None.
    """
    if start is None:
        return 0.0
    now = end or datetime.now(timezone.utc)
    start_utc = start if start.tzinfo else start.replace(tzinfo=timezone.utc)
    end_utc = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    delta = (end_utc - start_utc).total_seconds()
    return max(0.0, delta)


def format_duration_human(seconds: float) -> str:
    """Converts a duration in seconds into a clean, human-readable string.

    Examples:
        - 45 -> "< 1m"
        - 150 -> "2m 30s"
        - 3665 -> "1h 1m"
        - 90000 -> "1d 1h"
    """
    sec = max(0, int(seconds))
    if sec < 60:
        return "< 1m"

    minutes = sec // 60
    if minutes < 60:
        remaining_secs = sec % 60
        return f"{minutes}m {remaining_secs}s" if remaining_secs > 0 else f"{minutes}m"

    hours = minutes // 60
    remaining_mins = minutes % 60
    if hours < 24:
        return f"{hours}h {remaining_mins}m" if remaining_mins > 0 else f"{hours}h"

    days = hours // 24
    remaining_hours = hours % 24
    return f"{days}d {remaining_hours}h" if remaining_hours > 0 else f"{days}d"


def evaluate_node_state_changes(
    existing_node: Node,
    device: TailscaleDevice,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Compares an incoming TailscaleDevice against the existing Node database record.

    Detects:
    1. Online/offline connectivity transitions and computes previous state duration.
    2. OS family, OS version, or node:os attribute updates.
    3. Tailscale client version upgrades.

    Args:
        existing_node: Current Node ORM entity from the database.
        device: Newly fetched TailscaleDevice payload.
        now: Reference evaluation datetime (defaults to UTC now).

    Returns:
        Dictionary detailing detected changes, transition durations, and telemetry metadata.
    """
    eval_now = now or datetime.now(timezone.utc)
    now_online = device.check_is_online()
    was_online = existing_node.is_online
    is_online_changed = was_online != now_online

    # Calculate previous state duration
    metadata = existing_node.telemetry_metadata or {}
    uptime_info = metadata.get("uptime_info", {})
    last_transition_iso = uptime_info.get("last_state_change")

    if last_transition_iso:
        try:
            last_transition = datetime.fromisoformat(last_transition_iso)
            duration_secs = calculate_duration_seconds(last_transition, eval_now)
        except Exception:
            duration_secs = calculate_duration_seconds(existing_node.last_seen, eval_now)
    elif existing_node.last_seen:
        duration_secs = calculate_duration_seconds(existing_node.last_seen, eval_now)
    else:
        duration_secs = 0.0

    duration_human = format_duration_human(duration_secs)

    # OS changes
    os_attrs = parse_node_os_attributes(device)
    new_os = os_attrs["os_family"]
    was_os = existing_node.os or ""
    new_os_version = device.os_version
    was_os_version = existing_node.os_version

    is_os_changed = (was_os.lower() != new_os.lower() if was_os else bool(new_os)) or (
        new_os_version is not None and was_os_version != new_os_version
    )

    # Client version change
    new_client = device.client_version
    was_client = existing_node.client_version
    is_client_changed = bool(new_client and was_client and was_client != new_client)

    return {
        "is_online_changed": is_online_changed,
        "was_online": was_online,
        "now_online": now_online,
        "duration_seconds": duration_secs,
        "duration_human": duration_human,
        "is_os_changed": is_os_changed,
        "was_os": was_os,
        "new_os": new_os,
        "was_os_version": was_os_version,
        "new_os_version": new_os_version,
        "is_client_changed": is_client_changed,
        "was_client_version": was_client,
        "new_client_version": new_client,
        "os_attributes": os_attrs,
    }


async def get_fleet_os_distribution(
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Dict[str, Any]:
    """Calculates aggregated OS fleet statistics and version distribution across nodes.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet domain to filter by.

    Returns:
        Dictionary containing fleet-wide counts, percentage breakdown by OS family,
        online/offline counts per OS, and detailed version breakdowns.
    """
    stmt = select(Node)
    if tailnet:
        stmt = stmt.where(Node.tailnet == tailnet)

    result = await session.execute(stmt)
    nodes = list(result.scalars().all())

    total_devices = len(nodes)
    if total_devices == 0:
        return {
            "total_devices": 0,
            "online_devices": 0,
            "offline_devices": 0,
            "fleet_uptime_percentage": 0.0,
            "by_os": {},
            "by_category": {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    online_count = sum(1 for n in nodes if n.is_online)
    offline_count = total_devices - online_count
    fleet_uptime_pct = round((online_count / total_devices) * 100.0, 2)

    by_os: Dict[str, Dict[str, Any]] = {}
    by_category: Dict[str, int] = {}

    for node in nodes:
        os_fam = normalize_os(node.os)
        if os_fam not in by_os:
            by_os[os_fam] = {
                "count": 0,
                "percentage": 0.0,
                "online": 0,
                "offline": 0,
                "uptime_percentage": 0.0,
                "versions": {},
            }

        os_entry = by_os[os_fam]
        os_entry["count"] += 1
        if node.is_online:
            os_entry["online"] += 1
        else:
            os_entry["offline"] += 1

        v_key = node.os_version or "Unknown Version"
        os_entry["versions"][v_key] = os_entry["versions"].get(v_key, 0) + 1

        cat = categorize_os_device(os_fam, tags=node.tags, hostname=node.hostname)
        by_category[cat] = by_category.get(cat, 0) + 1

    # Calculate percentages
    for os_fam, data in by_os.items():
        data["percentage"] = round((data["count"] / total_devices) * 100.0, 2)
        data["uptime_percentage"] = (
            round((data["online"] / data["count"]) * 100.0, 2) if data["count"] > 0 else 0.0
        )

    return {
        "total_devices": total_devices,
        "online_devices": online_count,
        "offline_devices": offline_count,
        "fleet_uptime_percentage": fleet_uptime_pct,
        "by_os": by_os,
        "by_category": by_category,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def get_fleet_uptime_overview(
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Dict[str, Any]:
    """Generates an overview of fleet uptime and individual node uptime streaks.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet filter.

    Returns:
        Fleet overview containing summary metrics and per-node uptime data.
    """
    stmt = select(Node).order_by(Node.is_online.desc(), Node.hostname.asc())
    if tailnet:
        stmt = stmt.where(Node.tailnet == tailnet)

    result = await session.execute(stmt)
    nodes = list(result.scalars().all())

    now = datetime.now(timezone.utc)
    nodes_overview = []
    total = len(nodes)
    online_count = 0

    for node in nodes:
        if node.is_online:
            online_count += 1

        meta = node.telemetry_metadata or {}
        uptime_info = meta.get("uptime_info", {})
        last_change_iso = uptime_info.get("last_state_change")
        if last_change_iso:
            try:
                change_dt = datetime.fromisoformat(last_change_iso)
                streak_secs = calculate_duration_seconds(change_dt, now)
            except Exception:
                streak_secs = calculate_duration_seconds(node.last_seen, now)
        else:
            streak_secs = calculate_duration_seconds(node.last_seen, now)

        nodes_overview.append(
            {
                "id": node.id,
                "node_id": node.node_id,
                "hostname": node.hostname,
                "name": node.name,
                "os": normalize_os(node.os),
                "os_version": node.os_version,
                "is_online": node.is_online,
                "last_seen": node.last_seen.isoformat() if node.last_seen else None,
                "streak_duration_seconds": streak_secs,
                "streak_duration_human": format_duration_human(streak_secs),
                "addresses": node.addresses,
            }
        )

    uptime_pct = round((online_count / total) * 100.0, 2) if total > 0 else 0.0

    return {
        "total_nodes": total,
        "online_nodes": online_count,
        "offline_nodes": total - online_count,
        "fleet_uptime_percentage": uptime_pct,
        "nodes": nodes_overview,
        "timestamp": now.isoformat(),
    }


async def get_node_uptime_history(
    session: AsyncSession,
    node_id: str,
    limit: int = 50,
) -> Dict[str, Any]:
    """Retrieves historical posture snapshots and uptime percentage for a given node.

    Args:
        session: Active SQLAlchemy AsyncSession.
        node_id: Primary or stable node identifier.
        limit: Maximum historical snapshots to return.

    Returns:
        Historical telemetry summary including uptime ratio and recent timeline snapshots.
    """
    # Fetch node
    stmt = select(Node).where((Node.id == node_id) | (Node.node_id == node_id))
    result = await session.execute(stmt)
    node = result.scalar_one_or_none()

    if node is None:
        return {"error": "node_not_found", "node_id": node_id}

    # Fetch historical NodeState records
    state_stmt = (
        select(NodeState)
        .where(NodeState.node_id == node.id)
        .order_by(NodeState.recorded_at.desc())
        .limit(limit)
    )
    state_result = await session.execute(state_stmt)
    states = list(state_result.scalars().all())

    total_snapshots = len(states)
    online_snapshots = sum(1 for s in states if s.is_online)
    uptime_ratio = (
        round((online_snapshots / total_snapshots) * 100.0, 2) if total_snapshots > 0 else 0.0
    )

    history = [
        {
            "id": s.id,
            "recorded_at": s.recorded_at.isoformat() if s.recorded_at else None,
            "is_online": s.is_online,
            "compliance_status": s.compliance_status,
            "os_version": s.os_version,
            "client_version": s.client_version,
            "latency_ms": s.latency_ms,
            "derp_region": s.derp_region,
        }
        for s in states
    ]

    return {
        "node_id": node.id,
        "hostname": node.hostname,
        "os": normalize_os(node.os),
        "os_version": node.os_version,
        "is_online": node.is_online,
        "total_snapshots_evaluated": total_snapshots,
        "online_snapshots": online_snapshots,
        "uptime_percentage": uptime_ratio,
        "history": history,
    }
