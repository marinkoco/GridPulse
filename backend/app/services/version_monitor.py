from __future__ import annotations

from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.enums import ComplianceStatus
from app.models.node import Node
from app.models.node_state import NodeState
from app.schemas.tailscale import TailscaleDevice

logger = logging.getLogger(__name__)


def parse_semver_tuple(version_str: Optional[str]) -> Optional[Tuple[int, int, int]]:
    """Parses a version string into a (major, minor, patch) integer tuple.

    Strips leading 'v' or 'V' prefixes and suffixes (pre-release tags, git commits, build metadata).

    Examples:
        - "1.60.0" -> (1, 60, 0)
        - "v1.58.2" -> (1, 58, 2)
        - "1.56.0-t1234abcd" -> (1, 56, 0)
        - "1.54" -> (1, 54, 0)
        - "invalid" -> None
    """
    if not version_str:
        return None

    cleaned = str(version_str).strip().lstrip("vV")
    if not cleaned:
        return None

    # Strip pre-release, commit hashes, or build metadata (+, -, ~)
    core = re.split(r"[-+~]", cleaned, maxsplit=1)[0]
    parts = core.split(".")

    if not parts or not parts[0].isdigit():
        return None

    try:
        major = int(parts[0])
        if len(parts) > 1 and not parts[1].isdigit():
            return None
        minor = int(parts[1]) if len(parts) > 1 else 0
        if len(parts) > 2 and not parts[2].isdigit():
            return None
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except (ValueError, IndexError):
        return None


def parse_node_ts_version(device: TailscaleDevice) -> Optional[str]:
    """Extracts the 'node:tsVersion' posture attribute or client version from a TailscaleDevice.

    Priority:
    1. device.attributes['node:tsVersion']
    2. device.tags matching 'node:tsVersion:<version>'
    3. device.client_version
    4. device.client_connectivity.client_version.running_version
    """
    return device.get_node_ts_version_attribute()


def evaluate_version_drift(
    current_version: Optional[str],
    stable_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluates version drift and vulnerability risk by comparing a node version against stable.

    Args:
        current_version: The version string running on the node (e.g. from node:tsVersion).
        stable_version: Target stable release (defaults to settings.TAILSCALE_STABLE_VERSION).

    Returns:
        Dictionary containing drift indicators, drift type ('major', 'minor', 'patch', 'none', 'ahead'),
        vulnerability severity, and human-readable summary.
    """
    target_stable = stable_version or settings.TAILSCALE_STABLE_VERSION
    current_parsed = parse_semver_tuple(current_version)
    stable_parsed = parse_semver_tuple(target_stable)

    if current_parsed is None or stable_parsed is None:
        return {
            "current_version": current_version,
            "stable_version": target_stable,
            "is_valid": False,
            "is_behind": True,
            "is_ahead": False,
            "is_stable": False,
            "drift_type": "unknown",
            "major_behind": 0,
            "minor_behind": 0,
            "patch_behind": 0,
            "versions_behind": 0,
            "is_vulnerable": True,
            "vulnerability_severity": "high",
            "vulnerability_summary": (
                f"Undetermined Tailscale version '{current_version}' "
                f"(unable to verify against stable {target_stable})."
            ),
        }

    c_maj, c_min, c_patch = current_parsed
    s_maj, s_min, s_patch = stable_parsed

    if (c_maj, c_min, c_patch) == (s_maj, s_min, s_patch):
        return {
            "current_version": current_version,
            "stable_version": target_stable,
            "is_valid": True,
            "is_behind": False,
            "is_ahead": False,
            "is_stable": True,
            "drift_type": "none",
            "major_behind": 0,
            "minor_behind": 0,
            "patch_behind": 0,
            "versions_behind": 0,
            "is_vulnerable": False,
            "vulnerability_severity": "none",
            "vulnerability_summary": f"Node version {current_version} is up to date with stable {target_stable}.",
        }

    if (c_maj, c_min, c_patch) > (s_maj, s_min, s_patch):
        return {
            "current_version": current_version,
            "stable_version": target_stable,
            "is_valid": True,
            "is_behind": False,
            "is_ahead": True,
            "is_stable": False,
            "drift_type": "ahead",
            "major_behind": 0,
            "minor_behind": 0,
            "patch_behind": 0,
            "versions_behind": 0,
            "is_vulnerable": False,
            "vulnerability_severity": "none",
            "vulnerability_summary": f"Node version {current_version} is ahead of stable {target_stable} (unstable/preview).",
        }

    # Node is behind stable: compute differences
    major_diff = max(0, s_maj - c_maj)
    if major_diff > 0:
        minor_diff = 0
        patch_diff = 0
    else:
        minor_diff = max(0, s_min - c_min)
        patch_diff = max(0, s_patch - c_patch) if minor_diff == 0 else 0

    if major_diff > 0:
        drift_type = "major"
        severity = "critical"
        summary = (
            f"Vulnerable: Node version {current_version} is {major_diff} major version(s) "
            f"behind stable {target_stable} (critical vulnerability risk)."
        )
    elif minor_diff >= 3:
        drift_type = "minor"
        severity = "high"
        summary = (
            f"Vulnerable: Node version {current_version} is {minor_diff} minor versions "
            f"behind stable {target_stable} (high vulnerability risk)."
        )
    elif minor_diff >= 1:
        drift_type = "minor"
        severity = "medium"
        summary = (
            f"Vulnerable: Node version {current_version} is {minor_diff} minor version(s) "
            f"behind stable {target_stable} (medium risk)."
        )
    else:
        drift_type = "patch"
        severity = "low"
        summary = (
            f"Node version {current_version} is {patch_diff} patch release(s) "
            f"behind stable {target_stable} (low risk)."
        )

    return {
        "current_version": current_version,
        "stable_version": target_stable,
        "is_valid": True,
        "is_behind": True,
        "is_ahead": False,
        "is_stable": False,
        "drift_type": drift_type,
        "major_behind": major_diff,
        "minor_behind": minor_diff,
        "patch_behind": patch_diff,
        "versions_behind": major_diff + minor_diff + patch_diff,
        "is_vulnerable": True,
        "vulnerability_severity": severity,
        "vulnerability_summary": summary,
    }


def format_countdown_human(seconds: float) -> str:
    """Formats countdown seconds into clean, human-readable countdown string.

    Examples:
        - 30 -> "< 1m"
        - 120 -> "2m"
        - 3665 -> "1h 1m"
        - 90000 -> "1d 1h"
        - 1209600 -> "14d"
    """
    sec = max(0, int(seconds))
    if sec < 60:
        return "< 1m"

    minutes = sec // 60
    if minutes < 60:
        return f"{minutes}m"

    hours = minutes // 60
    remaining_mins = minutes % 60
    if hours < 24:
        return f"{hours}h {remaining_mins}m" if remaining_mins > 0 else f"{hours}h"

    days = hours // 24
    remaining_hours = hours % 24
    return f"{days}d {remaining_hours}h" if remaining_hours > 0 else f"{days}d"


def calculate_key_expiry_countdown(
    expires_at: Optional[Union[datetime, str]],
    key_expiry_disabled: bool = False,
    warning_days: Optional[int] = None,
    critical_days: Optional[int] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Calculates countdown metrics and status for the keyExpiry field.

    Args:
        expires_at: Expiration timestamp (datetime, ISO string, or None).
        key_expiry_disabled: Whether key expiry is disabled on the device.
        warning_days: Threshold in days to flag upcoming expiration (defaults to settings.KEY_EXPIRY_WARNING_DAYS).
        critical_days: Threshold in days for critical countdown (defaults to settings.KEY_EXPIRY_CRITICAL_DAYS).
        now: Reference evaluation datetime (defaults to current UTC time).

    Returns:
        Dictionary containing remaining seconds/days/hours, human countdown, status, and severity.
    """
    warn_days = warning_days if warning_days is not None else settings.KEY_EXPIRY_WARNING_DAYS
    crit_days = critical_days if critical_days is not None else settings.KEY_EXPIRY_CRITICAL_DAYS
    eval_now = now or datetime.now(timezone.utc)
    eval_now_utc = eval_now if eval_now.tzinfo else eval_now.replace(tzinfo=timezone.utc)

    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except Exception:
            expires_at = None

    if key_expiry_disabled:
        return {
            "key_expiry_disabled": True,
            "expires_at": None,
            "status": "disabled",
            "is_expired": False,
            "is_expiring_soon": False,
            "remaining_seconds": None,
            "remaining_days": None,
            "remaining_hours": None,
            "countdown_human": "Key expiry disabled",
            "severity": "info",
            "summary": "Key expiry is explicitly disabled for this node",
        }

    if expires_at is None:
        return {
            "key_expiry_disabled": False,
            "expires_at": None,
            "status": "unknown",
            "is_expired": False,
            "is_expiring_soon": False,
            "remaining_seconds": None,
            "remaining_days": None,
            "remaining_hours": None,
            "countdown_human": "No expiry configured",
            "severity": "info",
            "summary": "No expiration date reported for key",
        }

    exp_utc = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
    delta_seconds = (exp_utc - eval_now_utc).total_seconds()

    if delta_seconds <= 0:
        expired_sec = abs(delta_seconds)
        expired_human = format_countdown_human(expired_sec)
        return {
            "key_expiry_disabled": False,
            "expires_at": exp_utc.isoformat(),
            "status": "expired",
            "is_expired": True,
            "is_expiring_soon": False,
            "remaining_seconds": 0.0,
            "remaining_days": 0.0,
            "remaining_hours": 0.0,
            "countdown_human": f"Expired {expired_human} ago",
            "severity": "critical",
            "summary": f"Tailscale authentication key expired on {exp_utc.isoformat()}",
        }

    remaining_days = round(delta_seconds / 86400, 2)
    remaining_hours = round(delta_seconds / 3600, 1)
    countdown_human = format_countdown_human(delta_seconds)

    if delta_seconds <= crit_days * 86400:
        status = "critical"
        is_expiring_soon = True
        severity = "critical"
        summary = f"Key expires in {countdown_human} (critical threshold <= {crit_days}d)"
    elif delta_seconds <= warn_days * 86400:
        status = "expiring_soon"
        is_expiring_soon = True
        severity = "warning"
        summary = f"Key expires in {countdown_human} (warning threshold <= {warn_days}d)"
    else:
        status = "valid"
        is_expiring_soon = False
        severity = "info"
        summary = f"Key valid for {countdown_human}"

    return {
        "key_expiry_disabled": False,
        "expires_at": exp_utc.isoformat(),
        "status": status,
        "is_expired": False,
        "is_expiring_soon": is_expiring_soon,
        "remaining_seconds": round(delta_seconds, 1),
        "remaining_days": remaining_days,
        "remaining_hours": remaining_hours,
        "countdown_human": countdown_human,
        "severity": severity,
        "summary": summary,
    }


def evaluate_node_security_posture(
    device: TailscaleDevice,
    existing_node: Optional[Node] = None,
    stable_version: Optional[str] = None,
    warning_days: Optional[int] = None,
    critical_days: Optional[int] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Comprehensive posture check for a node evaluating version drift, keyExpiry countdown, and vulnerabilities.

    Args:
        device: Newly polled TailscaleDevice instance.
        existing_node: Optional existing Node ORM instance.
        stable_version: Target stable version.
        warning_days: Warning threshold for key expiry countdown.
        critical_days: Critical threshold for key expiry countdown.
        now: Evaluation reference timestamp.

    Returns:
        Dictionary containing posture outcomes, compliance status, and list of flagged vulnerabilities.
    """
    eval_now = now or datetime.now(timezone.utc)
    node_ts_version = parse_node_ts_version(device)
    version_drift = evaluate_version_drift(node_ts_version, stable_version=stable_version)

    key_exp_dt = device.expires or getattr(device, "key_expiry", None)
    key_expiry = calculate_key_expiry_countdown(
        expires_at=key_exp_dt,
        key_expiry_disabled=device.key_expiry_disabled,
        warning_days=warning_days,
        critical_days=critical_days,
        now=eval_now,
    )

    vulnerabilities = []

    # Flag version drift vulnerability
    if version_drift["is_vulnerable"]:
        vulnerabilities.append(
            {
                "type": "version_drift",
                "severity": version_drift["vulnerability_severity"],
                "title": f"Tailscale version drift: {version_drift['drift_type']}",
                "description": version_drift["vulnerability_summary"],
                "current_version": node_ts_version,
                "stable_version": version_drift["stable_version"],
                "versions_behind": version_drift["versions_behind"],
            }
        )

    # Flag key expiry vulnerability or upcoming expiration
    if key_expiry["is_expired"]:
        vulnerabilities.append(
            {
                "type": "key_expired",
                "severity": "critical",
                "title": "Tailscale authentication key expired",
                "description": key_expiry["summary"],
                "expires_at": key_expiry["expires_at"],
            }
        )
    elif key_expiry["is_expiring_soon"]:
        vulnerabilities.append(
            {
                "type": "key_expiring_soon",
                "severity": key_expiry["severity"],
                "title": f"Authentication key expiring soon ({key_expiry['countdown_human']})",
                "description": key_expiry["summary"],
                "expires_at": key_expiry["expires_at"],
            }
        )

    # Flag control plane update availability
    if device.update_available:
        vulnerabilities.append(
            {
                "type": "update_available",
                "severity": "medium",
                "title": "Tailscale client update available",
                "description": f"Tailscale control plane reports an update is available for '{device.hostname}'.",
            }
        )

    # Calculate overall compliance
    if key_expiry["is_expired"] or version_drift["vulnerability_severity"] == "critical":
        compliance_status = ComplianceStatus.NON_COMPLIANT.value
        is_compliant = False
    elif key_expiry["is_expiring_soon"] or version_drift["vulnerability_severity"] in ("high", "medium"):
        compliance_status = ComplianceStatus.WARNING.value
        is_compliant = True
    elif version_drift["vulnerability_severity"] == "low" or device.update_available:
        compliance_status = ComplianceStatus.WARNING.value
        is_compliant = True
    else:
        compliance_status = ComplianceStatus.COMPLIANT.value
        is_compliant = True

    return {
        "hostname": device.hostname,
        "node_ts_version": node_ts_version,
        "version_drift": version_drift,
        "key_expiry": key_expiry,
        "vulnerabilities": vulnerabilities,
        "is_compliant": is_compliant,
        "compliance_status": compliance_status,
        "update_available": device.update_available,
        "evaluated_at": eval_now.isoformat(),
    }


async def get_fleet_version_drift_overview(
    session: AsyncSession,
    tailnet: Optional[str] = None,
    stable_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Aggregates fleet-wide Tailscale version distribution and flags vulnerable outdated devices.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet domain filter.
        stable_version: Target stable version override.

    Returns:
        Dictionary containing counts of stable vs outdated nodes, breakdown by severity,
        version distribution map, and per-node drift details.
    """
    target_stable = stable_version or settings.TAILSCALE_STABLE_VERSION
    stmt = select(Node).order_by(Node.hostname.asc())
    if tailnet:
        stmt = stmt.where(Node.tailnet == tailnet)

    result = await session.execute(stmt)
    nodes = list(result.scalars().all())
    total_nodes = len(nodes)

    stable_count = 0
    outdated_count = 0
    vulnerable_count = 0
    drift_breakdown = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "none": 0,
        "unknown": 0,
    }
    version_distribution: Dict[str, int] = {}
    nodes_summary = []

    for node in nodes:
        meta = node.telemetry_metadata or {}
        ts_ver = (
            meta.get("node_ts_version")
            or (meta.get("security_posture", {}).get("node_ts_version"))
            or node.client_version
        )
        if not ts_ver and node.tags:
            for tag in node.tags:
                tag_lower = tag.lower()
                if tag_lower.startswith("node:tsversion:") or tag_lower.startswith("node:ts_version:"):
                    ts_ver = tag.split(":", 2)[-1]
                    break
        if not ts_ver:
            ts_ver = "unknown"
        if ts_ver != "unknown":
            version_distribution[ts_ver] = version_distribution.get(ts_ver, 0) + 1
        else:
            version_distribution["unknown"] = version_distribution.get("unknown", 0) + 1

        drift = evaluate_version_drift(
            ts_ver if ts_ver != "unknown" else None,
            stable_version=target_stable,
        )
        sev = drift["vulnerability_severity"]
        drift_breakdown[sev] = drift_breakdown.get(sev, 0) + 1

        if drift["is_stable"] or drift["is_ahead"]:
            stable_count += 1
        else:
            outdated_count += 1

        if drift["is_vulnerable"]:
            vulnerable_count += 1

        nodes_summary.append(
            {
                "id": node.id,
                "node_id": node.node_id,
                "hostname": node.hostname,
                "name": node.name,
                "os": node.os,
                "is_online": node.is_online,
                "node_ts_version": ts_ver,
                "stable_version": target_stable,
                "is_vulnerable": drift["is_vulnerable"],
                "vulnerability_severity": drift["vulnerability_severity"],
                "drift_type": drift["drift_type"],
                "versions_behind": drift["versions_behind"],
                "summary": drift["vulnerability_summary"],
                "update_available": node.update_available,
            }
        )

    vuln_rate = round((vulnerable_count / total_nodes) * 100.0, 2) if total_nodes > 0 else 0.0

    return {
        "stable_version": target_stable,
        "total_nodes": total_nodes,
        "stable_nodes": stable_count,
        "outdated_nodes": outdated_count,
        "vulnerable_nodes": vulnerable_count,
        "vulnerability_rate_percentage": vuln_rate,
        "drift_breakdown": drift_breakdown,
        "version_distribution": version_distribution,
        "nodes": nodes_summary,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def get_fleet_key_expiry_overview(
    session: AsyncSession,
    tailnet: Optional[str] = None,
    warning_days: Optional[int] = None,
    critical_days: Optional[int] = None,
) -> Dict[str, Any]:
    """Calculates key expiry countdowns across all nodes and sorts by expiration urgency.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet domain filter.
        warning_days: Optional custom warning days threshold.
        critical_days: Optional custom critical days threshold.

    Returns:
        Dictionary containing counts of valid, expiring soon, expired, and disabled keys,
        with full countdown list sorted by urgency.
    """
    warn_days = warning_days if warning_days is not None else settings.KEY_EXPIRY_WARNING_DAYS
    crit_days = critical_days if critical_days is not None else settings.KEY_EXPIRY_CRITICAL_DAYS
    now = datetime.now(timezone.utc)

    stmt = select(Node).order_by(Node.expires_at.asc().nulls_last(), Node.hostname.asc())
    if tailnet:
        stmt = stmt.where(Node.tailnet == tailnet)

    result = await session.execute(stmt)
    nodes = list(result.scalars().all())
    total_nodes = len(nodes)

    valid_count = 0
    expiring_soon_count = 0
    expired_count = 0
    disabled_count = 0
    unknown_count = 0
    nodes_summary = []

    for node in nodes:
        countdown = calculate_key_expiry_countdown(
            expires_at=node.expires_at,
            key_expiry_disabled=node.key_expiry_disabled,
            warning_days=warn_days,
            critical_days=crit_days,
            now=now,
        )

        status = countdown["status"]
        if status == "disabled":
            disabled_count += 1
        elif status == "expired":
            expired_count += 1
        elif status in ("critical", "expiring_soon"):
            expiring_soon_count += 1
        elif status == "valid":
            valid_count += 1
        else:
            unknown_count += 1

        nodes_summary.append(
            {
                "id": node.id,
                "node_id": node.node_id,
                "hostname": node.hostname,
                "name": node.name,
                "os": node.os,
                "is_online": node.is_online,
                "key_expiry_disabled": node.key_expiry_disabled,
                "expires_at": node.expires_at.isoformat() if node.expires_at else None,
                "status": countdown["status"],
                "severity": countdown["severity"],
                "is_expired": countdown["is_expired"],
                "is_expiring_soon": countdown["is_expiring_soon"],
                "remaining_seconds": countdown["remaining_seconds"],
                "remaining_days": countdown["remaining_days"],
                "countdown_human": countdown["countdown_human"],
                "summary": countdown["summary"],
            }
        )

    # Sort nodes so expired and expiring soon appear at the top
    nodes_summary.sort(
        key=lambda n: (
            0 if n["is_expired"] else (1 if n["is_expiring_soon"] else 2),
            n["remaining_seconds"] if n["remaining_seconds"] is not None else float("inf"),
        )
    )

    return {
        "warning_threshold_days": warn_days,
        "critical_threshold_days": crit_days,
        "total_nodes": total_nodes,
        "valid_keys": valid_count,
        "expiring_soon_keys": expiring_soon_count,
        "expired_keys": expired_count,
        "disabled_expiry_keys": disabled_count,
        "unknown_keys": unknown_count,
        "nodes": nodes_summary,
        "timestamp": now.isoformat(),
    }


async def get_node_security_posture(
    session: AsyncSession,
    node_id: str,
    stable_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieves deep security posture evaluation, version drift analysis, and key expiry for a specific node.

    Args:
        session: Active SQLAlchemy AsyncSession.
        node_id: Primary UUID or stable Tailscale node ID.
        stable_version: Optional target stable version override.

    Returns:
        Dictionary containing security status or error dict if not found.
    """
    stmt = select(Node).where((Node.id == node_id) | (Node.node_id == node_id))
    result = await session.execute(stmt)
    node = result.scalar_one_or_none()

    if node is None:
        return {"error": "node_not_found", "node_id": node_id}

    target_stable = stable_version or settings.TAILSCALE_STABLE_VERSION
    now = datetime.now(timezone.utc)
    meta = node.telemetry_metadata or {}
    ts_ver = (
        meta.get("node_ts_version")
        or (meta.get("security_posture", {}).get("node_ts_version"))
        or node.client_version
    )
    if not ts_ver and node.tags:
        for tag in node.tags:
            tag_lower = tag.lower()
            if tag_lower.startswith("node:tsversion:") or tag_lower.startswith("node:ts_version:"):
                ts_ver = tag.split(":", 2)[-1]
                break

    drift = evaluate_version_drift(ts_ver, stable_version=target_stable)
    countdown = calculate_key_expiry_countdown(
        expires_at=node.expires_at,
        key_expiry_disabled=node.key_expiry_disabled,
        now=now,
    )

    # Retrieve most recent NodeState
    state_stmt = (
        select(NodeState)
        .where(NodeState.node_id == node.id)
        .order_by(NodeState.recorded_at.desc())
        .limit(1)
    )
    state_res = await session.execute(state_stmt)
    latest_state = state_res.scalar_one_or_none()

    vulnerabilities = []
    if drift["is_vulnerable"]:
        vulnerabilities.append(
            {
                "type": "version_drift",
                "severity": drift["vulnerability_severity"],
                "title": f"Tailscale version drift: {drift['drift_type']}",
                "description": drift["vulnerability_summary"],
                "current_version": ts_ver,
                "stable_version": target_stable,
            }
        )

    if countdown["is_expired"]:
        vulnerabilities.append(
            {
                "type": "key_expired",
                "severity": "critical",
                "title": "Tailscale authentication key expired",
                "description": countdown["summary"],
                "expires_at": countdown["expires_at"],
            }
        )
    elif countdown["is_expiring_soon"]:
        vulnerabilities.append(
            {
                "type": "key_expiring_soon",
                "severity": countdown["severity"],
                "title": f"Key expiring soon ({countdown['countdown_human']})",
                "description": countdown["summary"],
                "expires_at": countdown["expires_at"],
            }
        )

    if node.update_available:
        vulnerabilities.append(
            {
                "type": "update_available",
                "severity": "medium",
                "title": "Tailscale client update available",
                "description": "Tailscale control plane reports a newer client release available for this device.",
            }
        )

    # Determine compliance status
    if countdown["is_expired"] or drift["vulnerability_severity"] == "critical":
        compliance_status = ComplianceStatus.NON_COMPLIANT.value
        is_compliant = False
    elif countdown["is_expiring_soon"] or drift["vulnerability_severity"] in ("high", "medium"):
        compliance_status = ComplianceStatus.WARNING.value
        is_compliant = True
    elif drift["vulnerability_severity"] == "low" or node.update_available:
        compliance_status = ComplianceStatus.WARNING.value
        is_compliant = True
    else:
        compliance_status = ComplianceStatus.COMPLIANT.value
        is_compliant = True

    return {
        "id": node.id,
        "node_id": node.node_id,
        "hostname": node.hostname,
        "name": node.name,
        "os": node.os,
        "os_version": node.os_version,
        "node_ts_version": ts_ver,
        "is_online": node.is_online,
        "is_compliant": is_compliant,
        "compliance_status": compliance_status,
        "version_drift": drift,
        "key_expiry": countdown,
        "vulnerabilities": vulnerabilities,
        "update_available": node.update_available,
        "latest_state_recorded_at": (
            latest_state.recorded_at.isoformat()
            if latest_state and latest_state.recorded_at
            else None
        ),
        "timestamp": now.isoformat(),
    }
