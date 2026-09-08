from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select, delete, delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import settings
from app.database import async_session_maker
from app.models.audit_log import AuditLog
from app.models.enums import (
    AuditSeverity,
    AuditEventType,
    ComplianceStatus,
    EventCategory,
)
from app.models.node import Node
from app.models.node_state import NodeState
from app.schemas.tailscale import TailscaleDevice, TailscaleDevicesResponse
from app.services.fleet import (
    calculate_duration_seconds,
    evaluate_node_state_changes,
    format_duration_human,
    normalize_os,
    parse_node_os_attributes,
)
from app.services.network_auditor import audit_node_network_routing
from app.services.posture import audit_node_device_posture
from app.services.geolocation import audit_node_geolocation
from app.services.version_monitor import (
    calculate_key_expiry_countdown,
    evaluate_node_security_posture,
    evaluate_version_drift,
    parse_node_ts_version,
)
from app.services.tailscale_client import (
    TailscaleAPIError,
    TailscaleAuthError,
    TailscaleClient,
    TailscaleConnectionError,
    TailscaleError,
    TailscaleRateLimitError,
)

logger = logging.getLogger(__name__)


async def sync_tailscale_devices(
    devices: List[TailscaleDevice],
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Tuple[int, int, int]:
    """Synchronizes a list of TailscaleDevice models into the database.

    Inserts newly discovered devices into the `nodes` table, updates existing node
    records with latest metadata, parses `node:os` and system attributes, appends
    a new `NodeState` telemetry snapshot, tracks uptime durations, and logs state
    transitions (connectivity, OS drift, client updates) to `audit_logs`.

    Args:
        devices: List of validated `TailscaleDevice` payloads.
        session: Active SQLAlchemy `AsyncSession`.
        tailnet: Optional tailnet name override.

    Returns:
        Tuple of `(nodes_created, nodes_updated, node_states_recorded)`.
    """
    nodes_created = 0
    nodes_updated = 0
    node_states_recorded = 0
    online_count = 0
    eval_now = datetime.now(timezone.utc)
    eval_now_iso = eval_now.isoformat()

    for device in devices:
        # Search by primary id first, then fallback to nodeId
        stmt = select(Node).where(Node.id == device.id)
        result = await session.execute(stmt)
        existing_node = result.scalar_one_or_none()

        if existing_node is None and device.node_id:
            stmt = select(Node).where(Node.node_id == device.node_id)
            result = await session.execute(stmt)
            existing_node = result.scalar_one_or_none()

        node_dict = device.to_node_dict(tailnet_override=tailnet)
        os_info = parse_node_os_attributes(device)
        os_family = os_info["os_family"]
        now_online = device.check_is_online()

        if now_online:
            online_count += 1

        # Standardize OS to canonical family on the node dict
        node_dict["os"] = os_family
        node_dict["is_online"] = now_online

        # Evaluate Version Drift, Key Expiry, and Security Posture (Step 8)
        security_posture = evaluate_node_security_posture(
            device=device,
            existing_node=existing_node,
            now=eval_now,
        )
        version_drift = security_posture["version_drift"]
        key_expiry = security_posture["key_expiry"]
        vulnerabilities = security_posture["vulnerabilities"]
        node_ts_ver = security_posture["node_ts_version"]

        # Evaluate Network Routing and DERP fallbacks (Step 9)
        network_routing = audit_node_network_routing(
            device=device,
            existing_node=existing_node,
        )

        # Evaluate Device Posture & Compliance (Step 10)
        device_posture = audit_node_device_posture(
            device=device,
            existing_node=existing_node,
            now=eval_now,
        )

        # Evaluate Geolocation Anomaly & Impossible Travel (Step 11)
        geolocation = audit_node_geolocation(
            device=device,
            existing_node=existing_node,
            now=eval_now,
        )

        if existing_node is not None:
            # Evaluate connectivity, OS, and client updates
            changes = evaluate_node_state_changes(existing_node, device, now=eval_now)
            was_online = changes["was_online"]
            duration_secs = changes["duration_seconds"]
            duration_human = changes["duration_human"]

            # Update mutable columns on existing record
            for field, value in node_dict.items():
                if field not in ("id", "telemetry_metadata"):
                    setattr(existing_node, field, value)

            # Preserve and enrich telemetry_metadata with uptime and OS info
            current_metadata = dict(existing_node.telemetry_metadata or {})
            uptime_info = dict(current_metadata.get("uptime_info", {}))

            if changes["is_online_changed"]:
                event_type = (
                    AuditEventType.NODE_ONLINE.value
                    if now_online
                    else AuditEventType.NODE_OFFLINE.value
                )
                severity = (
                    AuditSeverity.INFO.value
                    if now_online
                    else AuditSeverity.WARNING.value
                )
                action = (
                    f"Device '{device.hostname}' came online"
                    if now_online
                    else f"Device '{device.hostname}' went offline"
                )
                state_desc = "online" if now_online else "offline"
                prev_desc = "online" if was_online else "offline"
                msg = (
                    f"Device '{device.hostname}' ({os_info['display_name']}) transitioned "
                    f"from {prev_desc} to {state_desc} after {duration_human} in previous state."
                )

                session.add(
                    AuditLog(
                        node_id=existing_node.id,
                        event_type=event_type,
                        event_category=EventCategory.DEVICE.value,
                        severity=severity,
                        action=action,
                        actor="system/apscheduler",
                        message=msg,
                        details={
                            "hostname": device.hostname,
                            "addresses": device.addresses,
                            "os": os_family,
                            "os_version": device.os_version,
                            "node_os_attribute": os_info["node_os"],
                            "previous_state": prev_desc,
                            "new_state": state_desc,
                            "duration_seconds": duration_secs,
                            "duration_human": duration_human,
                            "transition_type": (
                                "offline_to_online" if now_online else "online_to_offline"
                            ),
                            "last_seen": (
                                device.last_seen.isoformat()
                                if device.last_seen
                                else None
                            ),
                        },
                    )
                )

                uptime_info["last_state_change"] = eval_now_iso
                if now_online:
                    uptime_info["last_online_transition"] = eval_now_iso
                else:
                    uptime_info["last_offline_transition"] = eval_now_iso

                uptime_info["state_change_count"] = (
                    uptime_info.get("state_change_count", 0) + 1
                )
                uptime_info["current_streak_seconds"] = 0.0
                uptime_info["current_streak_human"] = "< 1m"
            else:
                # No transition: compute ongoing streak duration
                last_change = uptime_info.get("last_state_change")
                if last_change:
                    try:
                        streak = calculate_duration_seconds(
                            datetime.fromisoformat(last_change), eval_now
                        )
                    except Exception:
                        streak = calculate_duration_seconds(device.last_seen, eval_now)
                else:
                    streak = calculate_duration_seconds(device.last_seen, eval_now)
                    uptime_info["last_state_change"] = (
                        device.last_seen.isoformat()
                        if device.last_seen
                        else eval_now_iso
                    )

                uptime_info["current_streak_seconds"] = streak
                uptime_info["current_streak_human"] = format_duration_human(streak)

            # Record OS change if operating system or version shifted
            if changes["is_os_changed"]:
                session.add(
                    AuditLog(
                        node_id=existing_node.id,
                        event_type=AuditEventType.NODE_OS_CHANGED.value,
                        event_category=EventCategory.DEVICE.value,
                        severity=AuditSeverity.INFO.value,
                        action=f"Device '{device.hostname}' OS updated",
                        actor="system/apscheduler",
                        message=(
                            f"Device '{device.hostname}' OS changed from "
                            f"'{changes['was_os']}' ({changes['was_os_version']}) to "
                            f"'{changes['new_os']}' ({changes['new_os_version']})."
                        ),
                        details={
                            "hostname": device.hostname,
                            "previous_os": changes["was_os"],
                            "new_os": changes["new_os"],
                            "previous_os_version": changes["was_os_version"],
                            "new_os_version": changes["new_os_version"],
                            "node_os_attribute": os_info["node_os"],
                            "os_category": os_info["os_category"],
                        },
                    )
                )

            # Record client version change if Tailscale daemon was updated
            if changes["is_client_changed"]:
                session.add(
                    AuditLog(
                        node_id=existing_node.id,
                        event_type=AuditEventType.NODE_CLIENT_UPDATED.value,
                        event_category=EventCategory.DEVICE.value,
                        severity=AuditSeverity.INFO.value,
                        action=f"Device '{device.hostname}' client version updated",
                        actor="system/apscheduler",
                        message=(
                            f"Device '{device.hostname}' updated Tailscale client from "
                            f"'{changes['was_client_version']}' to '{changes['new_client_version']}'."
                        ),
                        details={
                            "hostname": device.hostname,
                            "previous_client_version": changes["was_client_version"],
                            "new_client_version": changes["new_client_version"],
                        },
                    )
                )

            # Detect and log Version Drift and Key Expiry warnings for existing nodes
            prev_posture = (existing_node.telemetry_metadata or {}).get("security_posture", {})
            prev_drift = prev_posture.get("version_drift", {})
            prev_vuln = prev_drift.get("is_vulnerable", False)
            prev_drift_sev = prev_drift.get("vulnerability_severity", "none")

            if version_drift["is_vulnerable"] and (
                not prev_vuln
                or changes["is_client_changed"]
                or prev_drift_sev != version_drift["vulnerability_severity"]
            ):
                session.add(
                    AuditLog(
                        node_id=existing_node.id,
                        event_type=AuditEventType.VERSION_DRIFT_WARNING.value,
                        event_category=EventCategory.SECURITY.value,
                        severity=(
                            AuditSeverity.CRITICAL.value
                            if version_drift["vulnerability_severity"] == "critical"
                            else AuditSeverity.HIGH.value
                            if version_drift["vulnerability_severity"] == "high"
                            else AuditSeverity.WARNING.value
                        ),
                        action=f"Device '{device.hostname}' version drift detected",
                        actor="system/apscheduler",
                        message=version_drift["vulnerability_summary"],
                        details={
                            "hostname": device.hostname,
                            "current_version": node_ts_ver,
                            "stable_version": version_drift["stable_version"],
                            "drift_type": version_drift["drift_type"],
                            "versions_behind": version_drift["versions_behind"],
                            "severity": version_drift["vulnerability_severity"],
                        },
                    )
                )

            prev_expiry = prev_posture.get("key_expiry", {})
            prev_exp_soon = prev_expiry.get("is_expiring_soon", False)
            prev_exp_status = prev_expiry.get("status")

            if key_expiry["is_expiring_soon"] and (
                not prev_exp_soon
                or (key_expiry["status"] == "critical" and prev_exp_status != "critical")
            ):
                session.add(
                    AuditLog(
                        node_id=existing_node.id,
                        event_type=AuditEventType.KEY_EXPIRY_WARNING.value,
                        event_category=EventCategory.SECURITY.value,
                        severity=(
                            AuditSeverity.CRITICAL.value
                            if key_expiry["status"] == "critical"
                            else AuditSeverity.WARNING.value
                        ),
                        action=f"Device '{device.hostname}' key expiring soon",
                        actor="system/apscheduler",
                        message=f"Tailscale key for '{device.hostname}' expires in {key_expiry['countdown_human']}.",
                        details={
                            "hostname": device.hostname,
                            "expires_at": key_expiry["expires_at"],
                            "remaining_days": key_expiry["remaining_days"],
                            "countdown_human": key_expiry["countdown_human"],
                            "status": key_expiry["status"],
                        },
                    )
                )

            uptime_info["current_status"] = "online" if now_online else "offline"
            current_metadata["uptime_info"] = uptime_info
            current_metadata["os_attributes"] = os_info
            current_metadata["node_ts_version"] = node_ts_ver
            current_metadata["security_posture"] = security_posture
            current_metadata["network_routing"] = network_routing
            current_metadata["exposed_routes"] = network_routing["exposed_routes"]
            current_metadata["is_exit_node"] = network_routing["is_advertising_exit_node"]
            current_metadata["device_posture"] = device_posture
            current_metadata["ts_auto_update"] = device_posture["ts_auto_update"]
            current_metadata["ts_state_encrypted"] = device_posture["ts_state_encrypted"]
            current_metadata["geolocation"] = geolocation
            current_metadata["country"] = geolocation.get("country")
            current_metadata["public_address"] = geolocation.get("public_address")
            existing_node.telemetry_metadata = current_metadata

            target_node_id = existing_node.id
            nodes_updated += 1
        else:
            # Create new Node entry
            metadata = node_dict.get("telemetry_metadata", {})
            metadata["uptime_info"] = {
                "current_status": "online" if now_online else "offline",
                "last_state_change": eval_now_iso,
                "last_online_transition": eval_now_iso if now_online else None,
                "last_offline_transition": eval_now_iso if not now_online else None,
                "current_streak_seconds": 0.0,
                "current_streak_human": "< 1m",
                "state_change_count": 0,
            }
            metadata["os_attributes"] = os_info
            metadata["node_ts_version"] = node_ts_ver
            metadata["security_posture"] = security_posture
            metadata["network_routing"] = network_routing
            metadata["exposed_routes"] = network_routing["exposed_routes"]
            metadata["is_exit_node"] = network_routing["is_advertising_exit_node"]
            metadata["device_posture"] = device_posture
            metadata["ts_auto_update"] = device_posture["ts_auto_update"]
            metadata["ts_state_encrypted"] = device_posture["ts_state_encrypted"]
            metadata["geolocation"] = geolocation
            metadata["country"] = geolocation.get("country")
            metadata["public_address"] = geolocation.get("public_address")
            node_dict["telemetry_metadata"] = metadata

            new_node = Node(**node_dict)
            session.add(new_node)
            await session.flush()  # Ensure new_node.id is assigned and ready for FK
            target_node_id = new_node.id

            session.add(
                AuditLog(
                    node_id=target_node_id,
                    event_type=AuditEventType.NODE_CREATED.value,
                    event_category=EventCategory.DEVICE.value,
                    severity=AuditSeverity.INFO.value,
                    action=f"Device '{device.hostname}' registered in fleet",
                    actor="system/apscheduler",
                    message=(
                        f"Discovered new device '{device.hostname}' ({os_info['display_name']}) "
                        f"during scheduled Tailscale poll."
                    ),
                    details={
                        "hostname": device.hostname,
                        "addresses": device.addresses,
                        "os": os_family,
                        "raw_os": device.os,
                        "os_version": device.os_version,
                        "node_os_attribute": os_info["node_os"],
                        "os_category": os_info["os_category"],
                        "client_version": device.client_version,
                        "is_online": now_online,
                    },
                )
            )

            # Log Version Drift warning on initial registration if vulnerable
            if version_drift["is_vulnerable"]:
                session.add(
                    AuditLog(
                        node_id=target_node_id,
                        event_type=AuditEventType.VERSION_DRIFT_WARNING.value,
                        event_category=EventCategory.SECURITY.value,
                        severity=(
                            AuditSeverity.CRITICAL.value
                            if version_drift["vulnerability_severity"] == "critical"
                            else AuditSeverity.HIGH.value
                            if version_drift["vulnerability_severity"] == "high"
                            else AuditSeverity.WARNING.value
                        ),
                        action=f"Device '{device.hostname}' version drift detected",
                        actor="system/apscheduler",
                        message=version_drift["vulnerability_summary"],
                        details={
                            "hostname": device.hostname,
                            "current_version": node_ts_ver,
                            "stable_version": version_drift["stable_version"],
                            "drift_type": version_drift["drift_type"],
                            "versions_behind": version_drift["versions_behind"],
                            "severity": version_drift["vulnerability_severity"],
                        },
                    )
                )

            # Log Key Expiry warning on initial registration if expiring soon
            if key_expiry["is_expiring_soon"]:
                session.add(
                    AuditLog(
                        node_id=target_node_id,
                        event_type=AuditEventType.KEY_EXPIRY_WARNING.value,
                        event_category=EventCategory.SECURITY.value,
                        severity=(
                            AuditSeverity.CRITICAL.value
                            if key_expiry["status"] == "critical"
                            else AuditSeverity.WARNING.value
                        ),
                        action=f"Device '{device.hostname}' key expiring soon",
                        actor="system/apscheduler",
                        message=f"Tailscale key for '{device.hostname}' expires in {key_expiry['countdown_human']}.",
                        details={
                            "hostname": device.hostname,
                            "expires_at": key_expiry["expires_at"],
                            "remaining_days": key_expiry["remaining_days"],
                            "countdown_human": key_expiry["countdown_human"],
                            "status": key_expiry["status"],
                        },
                    )
                )

            nodes_created += 1

        # Trigger Alerts from Network Routing Auditor (Step 9)
        for alert in network_routing.get("alerts", []):
            session.add(
                AuditLog(
                    node_id=target_node_id,
                    event_type=alert.get("event_type", AuditEventType.UNAUTHORIZED_EXIT_NODE.value),
                    event_category=alert.get("event_category", EventCategory.NETWORK.value),
                    severity=alert.get("severity", AuditSeverity.WARNING.value),
                    action=alert.get("title", f"Network routing alert for {device.hostname}"),
                    actor="system/apscheduler",
                    message=alert.get("message", ""),
                    details=alert.get("details", {}),
                )
            )

        # Trigger Alerts from Device Posture Auditor (Step 10)
        for alert in device_posture.get("alerts", []):
            session.add(
                AuditLog(
                    node_id=target_node_id,
                    event_type=alert.get("event_type", AuditEventType.POSTURE_VIOLATION.value),
                    event_category=alert.get("event_category", EventCategory.POSTURE.value),
                    severity=alert.get("severity", AuditSeverity.HIGH.value),
                    action=alert.get("title", f"Posture alert for {device.hostname}"),
                    actor="system/apscheduler",
                    message=alert.get("message", ""),
                    details=alert.get("details", {}),
                )
            )

        # Trigger Alerts from Geolocation Anomaly Tracker (Step 11)
        for alert in geolocation.get("alerts", []):
            session.add(
                AuditLog(
                    node_id=target_node_id,
                    event_type=alert.get("event_type", AuditEventType.IMPOSSIBLE_TRAVEL.value),
                    event_category=alert.get("event_category", EventCategory.SECURITY.value),
                    severity=alert.get("severity", AuditSeverity.CRITICAL.value),
                    action=alert.get("title", f"Impossible travel detected for device '{device.hostname}'"),
                    actor="system/apscheduler",
                    message=alert.get("message", ""),
                    details=alert.get("details", {}),
                )
            )

        # Record NodeState snapshot
        state_dict = device.to_node_state_dict(node_id_override=target_node_id)
        # Ensure telemetry_data contains OS fleet, uptime, network routing, and posture metadata
        telemetry = dict(state_dict.get("telemetry_data") or {})
        telemetry["os_family"] = os_family
        telemetry["node_os"] = os_info["node_os"]
        telemetry["os_category"] = os_info["os_category"]
        telemetry["exposed_routes"] = network_routing["exposed_routes"]
        telemetry["network_routing"] = network_routing
        telemetry["device_posture"] = device_posture
        telemetry["ts_auto_update"] = device_posture["ts_auto_update"]
        telemetry["ts_state_encrypted"] = device_posture["ts_state_encrypted"]
        telemetry["geolocation"] = geolocation
        telemetry["country"] = geolocation.get("country")
        telemetry["public_address"] = geolocation.get("public_address")
        telemetry["uptime_streak_seconds"] = (
            (existing_node.telemetry_metadata or {}).get("uptime_info", {}).get("current_streak_seconds", 0.0)
            if existing_node
            else 0.0
        )
        state_dict["telemetry_data"] = telemetry

        # Update posture_checks and compliance_status from security posture, network routing, device posture, and geolocation
        overall_compliant = (
            security_posture["is_compliant"]
            and network_routing["is_compliant"]
            and device_posture["is_compliant"]
            and geolocation["is_compliant"]
        )
        state_dict["is_compliant"] = overall_compliant
        if (
            security_posture["compliance_status"] == ComplianceStatus.NON_COMPLIANT.value
            or network_routing["compliance_status"] == ComplianceStatus.NON_COMPLIANT.value
            or device_posture["compliance_status"] == ComplianceStatus.NON_COMPLIANT.value
            or geolocation["compliance_status"] == ComplianceStatus.NON_COMPLIANT.value
        ):
            state_dict["compliance_status"] = ComplianceStatus.NON_COMPLIANT.value
        elif (
            security_posture["compliance_status"] == ComplianceStatus.WARNING.value
            or network_routing["compliance_status"] == ComplianceStatus.WARNING.value
            or device_posture["compliance_status"] == ComplianceStatus.WARNING.value
            or geolocation["compliance_status"] == ComplianceStatus.WARNING.value
        ):
            state_dict["compliance_status"] = ComplianceStatus.WARNING.value
        elif (
            device_posture["compliance_status"] == ComplianceStatus.EXEMPT.value
        ):
            state_dict["compliance_status"] = (
                ComplianceStatus.EXEMPT.value
                if overall_compliant
                else ComplianceStatus.NON_COMPLIANT.value
            )
        else:
            state_dict["compliance_status"] = ComplianceStatus.COMPLIANT.value

        posture_checks = dict(state_dict.get("posture_checks") or {})
        posture_checks["node_ts_version"] = node_ts_ver
        posture_checks["version_drift"] = version_drift
        posture_checks["key_expiry"] = key_expiry
        posture_checks["vulnerabilities"] = vulnerabilities
        posture_checks["network_routing"] = network_routing
        posture_checks["device_posture"] = device_posture
        posture_checks["ts_auto_update"] = device_posture["ts_auto_update"]
        posture_checks["ts_state_encrypted"] = device_posture["ts_state_encrypted"]
        posture_checks["geolocation"] = geolocation
        posture_checks["country"] = geolocation.get("country")
        posture_checks["public_address"] = geolocation.get("public_address")
        posture_checks["compliance_status"] = state_dict["compliance_status"]
        state_dict["posture_checks"] = posture_checks

        if device_posture.get("ts_state_encrypted") is not None:
            state_dict["disk_encryption_enabled"] = device_posture["ts_state_encrypted"]

        node_state = NodeState(**state_dict)
        session.add(node_state)
        node_states_recorded += 1

        # Detect and log key expiration
        if state_dict.get("key_expired") or key_expiry.get("is_expired"):
            prev_expired = (
                (existing_node.telemetry_metadata or {})
                .get("security_posture", {})
                .get("key_expiry", {})
                .get("is_expired", False)
                if existing_node
                else False
            )
            if not prev_expired:
                session.add(
                    AuditLog(
                        node_id=target_node_id,
                        event_type=AuditEventType.NODE_EXPIRED.value,
                        event_category=EventCategory.SECURITY.value,
                        severity=AuditSeverity.WARNING.value,
                        action=f"Device '{device.hostname}' key expired",
                        actor="system/apscheduler",
                        message=(
                            f"Tailscale authentication key for device '{device.hostname}' "
                            f"expired at {key_expiry.get('expires_at') or device.expires}."
                        ),
                        details={
                            "expires_at": (
                                key_expiry.get("expires_at")
                                or (device.expires.isoformat() if device.expires else None)
                            ),
                            "key_expiry_disabled": device.key_expiry_disabled,
                        },
                    )
                )

    # Record overall sync audit log entry
    offline_count = len(devices) - online_count
    session.add(
        AuditLog(
            event_type=AuditEventType.SYNC_COMPLETED.value,
            event_category=EventCategory.SYSTEM.value,
            severity=AuditSeverity.INFO.value,
            action="Tailscale fleet synchronization completed",
            actor="system/apscheduler",
            message=(
                f"Synchronized {len(devices)} devices ({online_count} online, {offline_count} offline): "
                f"{nodes_created} created, {nodes_updated} updated, {node_states_recorded} telemetry states recorded."
            ),
            details={
                "devices_count": len(devices),
                "online_devices": online_count,
                "offline_devices": offline_count,
                "fleet_uptime_percentage": (
                    round((online_count / len(devices)) * 100.0, 2)
                    if len(devices) > 0
                    else 0.0
                ),
                "nodes_created": nodes_created,
                "nodes_updated": nodes_updated,
                "node_states_recorded": node_states_recorded,
                "tailnet": tailnet,
            },
        )
    )

    # Automatic Node Pruning: Delete nodes removed from Tailscale
    live_ids = {str(d.id) for d in devices if getattr(d, 'id', None)}
    live_node_ids = {str(d.node_id) for d in devices if getattr(d, 'node_id', None)}

    all_db_nodes_res = await session.execute(select(Node))
    existing_db_nodes = all_db_nodes_res.scalars().all()

    stale_node_ids = [
        n.id for n in existing_db_nodes
        if str(n.id) not in live_ids and str(getattr(n, 'node_id', '')) not in live_node_ids
    ]

    if stale_node_ids:
        logger.info("Pruning %d deleted Tailscale node(s) from database: %s", len(stale_node_ids), stale_node_ids)
        await session.execute(delete(Node).where(Node.id.in_(stale_node_ids)))
        await session.flush()

    return nodes_created, nodes_updated, node_states_recorded


async def poll_tailscale_devices(
    session_factory: Optional[async_sessionmaker[AsyncSession]] = None,
    client: Optional[TailscaleClient] = None,
) -> Dict[str, Any]:
    """Scheduled task executed by APScheduler to poll Tailscale device telemetry.

    Queries the Tailscale API via `TailscaleClient`, validates device records,
    and synchronizes telemetry and posture states to the database without blocking
    the asynchronous event loop.

    Args:
        session_factory: Optional sessionmaker instance for database sessions.
        client: Optional pre-configured `TailscaleClient` instance.

    Returns:
        Dictionary summarizing execution status, metrics, and any errors.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    logger.info("Initiating scheduled Tailscale fleet device telemetry poll...")

    owns_client = False
    active_client = client

    if active_client is None:
        if not settings.TAILSCALE_API_KEY:
            logger.info(
                "Tailscale API credentials not configured (TAILSCALE_API_KEY is empty). "
                "Skipping scheduled poll."
            )
            return {
                "status": "skipped",
                "reason": "Tailscale API credentials not configured",
                "timestamp": now_iso,
                "devices_polled": 0,
                "nodes_created": 0,
                "nodes_updated": 0,
                "node_states_recorded": 0,
            }
        active_client = TailscaleClient()
        owns_client = True
    elif not active_client.is_configured:
        logger.info(
            "Tailscale client is not configured with an API key. Skipping scheduled poll."
        )
        return {
            "status": "skipped",
            "reason": "Tailscale client is not configured",
            "timestamp": now_iso,
            "devices_polled": 0,
            "nodes_created": 0,
            "nodes_updated": 0,
            "node_states_recorded": 0,
        }

    try:
        # Fetch device telemetry from Tailscale API
        try:
            target_tailnet = settings.TAILSCALE_TAILNET or active_client.tailnet
            if owns_client:
                async with active_client:
                    response: TailscaleDevicesResponse = await active_client.get_devices(
                        tailnet=target_tailnet
                    )
            else:
                response = await active_client.get_devices(tailnet=target_tailnet)
        except TailscaleAuthError as exc:
            logger.error("Tailscale API authentication failed during scheduled poll: %s", exc)
            return {
                "status": "error",
                "reason": "authentication_failed",
                "error": str(exc),
                "timestamp": now_iso,
                "devices_polled": 0,
            }
        except TailscaleRateLimitError as exc:
            logger.warning("Tailscale API rate limit exceeded during scheduled poll: %s", exc)
            return {
                "status": "error",
                "reason": "rate_limit_exceeded",
                "error": str(exc),
                "timestamp": now_iso,
                "devices_polled": 0,
            }
        except TailscaleConnectionError as exc:
            logger.warning("Tailscale connection/timeout error during scheduled poll: %s", exc)
            return {
                "status": "error",
                "reason": "connection_error",
                "error": str(exc),
                "timestamp": now_iso,
                "devices_polled": 0,
            }
        except TailscaleError as exc:
            logger.error("Tailscale API error during scheduled poll: %s", exc)
            return {
                "status": "error",
                "reason": "tailscale_api_error",
                "error": str(exc),
                "timestamp": now_iso,
                "devices_polled": 0,
            }
        except Exception as exc:
            logger.exception("Unexpected error fetching Tailscale devices: %s", exc)
            return {
                "status": "error",
                "reason": "unexpected_fetch_error",
                "error": str(exc),
                "timestamp": now_iso,
                "devices_polled": 0,
            }

        devices = response.devices
        logger.info("Successfully fetched %d devices from Tailscale API.", len(devices))

        # Synchronize devices into database
        maker = session_factory or async_session_maker
        async with maker() as session:
            try:
                created, updated, states = await sync_tailscale_devices(
                    devices=devices,
                    session=session,
                    tailnet=target_tailnet,
                )
                await session.commit()
                logger.info(
                    "Tailscale sync successfully committed: %d created, %d updated, %d states recorded.",
                    created,
                    updated,
                    states,
                )
                return {
                    "status": "success",
                    "timestamp": now_iso,
                    "devices_polled": len(devices),
                    "nodes_created": created,
                    "nodes_updated": updated,
                    "node_states_recorded": states,
                }
            except Exception as db_exc:
                await session.rollback()
                logger.exception("Database error while committing Tailscale sync: %s", db_exc)
                return {
                    "status": "error",
                    "reason": "database_error",
                    "error": str(db_exc),
                    "timestamp": now_iso,
                    "devices_polled": len(devices),
                    "nodes_created": 0,
                    "nodes_updated": 0,
                    "node_states_recorded": 0,
                }
    except Exception as exc:
        logger.exception("Fatal unhandled error in poll_tailscale_devices: %s", exc)
        return {
            "status": "error",
            "reason": "fatal_error",
            "error": str(exc),
            "timestamp": now_iso,
            "devices_polled": 0,
        }
