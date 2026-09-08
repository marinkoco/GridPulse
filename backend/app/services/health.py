from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.audit_log import AuditLog
from app.models.enums import (
    AuditSeverity,
    AuditEventType,
    SSLCertificateStatus,
    TailnetLockStatus,
)
from app.models.node import Node
from app.schemas.health import (
    ActiveAlertItem,
    AggregatedHealthStatsResponse,
    HealthSummaryAuditAlerts,
    HealthSummaryCertificates,
    HealthSummaryFleet,
    HealthSummaryGeolocation,
    HealthSummaryKeyExpiry,
    HealthSummaryNetwork,
    HealthSummaryPosture,
    HealthSummaryTailnetLock,
    HealthSummaryVersionDrift,
)
from app.services.fleet import calculate_duration_seconds
from app.services.fleet_matrix import evaluate_node_matrix_item
from app.services.scheduler import get_scheduler_status
from app.services.version_monitor import evaluate_version_drift

logger = logging.getLogger(__name__)


async def get_aggregated_health_statistics(
    session: AsyncSession,
    tailnet: Optional[str] = None,
    scheduler_instance: Optional[Any] = None,
) -> AggregatedHealthStatsResponse:
    """Aggregates fleet telemetry, security compliance, key status, lock state, TLS certs,

    audit alerts, and background scheduler status into a comprehensive health overview.
    """
    now = datetime.now(timezone.utc)

    # 1. Fetch fleet nodes
    node_stmt = select(Node)
    if tailnet:
        node_stmt = node_stmt.where(Node.tailnet == tailnet)

    node_res = await session.execute(node_stmt)
    nodes = list(node_res.scalars().all())
    total_nodes = len(nodes)

    # Transform into matrix evaluation for consistent metric calculation
    matrix_items = [evaluate_node_matrix_item(n, now=now) for n in nodes]

    # 2. Fleet Connectivity & Availability Summary
    online_count = sum(1 for m in matrix_items if m.is_online)
    offline_count = total_nodes - online_count
    fleet_uptime_pct = round((online_count / total_nodes) * 100.0, 2) if total_nodes > 0 else 0.0

    healthy_nodes = sum(1 for m in matrix_items if m.health_status == "healthy")
    warning_nodes = sum(1 for m in matrix_items if m.health_status == "warning")
    critical_nodes = sum(1 for m in matrix_items if m.health_status == "critical")

    fleet_summary = HealthSummaryFleet(
        total_devices=total_nodes,
        online_devices=online_count,
        offline_devices=offline_count,
        fleet_uptime_percentage=fleet_uptime_pct,
        healthy_devices=healthy_nodes,
        warning_devices=warning_nodes,
        critical_devices=critical_nodes,
    )

    # 3. Posture Compliance Summary
    compliant_count = sum(1 for m in matrix_items if m.is_compliant)
    non_compliant_count = total_nodes - compliant_count
    compliance_pct = round((compliant_count / total_nodes) * 100.0, 2) if total_nodes > 0 else 100.0

    auto_update_enabled = sum(1 for n in nodes if n.ts_auto_update is True)
    auto_update_disabled = sum(1 for n in nodes if n.ts_auto_update is False)
    state_encrypted = sum(1 for n in nodes if n.ts_state_encrypted is True)
    state_unencrypted = sum(1 for n in nodes if n.ts_state_encrypted is False)

    posture_summary = HealthSummaryPosture(
        total_evaluated=total_nodes,
        compliant_count=compliant_count,
        non_compliant_count=non_compliant_count,
        compliance_percentage=compliance_pct,
        auto_update_enabled=auto_update_enabled,
        auto_update_disabled=auto_update_disabled,
        state_encrypted=state_encrypted,
        state_unencrypted=state_unencrypted,
    )

    # 4. Version Drift Summary
    target_version = getattr(settings, "TAILSCALE_STABLE_VERSION", "1.60.0")
    up_to_date_count = 0
    outdated_count = 0
    for node in nodes:
        drift = evaluate_version_drift(node.client_version, stable_version=target_version)
        if drift["is_behind"]:
            outdated_count += 1
        else:
            up_to_date_count += 1

    drift_pct = round((outdated_count / total_nodes) * 100.0, 2) if total_nodes > 0 else 0.0
    version_drift_summary = HealthSummaryVersionDrift(
        stable_version=target_version,
        up_to_date_count=up_to_date_count,
        outdated_count=outdated_count,
        drift_percentage=drift_pct,
    )

    # 5. Key Expiry Summary
    key_healthy = sum(1 for m in matrix_items if m.key_expiry_status == "healthy")
    key_warning = sum(1 for m in matrix_items if m.key_expiry_status == "warning")
    key_critical = sum(1 for m in matrix_items if m.key_expiry_status == "critical")
    key_expired = sum(1 for m in matrix_items if m.key_expiry_status == "expired")
    key_disabled = sum(1 for m in matrix_items if m.key_expiry_status == "disabled")

    key_expiry_summary = HealthSummaryKeyExpiry(
        healthy_count=key_healthy,
        warning_count=key_warning,
        critical_count=key_critical,
        expired_count=key_expired,
        disabled_count=key_disabled,
    )

    # 6. Tailnet Lock Summary
    lock_signed = sum(1 for m in matrix_items if m.tailnet_lock_status == TailnetLockStatus.SIGNED.value)
    lock_unsigned = sum(1 for m in matrix_items if m.tailnet_lock_status == TailnetLockStatus.UNSIGNED.value)
    lock_locked_out = sum(1 for m in matrix_items if m.is_locked_out)
    lock_quarantined = sum(1 for m in matrix_items if m.is_quarantined)
    lock_signing_nodes = sum(1 for m in matrix_items if m.is_signing_node)

    tailnet_lock_summary = HealthSummaryTailnetLock(
        total_nodes=total_nodes,
        signed_count=lock_signed,
        unsigned_count=lock_unsigned,
        locked_out_count=lock_locked_out,
        quarantined_count=lock_quarantined,
        signing_nodes_count=lock_signing_nodes,
    )

    # 7. Certificates Summary
    cert_valid = sum(1 for m in matrix_items if m.ssl_cert_status == SSLCertificateStatus.VALID.value)
    cert_expiring = sum(1 for m in matrix_items if m.is_ssl_cert_expiring)
    cert_expired = sum(1 for m in matrix_items if m.is_ssl_cert_expired)
    cert_not_configured = sum(1 for m in matrix_items if m.ssl_cert_status == SSLCertificateStatus.NOT_CONFIGURED.value)
    cert_total_tracked = cert_valid + cert_expiring + cert_expired

    cert_summary = HealthSummaryCertificates(
        total_tracked=cert_total_tracked,
        valid_count=cert_valid,
        expiring_soon_count=cert_expiring,
        expired_count=cert_expired,
        not_configured_count=cert_not_configured,
    )

    # 8. Network Summary
    exit_nodes_count = sum(1 for m in matrix_items if m.is_exit_node)
    latencies = [m.latency_ms for m in matrix_items if m.latency_ms is not None]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None
    derp_regions = {m.derp_region for m in matrix_items if m.derp_region}

    network_summary = HealthSummaryNetwork(
        exit_nodes_count=exit_nodes_count,
        derp_regions_count=len(derp_regions),
        avg_latency_ms=avg_latency,
    )

    # 9. Geolocation Summary
    countries = {m.country for m in matrix_items if m.country}

    # Query impossible travel count from AuditLog
    geo_stmt = select(func.count(AuditLog.id)).where(
        AuditLog.event_type == AuditEventType.IMPOSSIBLE_TRAVEL.value
    )
    geo_res = await session.execute(geo_stmt)
    impossible_travel_alerts = geo_res.scalar() or 0

    geolocation_summary = HealthSummaryGeolocation(
        total_countries=len(countries),
        impossible_travel_alerts=impossible_travel_alerts,
    )

    # 10. Audit Alerts Summary (All time and last 24h)
    since_24h = now - timedelta(hours=24)
    audit_all_stmt = select(func.count(AuditLog.id))
    all_res = await session.execute(audit_all_stmt)
    total_audit_events = all_res.scalar() or 0

    audit_24h_stmt = select(func.count(AuditLog.id)).where(AuditLog.created_at >= since_24h)
    res_24h = await session.execute(audit_24h_stmt)
    events_last_24h = res_24h.scalar() or 0

    crit_stmt = select(func.count(AuditLog.id)).where(AuditLog.severity == AuditSeverity.CRITICAL.value)
    crit_res = await session.execute(crit_stmt)
    critical_count = crit_res.scalar() or 0

    err_stmt = select(func.count(AuditLog.id)).where(AuditLog.severity == AuditSeverity.ERROR.value)
    err_res = await session.execute(err_stmt)
    error_count = err_res.scalar() or 0

    warn_stmt = select(func.count(AuditLog.id)).where(AuditLog.severity == AuditSeverity.WARNING.value)
    warn_res = await session.execute(warn_stmt)
    warning_count = warn_res.scalar() or 0

    info_stmt = select(func.count(AuditLog.id)).where(AuditLog.severity == AuditSeverity.INFO.value)
    info_res = await session.execute(info_stmt)
    info_count = info_res.scalar() or 0

    audit_summary = HealthSummaryAuditAlerts(
        total_events=total_audit_events,
        events_last_24h=events_last_24h,
        critical_count=critical_count,
        error_count=error_count,
        warning_count=warning_count,
        info_count=info_count,
    )

    # 11. Active Alerts
    active_alerts: List[ActiveAlertItem] = []

    if lock_locked_out > 0:
        active_alerts.append(
            ActiveAlertItem(
                severity="critical",
                category="lock",
                source="TailnetLockTracker",
                message=f"{lock_locked_out} device(s) are locked out or quarantined by Tailnet Lock.",
                details={"locked_out_count": lock_locked_out},
            )
        )

    if key_expired > 0:
        active_alerts.append(
            ActiveAlertItem(
                severity="critical",
                category="key_expiry",
                source="VersionMonitor",
                message=f"{key_expired} device(s) have expired Tailscale node keys.",
                details={"expired_count": key_expired},
            )
        )

    if cert_expired > 0:
        active_alerts.append(
            ActiveAlertItem(
                severity="critical",
                category="ssl",
                source="MagicDNSSSLMonitor",
                message=f"{cert_expired} MagicDNS TLS certificate(s) have expired.",
                details={"expired_count": cert_expired},
            )
        )

    if non_compliant_count > 0:
        active_alerts.append(
            ActiveAlertItem(
                severity="warning",
                category="posture",
                source="DevicePostureEngine",
                message=f"{non_compliant_count} device(s) violate organization device posture rules.",
                details={"non_compliant_count": non_compliant_count},
            )
        )

    if key_critical > 0 or key_warning > 0:
        active_alerts.append(
            ActiveAlertItem(
                severity="warning",
                category="key_expiry",
                source="VersionMonitor",
                message=f"{key_critical + key_warning} device(s) have authentication keys expiring soon.",
                details={"critical": key_critical, "warning": key_warning},
            )
        )

    if cert_expiring > 0:
        active_alerts.append(
            ActiveAlertItem(
                severity="warning",
                category="ssl",
                source="MagicDNSSSLMonitor",
                message=f"{cert_expiring} MagicDNS TLS certificate(s) are expiring soon.",
                details={"expiring_soon": cert_expiring},
            )
        )

    if drift_pct > 30.0:
        active_alerts.append(
            ActiveAlertItem(
                severity="warning",
                category="security",
                source="VersionMonitor",
                message=f"{drift_pct}% of fleet endpoints are running outdated Tailscale client versions.",
                details={"outdated_count": outdated_count, "drift_percentage": drift_pct},
            )
        )

    # 12. Composite Fleet Health Score (0 - 100)
    if total_nodes == 0:
        overall_score = 100.0
        overall_status = "healthy"
    else:
        # Score components
        uptime_weight = (online_count / total_nodes) * 25.0
        posture_weight = (compliant_count / total_nodes) * 25.0

        key_deduction = (key_expired * 1.0 + key_critical * 0.5 + key_warning * 0.2) / total_nodes
        key_weight = max(0.0, 1.0 - key_deduction) * 20.0

        cert_deduction = (cert_expired * 1.0 + cert_expiring * 0.3) / max(1, cert_total_tracked) if cert_total_tracked > 0 else 0.0
        cert_weight = max(0.0, 1.0 - cert_deduction) * 15.0

        lock_deduction = (lock_locked_out * 1.0 + lock_unsigned * 0.3) / total_nodes
        lock_weight = max(0.0, 1.0 - lock_deduction) * 15.0

        overall_score = round(uptime_weight + posture_weight + key_weight + cert_weight + lock_weight, 1)
        overall_score = max(0.0, min(100.0, overall_score))

        has_critical_alerts = any(a.severity == "critical" for a in active_alerts)
        has_warning_alerts = any(a.severity == "warning" for a in active_alerts)

        if has_critical_alerts or overall_score < 60.0:
            overall_status = "critical"
        elif has_warning_alerts or overall_score < 85.0:
            overall_status = "warning"
        else:
            overall_status = "healthy"

    # 13. System Services Status
    scheduler_status = get_scheduler_status(scheduler_instance)
    services_info = {
        "database": "connected",
        "scheduler": scheduler_status,
        "tailscale_poll_enabled": settings.TAILSCALE_POLL_ENABLED,
        "tailscale_poll_interval_minutes": settings.TAILSCALE_POLL_INTERVAL_MINUTES,
    }

    return AggregatedHealthStatsResponse(
        overall_status=overall_status,
        health_score=overall_score,
        tailnet=tailnet,
        fleet=fleet_summary,
        posture=posture_summary,
        version_drift=version_drift_summary,
        key_expiry=key_expiry_summary,
        tailnet_lock=tailnet_lock_summary,
        certificates=cert_summary,
        network=network_summary,
        geolocation=geolocation_summary,
        audit_alerts=audit_summary,
        services=services_info,
        active_alerts=active_alerts,
        timestamp=now.isoformat(),
    )
