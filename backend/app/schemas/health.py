from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ActiveAlertItem(BaseModel):
    """Alert item representing an active warning or critical condition across the fleet."""

    severity: str  # 'critical', 'warning', 'info'
    category: str  # 'security', 'posture', 'network', 'key_expiry', 'lock', 'ssl'
    source: str
    message: str
    node_id: Optional[str] = None
    hostname: Optional[str] = None
    created_at: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


class HealthSummaryFleet(BaseModel):
    """Summary statistics for fleet availability and online streak status."""

    total_devices: int = 0
    online_devices: int = 0
    offline_devices: int = 0
    fleet_uptime_percentage: float = 0.0
    healthy_devices: int = 0
    warning_devices: int = 0
    critical_devices: int = 0

    model_config = ConfigDict(populate_by_name=True)


class HealthSummaryPosture(BaseModel):
    """Summary statistics for device posture compliance."""

    total_evaluated: int = 0
    compliant_count: int = 0
    non_compliant_count: int = 0
    compliance_percentage: float = 100.0
    auto_update_enabled: int = 0
    auto_update_disabled: int = 0
    state_encrypted: int = 0
    state_unencrypted: int = 0

    model_config = ConfigDict(populate_by_name=True)


class HealthSummaryVersionDrift(BaseModel):
    """Summary statistics for version drift and outdated client software."""

    target_stable_version: str = "1.60.0"
    up_to_date_count: int = 0
    outdated_count: int = 0
    drift_percentage: float = 0.0

    model_config = ConfigDict(populate_by_name=True)


class HealthSummaryKeyExpiry(BaseModel):
    """Summary statistics for device authentication key expiration countdowns."""

    healthy_count: int = 0
    warning_count: int = 0
    critical_count: int = 0
    expired_count: int = 0
    disabled_count: int = 0

    model_config = ConfigDict(populate_by_name=True)


class HealthSummaryTailnetLock(BaseModel):
    """Summary statistics for Tailnet Lock status."""

    total_nodes: int = 0
    signed_count: int = 0
    unsigned_count: int = 0
    locked_out_count: int = 0
    quarantined_count: int = 0
    signing_nodes_count: int = 0

    model_config = ConfigDict(populate_by_name=True)


class HealthSummaryCertificates(BaseModel):
    """Summary statistics for MagicDNS TLS/SSL certificates."""

    total_tracked: int = 0
    valid_count: int = 0
    expiring_soon_count: int = 0
    expired_count: int = 0
    not_configured_count: int = 0

    model_config = ConfigDict(populate_by_name=True)


class HealthSummaryNetwork(BaseModel):
    """Summary statistics for network routing and DERP relay performance."""

    exit_nodes_count: int = 0
    derp_regions_count: int = 0
    avg_latency_ms: Optional[float] = None

    model_config = ConfigDict(populate_by_name=True)


class HealthSummaryGeolocation(BaseModel):
    """Summary statistics for device geographic distribution and travel anomalies."""

    total_countries: int = 0
    impossible_travel_alerts: int = 0

    model_config = ConfigDict(populate_by_name=True)


class HealthSummaryAuditAlerts(BaseModel):
    """Summary statistics for logged audit events and security alerts."""

    total_events: int = 0
    events_last_24h: int = 0
    critical_count: int = 0
    error_count: int = 0
    warning_count: int = 0
    info_count: int = 0

    model_config = ConfigDict(populate_by_name=True)


class AggregatedHealthStatsResponse(BaseModel):
    """Comprehensive aggregated health metrics response covering all fleet telemetry domains."""

    overall_status: str  # 'healthy', 'warning', 'critical'
    health_score: float  # 0.0 - 100.0
    tailnet: Optional[str] = None
    fleet: HealthSummaryFleet
    posture: HealthSummaryPosture
    version_drift: HealthSummaryVersionDrift
    key_expiry: HealthSummaryKeyExpiry
    tailnet_lock: HealthSummaryTailnetLock
    certificates: HealthSummaryCertificates
    network: HealthSummaryNetwork
    geolocation: HealthSummaryGeolocation
    audit_alerts: HealthSummaryAuditAlerts
    services: Dict[str, Any] = Field(default_factory=dict)
    active_alerts: List[ActiveAlertItem] = Field(default_factory=list)
    timestamp: str

    model_config = ConfigDict(populate_by_name=True)