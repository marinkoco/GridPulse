from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FleetMatrixColumn(BaseModel):
    """Schema describing column attributes and UI metadata for the fleet matrix."""

    key: str
    label: str
    category: str
    type: str  # 'string', 'boolean', 'number', 'list', 'datetime', 'status'
    sortable: bool = True
    filterable: bool = True

    model_config = ConfigDict(populate_by_name=True)


class NodeMatrixItem(BaseModel):
    """Unified multidimensional matrix row for a Tailscale node across all telemetry dimensions."""

    id: str
    node_id: Optional[str] = None
    name: str
    hostname: str
    user: Optional[str] = None
    tailnet: Optional[str] = None
    addresses: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    # System & OS
    os: str
    os_raw: Optional[str] = None
    os_version: Optional[str] = None
    client_version: Optional[str] = None
    category: str = "unknown"

    # Status & Uptime
    is_online: bool = False
    last_seen: Optional[str] = None
    streak_duration_seconds: float = 0.0
    streak_duration_human: str = "< 1m"

    # Security Posture & Compliance
    is_compliant: bool = True
    compliance_status: str = "compliant"
    violations: List[str] = Field(default_factory=list)
    update_available: bool = False

    # Key Lifecycle
    key_expiry_disabled: bool = False
    expires_at: Optional[str] = None
    key_expiry_status: str = "healthy"
    days_until_key_expiry: Optional[float] = None

    # Network & Routing
    is_exit_node: bool = False
    exposed_routes: List[str] = Field(default_factory=list)
    derp_region: Optional[str] = None
    latency_ms: Optional[float] = None

    # Geolocation
    country: Optional[str] = None
    public_address: Optional[str] = None
    country_name: Optional[str] = None
    is_impossible_travel: bool = False
    geo_anomaly_reason: Optional[str] = None

    # Tailnet Lock
    tailnet_lock_status: str = "unknown"
    is_locked_out: bool = False
    is_quarantined: bool = False
    is_signing_node: bool = False

    # MagicDNS & TLS
    magicdns_domain: Optional[str] = None
    ssl_cert_status: str = "not_configured"
    ssl_cert_expires_at: Optional[str] = None
    is_ssl_cert_expiring: bool = False
    is_ssl_cert_expired: bool = False

    # Overall Node Health
    health_status: str = "healthy"  # 'healthy', 'warning', 'critical'
    health_score: float = 100.0

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class FleetMatrixCrossTabulation(BaseModel):
    """Cross-tabulated 2D summary matrix breakdown across fleet dimensions."""

    os_by_status: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    os_by_compliance: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    category_by_status: Dict[str, Dict[str, int]] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


class FleetMatrixResponse(BaseModel):
    """Full API response for the fleet matrix endpoint with pagination, columns, and matrix rows."""

    total_devices: int
    filtered_devices: int
    limit: int
    offset: int
    has_more: bool
    columns: List[FleetMatrixColumn] = Field(default_factory=list)
    cross_tabulation: FleetMatrixCrossTabulation = Field(default_factory=FleetMatrixCrossTabulation)
    matrix: List[NodeMatrixItem] = Field(default_factory=list)
    timestamp: str

    model_config = ConfigDict(populate_by_name=True)
