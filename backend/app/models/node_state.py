from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    JSON,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import ComplianceStatus

if TYPE_CHECKING:
    from app.models.node import Node

# Support native PostgreSQL JSONB with fallback to standard JSON
JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class NodeState(Base):
    """SQLAlchemy ORM model storing device posture states and telemetry snapshots over time."""

    __tablename__ = "node_states"

    # Primary key
    id: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique identifier for the posture/telemetry state record",
    )

    # Foreign key referencing the parent Node
    node_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("nodes.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
        doc="Reference to the parent device node",
    )

    # Connectivity & Overall Posture Compliance
    is_online: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        index=True,
        nullable=False,
        doc="Whether the device was connected/online during this evaluation",
    )
    is_compliant: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        index=True,
        nullable=False,
        doc="Overall device posture compliance flag based on organization rules",
    )
    compliance_status: Mapped[str] = mapped_column(
        String(64),
        default=ComplianceStatus.COMPLIANT.value,
        index=True,
        nullable=False,
        doc="Detailed compliance status (compliant, non_compliant, warning, unknown)",
    )

    # Specific Device Posture Check Attributes
    firewall_enabled: Mapped[Optional[bool]] = mapped_column(
        Boolean,
        nullable=True,
        doc="Host firewall posture state (ufw, iptables, Windows Firewall, pf)",
    )
    disk_encryption_enabled: Mapped[Optional[bool]] = mapped_column(
        Boolean,
        nullable=True,
        doc="Full disk encryption posture (LUKS, BitLocker, FileVault)",
    )
    screen_lock_enabled: Mapped[Optional[bool]] = mapped_column(
        Boolean,
        nullable=True,
        doc="Automatic screen lock posture check",
    )
    antivirus_active: Mapped[Optional[bool]] = mapped_column(
        Boolean,
        nullable=True,
        doc="Endpoint Detection and Response (EDR) or antivirus active status",
    )
    tailscale_ssh_enabled: Mapped[Optional[bool]] = mapped_column(
        Boolean,
        nullable=True,
        doc="Indicates whether Tailscale SSH is enabled on the device",
    )
    key_expired: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        doc="Indicates whether the device authentication key has expired",
    )
    os_version: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        doc="Reported operating system version at time of evaluation",
    )
    client_version: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        doc="Reported Tailscale client version at time of evaluation",
    )

    # Telemetry & Network Performance Metrics
    latency_ms: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        doc="Observed ping latency to nearest DERP relay or peers in milliseconds",
    )
    derp_region: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        doc="Current preferred DERP region (e.g., 'fra', 'ord', 'syd')",
    )
    packet_loss: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        doc="Observed packet loss percentage (0.0 - 100.0)",
    )
    rx_bytes: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
        doc="Cumulative received network bytes on tailscale interface",
    )
    tx_bytes: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
        doc="Cumulative transmitted network bytes on tailscale interface",
    )

    # Structured Posture & Telemetry Payloads
    posture_checks: Mapped[dict[str, Any]] = mapped_column(
        JSON_TYPE,
        default=dict,
        nullable=False,
        doc="Detailed breakdown of individual posture check rule outcomes",
    )
    telemetry_data: Mapped[dict[str, Any]] = mapped_column(
        JSON_TYPE,
        default=dict,
        nullable=False,
        doc="Raw or extended telemetry payload (DERP latencies, peer mesh stats)",
    )

    # Timestamps
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
        nullable=False,
        doc="Timestamp when the posture/telemetry state was recorded",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Record insertion timestamp",
    )

    # Relationship to parent Node
    node: Mapped[Node] = relationship(
        "Node",
        back_populates="states",
    )

    # Composite indexes for time-series and filtered telemetry queries
    __table_args__ = (
        Index("ix_node_states_node_id_recorded_at", "node_id", "recorded_at"),
        Index("ix_node_states_compliance_recorded_at", "compliance_status", "recorded_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<NodeState(id='{self.id}', node_id='{self.node_id}', "
            f"status='{self.compliance_status}', online={self.is_online}, "
            f"recorded_at='{self.recorded_at}')>"
        )
