from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    JSON,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.audit_log import AuditLog
    from app.models.node_state import NodeState

# Support native PostgreSQL JSONB with fallback to standard JSON
JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class Node(Base):
    """SQLAlchemy ORM model representing a Tailscale device node in the fleet."""

    __tablename__ = "nodes"

    # Primary key: accepts external Tailscale node ID or generates UUID4 string
    id: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Primary identifier (Tailscale device ID or internal UUID)",
    )

    # Unique Tailscale node identifier (e.g., 'n123456CNTRL')
    node_id: Mapped[Optional[str]] = mapped_column(
        String(128),
        unique=True,
        index=True,
        nullable=True,
        doc="Tailscale stable node identifier (nodeId)",
    )

    # Host & Identity metadata
    name: Mapped[str] = mapped_column(
        String(255),
        index=True,
        nullable=False,
        doc="Tailscale Fully Qualified Domain Name (FQDN) or device name",
    )
    hostname: Mapped[str] = mapped_column(
        String(255),
        index=True,
        nullable=False,
        doc="Device hostname reported by the operating system",
    )
    user: Mapped[Optional[str]] = mapped_column(
        String(255),
        index=True,
        nullable=True,
        doc="Owner email or Tailscale identity of the device",
    )
    tailnet: Mapped[Optional[str]] = mapped_column(
        String(255),
        index=True,
        nullable=True,
        doc="Tailnet organization or domain name",
    )

    # System & Client specifications
    os: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
        doc="Operating system family (e.g. linux, macOS, windows, iOS, android)",
    )
    os_version: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        doc="Detailed OS version string (e.g., Ubuntu 22.04.3 LTS, macOS 14.4)",
    )
    client_version: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        doc="Tailscale client daemon version (e.g., 1.56.0)",
    )

    # Network configuration & Addressing
    addresses: Mapped[list[str]] = mapped_column(
        JSON_TYPE,
        default=list,
        nullable=False,
        doc="Assigned Tailscale IP addresses (IPv4 100.x.y.z and IPv6)",
    )
    tags: Mapped[list[str]] = mapped_column(
        JSON_TYPE,
        default=list,
        nullable=False,
        doc="ACL tags assigned to the node (e.g. ['tag:server', 'tag:prod'])",
    )
    endpoints: Mapped[list[str]] = mapped_column(
        JSON_TYPE,
        default=list,
        nullable=False,
        doc="Public/DERP network endpoints discovered for the node",
    )

    # Telemetry & Status
    is_online: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        index=True,
        nullable=False,
        doc="Current connectivity status in Tailscale",
    )
    last_seen: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=True,
        doc="Last active telemetry heartbeat timestamp from Tailscale",
    )

    # Security & Keys
    machine_key: Mapped[Optional[str]] = mapped_column(
        String(256),
        nullable=True,
        doc="Tailscale machine public key (mkey:...)",
    )
    node_key: Mapped[Optional[str]] = mapped_column(
        String(256),
        nullable=True,
        doc="Tailscale node public key (nodekey:...)",
    )
    is_external: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        doc="Indicates whether this device is shared in from another tailnet",
    )
    authorized: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        doc="Indicates whether machine is authorized on the tailnet",
    )
    key_expiry_disabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        doc="Indicates whether key expiry is disabled for this machine",
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Timestamp when the node key expires",
    )
    update_available: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        doc="Indicates if a newer Tailscale version is available",
    )

    # Arbitrary metadata & telemetry extension
    telemetry_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSON_TYPE,
        default=dict,
        nullable=False,
        doc="Extended telemetry dictionary (DERP latency map, routes, capabilities)",
    )

    # Audit timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Record creation timestamp",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        doc="Record last update timestamp",
    )

    # Relationships
    states: Mapped[list[NodeState]] = relationship(
        "NodeState",
        back_populates="node",
        cascade="all, delete-orphan",
        order_by="desc(NodeState.recorded_at)",
        doc="Historical posture states and telemetry snapshots for this node",
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(
        "AuditLog",
        back_populates="node",
        passive_deletes=True,
        order_by="desc(AuditLog.created_at)",
        doc="Audit and network events associated with this node (preserved on node deletion with node_id=NULL)",
    )

    # Indexes
    __table_args__ = (
        Index("ix_nodes_tailnet_is_online", "tailnet", "is_online"),
        Index("ix_nodes_os_is_online", "os", "is_online"),
    )

    @property
    def tailscale_id(self) -> str:
        """Returns the primary Tailscale node identifier (node_id or id)."""
        return self.node_id or self.id

    @property
    def ip_addresses(self) -> list[str]:
        """Convenience alias for addresses list."""
        return self.addresses

    @property
    def exposed_routes(self) -> list[str]:
        """Convenience accessor for exposed/advertised routes from telemetry metadata."""
        meta = self.telemetry_metadata or {}
        return meta.get("exposed_routes", [])

    @property
    def is_exit_node(self) -> bool:
        """Indicates whether this device advertises default exit node route (0.0.0.0/0 or ::/0)."""
        return any(r in ("0.0.0.0/0", "::/0") for r in self.exposed_routes)

    @property
    def ts_auto_update(self) -> Optional[bool]:
        """Convenience accessor for automatic update posture attribute."""
        meta = self.telemetry_metadata or {}
        posture = meta.get("device_posture", {})
        return posture.get("ts_auto_update", meta.get("ts_auto_update"))

    @property
    def ts_state_encrypted(self) -> Optional[bool]:
        """Convenience accessor for state encryption posture attribute."""
        meta = self.telemetry_metadata or {}
        posture = meta.get("device_posture", {})
        return posture.get("ts_state_encrypted", meta.get("ts_state_encrypted"))

    @property
    def is_posture_compliant(self) -> bool:
        """Convenience accessor indicating whether endpoint satisfies device posture policy."""
        meta = self.telemetry_metadata or {}
        posture = meta.get("device_posture", {})
        return posture.get("is_compliant", True)

    @property
    def country(self) -> Optional[str]:
        """Convenience accessor for country code from telemetry metadata."""
        meta = self.telemetry_metadata or {}
        geo = meta.get("geolocation", {})
        return geo.get("country", meta.get("country"))

    @property
    def public_address(self) -> Optional[str]:
        """Convenience accessor for public IP address from telemetry metadata."""
        meta = self.telemetry_metadata or {}
        geo = meta.get("geolocation", {})
        return geo.get("public_address", meta.get("public_address"))

    @property
    def geolocation(self) -> dict[str, Any]:
        """Convenience accessor for geolocation tracking payload."""
        meta = self.telemetry_metadata or {}
        return meta.get("geolocation", {})

    @property
    def tailnet_lock_key(self) -> Optional[str]:
        """Convenience accessor for Tailnet Lock public key (nlpub:... or tlpub:...) from telemetry metadata."""
        meta = self.telemetry_metadata or {}
        lock = meta.get("tailnet_lock", {})
        return lock.get("tailnet_lock_key", meta.get("tailnet_lock_key"))

    @property
    def tailnet_lock_error(self) -> Optional[str]:
        """Convenience accessor for Tailnet Lock error string from telemetry metadata."""
        meta = self.telemetry_metadata or {}
        lock = meta.get("tailnet_lock", {})
        return lock.get("tailnet_lock_error", meta.get("tailnet_lock_error"))

    @property
    def is_locked_out(self) -> bool:
        """Convenience accessor indicating whether node is locked out / quarantined by Tailnet Lock."""
        meta = self.telemetry_metadata or {}
        lock = meta.get("tailnet_lock", {})
        return lock.get("is_locked_out", meta.get("is_locked_out", False))

    @property
    def is_quarantined(self) -> bool:
        """Convenience alias indicating whether node is quarantined / locked out."""
        meta = self.telemetry_metadata or {}
        lock = meta.get("tailnet_lock", {})
        return lock.get("is_quarantined", self.is_locked_out)

    @property
    def is_signing_node(self) -> bool:
        """Convenience accessor indicating whether node possesses a trusted Tailnet Lock signing key."""
        meta = self.telemetry_metadata or {}
        lock = meta.get("tailnet_lock", {})
        return lock.get("is_signing_node", False)

    @property
    def tailnet_lock_status(self) -> str:
        """Convenience accessor for detailed Tailnet Lock status."""
        meta = self.telemetry_metadata or {}
        lock = meta.get("tailnet_lock", {})
        return lock.get("lock_status", "unknown")

    @property
    def tailnet_lock(self) -> dict[str, Any]:
        """Convenience accessor for tailnet lock tracking payload."""
        meta = self.telemetry_metadata or {}
        return meta.get("tailnet_lock", {})

    @property
    def magicdns_domain(self) -> Optional[str]:
        """Convenience accessor for internal MagicDNS .ts.net domain."""
        if self.name and ".ts.net" in self.name.lower():
            return self.name.strip().lower().rstrip(".")
        if self.hostname and ".ts.net" in self.hostname.lower():
            return self.hostname.strip().lower().rstrip(".")
        meta = self.telemetry_metadata or {}
        ssl_info = meta.get("magicdns_ssl", {})
        if ssl_info.get("domain"):
            return str(ssl_info["domain"]).strip().lower().rstrip(".")
        if self.tailnet and ".ts.net" in self.tailnet.lower() and self.hostname:
            return f"{self.hostname.strip().lower()}.{self.tailnet.strip().lower()}".rstrip(".")
        return None

    @property
    def ssl_cert_info(self) -> dict[str, Any]:
        """Convenience accessor for monitored MagicDNS SSL certificate details."""
        meta = self.telemetry_metadata or {}
        return meta.get("magicdns_ssl", {})

    @property
    def ssl_cert_expires_at(self) -> Optional[str]:
        """Expiration timestamp ISO string for node TLS certificate."""
        return self.ssl_cert_info.get("expires_at")

    @property
    def ssl_cert_status(self) -> str:
        """Current status classification of node TLS certificate."""
        return self.ssl_cert_info.get("status", "not_configured")

    @property
    def is_ssl_cert_expiring(self) -> bool:
        """Indicates whether TLS certificate is expiring soon."""
        return bool(self.ssl_cert_info.get("is_expiring_soon", False))

    @property
    def is_ssl_cert_expired(self) -> bool:
        """Indicates whether TLS certificate has expired."""
        return bool(self.ssl_cert_info.get("is_expired", False))

    def __repr__(self) -> str:
        return (
            f"<Node(id='{self.id}', hostname='{self.hostname}', "
            f"os='{self.os}', is_online={self.is_online})>"
        )

