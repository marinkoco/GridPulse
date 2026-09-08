from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional
import uuid

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import AuditSeverity, EventCategory

if TYPE_CHECKING:
    from app.models.node import Node

# Support native PostgreSQL JSONB with fallback to standard JSON
JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class AuditLog(Base):
    """SQLAlchemy ORM model storing security events, posture changes, network events, and fleet audit logs."""

    __tablename__ = "audit_logs"

    # Primary key
    id: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        doc="Unique identifier for the audit event",
    )

    # Optional foreign key to associated device Node (nullable if event is fleet/tailnet wide)
    node_id: Mapped[Optional[str]] = mapped_column(
        String(128),
        ForeignKey("nodes.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
        doc="Reference to the target device node (if applicable)",
    )

    # Event Classification
    event_type: Mapped[str] = mapped_column(
        String(128),
        index=True,
        nullable=False,
        doc="Specific event type (e.g. node.online, posture.failed, security.alert)",
    )
    event_category: Mapped[str] = mapped_column(
        String(64),
        default=EventCategory.DEVICE.value,
        index=True,
        nullable=False,
        doc="High-level category (device, posture, security, network, acl, system)",
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        default=AuditSeverity.INFO.value,
        index=True,
        nullable=False,
        doc="Event severity rating (info, low, warning, high, error, critical)",
    )

    # Action & Actor Details
    action: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Concise summary of action or event (e.g., 'Device connected to tailnet')",
    )
    actor: Mapped[Optional[str]] = mapped_column(
        String(255),
        index=True,
        nullable=True,
        doc="User, API client, or system service initiating the event",
    )
    message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Human-readable description or error details",
    )

    # Event Payload & Context
    details: Mapped[dict[str, Any]] = mapped_column(
        JSON_TYPE,
        default=dict,
        nullable=False,
        doc="Structured event data, diffs, webhook payload, or metadata",
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        doc="Source IP address associated with the event",
    )

    # Timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
        nullable=False,
        doc="Timestamp when the event occurred",
    )

    # Relationship to target Node
    node: Mapped[Optional[Node]] = relationship(
        "Node",
        back_populates="audit_logs",
    )

    # Composite indexes for event filtering and chronological queries
    __table_args__ = (
        Index("ix_audit_logs_event_type_created_at", "event_type", "created_at"),
        Index("ix_audit_logs_node_id_created_at", "node_id", "created_at"),
        Index("ix_audit_logs_severity_created_at", "severity", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLog(id='{self.id}', event_type='{self.event_type}', "
            f"severity='{self.severity}', node_id='{self.node_id}', "
            f"created_at='{self.created_at}')>"
        )
