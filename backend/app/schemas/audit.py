from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AuditLogEventItem(BaseModel):
    """Schema representing a single chronologically ordered audit log event with node context."""

    id: str
    node_id: Optional[str] = None
    hostname: Optional[str] = None
    device_name: Optional[str] = None
    os: Optional[str] = None
    tailnet: Optional[str] = None
    event_type: str
    event_category: str
    severity: str
    action: str
    actor: Optional[str] = None
    message: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    created_at: str

    model_config = ConfigDict(populate_by_name=True)


class AuditFeedSummary(BaseModel):
    """Breakdown summary of audit log events by severity and category."""

    total_matching: int = 0
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


class AuditFeedResponse(BaseModel):
    """Chronological audit log feed response with filtering, search, and pagination metadata."""

    total: int
    count: int
    limit: int
    offset: int
    has_more: bool
    order: str = "desc"  # 'desc' (chronologically newest first) or 'asc' (oldest first)
    summary: AuditFeedSummary = Field(default_factory=AuditFeedSummary)
    events: List[AuditLogEventItem] = Field(default_factory=list)
    timestamp: str

    model_config = ConfigDict(populate_by_name=True)
