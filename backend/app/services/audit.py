from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.node import Node
from app.schemas.audit import (
    AuditFeedResponse,
    AuditFeedSummary,
    AuditLogEventItem,
)
from app.services.fleet import normalize_os

logger = logging.getLogger(__name__)


async def get_chronological_audit_log_feed(
    session: AsyncSession,
    node_id: Optional[str] = None,
    tailnet: Optional[str] = None,
    severity: Optional[str] = None,
    event_category: Optional[str] = None,
    event_type: Optional[str] = None,
    actor: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    q: Optional[str] = None,
    order: str = "desc",
    limit: int = 50,
    offset: int = 0,
) -> AuditFeedResponse:
    """Queries the audit_logs table, ordered chronologically, with rich filtering, search,

    node context resolution, and summary statistics.
    """
    now = datetime.now(timezone.utc)

    # Base query joining AuditLog with Node
    base_stmt = select(AuditLog, Node).outerjoin(Node, AuditLog.node_id == Node.id)
    count_stmt = select(func.count(AuditLog.id)).outerjoin(Node, AuditLog.node_id == Node.id)

    filters = []

    # Node filter
    if node_id:
        filters.append(
            or_(
                AuditLog.node_id == node_id,
                Node.node_id == node_id,
            )
        )

    # Tailnet filter
    if tailnet:
        filters.append(Node.tailnet == tailnet)

    # Severity filter
    if severity:
        filters.append(AuditLog.severity == severity.lower().strip())

    # Category filter
    if event_category:
        filters.append(AuditLog.event_category == event_category.lower().strip())

    # Event type filter
    if event_type:
        filters.append(AuditLog.event_type == event_type.strip())

    # Actor filter
    if actor:
        filters.append(AuditLog.actor.ilike(f"%{actor.strip()}%"))

    # Time range filter
    if since:
        since_utc = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
        filters.append(AuditLog.created_at >= since_utc)
    if until:
        until_utc = until if until.tzinfo else until.replace(tzinfo=timezone.utc)
        filters.append(AuditLog.created_at <= until_utc)

    # Text search in action, message, actor
    if q and q.strip():
        search_pattern = f"%{q.strip()}%"
        filters.append(
            or_(
                AuditLog.action.ilike(search_pattern),
                AuditLog.message.ilike(search_pattern),
                AuditLog.actor.ilike(search_pattern),
            )
        )

    if filters:
        base_stmt = base_stmt.where(*filters)
        count_stmt = count_stmt.where(*filters)

    # Total matching count
    count_result = await session.execute(count_stmt)
    total_matching = count_result.scalar() or 0

    # Summary by severity and category across filtered events
    # Severity breakdown
    sev_stmt = (
        select(AuditLog.severity, func.count(AuditLog.id))
        .outerjoin(Node, AuditLog.node_id == Node.id)
    )
    if filters:
        sev_stmt = sev_stmt.where(*filters)
    sev_stmt = sev_stmt.group_by(AuditLog.severity)
    sev_res = await session.execute(sev_stmt)
    by_severity = {str(row[0]): int(row[1]) for row in sev_res.all() if row[0]}

    # Category breakdown
    cat_stmt = (
        select(AuditLog.event_category, func.count(AuditLog.id))
        .outerjoin(Node, AuditLog.node_id == Node.id)
    )
    if filters:
        cat_stmt = cat_stmt.where(*filters)
    cat_stmt = cat_stmt.group_by(AuditLog.event_category)
    cat_res = await session.execute(cat_stmt)
    by_category = {str(row[0]): int(row[1]) for row in cat_res.all() if row[0]}

    summary = AuditFeedSummary(
        total_matching=total_matching,
        by_severity=by_severity,
        by_category=by_category,
    )

    # Chronological ordering
    is_asc = (order.lower().strip() == "asc")
    if is_asc:
        base_stmt = base_stmt.order_by(asc(AuditLog.created_at), asc(AuditLog.id))
    else:
        base_stmt = base_stmt.order_by(desc(AuditLog.created_at), desc(AuditLog.id))

    # Pagination
    base_stmt = base_stmt.offset(offset).limit(limit)

    results = await session.execute(base_stmt)
    rows = results.all()

    events: List[AuditLogEventItem] = []
    for audit_log, node in rows:
        events.append(
            AuditLogEventItem(
                id=audit_log.id,
                node_id=audit_log.node_id,
                hostname=node.hostname if node else None,
                device_name=node.name if node else None,
                os=normalize_os(node.os) if node else None,
                tailnet=node.tailnet if node else None,
                event_type=audit_log.event_type,
                event_category=audit_log.event_category,
                severity=audit_log.severity,
                action=audit_log.action,
                actor=audit_log.actor,
                message=audit_log.message,
                details=audit_log.details or {},
                ip_address=audit_log.ip_address,
                created_at=audit_log.created_at.isoformat() if audit_log.created_at else now.isoformat(),
            )
        )

    has_more = (offset + limit) < total_matching

    return AuditFeedResponse(
        total=total_matching,
        count=len(events),
        limit=limit,
        offset=offset,
        has_more=has_more,
        order="asc" if is_asc else "desc",
        summary=summary,
        events=events,
        timestamp=now.isoformat(),
    )


async def get_node_audit_log_feed(
    session: AsyncSession,
    node_id: str,
    severity: Optional[str] = None,
    event_category: Optional[str] = None,
    event_type: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    q: Optional[str] = None,
    order: str = "desc",
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any] | AuditFeedResponse:
    """Retrieves the chronological audit log feed for a specific node, returning 404 error indicator if not found."""
    node_stmt = select(Node).where((Node.id == node_id) | (Node.node_id == node_id))
    node_res = await session.execute(node_stmt)
    node = node_res.scalar_one_or_none()

    if node is None:
        return {"error": "node_not_found", "node_id": node_id}

    return await get_chronological_audit_log_feed(
        session=session,
        node_id=node.id,
        severity=severity,
        event_category=event_category,
        event_type=event_type,
        since=since,
        until=until,
        q=q,
        order=order,
        limit=limit,
        offset=offset,
    )
