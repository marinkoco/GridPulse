"""MagicDNS SSL Monitor Background Task Module.

Executes asynchronous HTTP and TLS requests against internal `.ts.net` Tailscale MagicDNS domains,
parsing and logging TLS certificate expiration dates and posture.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import settings
from app.database import async_session_maker
from app.models.enums import SSLCertificateStatus
from app.models.node import Node
from app.services.magicdns_ssl import (
    DEFAULT_CONCURRENCY_LIMIT,
    DEFAULT_CRITICAL_DAYS,
    DEFAULT_SSL_PORT,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_WARNING_DAYS,
    MAGICDNS_DOMAIN_SUFFIX,
    audit_node_magicdns_ssl,
    extract_magicdns_domain,
    format_countdown_human,
    get_fleet_expiring_certificates,
    get_fleet_magicdns_ssl_overview,
    get_node_magicdns_ssl_audit,
    monitor_magicdns_certificates,
    parse_date_to_utc,
    parse_name_tuples,
    parse_tls_certificate_info,
    probe_domain_ssl,
)

logger = logging.getLogger(__name__)

# Canonical Job ID for APScheduler
MAGICDNS_SSL_JOB_ID = "monitor_magicdns_certificates"


async def check_ssl_certificates(
    session_factory: Optional[async_sessionmaker[AsyncSession]] = None,
    tailnet: Optional[str] = None,
    concurrency_limit: Optional[int] = None,
    log_events: bool = True,
    http_client: Optional[httpx.AsyncClient] = None,
) -> Dict[str, Any]:
    """Background task function that performs async HTTP/TLS requests against internal `.ts.net` domains.

    Discovers all fleet nodes with internal `.ts.net` domains, executes concurrent
    asynchronous TLS handshakes and HTTP requests, parses certificate expiration dates,
    logs the parsed expiration dates at INFO level, updates database state, and records
    audit alerts when certificates are expired or expiring soon.

    Args:
        session_factory: Optional SQLAlchemy `async_sessionmaker`.
        tailnet: Optional tailnet domain filter.
        concurrency_limit: Max concurrent socket connections.
        log_events: Whether to record audit logs for critical/warning conditions.
        http_client: Optional shared `httpx.AsyncClient`.

    Returns:
        Summary dict containing scan results, counts, and node details.
    """
    logger.info("Executing MagicDNS SSL Monitor background task (check_ssl_certificates)...")
    return await monitor_magicdns_certificates(
        session_factory=session_factory,
        tailnet=tailnet,
        concurrency_limit=concurrency_limit,
        log_events=log_events,
        http_client=http_client,
    )


# Alias for compatibility with various background task invocation conventions
run_magicdns_ssl_monitor = check_ssl_certificates
run_ssl_monitor = check_ssl_certificates

__all__ = [
    "MAGICDNS_DOMAIN_SUFFIX",
    "DEFAULT_SSL_PORT",
    "DEFAULT_WARNING_DAYS",
    "DEFAULT_CRITICAL_DAYS",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_CONCURRENCY_LIMIT",
    "MAGICDNS_SSL_JOB_ID",
    "extract_magicdns_domain",
    "parse_date_to_utc",
    "parse_name_tuples",
    "parse_tls_certificate_info",
    "probe_domain_ssl",
    "audit_node_magicdns_ssl",
    "check_ssl_certificates",
    "monitor_magicdns_certificates",
    "run_magicdns_ssl_monitor",
    "run_ssl_monitor",
    "get_fleet_magicdns_ssl_overview",
    "get_fleet_expiring_certificates",
    "get_node_magicdns_ssl_audit",
]
