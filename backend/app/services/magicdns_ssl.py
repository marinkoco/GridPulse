from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import httpx
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import settings
from app.database import async_session_maker
from app.models.audit_log import AuditLog
from app.models.enums import (
    AuditSeverity,
    AuditEventType,
    EventCategory,
    SSLCertificateStatus,
)
from app.models.node import Node
from app.models.node_state import NodeState
from app.schemas.tailscale import TailscaleDevice

logger = logging.getLogger(__name__)

# Standard constants
DEFAULT_SSL_PORT: int = 443
DEFAULT_WARNING_DAYS: int = 30
DEFAULT_CRITICAL_DAYS: int = 7
DEFAULT_TIMEOUT_SECONDS: float = 10.0
DEFAULT_CONCURRENCY_LIMIT: int = 10

# Suffix identifying Tailscale MagicDNS domains
MAGICDNS_DOMAIN_SUFFIX: str = ".ts.net"


def extract_magicdns_domain(
    node_or_device: Union[Node, TailscaleDevice, Dict[str, Any]],
    tailnet: Optional[str] = None,
) -> Optional[str]:
    """Extracts and normalizes the internal `.ts.net` MagicDNS domain from a node or device.

    Inspection order:
    1. Explicit `magicdns_domain` property or attribute.
    2. `name`: If it contains or ends with `.ts.net` (standard Tailscale node FQDN).
    3. `hostname`: If it ends with `.ts.net`.
    4. Derived from `hostname` and `tailnet`: If `tailnet` is provided or configured.
    5. `attributes`: Keys like `dns:magicdnsName`, `magicdns_domain`, `dnsName`, `fqdn`.
    6. `tags`: Tags like `tag:domain:<domain>` or `domain:<domain>`.

    Args:
        node_or_device: A Node ORM instance, TailscaleDevice schema, or dictionary.
        tailnet: Optional tailnet domain or alias override.

    Returns:
        Normalized lower-case `.ts.net` domain string without trailing dot, or None.
    """
    candidate: Optional[str] = None

    # Check for direct attribute / property
    if hasattr(node_or_device, "magicdns_domain") and getattr(node_or_device, "magicdns_domain", None):
        candidate = str(node_or_device.magicdns_domain)

    # Check 'name' attribute
    if not candidate:
        name_val = getattr(node_or_device, "name", None)
        if isinstance(node_or_device, dict) and "name" in node_or_device:
            name_val = node_or_device["name"]
        if name_val and isinstance(name_val, str) and MAGICDNS_DOMAIN_SUFFIX in name_val.lower():
            candidate = name_val

    # Check 'hostname' attribute
    if not candidate:
        host_val = getattr(node_or_device, "hostname", None)
        if isinstance(node_or_device, dict) and "hostname" in node_or_device:
            host_val = node_or_device["hostname"]
        if host_val and isinstance(host_val, str) and MAGICDNS_DOMAIN_SUFFIX in host_val.lower():
            candidate = host_val

    # Check attributes dictionary
    attrs = getattr(node_or_device, "attributes", None)
    if isinstance(node_or_device, dict) and "attributes" in node_or_device:
        attrs = node_or_device["attributes"]
    if not candidate and attrs and isinstance(attrs, dict):
        for k in (
            "dns:magicdnsName",
            "magicdnsName",
            "magicdns_domain",
            "magicdns",
            "dnsName",
            "fqdn",
            "ts_net_domain",
        ):
            if k in attrs and attrs[k]:
                candidate = str(attrs[k])
                break

    # Check telemetry_metadata
    telemetry = getattr(node_or_device, "telemetry_metadata", None)
    if isinstance(node_or_device, dict) and "telemetry_metadata" in node_or_device:
        telemetry = node_or_device["telemetry_metadata"]
    if not candidate and telemetry and isinstance(telemetry, dict):
        ssl_meta = telemetry.get("magicdns_ssl", {})
        if isinstance(ssl_meta, dict) and ssl_meta.get("domain"):
            candidate = str(ssl_meta["domain"])

    # Derive from hostname + tailnet if tailnet contains .ts.net or ends with .ts.net
    if not candidate:
        host_val = getattr(node_or_device, "hostname", None)
        if isinstance(node_or_device, dict):
            host_val = node_or_device.get("hostname")
        node_tailnet = tailnet or getattr(node_or_device, "tailnet", None)
        if isinstance(node_or_device, dict) and not node_tailnet:
            node_tailnet = node_or_device.get("tailnet")

        if host_val and node_tailnet and isinstance(host_val, str) and isinstance(node_tailnet, str):
            clean_host = host_val.strip().lower()
            clean_tailnet = node_tailnet.strip().lower()
            if MAGICDNS_DOMAIN_SUFFIX in clean_tailnet:
                candidate = f"{clean_host}.{clean_tailnet}"
            elif not clean_tailnet.endswith(".ts.net") and not clean_tailnet.endswith(".com") and not clean_tailnet.endswith(".net"):
                # E.g. tailnet name like 'example' or 'tailscale-demo'
                candidate = f"{clean_host}.{clean_tailnet}.ts.net"

    if candidate:
        normalized = candidate.strip().lower().rstrip(".")
        if MAGICDNS_DOMAIN_SUFFIX in normalized:
            return normalized

    return None


def format_countdown_human(seconds: float) -> str:
    """Formats a duration in seconds into a human-readable countdown string.

    Examples:
        - 2592000 -> "30 days"
        - 86400 + 3600 -> "1 day, 1 hour"
        - 3600 + 120 -> "1 hour, 2 minutes"
        - 45 -> "< 1 minute"
        - -86400 -> "expired 1 day ago"

    Args:
        seconds: Duration in seconds (positive for future, negative for past).

    Returns:
        Formatted human-readable string.
    """
    is_expired = seconds < 0
    abs_secs = abs(seconds)

    days = int(abs_secs // 86400)
    hours = int((abs_secs % 86400) // 3600)
    minutes = int((abs_secs % 3600) // 60)

    parts: List[str] = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0 and (days < 7 or not is_expired):
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if not parts:
        if minutes > 0:
            parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
        else:
            parts.append("< 1 minute")

    text = ", ".join(parts[:2])
    if is_expired:
        return f"expired {text} ago"
    return text


def parse_date_to_utc(date_val: Any) -> Optional[datetime]:
    """Parses various date representations into a timezone-aware UTC datetime.

    Supports:
    - `datetime` objects (naive or aware)
    - OpenSSL GMT string: 'May 25 12:00:00 2027 GMT'
    - ISO 8601 strings: '2027-05-25T12:00:00Z', '2027-05-25 12:00:00'
    - Epoch timestamps (int / float)

    Args:
        date_val: Raw date input.

    Returns:
        timezone-aware datetime in UTC, or None if unparseable.
    """
    if date_val is None:
        return None

    if isinstance(date_val, datetime):
        if date_val.tzinfo is None:
            return date_val.replace(tzinfo=timezone.utc)
        return date_val.astimezone(timezone.utc)

    if isinstance(date_val, (int, float)):
        return datetime.fromtimestamp(float(date_val), tz=timezone.utc)

    if isinstance(date_val, str):
        val_clean = date_val.strip()
        if not val_clean:
            return None

        # 1. Standard library ssl cert_time_to_seconds (handles 'May 25 12:00:00 2027 GMT')
        try:
            ts = ssl.cert_time_to_seconds(val_clean)
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except Exception:
            pass

        # 2. ISO 8601 parsing
        try:
            iso_str = val_clean.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

        # 3. Common strptime patterns
        formats = (
            "%b %d %H:%M:%S %Y %Z",
            "%b %d %H:%M:%S %Y",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y%m%d%H%M%SZ",
            "%y%m%d%H%M%SZ",
        )
        for fmt in formats:
            try:
                dt = datetime.strptime(val_clean, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                continue

    return None


def parse_name_tuples(tuples_list: Any) -> Dict[str, str]:
    """Flattens OpenSSL subject or issuer tuple structure into a key-value dictionary.

    Structure typically returned by `getpeercert()`:
    `((('countryName', 'US'),), (('organizationName', "Let's Encrypt"),), (('commonName', 'R3'),))`
    """
    out: Dict[str, str] = {}
    if not tuples_list or not isinstance(tuples_list, (list, tuple)):
        return out

    for item in tuples_list:
        if isinstance(item, (list, tuple)):
            for sub in item:
                if isinstance(sub, (list, tuple)) and len(sub) == 2:
                    k, v = sub
                    out[str(k)] = str(v)
    return out


def parse_tls_certificate_info(
    cert: Dict[str, Any],
    now: Optional[datetime] = None,
    warning_days: Optional[int] = None,
    critical_days: Optional[int] = None,
) -> Dict[str, Any]:
    """Parses raw certificate dictionary from `getpeercert()` or simulated payload.

    Args:
        cert: Raw certificate dictionary.
        now: Reference evaluation datetime (defaults to UTC now).
        warning_days: Threshold in days for 'expiring_soon' warning (defaults to settings).
        critical_days: Threshold in days for 'critical' warning (defaults to settings).

    Returns:
        Structured certificate telemetry and expiration analysis dictionary.
    """
    eval_now = now or datetime.now(timezone.utc)
    warn_d = (
        warning_days
        if warning_days is not None
        else getattr(settings, "MAGICDNS_SSL_EXPIRY_WARNING_DAYS", DEFAULT_WARNING_DAYS)
    )
    crit_d = (
        critical_days
        if critical_days is not None
        else getattr(settings, "MAGICDNS_SSL_EXPIRY_CRITICAL_DAYS", DEFAULT_CRITICAL_DAYS)
    )

    raw_not_after = cert.get("notAfter") or cert.get("not_after") or cert.get("expires_at")
    raw_not_before = cert.get("notBefore") or cert.get("not_before") or cert.get("issued_at")

    expires_at = parse_date_to_utc(raw_not_after)
    issued_at = parse_date_to_utc(raw_not_before)

    # Parse Subject Alternative Names (SAN)
    sans: List[str] = []
    raw_sans = cert.get("subjectAltName") or cert.get("san") or cert.get("subject_alt_names") or []
    if isinstance(raw_sans, (list, tuple)):
        for item in raw_sans:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                # E.g. ('DNS', 'my-node.example.ts.net')
                sans.append(str(item[1]))
            elif isinstance(item, str):
                sans.append(item)

    # Parse Issuer and Subject
    issuer_dict = parse_name_tuples(cert.get("issuer"))
    if not issuer_dict and isinstance(cert.get("issuer"), dict):
        issuer_dict = cert.get("issuer")

    subject_dict = parse_name_tuples(cert.get("subject"))
    if not subject_dict and isinstance(cert.get("subject"), dict):
        subject_dict = cert.get("subject")

    # Expiration analysis
    if expires_at is not None:
        delta_seconds = (expires_at - eval_now).total_seconds()
        remaining_days = round(delta_seconds / 86400.0, 2)
        is_expired = delta_seconds <= 0
        is_expiring_soon = remaining_days <= warn_d and not is_expired
        is_critical = remaining_days <= crit_d and not is_expired

        if is_expired:
            status = SSLCertificateStatus.EXPIRED.value
            severity = AuditSeverity.CRITICAL.value
        elif is_critical:
            status = SSLCertificateStatus.EXPIRING_SOON.value
            severity = AuditSeverity.CRITICAL.value
        elif is_expiring_soon:
            status = SSLCertificateStatus.EXPIRING_SOON.value
            severity = AuditSeverity.WARNING.value
        else:
            status = SSLCertificateStatus.VALID.value
            severity = AuditSeverity.INFO.value

        countdown_human = format_countdown_human(delta_seconds)
        logger.info(
            "Parsed TLS certificate: expiration date is %s (remaining: %.1f days, status: %s)",
            expires_at.isoformat(),
            remaining_days,
            status,
        )
    else:
        delta_seconds = 0.0
        remaining_days = 0.0
        is_expired = False
        is_expiring_soon = False
        status = SSLCertificateStatus.ERROR.value
        severity = AuditSeverity.ERROR.value
        countdown_human = "unknown"

    return {
        "status": status,
        "severity": severity,
        "is_expired": is_expired,
        "is_expiring_soon": is_expiring_soon,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "issued_at": issued_at.isoformat() if issued_at else None,
        "remaining_seconds": delta_seconds,
        "remaining_days": remaining_days,
        "countdown_human": countdown_human,
        "warning_threshold_days": warn_d,
        "critical_threshold_days": crit_d,
        "common_name": subject_dict.get("commonName") if subject_dict else None,
        "issuer": issuer_dict,
        "subject": subject_dict,
        "subject_alt_names": sans,
        "serial_number": str(cert.get("serialNumber", "")) if cert.get("serialNumber") else None,
        "version": cert.get("version"),
    }


async def probe_domain_ssl(
    domain: str,
    port: int = DEFAULT_SSL_PORT,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    verify_tls: bool = True,
    custom_ssl_context: Optional[ssl.SSLContext] = None,
    http_client: Optional[httpx.AsyncClient] = None,
    now: Optional[datetime] = None,
    warning_days: Optional[int] = None,
    critical_days: Optional[int] = None,
) -> Dict[str, Any]:
    """Asynchronously probes an internal `.ts.net` MagicDNS endpoint over TLS and HTTP.

    Executes:
    1. An asynchronous TLS socket handshake via `asyncio.open_connection` to extract
       the peer certificate details directly from the TLS layer.
    2. An asynchronous HTTP/HTTPS request via `httpx.AsyncClient` against `https://{domain}:{port}/`
       to verify HTTP reachability, latency, and status code.
    3. Comprehensive expiration calculation and status classification.

    Args:
        domain: Fully qualified `.ts.net` domain name.
        port: TLS port (default 443).
        timeout: Socket and HTTP timeout in seconds.
        verify_tls: Whether to strictly verify the certificate authority.
        custom_ssl_context: Optional custom `ssl.SSLContext` instance.
        http_client: Optional existing `httpx.AsyncClient` to reuse.
        now: Reference datetime for expiration calculations.
        warning_days: Custom warning threshold in days.
        critical_days: Custom critical threshold in days.

    Returns:
        Structured probe result containing certificate, HTTP status, and error details.
    """
    start_time = time.monotonic()
    check_timestamp = (now or datetime.now(timezone.utc)).isoformat()
    clean_domain = domain.strip().lower().rstrip(".")

    result: Dict[str, Any] = {
        "domain": clean_domain,
        "port": port,
        "is_reachable": False,
        "http_reachable": False,
        "http_status_code": None,
        "response_time_ms": None,
        "tls_version": None,
        "cipher": None,
        "certificate": {},
        "expires_at": None,
        "remaining_days": None,
        "countdown_human": None,
        "is_expired": False,
        "is_expiring_soon": False,
        "status": SSLCertificateStatus.UNREACHABLE.value,
        "error": None,
        "error_type": None,
        "checked_at": check_timestamp,
    }

    # Prepare SSL Context
    if custom_ssl_context is not None:
        ssl_ctx = custom_ssl_context
    else:
        ssl_ctx = ssl.create_default_context()
        if not verify_tls:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    # Phase 1: TLS Handshake & Certificate Extraction via asyncio
    raw_cert: Optional[Dict[str, Any]] = None
    tls_version: Optional[str] = None
    cipher_info: Optional[Tuple[str, str, int]] = None

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                clean_domain,
                port,
                ssl=ssl_ctx,
                server_hostname=clean_domain,
            ),
            timeout=timeout,
        )
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                raw_cert = ssl_obj.getpeercert()
                tls_version = ssl_obj.version()
                cipher_info = ssl_obj.cipher()
            result["is_reachable"] = True
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    except ssl.SSLCertVerificationError as ssl_err:
        result["is_reachable"] = True
        result["error"] = f"SSL Certificate Verification Failed: {ssl_err}"
        result["error_type"] = "ssl_verification_error"
        err_msg_lower = str(ssl_err).lower()
        if "certificate has expired" in err_msg_lower or "expired" in err_msg_lower:
            result["is_expired"] = True
            result["status"] = SSLCertificateStatus.EXPIRED.value
        else:
            result["status"] = SSLCertificateStatus.ERROR.value

    except ssl.SSLError as ssl_err:
        result["is_reachable"] = True
        result["error"] = f"SSL Error: {ssl_err}"
        result["error_type"] = "ssl_error"
        result["status"] = SSLCertificateStatus.ERROR.value

    except asyncio.TimeoutError:
        result["error"] = f"Connection timed out after {timeout:.1f}s"
        result["error_type"] = "timeout"
        result["status"] = SSLCertificateStatus.UNREACHABLE.value

    except ConnectionRefusedError:
        result["error"] = f"Connection refused on {clean_domain}:{port}"
        result["error_type"] = "connection_refused"
        result["status"] = SSLCertificateStatus.UNREACHABLE.value

    except socket.gaierror as gai_err:
        result["error"] = f"DNS resolution failed for {clean_domain}: {gai_err}"
        result["error_type"] = "dns_resolution_failed"
        result["status"] = SSLCertificateStatus.UNREACHABLE.value

    except Exception as exc:
        result["error"] = f"Connection error: {exc}"
        result["error_type"] = "connection_error"
        result["status"] = SSLCertificateStatus.UNREACHABLE.value

    # Parse extracted TLS certificate if available
    if raw_cert:
        cert_info = parse_tls_certificate_info(
            raw_cert,
            now=now,
            warning_days=warning_days,
            critical_days=critical_days,
        )
        result["certificate"] = cert_info
        result["expires_at"] = cert_info["expires_at"]
        result["remaining_days"] = cert_info["remaining_days"]
        result["countdown_human"] = cert_info["countdown_human"]
        result["is_expired"] = cert_info["is_expired"]
        result["is_expiring_soon"] = cert_info["is_expiring_soon"]
        result["status"] = cert_info["status"]
        result["tls_version"] = tls_version
        result["cipher"] = cipher_info
        logger.info(
            "Parsed TLS certificate for domain '%s': expires at %s (%s remaining, status: %s)",
            clean_domain,
            result["expires_at"],
            result["countdown_human"],
            result["status"],
        )

    # Phase 2: Async HTTP/HTTPS request via HTTPX to verify HTTP service availability
    # Execute HTTP probe if reachable or if TLS succeeded
    if result["is_reachable"]:
        close_client = False
        client = http_client
        if client is None:
            client = httpx.AsyncClient(
                verify=verify_tls,
                timeout=timeout,
                follow_redirects=True,
            )
            close_client = True

        try:
            http_url = f"https://{clean_domain}:{port}/"
            http_resp = await client.get(http_url)
            result["http_reachable"] = True
            result["http_status_code"] = http_resp.status_code
            elapsed = (time.monotonic() - start_time) * 1000.0
            result["response_time_ms"] = round(elapsed, 2)
        except httpx.HTTPError as http_exc:
            # HTTP probe failure is captured without overwriting valid TLS certificate results
            if not result.get("error"):
                result["error"] = str(http_exc)
                result["error_type"] = "http_error"
        except Exception as exc:
            if not result.get("error"):
                result["error"] = str(exc)
                result["error_type"] = "network_error"
        finally:
            if close_client:
                await client.aclose()

    if result["response_time_ms"] is None:
        elapsed = (time.monotonic() - start_time) * 1000.0
        result["response_time_ms"] = round(elapsed, 2)

    return result


async def audit_node_magicdns_ssl(
    node: Node,
    port: Optional[int] = None,
    timeout: Optional[float] = None,
    verify_tls: Optional[bool] = None,
    now: Optional[datetime] = None,
    log_events: bool = True,
    session: Optional[AsyncSession] = None,
    http_client: Optional[httpx.AsyncClient] = None,
    custom_ssl_context: Optional[ssl.SSLContext] = None,
) -> Dict[str, Any]:
    """Audits a single Node for MagicDNS SSL certificate posture, alerts, and state tracking.

    Args:
        node: The target Node model.
        port: Optional port override.
        timeout: Optional timeout override.
        verify_tls: Optional TLS verification override.
        now: Optional evaluation timestamp.
        log_events: Whether to create AuditLog entries on warnings.
        session: Active AsyncSession (required if log_events=True).
        http_client: Reusable httpx.AsyncClient.
        custom_ssl_context: Custom SSL context for test or private CAs.

    Returns:
        Structured audit report for the node.
    """
    eval_now = now or datetime.now(timezone.utc)
    domain = extract_magicdns_domain(node)

    if not domain:
        return {
            "node_id": node.id,
            "hostname": node.hostname,
            "domain": None,
            "is_configured": False,
            "status": SSLCertificateStatus.NOT_CONFIGURED.value,
            "is_reachable": False,
            "is_expired": False,
            "is_expiring_soon": False,
            "alerts": [],
            "audited_at": eval_now.isoformat(),
        }

    p_port = port or getattr(settings, "MAGICDNS_SSL_PORT", DEFAULT_SSL_PORT)
    p_timeout = timeout or getattr(settings, "MAGICDNS_SSL_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
    p_verify = verify_tls if verify_tls is not None else getattr(settings, "MAGICDNS_SSL_VERIFY_TLS", True)

    probe_result = await probe_domain_ssl(
        domain=domain,
        port=p_port,
        timeout=p_timeout,
        verify_tls=p_verify,
        custom_ssl_context=custom_ssl_context,
        http_client=http_client,
        now=eval_now,
    )

    alerts: List[Dict[str, Any]] = []
    prev_meta = node.telemetry_metadata or {}
    prev_ssl = prev_meta.get("magicdns_ssl", {})
    prev_status = prev_ssl.get("status")

    curr_status = probe_result["status"]
    is_expired = probe_result["is_expired"]
    is_expiring_soon = probe_result["is_expiring_soon"]
    countdown = probe_result.get("countdown_human", "unknown")
    expires_at = probe_result.get("expires_at")

    # Generate Audit Logs / Alerts
    if log_events and session is not None:
        if is_expired:
            alert = {
                "event_type": AuditEventType.SSL_CERT_EXPIRED.value,
                "event_category": EventCategory.SECURITY.value,
                "severity": AuditSeverity.CRITICAL.value,
                "title": f"MagicDNS TLS Certificate Expired for '{node.hostname}'",
                "message": (
                    f"TLS certificate for MagicDNS domain '{domain}' expired on {expires_at} "
                    f"({countdown}). Endpoint connections will fail TLS verification."
                ),
                "details": {
                    "hostname": node.hostname,
                    "domain": domain,
                    "expires_at": expires_at,
                    "countdown_human": countdown,
                    "port": p_port,
                    "error": probe_result.get("error"),
                },
            }
            alerts.append(alert)
            session.add(
                AuditLog(
                    node_id=node.id,
                    event_type=alert["event_type"],
                    event_category=alert["event_category"],
                    severity=alert["severity"],
                    action=alert["title"],
                    actor="system/magicdns-ssl-monitor",
                    message=alert["message"],
                    details=alert["details"],
                )
            )

        elif is_expiring_soon and (prev_status != SSLCertificateStatus.EXPIRING_SOON.value or prev_status is None):
            rem_days = probe_result.get("remaining_days", 0)
            sev = AuditSeverity.CRITICAL.value if rem_days <= getattr(settings, "MAGICDNS_SSL_EXPIRY_CRITICAL_DAYS", DEFAULT_CRITICAL_DAYS) else AuditSeverity.WARNING.value
            alert = {
                "event_type": AuditEventType.SSL_CERT_EXPIRING.value,
                "event_category": EventCategory.SECURITY.value,
                "severity": sev,
                "title": f"MagicDNS TLS Certificate Expiring Soon for '{node.hostname}'",
                "message": (
                    f"TLS certificate for MagicDNS domain '{domain}' expires in {countdown} "
                    f"({expires_at}). Automated or manual renewal required."
                ),
                "details": {
                    "hostname": node.hostname,
                    "domain": domain,
                    "expires_at": expires_at,
                    "remaining_days": rem_days,
                    "countdown_human": countdown,
                    "port": p_port,
                },
            }
            alerts.append(alert)
            session.add(
                AuditLog(
                    node_id=node.id,
                    event_type=alert["event_type"],
                    event_category=alert["event_category"],
                    severity=alert["severity"],
                    action=alert["title"],
                    actor="system/magicdns-ssl-monitor",
                    message=alert["message"],
                    details=alert["details"],
                )
            )

        elif curr_status == SSLCertificateStatus.ERROR.value and prev_status != SSLCertificateStatus.ERROR.value:
            alert = {
                "event_type": AuditEventType.SSL_CERT_ERROR.value,
                "event_category": EventCategory.SECURITY.value,
                "severity": AuditSeverity.ERROR.value,
                "title": f"MagicDNS TLS Handshake Error for '{node.hostname}'",
                "message": f"Encountered error probing TLS certificate for domain '{domain}': {probe_result.get('error')}",
                "details": {
                    "hostname": node.hostname,
                    "domain": domain,
                    "error": probe_result.get("error"),
                    "error_type": probe_result.get("error_type"),
                },
            }
            alerts.append(alert)
            session.add(
                AuditLog(
                    node_id=node.id,
                    event_type=alert["event_type"],
                    event_category=alert["event_category"],
                    severity=alert["severity"],
                    action=alert["title"],
                    actor="system/magicdns-ssl-monitor",
                    message=alert["message"],
                    details=alert["details"],
                )
            )

        elif curr_status == SSLCertificateStatus.VALID.value and prev_status in (
            SSLCertificateStatus.EXPIRED.value,
            SSLCertificateStatus.EXPIRING_SOON.value,
            SSLCertificateStatus.ERROR.value,
        ):
            # Log certificate renewal / recovery
            alert = {
                "event_type": AuditEventType.SSL_CERT_VALID.value,
                "event_category": EventCategory.SECURITY.value,
                "severity": AuditSeverity.INFO.value,
                "title": f"MagicDNS TLS Certificate Valid/Renewed for '{node.hostname}'",
                "message": f"TLS certificate for '{domain}' is now valid, expiring in {countdown} ({expires_at}).",
                "details": {
                    "hostname": node.hostname,
                    "domain": domain,
                    "expires_at": expires_at,
                    "countdown_human": countdown,
                },
            }
            alerts.append(alert)
            session.add(
                AuditLog(
                    node_id=node.id,
                    event_type=alert["event_type"],
                    event_category=alert["event_category"],
                    severity=alert["severity"],
                    action=alert["title"],
                    actor="system/magicdns-ssl-monitor",
                    message=alert["message"],
                    details=alert["details"],
                )
            )

    return {
        "node_id": node.id,
        "hostname": node.hostname,
        "domain": domain,
        "is_configured": True,
        "probe": probe_result,
        "alerts": alerts,
        "audited_at": eval_now.isoformat(),
    }


async def monitor_magicdns_certificates(
    session_factory: Optional[async_sessionmaker[AsyncSession]] = None,
    tailnet: Optional[str] = None,
    concurrency_limit: Optional[int] = None,
    log_events: bool = True,
    http_client: Optional[httpx.AsyncClient] = None,
) -> Dict[str, Any]:
    """APScheduler background task worker executing async TLS and HTTP probes on all `.ts.net` nodes.

    Discovers all fleet nodes with internal `.ts.net` MagicDNS domains, executes concurrent
    async HTTP requests and TLS handshake evaluations, updates `Node.telemetry_metadata['magicdns_ssl']`,
    logs warnings to `audit_logs`, and persists the results.

    Args:
        session_factory: Optional SQLAlchemy `async_sessionmaker`.
        tailnet: Optional tailnet domain filter.
        concurrency_limit: Max concurrent socket connections.
        log_events: Whether to log audit events on expiration or warnings.
        http_client: Optional shared HTTP client.

    Returns:
        Aggregated summary dictionary of the monitoring execution.
    """
    logger.info("Starting MagicDNS SSL Monitor background task run...")
    start_time = time.monotonic()
    maker = session_factory or async_session_maker
    limit = concurrency_limit or getattr(settings, "MAGICDNS_SSL_CONCURRENCY_LIMIT", DEFAULT_CONCURRENCY_LIMIT)
    sem = asyncio.Semaphore(limit)

    close_client = False
    client = http_client
    if client is None:
        client = httpx.AsyncClient(
            verify=getattr(settings, "MAGICDNS_SSL_VERIFY_TLS", True),
            timeout=getattr(settings, "MAGICDNS_SSL_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS),
            follow_redirects=True,
        )
        close_client = True

    checked_nodes = 0
    valid_count = 0
    expiring_soon_count = 0
    expired_count = 0
    unreachable_count = 0
    error_count = 0
    alerts_logged = 0
    results_list: List[Dict[str, Any]] = []

    try:
        async with maker() as session:
            stmt = select(Node)
            if tailnet:
                stmt = stmt.where(Node.tailnet == tailnet)

            res = await session.execute(stmt)
            nodes = list(res.scalars().all())

            # Filter or extract candidate domains
            candidate_pairs: List[Tuple[Node, str]] = []
            for n in nodes:
                d = extract_magicdns_domain(n, tailnet=tailnet)
                if d:
                    candidate_pairs.append((n, d))

            logger.info("Discovered %d fleet nodes with active .ts.net MagicDNS domains.", len(candidate_pairs))

            async def _check_node(n: Node, d: str) -> Dict[str, Any]:
                async with sem:
                    return await audit_node_magicdns_ssl(
                        node=n,
                        session=session,
                        log_events=log_events,
                        http_client=client,
                    )

            # Concurrently probe all candidate nodes
            tasks = [_check_node(n, d) for n, d in candidate_pairs]
            audit_results = await asyncio.gather(*tasks, return_exceptions=True)

            for idx, res_item in enumerate(audit_results):
                node_obj = candidate_pairs[idx][0]
                if isinstance(res_item, Exception):
                    logger.warning("Error auditing node %s SSL: %s", node_obj.hostname, res_item)
                    error_count += 1
                    continue

                checked_nodes += 1
                probe_data = res_item.get("probe", {})
                status = probe_data.get("status", SSLCertificateStatus.UNREACHABLE.value)

                if status == SSLCertificateStatus.VALID.value:
                    valid_count += 1
                elif status == SSLCertificateStatus.EXPIRING_SOON.value:
                    expiring_soon_count += 1
                elif status == SSLCertificateStatus.EXPIRED.value:
                    expired_count += 1
                elif status == SSLCertificateStatus.UNREACHABLE.value:
                    unreachable_count += 1
                else:
                    error_count += 1

                alerts_logged += len(res_item.get("alerts", []))

                # Update Node telemetry_metadata
                meta = dict(node_obj.telemetry_metadata or {})
                meta["magicdns_ssl"] = {
                    "domain": res_item.get("domain"),
                    "is_configured": True,
                    "status": status,
                    "is_reachable": probe_data.get("is_reachable", False),
                    "http_reachable": probe_data.get("http_reachable", False),
                    "http_status_code": probe_data.get("http_status_code"),
                    "response_time_ms": probe_data.get("response_time_ms"),
                    "tls_version": probe_data.get("tls_version"),
                    "expires_at": probe_data.get("expires_at"),
                    "remaining_days": probe_data.get("remaining_days"),
                    "countdown_human": probe_data.get("countdown_human"),
                    "is_expired": probe_data.get("is_expired", False),
                    "is_expiring_soon": probe_data.get("is_expiring_soon", False),
                    "error": probe_data.get("error"),
                    "error_type": probe_data.get("error_type"),
                    "certificate": probe_data.get("certificate", {}),
                    "checked_at": probe_data.get("checked_at"),
                }
                node_obj.telemetry_metadata = meta

                if probe_data.get("expires_at"):
                    logger.info(
                        "MagicDNS SSL Monitor node '%s' (%s): parsed certificate expiration date %s (remaining: %s days, status: %s)",
                        node_obj.hostname,
                        res_item.get("domain"),
                        probe_data.get("expires_at"),
                        probe_data.get("remaining_days"),
                        status,
                    )

                results_list.append(
                    {
                        "node_id": node_obj.id,
                        "hostname": node_obj.hostname,
                        "domain": res_item.get("domain"),
                        "status": status,
                        "expires_at": probe_data.get("expires_at"),
                        "remaining_days": probe_data.get("remaining_days"),
                        "countdown_human": probe_data.get("countdown_human"),
                        "is_expired": probe_data.get("is_expired", False),
                        "is_expiring_soon": probe_data.get("is_expiring_soon", False),
                        "http_reachable": probe_data.get("http_reachable", False),
                        "http_status_code": probe_data.get("http_status_code"),
                    }
                )

            await session.commit()

    finally:
        if close_client:
            await client.aclose()

    duration = round(time.monotonic() - start_time, 2)
    logger.info(
        "MagicDNS SSL Monitor task finished in %ss: checked=%d, valid=%d, expiring=%d, expired=%d, unreachable=%d, alerts=%d",
        duration,
        checked_nodes,
        valid_count,
        expiring_soon_count,
        expired_count,
        unreachable_count,
        alerts_logged,
    )

    return {
        "status": "completed",
        "duration_seconds": duration,
        "total_nodes_checked": checked_nodes,
        "valid_count": valid_count,
        "expiring_soon_count": expiring_soon_count,
        "expired_count": expired_count,
        "unreachable_count": unreachable_count,
        "error_count": error_count,
        "alerts_logged": alerts_logged,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "nodes": results_list,
    }


# ---------------------------------------------------------------------------
# Fleet-Wide SSL Certificate Aggregation & Reporting Functions
# ---------------------------------------------------------------------------


async def get_fleet_magicdns_ssl_overview(
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Dict[str, Any]:
    """Aggregates fleet MagicDNS TLS certificates status, expiration distribution, and warnings.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet filter.

    Returns:
        Structured fleet overview dictionary.
    """
    stmt = select(Node)
    if tailnet:
        stmt = stmt.where(Node.tailnet == tailnet)

    result = await session.execute(stmt)
    nodes = list(result.scalars().all())

    total_fleet_nodes = len(nodes)
    monitored_domains = 0
    valid_count = 0
    expiring_soon_count = 0
    expired_count = 0
    unreachable_count = 0
    not_configured_count = 0

    certificates_list: List[Dict[str, Any]] = []
    expiring_soon_list: List[Dict[str, Any]] = []

    for n in nodes:
        meta = n.telemetry_metadata or {}
        ssl_info = meta.get("magicdns_ssl", {})
        domain = ssl_info.get("domain") or extract_magicdns_domain(n, tailnet=tailnet)

        if not domain:
            not_configured_count += 1
            continue

        monitored_domains += 1
        status = ssl_info.get("status", SSLCertificateStatus.NOT_CONFIGURED.value)
        is_expired = bool(ssl_info.get("is_expired", False))
        is_expiring_soon = bool(ssl_info.get("is_expiring_soon", False))

        if status == SSLCertificateStatus.VALID.value:
            valid_count += 1
        elif status == SSLCertificateStatus.EXPIRING_SOON.value:
            expiring_soon_count += 1
        elif status == SSLCertificateStatus.EXPIRED.value:
            expired_count += 1
        elif status == SSLCertificateStatus.UNREACHABLE.value:
            unreachable_count += 1

        cert_item = {
            "node_id": n.id,
            "node_stable_id": n.node_id or n.id,
            "hostname": n.hostname,
            "name": n.name,
            "user": n.user,
            "tailnet": n.tailnet,
            "domain": domain,
            "status": status,
            "expires_at": ssl_info.get("expires_at"),
            "remaining_days": ssl_info.get("remaining_days"),
            "countdown_human": ssl_info.get("countdown_human"),
            "is_expired": is_expired,
            "is_expiring_soon": is_expiring_soon,
            "http_reachable": ssl_info.get("http_reachable"),
            "http_status_code": ssl_info.get("http_status_code"),
            "tls_version": ssl_info.get("tls_version"),
            "checked_at": ssl_info.get("checked_at"),
            "issuer": ssl_info.get("certificate", {}).get("issuer", {}),
            "common_name": ssl_info.get("certificate", {}).get("common_name"),
        }
        certificates_list.append(cert_item)

        if is_expired or is_expiring_soon:
            expiring_soon_list.append(cert_item)

    # Sort expiring soon by remaining days ascending (most urgent first)
    expiring_soon_list.sort(
        key=lambda x: x["remaining_days"] if x["remaining_days"] is not None else -999999.0
    )

    return {
        "tailnet": tailnet,
        "total_fleet_nodes": total_fleet_nodes,
        "monitored_domains_count": monitored_domains,
        "not_configured_count": not_configured_count,
        "valid_count": valid_count,
        "expiring_soon_count": expiring_soon_count,
        "expired_count": expired_count,
        "unreachable_count": unreachable_count,
        "expiring_soon_list": expiring_soon_list,
        "certificates": certificates_list,
        "audited_at": datetime.now(timezone.utc).isoformat(),
    }


async def get_fleet_expiring_certificates(
    session: AsyncSession,
    tailnet: Optional[str] = None,
    days_threshold: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Retrieves all fleet certificates expiring within a specified number of days or already expired.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet filter.
        days_threshold: Maximum days remaining to include (default: warning threshold).

    Returns:
        List of expiring certificate records sorted by urgency.
    """
    overview = await get_fleet_magicdns_ssl_overview(session, tailnet=tailnet)
    thresh = (
        days_threshold
        if days_threshold is not None
        else getattr(settings, "MAGICDNS_SSL_EXPIRY_WARNING_DAYS", DEFAULT_WARNING_DAYS)
    )

    filtered = []
    for cert in overview.get("certificates", []):
        rem = cert.get("remaining_days")
        if rem is not None and (rem <= thresh or cert.get("is_expired")):
            filtered.append(cert)

    filtered.sort(key=lambda x: x["remaining_days"] if x["remaining_days"] is not None else -999999.0)
    return filtered


async def get_node_magicdns_ssl_audit(
    session: AsyncSession,
    node_id: str,
) -> Dict[str, Any]:
    """Returns detailed MagicDNS SSL monitoring state and recent SSL audit logs for a node.

    Args:
        session: Active SQLAlchemy AsyncSession.
        node_id: Internal Node ID or Tailscale stable nodeId.

    Returns:
        Node certificate audit dictionary.
    """
    stmt = select(Node).where((Node.id == node_id) | (Node.node_id == node_id))
    result = await session.execute(stmt)
    node = result.scalar_one_or_none()

    if node is None:
        return {"error": "node_not_found", "node_id": node_id}

    meta = node.telemetry_metadata or {}
    ssl_info = meta.get("magicdns_ssl", {})
    domain = ssl_info.get("domain") or extract_magicdns_domain(node)

    # Fetch recent SSL audit logs for this node
    ssl_event_types = [
        AuditEventType.SSL_CERT_VALID.value,
        AuditEventType.SSL_CERT_EXPIRING.value,
        AuditEventType.SSL_CERT_EXPIRED.value,
        AuditEventType.SSL_CERT_ERROR.value,
        AuditEventType.SSL_CERT_UNREACHABLE.value,
    ]
    log_stmt = (
        select(AuditLog)
        .where(AuditLog.node_id == node.id)
        .where(AuditLog.event_type.in_(ssl_event_types))
        .order_by(desc(AuditLog.created_at))
        .limit(20)
    )
    log_result = await session.execute(log_stmt)
    logs = list(log_result.scalars().all())

    audit_history = [
        {
            "id": log.id,
            "event_type": log.event_type,
            "severity": log.severity,
            "action": log.action,
            "message": log.message,
            "details": log.details,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]

    return {
        "id": node.id,
        "node_id": node.node_id,
        "hostname": node.hostname,
        "name": node.name,
        "domain": domain,
        "is_configured": bool(domain),
        "status": ssl_info.get("status", SSLCertificateStatus.NOT_CONFIGURED.value),
        "expires_at": ssl_info.get("expires_at"),
        "remaining_days": ssl_info.get("remaining_days"),
        "countdown_human": ssl_info.get("countdown_human"),
        "is_expired": bool(ssl_info.get("is_expired", False)),
        "is_expiring_soon": bool(ssl_info.get("is_expiring_soon", False)),
        "http_reachable": ssl_info.get("http_reachable"),
        "http_status_code": ssl_info.get("http_status_code"),
        "response_time_ms": ssl_info.get("response_time_ms"),
        "tls_version": ssl_info.get("tls_version"),
        "certificate": ssl_info.get("certificate", {}),
        "error": ssl_info.get("error"),
        "checked_at": ssl_info.get("checked_at"),
        "audit_events": audit_history,
        "audited_at": datetime.now(timezone.utc).isoformat(),
    }
