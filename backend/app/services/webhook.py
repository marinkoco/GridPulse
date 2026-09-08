from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.audit_log import AuditLog
from app.models.enums import (
    AuditSeverity,
    AuditEventType,
    EventCategory,
)
from app.models.node import Node
from app.schemas.webhook import (
    AclAuditSummaryResponse,
    TailscaleWebhookEvent,
    WebhookProcessedEvent,
    WebhookResponse,
    WebhookStatusResponse,
)
from app.services.tailscale_client import TailscaleClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------


class WebhookError(Exception):
    """Base exception for webhook errors."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class WebhookVerificationError(WebhookError):
    """Raised when signature verification or timestamp validation fails."""

    def __init__(self, message: str = "Invalid webhook signature", status_code: int = 401):
        super().__init__(message=message, status_code=status_code)


class WebhookPayloadError(WebhookError):
    """Raised when incoming webhook body cannot be parsed as valid JSON or events."""

    def __init__(self, message: str = "Invalid webhook payload", status_code: int = 400):
        super().__init__(message=message, status_code=status_code)


# ---------------------------------------------------------------------------
# Signature Verification & Generation
# ---------------------------------------------------------------------------


def split_tailscale_signature_header(
    signature_header: Optional[str],
) -> Tuple[Optional[int], List[str]]:
    """Splits and extracts the `t` (timestamp) and `v1` (signature) values from the Tailscale-Webhook-Signature header.

    Expected header format:
        `t=1626380695,v1=93e986b208eb6757be...`
    or with multiple signatures (e.g. during secret rollover):
        `t=1626380695,v1=sig1,v1=sig2`

    Args:
        signature_header: The raw string value from the `Tailscale-Webhook-Signature` header.

    Returns:
        A tuple of `(timestamp, signatures)` where:
        - `timestamp` is the integer timestamp (or None if missing, unparseable, or negative).
        - `signatures` is a list of `v1` hex signature strings.
    """
    if not signature_header or not signature_header.strip():
        return None, []

    timestamp: Optional[int] = None
    signatures: List[str] = []

    # Parse key=value elements separated by commas
    parts = signature_header.split(",")
    for part in parts:
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, val = part.split("=", 1)
        key = key.strip().lower()
        val = val.strip().strip('"\'')

        if key == "t" and timestamp is None:
            try:
                parsed_ts = int(val)
                if parsed_ts >= 0:
                    timestamp = parsed_ts
                else:
                    logger.warning("Negative timestamp in Tailscale signature header: '%s'", val)
            except (ValueError, TypeError):
                logger.warning("Invalid integer timestamp in Tailscale signature header: '%s'", val)
                timestamp = None
        elif key == "v1":
            if val:
                signatures.append(val)

    return timestamp, signatures


def compute_tailscale_signature(
    raw_body: bytes | str,
    secret: str | bytes,
    timestamp: int | str,
) -> str:
    """Computes the HMAC-SHA256 signature for a Tailscale webhook payload.

    Message signed is: `<timestamp>.<raw_body>`

    Args:
        raw_body: Raw request body bytes or UTF-8 string.
        secret: Webhook shared secret string or bytes.
        timestamp: Unix timestamp integer or string.

    Returns:
        Lowercase hexadecimal HMAC-SHA256 digest string.
    """
    body_bytes = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    message = f"{timestamp}.".encode("utf-8") + body_bytes
    return hmac.new(secret_bytes, message, hashlib.sha256).hexdigest()


def generate_tailscale_signature(
    raw_body: bytes | str,
    secret: str,
    timestamp: Optional[int] = None,
) -> str:
    """Generates a valid Tailscale-Webhook-Signature header for a given body and secret.

    Format: `t=<timestamp>,v1=<hmac-sha256-hex>`
    String to sign: `<timestamp>.<raw_body>`

    Args:
        raw_body: Unmodified raw request body bytes or string.
        secret: Shared webhook secret key.
        timestamp: Unix epoch timestamp in seconds (defaults to current time).

    Returns:
        Formatted header value string.
    """
    ts = int(timestamp if timestamp is not None else time.time())
    sig = compute_tailscale_signature(raw_body=raw_body, secret=secret, timestamp=ts)
    return f"t={ts},v1={sig}"


def validate_tailscale_signature(
    raw_body: bytes | str,
    signature_header: Optional[str],
    secret: Optional[str | List[str]],
    tolerance_seconds: int = 300,
    current_time: Optional[float] = None,
) -> Tuple[bool, Optional[str]]:
    """Validates incoming Tailscale webhook signature and timestamp against the shared secret.

    Validation steps:
    1. Verify shared secret is configured and non-empty.
    2. Verify `Tailscale-Webhook-Signature` header is present and non-empty.
    3. Split `t` (timestamp) and `v1` (signature) values from header.
    4. Validate timestamp freshness against `tolerance_seconds` to prevent replay attacks.
    5. Perform constant-time HMAC-SHA256 comparison against each `v1` signature.

    Args:
        raw_body: Exact raw bytes or string received in the HTTP request body.
        signature_header: Raw string from `Tailscale-Webhook-Signature` header.
        secret: Webhook shared secret(s) configured for this tailnet.
        tolerance_seconds: Allowed clock drift / replay window in seconds (default 300s = 5m).
        current_time: Reference time for replay checks (defaults to time.time()).

    Returns:
        Tuple of `(is_valid, error_reason)`.
    """
    if not secret:
        return False, "Webhook secret is not configured on the server"

    # Normalize secrets to a non-empty list of candidate strings
    secrets_list: List[str] = []
    if isinstance(secret, str):
        for s in secret.split(","):
            s_clean = s.strip()
            if s_clean:
                secrets_list.append(s_clean)
    elif isinstance(secret, (list, tuple, set)):
        secrets_list = [str(s).strip() for s in secret if str(s).strip()]

    if not secrets_list:
        return False, "Webhook secret is empty or blank"

    if not signature_header or not signature_header.strip():
        return False, "Missing Tailscale-Webhook-Signature header"

    timestamp, signatures = split_tailscale_signature_header(signature_header)

    if timestamp is None:
        return False, "Missing or invalid timestamp 't' in signature header"

    if not signatures:
        return False, "Missing 'v1' signature in signature header"

    if tolerance_seconds < 0:
        return False, "Invalid tolerance window configuration"

    now = current_time if current_time is not None else time.time()
    drift = abs(now - timestamp)
    if drift > tolerance_seconds:
        return False, f"Timestamp rejected: clock drift of {drift:.1f}s exceeds tolerance of {tolerance_seconds}s"

    body_bytes = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body

    # Check each configured secret against each v1 signature using constant-time comparison
    for sec in secrets_list:
        expected_sig = compute_tailscale_signature(raw_body=body_bytes, secret=sec, timestamp=timestamp)
        for sig in signatures:
            if hmac.compare_digest(expected_sig, sig):
                return True, None

    return False, "HMAC signature mismatch: computed signature does not match any 'v1' value"


def verify_tailscale_signature(
    raw_body: bytes | str,
    signature_header: Optional[str],
    secret: Optional[str | List[str]],
    tolerance_seconds: int = 300,
    current_time: Optional[float] = None,
) -> bool:
    """Verifies that the incoming request body matches the Tailscale-Webhook-Signature header.

    Convenience boolean wrapper around `validate_tailscale_signature`.

    Args:
        raw_body: Exact raw bytes or string received in the HTTP request body.
        signature_header: Raw string from `Tailscale-Webhook-Signature` header.
        secret: Webhook shared secret configured for this tailnet.
        tolerance_seconds: Allowed clock drift / replay window in seconds (default 300s).
        current_time: Reference time for replay checks (defaults to time.time()).

    Returns:
        True if the signature and timestamp are valid, False otherwise.
    """
    is_valid, _ = validate_tailscale_signature(
        raw_body=raw_body,
        signature_header=signature_header,
        secret=secret,
        tolerance_seconds=tolerance_seconds,
        current_time=current_time,
    )
    return is_valid


# ---------------------------------------------------------------------------
# Event Parsing and Classification
# ---------------------------------------------------------------------------


def parse_webhook_events(payload: Any) -> List[TailscaleWebhookEvent]:
    """Parses a deserialized JSON payload into a list of TailscaleWebhookEvent models.

    Tailscale may deliver payloads as:
    1. A list of events: `[{"type": "policyUpdate", ...}, ...]`
    2. A single event object: `{"type": "nodeCreated", ...}`

    Args:
        payload: Python dict or list parsed from JSON.

    Returns:
        List of validated `TailscaleWebhookEvent` instances.
    """
    if isinstance(payload, list):
        return [TailscaleWebhookEvent.model_validate(item) for item in payload if isinstance(item, dict)]
    elif isinstance(payload, dict):
        return [TailscaleWebhookEvent.model_validate(payload)]
    return []


def classify_webhook_event(event: TailscaleWebhookEvent) -> Dict[str, Any]:
    """Classifies a Tailscale webhook event into canonical audit categorization and severity.

    Maps Tailscale event types (e.g., `policyUpdate`, `nodeCreated`, `nodeDeleted`) to:
    - `event_type`: Canonical AuditEventType string.
    - `event_category`: High-level category (acl, device, security, system).
    - `severity`: AuditSeverity level (info, warning, high, critical).
    - `action`: Concise description.
    - `actor`: Actor name or identifier.
    - `node_id`: Target node ID if applicable.
    - `message`: Human-readable summary.

    Args:
        event: Validated `TailscaleWebhookEvent`.

    Returns:
        Dictionary with classification metadata.
    """
    event_type_raw = event.type
    actor_name = event.actor_name
    target_node = event.target_node_id

    # 1. ACL & Policy Update Events
    if event_type_raw in ("policyUpdate", "policy.update", "aclUpdate", "acl.updated"):
        return {
            "event_type": AuditEventType.POLICY_UPDATE.value,
            "event_category": EventCategory.ACL.value,
            "severity": AuditSeverity.WARNING.value,
            "action": "Tailscale ACL policy updated",
            "actor": actor_name,
            "node_id": None,
            "message": event.message or f"Tailnet ACL policy file updated for {event.tailnet or 'tailnet'}.",
        }

    # 2. Node Lifecycle & Approval Events
    elif event_type_raw == "nodeCreated":
        return {
            "event_type": AuditEventType.NODE_CREATED.value,
            "event_category": EventCategory.DEVICE.value,
            "severity": AuditSeverity.INFO.value,
            "action": "New node joined tailnet",
            "actor": actor_name,
            "node_id": target_node,
            "message": event.message or f"New node joined tailnet {event.tailnet or ''}.",
        }
    elif event_type_raw == "nodeNeedsApproval":
        return {
            "event_type": AuditEventType.NODE_NEEDS_APPROVAL.value,
            "event_category": EventCategory.SECURITY.value,
            "severity": AuditSeverity.WARNING.value,
            "action": "Node requires admin approval",
            "actor": actor_name,
            "node_id": target_node,
            "message": event.message or "A new device requires administrative approval before joining.",
        }
    elif event_type_raw == "nodeApproved":
        return {
            "event_type": AuditEventType.NODE_APPROVED.value,
            "event_category": EventCategory.SECURITY.value,
            "severity": AuditSeverity.INFO.value,
            "action": "Node approved to join tailnet",
            "actor": actor_name,
            "node_id": target_node,
            "message": event.message or "Device was approved by administrator.",
        }
    elif event_type_raw == "nodeDeleted":
        return {
            "event_type": AuditEventType.NODE_DELETED.value,
            "event_category": EventCategory.DEVICE.value,
            "severity": AuditSeverity.WARNING.value,
            "action": "Node removed from tailnet",
            "actor": actor_name,
            "node_id": target_node,
            "message": event.message or "Device was removed/deleted from tailnet.",
        }
    elif event_type_raw == "nodeKeyExpiringInOneDay":
        return {
            "event_type": AuditEventType.KEY_EXPIRY_WARNING.value,
            "event_category": EventCategory.SECURITY.value,
            "severity": AuditSeverity.HIGH.value,
            "action": "Node key expiring within 24 hours",
            "actor": actor_name,
            "node_id": target_node,
            "message": event.message or "Tailscale device key expires in less than 24 hours.",
        }
    elif event_type_raw == "nodeKeyExpired":
        return {
            "event_type": AuditEventType.NODE_EXPIRED.value,
            "event_category": EventCategory.SECURITY.value,
            "severity": AuditSeverity.CRITICAL.value,
            "action": "Node key expired",
            "actor": actor_name,
            "node_id": target_node,
            "message": event.message or "Tailscale device key has expired; node is disconnected.",
        }

    # 3. User & Identity Management Events
    elif event_type_raw == "userCreated":
        return {
            "event_type": AuditEventType.USER_CREATED.value,
            "event_category": EventCategory.SECURITY.value,
            "severity": AuditSeverity.INFO.value,
            "action": "User account created",
            "actor": actor_name,
            "node_id": None,
            "message": event.message or "New user registered in tailnet.",
        }
    elif event_type_raw == "userNeedsApproval":
        return {
            "event_type": AuditEventType.USER_NEEDS_APPROVAL.value,
            "event_category": EventCategory.SECURITY.value,
            "severity": AuditSeverity.WARNING.value,
            "action": "User account requires approval",
            "actor": actor_name,
            "node_id": None,
            "message": event.message or "New user requires administrative approval.",
        }
    elif event_type_raw == "userApproved":
        return {
            "event_type": AuditEventType.USER_APPROVED.value,
            "event_category": EventCategory.SECURITY.value,
            "severity": AuditSeverity.INFO.value,
            "action": "User account approved",
            "actor": actor_name,
            "node_id": None,
            "message": event.message or "User was approved by administrator.",
        }
    elif event_type_raw == "userSuspended":
        return {
            "event_type": AuditEventType.USER_SUSPENDED.value,
            "event_category": EventCategory.SECURITY.value,
            "severity": AuditSeverity.HIGH.value,
            "action": "User account suspended",
            "actor": actor_name,
            "node_id": None,
            "message": event.message or "User account was suspended.",
        }
    elif event_type_raw == "userRestored":
        return {
            "event_type": AuditEventType.USER_RESTORED.value,
            "event_category": EventCategory.SECURITY.value,
            "severity": AuditSeverity.INFO.value,
            "action": "User account restored",
            "actor": actor_name,
            "node_id": None,
            "message": event.message or "Suspended user account was restored.",
        }
    elif event_type_raw == "userDeleted":
        return {
            "event_type": AuditEventType.USER_DELETED.value,
            "event_category": EventCategory.SECURITY.value,
            "severity": AuditSeverity.WARNING.value,
            "action": "User account deleted",
            "actor": actor_name,
            "node_id": None,
            "message": event.message or "User was removed from tailnet.",
        }
    elif event_type_raw == "userRoleUpdated":
        return {
            "event_type": AuditEventType.USER_ROLE_UPDATED.value,
            "event_category": EventCategory.SECURITY.value,
            "severity": AuditSeverity.HIGH.value,
            "action": "User role or permissions modified",
            "actor": actor_name,
            "node_id": None,
            "message": event.message or "User role or administrative permissions changed.",
        }

    # 4. Tailscale Test Event
    elif event_type_raw in ("test", "webhook.test"):
        return {
            "event_type": AuditEventType.WEBHOOK_TEST.value,
            "event_category": EventCategory.SYSTEM.value,
            "severity": AuditSeverity.INFO.value,
            "action": "Tailscale webhook test event received",
            "actor": actor_name,
            "node_id": None,
            "message": event.message or "Test event dispatched from Tailscale admin console.",
        }

    # 5. Tailnet Configuration Events
    elif "configuration" in event_type_raw.lower() or "settings" in event_type_raw.lower():
        return {
            "event_type": AuditEventType.CONFIG_CHANGED.value,
            "event_category": EventCategory.SYSTEM.value,
            "severity": AuditSeverity.INFO.value,
            "action": f"Tailnet configuration updated: {event_type_raw}",
            "actor": actor_name,
            "node_id": target_node,
            "message": event.message or f"Configuration change event: {event_type_raw}",
        }

    # 6. Fallback / Generic event
    return {
        "event_type": f"tailscale.{event_type_raw}",
        "event_category": EventCategory.SYSTEM.value,
        "severity": AuditSeverity.INFO.value,
        "action": f"Tailscale event: {event_type_raw}",
        "actor": actor_name,
        "node_id": target_node,
        "message": event.message or f"Received webhook event '{event_type_raw}'.",
    }


# ---------------------------------------------------------------------------
# Core Webhook Processing Pipeline
# ---------------------------------------------------------------------------


async def process_tailscale_webhook(
    raw_body: bytes,
    signature_header: Optional[str],
    session: AsyncSession,
    tailscale_client: Optional[TailscaleClient] = None,
    client_ip: Optional[str] = None,
    verify_signature: Optional[bool] = None,
    secret_override: Optional[str] = None,
    tolerance_seconds: Optional[int] = None,
) -> WebhookResponse:
    """Processes incoming Tailscale webhook payload.

    1. Enforces signature verification and timestamp freshness.
    2. Parses single or batched JSON events.
    3. Categorizes and creates AuditLog records.
    4. Handles ACL modifications (`policyUpdate`), optionally querying live ACL.
    5. Updates node states on lifecycle events (e.g. `nodeDeleted`).
    6. Commits changes and returns structured WebhookResponse.

    Args:
        raw_body: Raw request body bytes.
        signature_header: `Tailscale-Webhook-Signature` header value.
        session: Active SQLAlchemy AsyncSession.
        tailscale_client: Optional TailscaleClient instance for fetching live ACL or nodes.
        client_ip: Optional client IP address from the HTTP request.
        verify_signature: Flag to enforce signature verification (defaults to settings).
        secret_override: Optional secret override for testing.
        tolerance_seconds: Custom tolerance window in seconds.

    Returns:
        Validated `WebhookResponse` summary.

    Raises:
        WebhookVerificationError: If signature or timestamp check fails.
        WebhookPayloadError: If request body is not valid JSON.
    """
    enforce_verify = (
        verify_signature
        if verify_signature is not None
        else getattr(settings, "TAILSCALE_WEBHOOK_VERIFY_SIGNATURE", True)
    )
    secret = secret_override or getattr(settings, "TAILSCALE_WEBHOOK_SECRET", None)
    tolerance = (
        tolerance_seconds
        if tolerance_seconds is not None
        else getattr(settings, "TAILSCALE_WEBHOOK_TOLERANCE_SECONDS", 300)
    )

    if enforce_verify:
        if not secret:
            logger.error("Rejecting webhook: TAILSCALE_WEBHOOK_SECRET is not configured.")
            raise WebhookVerificationError(
                "Webhook secret is not configured on the server",
                status_code=500,
            )

        is_valid, error_reason = validate_tailscale_signature(
            raw_body=raw_body,
            signature_header=signature_header,
            secret=secret,
            tolerance_seconds=tolerance,
        )
        if not is_valid:
            logger.warning("Rejecting webhook: %s", error_reason)
            raise WebhookVerificationError(
                error_reason or "Invalid webhook signature or expired timestamp",
                status_code=401,
            )
    else:
        logger.debug("Webhook signature verification is bypassed by configuration.")

    # Deserialize JSON payload
    try:
        decoded_str = raw_body.decode("utf-8")
        payload = json.loads(decoded_str)
    except Exception as exc:
        logger.warning("Failed to parse webhook JSON body: %s", exc)
        raise WebhookPayloadError(f"Malformed JSON payload: {exc}", status_code=400) from exc

    events = parse_webhook_events(payload)
    if not events:
        logger.info("Webhook payload contained 0 events.")
        return WebhookResponse(
            status="ok",
            received_events=0,
            processed_events=0,
            ignored_events=0,
            events=[],
            message="No actionable events found in payload.",
        )

    processed_list: List[WebhookProcessedEvent] = []
    auto_fetch_acl = getattr(settings, "TAILSCALE_WEBHOOK_AUTO_FETCH_ACL", True)

    for event in events:
        classification = classify_webhook_event(event)

        # Build details dictionary preserving the original event payload
        details_data = {
            "source": "tailscale_webhook",
            "raw_type": event.type,
            "version": event.version,
            "tailnet": event.tailnet,
            "timestamp": event.timestamp,
            "data": event.data,
        }
        if event.actor:
            details_data["actor_raw"] = (
                event.actor.model_dump()
                if hasattr(event.actor, "model_dump")
                else event.actor
            )

        # If policyUpdate (ACL change): Optionally fetch live ACL policy
        if event.is_policy_update and auto_fetch_acl and tailscale_client and tailscale_client.is_configured:
            try:
                logger.info("Fetching latest ACL policy following webhook policyUpdate event...")
                live_acl = await tailscale_client.get_acl(tailnet=event.tailnet)
                details_data["fetched_policy"] = {
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "rules_count": len(live_acl.get("acls", live_acl.get("ACLs", []))),
                    "tag_owners_count": len(live_acl.get("tagOwners", {})),
                    "grants_count": len(live_acl.get("grants", [])),
                    "policy_summary": {k: len(v) if isinstance(v, list) else type(v).__name__ for k, v in live_acl.items()},
                }
            except Exception as exc:
                logger.warning("Could not fetch live ACL policy after webhook: %s", exc)
                details_data["fetched_policy_error"] = str(exc)

        # If nodeDeleted: Mark existing node offline if found
        target_node_id = classification["node_id"]
        if event.type == "nodeDeleted" and target_node_id:
            stmt = select(Node).where(
                (Node.id == target_node_id) | (Node.node_id == target_node_id)
            )
            node_res = await session.execute(stmt)
            target_node_obj = node_res.scalar_one_or_none()
            if target_node_obj:
                target_node_obj.is_online = False
                meta = dict(target_node_obj.telemetry_metadata or {})
                meta["deleted_via_webhook"] = True
                meta["deleted_at"] = datetime.now(timezone.utc).isoformat()
                target_node_obj.telemetry_metadata = meta

        # Record AuditLog entry
        audit_id = str(uuid.uuid4())
        audit_log = AuditLog(
            id=audit_id,
            node_id=target_node_id,
            event_type=classification["event_type"],
            event_category=classification["event_category"],
            severity=classification["severity"],
            action=classification["action"],
            actor=classification["actor"],
            message=classification["message"],
            details=details_data,
            ip_address=client_ip,
            created_at=datetime.now(timezone.utc),
        )
        session.add(audit_log)

        processed_list.append(
            WebhookProcessedEvent(
                id=audit_id,
                event_type=classification["event_type"],
                event_category=classification["event_category"],
                severity=classification["severity"],
                action=classification["action"],
                actor=classification["actor"],
                node_id=target_node_id,
                tailnet=event.tailnet,
                created_at=audit_log.created_at.isoformat(),
            )
        )

    await session.commit()
    logger.info("Successfully processed %d Tailscale webhook events.", len(processed_list))

    return WebhookResponse(
        status="ok",
        received_events=len(events),
        processed_events=len(processed_list),
        ignored_events=0,
        events=processed_list,
        message=f"Successfully ingested {len(processed_list)} event(s).",
    )


# ---------------------------------------------------------------------------
# Fleet ACL & Webhook Query Services
# ---------------------------------------------------------------------------


async def get_fleet_acl_events(
    session: AsyncSession,
    limit: int = 50,
    tailnet: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieves chronological history of ACL modification events and policy changes.

    Args:
        session: Active SQLAlchemy AsyncSession.
        limit: Maximum events to return (default 50).
        tailnet: Optional tailnet filter.

    Returns:
        List of formatted ACL event dictionaries.
    """
    stmt = (
        select(AuditLog)
        .where(
            (AuditLog.event_category == EventCategory.ACL.value)
            | (AuditLog.event_type.in_([
                AuditEventType.POLICY_UPDATE.value,
                AuditEventType.ACL_UPDATED.value,
                "policyUpdate",
                "aclUpdate",
            ]))
        )
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
    )
    result = await session.execute(stmt)
    logs = result.scalars().all()

    items: List[Dict[str, Any]] = []
    for log in logs:
        details = log.details or {}
        event_tailnet = details.get("tailnet")
        if tailnet and event_tailnet and event_tailnet != tailnet:
            continue

        items.append({
            "id": log.id,
            "event_type": log.event_type,
            "event_category": log.event_category,
            "severity": log.severity,
            "action": log.action,
            "actor": log.actor,
            "message": log.message,
            "tailnet": event_tailnet,
            "created_at": log.created_at.isoformat(),
            "url": details.get("data", {}).get("url"),
            "fetched_policy": details.get("fetched_policy"),
            "details": details,
        })
    return items


async def get_fleet_acl_overview(
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Dict[str, Any]:
    """Generates an executive overview of ACL policy modifications and change metrics.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet filter.

    Returns:
        Summary metrics dictionary matching `AclAuditSummaryResponse`.
    """
    events = await get_fleet_acl_events(session=session, limit=100, tailnet=tailnet)
    total_events = len(events)
    last_event = events[0] if events else None

    return {
        "total_acl_events": total_events,
        "last_policy_update_at": last_event["created_at"] if last_event else None,
        "last_actor": last_event["actor"] if last_event else None,
        "recent_events": events[:10],
    }


async def get_webhook_listener_status(
    session: AsyncSession,
) -> Dict[str, Any]:
    """Returns the operational status, security configuration, and traffic metrics of the webhook listener.

    Args:
        session: Active SQLAlchemy AsyncSession.

    Returns:
        Status dictionary matching `WebhookStatusResponse`.
    """
    secret = getattr(settings, "TAILSCALE_WEBHOOK_SECRET", None)
    tolerance = getattr(settings, "TAILSCALE_WEBHOOK_TOLERANCE_SECONDS", 300)
    verify_enabled = getattr(settings, "TAILSCALE_WEBHOOK_VERIFY_SIGNATURE", True)

    # Query all audit logs that originated from webhooks
    stmt = (
        select(AuditLog)
        .where(
            (AuditLog.event_category.in_([
                EventCategory.ACL.value,
                EventCategory.SYSTEM.value,
                EventCategory.DEVICE.value,
                EventCategory.SECURITY.value,
            ]))
        )
        .order_by(desc(AuditLog.created_at))
        .limit(100)
    )
    result = await session.execute(stmt)
    all_logs = result.scalars().all()

    # Filter to logs created from webhook source
    webhook_logs = [log for log in all_logs if (log.details or {}).get("source") == "tailscale_webhook"]

    breakdown: Dict[str, int] = {}
    for log in webhook_logs:
        raw_type = (log.details or {}).get("raw_type", log.event_type)
        breakdown[raw_type] = breakdown.get(raw_type, 0) + 1

    last_received_at = webhook_logs[0].created_at.isoformat() if webhook_logs else None

    recent_entries = [
        {
            "id": log.id,
            "event_type": log.event_type,
            "raw_type": (log.details or {}).get("raw_type", log.event_type),
            "severity": log.severity,
            "action": log.action,
            "actor": log.actor,
            "created_at": log.created_at.isoformat(),
        }
        for log in webhook_logs[:10]
    ]

    return {
        "webhook_enabled": True,
        "secret_configured": bool(secret and secret.strip()),
        "verify_signature_enabled": verify_enabled,
        "tolerance_seconds": tolerance,
        "total_webhook_events": len(webhook_logs),
        "last_event_received_at": last_received_at,
        "event_types_breakdown": breakdown,
        "recent_events": recent_entries,
    }
