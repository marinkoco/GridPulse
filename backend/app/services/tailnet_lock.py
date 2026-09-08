from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.audit_log import AuditLog
from app.models.enums import (
    AuditSeverity,
    AuditEventType,
    ComplianceStatus,
    EventCategory,
    TailnetLockStatus,
)
from app.models.node import Node
from app.models.node_state import NodeState
from app.schemas.tailscale import TailscaleDevice

logger = logging.getLogger(__name__)

# Standardized Posture & Tailnet Lock Attribute Keys in Tailscale
POSTURE_TAILNET_LOCK_KEY_ATTR: str = "node:tailnetLockKey"
POSTURE_TAILNET_LOCK_ERROR_ATTR: str = "node:tailnetLockError"
POSTURE_LOCKED_OUT_ATTR: str = "node:lockedOut"

# Default tags that grant exemption from Tailnet Lock enforcement
DEFAULT_EXEMPT_LOCK_TAGS: Set[str] = {
    "tag:tailnet-lock-exempt",
    "tag:lock-exempt",
    "tag:compliance-exempt",
    "tag:dev-exempt",
}

# Known substrings in error messages indicating an unsigned node
UNSIGNED_ERROR_SUBSTRINGS: Tuple[str, ...] = (
    "unsigned",
    "missing signature",
    "signature missing",
    "not signed",
    "no signature",
    "unauthorized node key",
    "missing node-key signature",
    "node key not signed",
)


def parse_tailnet_lock_key(device: TailscaleDevice) -> Optional[str]:
    """Extracts and normalizes the Tailnet Lock public key for a device.

    Tailnet Lock public keys typically carry prefixes like `nlpub:` or `tlpub:`
    (e.g., `nlpub:600a7b5...` or `tlpub:44fa...`).

    Inspection priority:
    1. Direct `device.get_tailnet_lock_key()` or `device.tailnet_lock_key`.
    2. `device.attributes`: keys such as `tailnetLockKey`, `tailnet_lock_key`, `node:tailnetLockKey`.
    3. `device.tags`: tags starting with `nlpub:`, `tlpub:`, `tag:tailnet-lock-key:`, `tag:lock-key:`.

    Args:
        device: The TailscaleDevice payload.

    Returns:
        Tailnet Lock public key string, or None if not present.
    """
    if hasattr(device, "get_tailnet_lock_key"):
        val = device.get_tailnet_lock_key()
        if val is not None and val.strip():
            return val.strip()

    if getattr(device, "tailnet_lock_key", None):
        return device.tailnet_lock_key.strip()

    if device.attributes:
        for k, v in device.attributes.items():
            k_norm = k.lower().replace(":", "_").replace("-", "_")
            if k_norm in (
                "tailnetlockkey",
                "tailnet_lock_key",
                "node_tailnetlockkey",
                "node_tailnet_lock_key",
                "tailnet_lock_public_key",
                "lock_key",
                "tlpub",
                "nlpub",
            ) and v is not None:
                cleaned = str(v).strip()
                if cleaned:
                    return cleaned

    for tag in device.tags:
        tag_clean = tag.strip()
        tag_lower = tag_clean.lower()
        if tag_lower.startswith("nlpub:") or tag_lower.startswith("tlpub:"):
            return tag_clean
        if tag_lower.startswith("node:tailnetlockkey:") or tag_lower.startswith("node:tailnet_lock_key:"):
            return tag_clean.split(":", 2)[-1].strip()
        if tag_lower.startswith("tag:tailnet-lock-key:") or tag_lower.startswith("tag:lock-key:"):
            return tag_clean.split(":", 2)[-1].strip()

    return None


def parse_tailnet_lock_error(device: TailscaleDevice) -> Optional[str]:
    """Extracts the Tailnet Lock error string if the node failed signature verification or is locked out.

    Inspection priority:
    1. Direct `device.get_tailnet_lock_error()` or `device.tailnet_lock_error`.
    2. `device.attributes`: `tailnetLockError`, `tailnetLockErr`, `tailnet_lock_error`, etc.
    3. `device.tags`: tags such as `tag:tailnet-lock-error:<msg>`, `tag:lock-error:<msg>`.

    Args:
        device: The TailscaleDevice payload.

    Returns:
        Error string if an error is present, else None.
    """
    if hasattr(device, "get_tailnet_lock_error"):
        val = device.get_tailnet_lock_error()
        if val is not None and val.strip():
            return val.strip()

    if getattr(device, "tailnet_lock_error", None):
        return device.tailnet_lock_error.strip()

    if device.attributes:
        for k, v in device.attributes.items():
            k_norm = k.lower().replace(":", "_").replace("-", "_")
            if k_norm in (
                "tailnetlockerror",
                "tailnetlockerr",
                "tailnet_lock_error",
                "tailnet_lock_err",
                "node_tailnetlockerror",
                "node_tailnet_lock_error",
                "lock_error",
                "lock_err",
            ) and v is not None:
                cleaned = str(v).strip()
                if cleaned:
                    return cleaned

    for tag in device.tags:
        tag_clean = tag.strip()
        tag_lower = tag_clean.lower()
        if tag_lower.startswith("tag:tailnet-lock-error:") or tag_lower.startswith("tag:lock-error:"):
            return tag_clean.split(":", 2)[-1].strip()
        if tag_lower.startswith("node:tailnetlockerror:") or tag_lower.startswith("node:tailnet_lock_error:"):
            return tag_clean.split(":", 2)[-1].strip()

    return None


def is_node_locked_out(device: TailscaleDevice) -> bool:
    """Determines whether a device is currently locked out by Tailnet Lock.

    A node is considered locked out if:
    - It has a non-empty `tailnetLockError`.
    - It has `lockedOut: True` in top-level fields or attributes.
    - It carries locked-out posture tags (e.g., `tag:locked-out`, `node:lockedOut`).

    Args:
        device: The TailscaleDevice payload.

    Returns:
        True if locked out, False otherwise.
    """
    if hasattr(device, "is_locked_out_status"):
        if device.is_locked_out_status():
            return True

    err = parse_tailnet_lock_error(device)
    if err:
        return True

    if getattr(device, "locked_out", None) is True:
        return True

    if device.attributes:
        for k, v in device.attributes.items():
            k_norm = k.lower().replace(":", "_").replace("-", "_")
            if k_norm in (
                "lockedout",
                "locked_out",
                "islockedout",
                "is_locked_out",
                "node_lockedout",
                "node_locked_out",
            ) and v is not None:
                if isinstance(v, bool):
                    return v
                if str(v).strip().lower() in ("true", "1", "yes", "enabled"):
                    return True

    for tag in device.tags:
        tag_lower = tag.strip().lower()
        if tag_lower in (
            "tag:locked-out",
            "tag:lockedout",
            "tag:lock-out",
            "node:lockedout",
            "node:locked-out",
        ):
            return True

    return False


def is_node_quarantined(device: TailscaleDevice) -> bool:
    """Determines whether a device is quarantined under Tailnet Lock.

    In Tailscale, locked out nodes are effectively quarantined because other nodes
    will reject network traffic from them until authorized with a valid signature.

    Args:
        device: The TailscaleDevice payload.

    Returns:
        True if the device is quarantined or locked out, False otherwise.
    """
    if hasattr(device, "is_quarantined_status"):
        if device.is_quarantined_status():
            return True

    if is_node_locked_out(device):
        return True

    for tag in device.tags:
        tag_lower = tag.strip().lower()
        if tag_lower in (
            "tag:quarantined",
            "tag:tailnet-lock-quarantined",
            "tag:lock-quarantined",
            "tag:quarantine",
        ):
            return True

    if device.attributes:
        for k, v in device.attributes.items():
            if "quarantine" in k.lower():
                if v is True or str(v).strip().lower() in ("true", "1", "yes"):
                    return True

    return False


def is_node_unsigned(device: TailscaleDevice, tailnet_lock_enabled: bool = True) -> bool:
    """Determines whether a device is unsigned under Tailnet Lock.

    An unsigned node is a device that has enrolled or renewed its node key, but has not
    yet had its node key signed by a trusted signing node.

    Args:
        device: The TailscaleDevice payload.
        tailnet_lock_enabled: Whether Tailnet Lock enforcement is active.

    Returns:
        True if the device is identified as unsigned, False otherwise.
    """
    if hasattr(device, "is_unsigned_status"):
        if device.is_unsigned_status():
            return True

    err = parse_tailnet_lock_error(device)
    if err:
        err_lower = err.lower()
        if any(term in err_lower for term in UNSIGNED_ERROR_SUBSTRINGS):
            return True

    if device.attributes:
        for k, v in device.attributes.items():
            k_norm = k.lower().replace(":", "_").replace("-", "_")
            if k_norm in ("unsigned", "is_unsigned", "not_signed") and v is not None:
                if isinstance(v, bool):
                    return v
                if str(v).strip().lower() in ("true", "1", "yes"):
                    return True

    for tag in device.tags:
        tag_lower = tag.strip().lower()
        if tag_lower in (
            "tag:unsigned",
            "tag:tailnet-lock-unsigned",
            "tag:not-signed",
            "tag:lock-unsigned",
        ):
            return True

    # If Tailnet Lock is globally enabled, the device has a node_key, is not external or exempt,
    # but does NOT have a tailnet_lock_key and is locked out -> it is unsigned
    if tailnet_lock_enabled and not is_node_lock_exempt(device):
        has_node_key = bool(device.node_key or getattr(device, "machine_key", None))
        has_lock_key = bool(parse_tailnet_lock_key(device))
        if has_node_key and not has_lock_key and is_node_locked_out(device):
            return True

    return False


def is_signing_node(device: TailscaleDevice) -> bool:
    """Determines whether a device is a trusted Tailnet Lock signing node.

    Signing nodes hold the private key authority to sign new or rotated node keys.

    Args:
        device: The TailscaleDevice payload.

    Returns:
        True if the device is a designated signing node, False otherwise.
    """
    if hasattr(device, "is_signing_node_status"):
        if device.is_signing_node_status():
            return True

    if device.attributes:
        for k, v in device.attributes.items():
            k_norm = k.lower().replace(":", "_").replace("-", "_")
            if k_norm in (
                "is_signing_node",
                "issigningnode",
                "signing_node",
                "tailnet_lock_signer",
                "lock_signer",
            ) and v is not None:
                if isinstance(v, bool):
                    return v
                if str(v).strip().lower() in ("true", "1", "yes"):
                    return True

    for tag in device.tags:
        tag_lower = tag.strip().lower()
        if tag_lower in (
            "tag:tailnet-lock-signer",
            "tag:lock-signer",
            "tag:signing-node",
            "tag:signer",
        ):
            return True

    return False


def is_node_lock_exempt(device: TailscaleDevice) -> bool:
    """Determines whether a device is exempt from Tailnet Lock enforcement.

    External/shared-in nodes and nodes with explicit exemption tags are exempt.

    Args:
        device: The TailscaleDevice payload.

    Returns:
        True if exempt, False otherwise.
    """
    if device.is_external:
        return True

    exempt_tags = set(settings.TAILNET_LOCK_EXEMPT_TAGS) | DEFAULT_EXEMPT_LOCK_TAGS
    for tag in device.tags:
        if tag.lower().strip() in exempt_tags:
            return True

    if device.attributes:
        for k, v in device.attributes.items():
            k_norm = k.lower().replace(":", "_").replace("-", "_")
            if k_norm in (
                "tailnet_lock_exempt",
                "lock_exempt",
                "compliance_exempt",
            ) and v is not None:
                if isinstance(v, bool):
                    return v
                if str(v).strip().lower() in ("true", "1", "yes"):
                    return True

    return False


def determine_tailnet_lock_status(
    device: TailscaleDevice,
    tailnet_lock_enabled: bool = True,
) -> TailnetLockStatus:
    """Determines the high-level Tailnet Lock status for a device.

    Classification order:
    1. NOT_APPLICABLE: Tailnet Lock disabled or not enforced.
    2. EXEMPT: Shared-in external device or explicitly exempted.
    3. SIGNING_NODE: Node acts as a trusted signing node.
    4. QUARANTINED: Locked out or flagged as quarantined.
    5. LOCKED_OUT: Device reported locked-out by Tailscale.
    6. UNSIGNED: Node lacks cryptographic signature.
    7. SIGNED: Node has verified key and signature.
    8. UNKNOWN: Unable to definitively determine status.

    Args:
        device: The TailscaleDevice payload.
        tailnet_lock_enabled: Whether Tailnet Lock enforcement is active.

    Returns:
        Canonical `TailnetLockStatus` enum value.
    """
    if not tailnet_lock_enabled:
        return TailnetLockStatus.NOT_APPLICABLE

    if is_node_lock_exempt(device):
        return TailnetLockStatus.EXEMPT

    if is_signing_node(device):
        return TailnetLockStatus.SIGNING_NODE

    locked = is_node_locked_out(device)
    quarantined = is_node_quarantined(device)

    # Check for unsigned first if error specifically says unsigned
    if is_node_unsigned(device, tailnet_lock_enabled=tailnet_lock_enabled):
        return TailnetLockStatus.UNSIGNED

    if quarantined:
        return TailnetLockStatus.QUARANTINED

    if locked:
        return TailnetLockStatus.LOCKED_OUT

    key = parse_tailnet_lock_key(device)
    if key or device.authorized:
        return TailnetLockStatus.SIGNED

    return TailnetLockStatus.UNKNOWN


def audit_node_tailnet_lock(
    device: TailscaleDevice,
    existing_node: Optional[Node] = None,
    tailnet_lock_enabled: Optional[bool] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Audits a device's Tailnet Lock status, detecting quarantined, unsigned, or locked-out nodes.

    Evaluates:
    - Tailnet Lock public key presence and format (`nlpub:...`, `tlpub:...`).
    - Locked-out status and error messages from `tailnetLockError`.
    - Quarantined node identification.
    - Unsigned node detection awaiting cryptographic authorization.
    - Signing node status.
    - Key rotation or modification compared against existing database state.

    Args:
        device: Incoming `TailscaleDevice` model.
        existing_node: Previous database `Node` record if already tracked.
        tailnet_lock_enabled: Optional override for global lock enforcement setting.
        now: Evaluation timestamp (defaults to current UTC).

    Returns:
        Structured Tailnet Lock audit dictionary with alerts, status, and compliance flag.
    """
    eval_now = now or datetime.now(timezone.utc)
    eval_now_iso = eval_now.isoformat()
    lock_enabled = (
        tailnet_lock_enabled
        if tailnet_lock_enabled is not None
        else settings.TAILNET_LOCK_ENABLED
    )

    lock_key = parse_tailnet_lock_key(device)
    lock_err = parse_tailnet_lock_error(device)
    is_locked = is_node_locked_out(device)
    is_quar = is_node_quarantined(device)
    is_unsign = is_node_unsigned(device, tailnet_lock_enabled=lock_enabled)
    is_signing = is_signing_node(device)
    is_exempt = is_node_lock_exempt(device)

    status = determine_tailnet_lock_status(device, tailnet_lock_enabled=lock_enabled)
    status_str = status.value

    alerts: List[Dict[str, Any]] = []

    # Check for Locked-Out / Quarantined events
    if lock_enabled and not is_exempt:
        if is_quar or is_locked:
            event_type = (
                AuditEventType.TAILNET_LOCK_QUARANTINED.value
                if is_quar
                else AuditEventType.TAILNET_LOCK_LOCKED_OUT.value
            )
            severity = (
                AuditSeverity.CRITICAL.value
                if settings.TAILNET_LOCK_LOCKED_OUT_SEVERITY == "critical"
                else AuditSeverity.HIGH.value
            )
            action_title = (
                f"Endpoint '{device.hostname}' quarantined by Tailnet Lock"
                if is_quar
                else f"Endpoint '{device.hostname}' locked out by Tailnet Lock"
            )
            err_msg = lock_err or "Node is locked out and cannot establish tailnet mesh connections"
            alerts.append(
                {
                    "event_type": event_type,
                    "event_category": EventCategory.SECURITY.value,
                    "severity": severity,
                    "title": action_title,
                    "message": (
                        f"Device '{device.hostname}' ({device.stable_id}) is quarantined/locked out "
                        f"under Tailnet Lock. Error: {err_msg}"
                    ),
                    "details": {
                        "device_id": device.id,
                        "hostname": device.hostname,
                        "tailnet_lock_key": lock_key,
                        "tailnet_lock_error": lock_err,
                        "lock_status": status_str,
                        "is_quarantined": is_quar,
                        "is_locked_out": is_locked,
                        "evaluated_at": eval_now_iso,
                    },
                }
            )

        # Check for Unsigned node events (if not already logged as quarantined)
        elif is_unsign:
            severity = (
                AuditSeverity.HIGH.value
                if settings.TAILNET_LOCK_UNSIGNED_SEVERITY == "high"
                else AuditSeverity.WARNING.value
            )
            alerts.append(
                {
                    "event_type": AuditEventType.TAILNET_LOCK_UNSIGNED.value,
                    "event_category": EventCategory.SECURITY.value,
                    "severity": severity,
                    "title": f"Endpoint '{device.hostname}' is unsigned under Tailnet Lock",
                    "message": (
                        f"Device '{device.hostname}' ({device.stable_id}) requires cryptographic "
                        f"signing by a trusted signing node before it can participate in the tailnet."
                    ),
                    "details": {
                        "device_id": device.id,
                        "hostname": device.hostname,
                        "tailnet_lock_key": lock_key,
                        "node_key": device.node_key,
                        "lock_status": status_str,
                        "evaluated_at": eval_now_iso,
                    },
                }
            )

        # Check for Tailnet Lock Key Rotation / Modification
        if existing_node is not None and settings.TAILNET_LOCK_ALERT_ON_KEY_ROTATION:
            prev_meta = existing_node.telemetry_metadata or {}
            prev_lock = prev_meta.get("tailnet_lock", {})
            prev_key = prev_lock.get("tailnet_lock_key", prev_meta.get("tailnet_lock_key"))
            if prev_key and lock_key and prev_key != lock_key:
                alerts.append(
                    {
                        "event_type": AuditEventType.TAILNET_LOCK_KEY_CHANGED.value,
                        "event_category": EventCategory.SECURITY.value,
                        "severity": AuditSeverity.WARNING.value,
                        "title": f"Tailnet Lock key rotated for device '{device.hostname}'",
                        "message": (
                            f"Tailnet Lock public key changed for '{device.hostname}'. "
                            f"Previous key: {prev_key[:12]}..., New key: {lock_key[:12]}..."
                        ),
                        "details": {
                            "device_id": device.id,
                            "hostname": device.hostname,
                            "previous_key": prev_key,
                            "new_key": lock_key,
                            "evaluated_at": eval_now_iso,
                        },
                    }
                )

    # Determine Compliance
    if not lock_enabled:
        is_compliant = True
        compliance_status = ComplianceStatus.COMPLIANT.value
    elif is_exempt:
        is_compliant = True
        compliance_status = ComplianceStatus.EXEMPT.value
    elif is_quar or is_locked:
        is_compliant = False
        compliance_status = ComplianceStatus.NON_COMPLIANT.value
    elif is_unsign:
        is_compliant = False
        compliance_status = ComplianceStatus.NON_COMPLIANT.value
    else:
        is_compliant = True
        compliance_status = ComplianceStatus.COMPLIANT.value

    return {
        "lock_status": status_str,
        "is_compliant": is_compliant,
        "compliance_status": compliance_status,
        "tailnet_lock_key": lock_key,
        "tailnet_lock_error": lock_err,
        "is_locked_out": is_locked,
        "is_quarantined": is_quar,
        "is_unsigned": is_unsign,
        "is_signing_node": is_signing,
        "is_exempt": is_exempt,
        "has_valid_key": bool(lock_key),
        "alerts": alerts,
        "evaluated_at": eval_now_iso,
    }


async def get_fleet_tailnet_lock_overview(
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Dict[str, Any]:
    """Generates an aggregated Tailnet Lock overview across all fleet endpoints.

    Calculates:
    - Total nodes audited.
    - Count of signed, unsigned, locked-out, quarantined, and signing nodes.
    - Lists of non-compliant endpoints needing administrative signing or unlock.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet domain filter.

    Returns:
        Structured fleet Tailnet Lock status dictionary.
    """
    stmt = select(Node)
    if tailnet:
        stmt = stmt.where(Node.tailnet == tailnet)

    result = await session.execute(stmt)
    nodes = list(result.scalars().all())

    total_endpoints = len(nodes)
    signed_count = 0
    unsigned_count = 0
    locked_out_count = 0
    quarantined_count = 0
    signing_nodes_count = 0
    exempt_count = 0

    locked_out_endpoints: List[Dict[str, Any]] = []
    unsigned_endpoints: List[Dict[str, Any]] = []
    quarantined_endpoints: List[Dict[str, Any]] = []
    signing_nodes: List[Dict[str, Any]] = []

    for node in nodes:
        meta = node.telemetry_metadata or {}
        lock_info = meta.get("tailnet_lock", {})
        status = lock_info.get("lock_status", node.tailnet_lock_status)

        endpoint_summary = {
            "id": node.id,
            "node_id": node.node_id,
            "hostname": node.hostname,
            "name": node.name,
            "user": node.user,
            "os": node.os,
            "is_online": node.is_online,
            "tailnet_lock_key": lock_info.get("tailnet_lock_key", node.tailnet_lock_key),
            "tailnet_lock_error": lock_info.get("tailnet_lock_error", node.tailnet_lock_error),
            "lock_status": status,
            "is_locked_out": lock_info.get("is_locked_out", node.is_locked_out),
            "is_quarantined": lock_info.get("is_quarantined", node.is_quarantined),
            "is_unsigned": lock_info.get("is_unsigned", False),
            "is_signing_node": lock_info.get("is_signing_node", node.is_signing_node),
            "is_exempt": lock_info.get("is_exempt", False),
        }

        if endpoint_summary["is_signing_node"] or status == TailnetLockStatus.SIGNING_NODE.value:
            signing_nodes_count += 1
            signing_nodes.append(endpoint_summary)

        if endpoint_summary["is_exempt"] or status == TailnetLockStatus.EXEMPT.value:
            exempt_count += 1
        elif endpoint_summary["is_quarantined"] or status == TailnetLockStatus.QUARANTINED.value:
            quarantined_count += 1
            quarantined_endpoints.append(endpoint_summary)
            if endpoint_summary["is_locked_out"]:
                locked_out_count += 1
                locked_out_endpoints.append(endpoint_summary)
        elif endpoint_summary["is_locked_out"] or status == TailnetLockStatus.LOCKED_OUT.value:
            locked_out_count += 1
            locked_out_endpoints.append(endpoint_summary)
        elif endpoint_summary["is_unsigned"] or status == TailnetLockStatus.UNSIGNED.value:
            unsigned_count += 1
            unsigned_endpoints.append(endpoint_summary)
        elif status == TailnetLockStatus.SIGNED.value or endpoint_summary["tailnet_lock_key"]:
            signed_count += 1
        else:
            # Fallback based on node authorization
            if node.authorized:
                signed_count += 1
            else:
                unsigned_count += 1
                unsigned_endpoints.append(endpoint_summary)

    return {
        "tailnet": tailnet,
        "tailnet_lock_enabled": settings.TAILNET_LOCK_ENABLED,
        "total_endpoints": total_endpoints,
        "signed_count": signed_count,
        "unsigned_count": unsigned_count,
        "locked_out_count": locked_out_count,
        "quarantined_count": quarantined_count,
        "signing_nodes_count": signing_nodes_count,
        "exempt_count": exempt_count,
        "locked_out_endpoints": locked_out_endpoints,
        "unsigned_endpoints": unsigned_endpoints,
        "quarantined_endpoints": quarantined_endpoints,
        "signing_nodes": signing_nodes,
        "audited_at": datetime.now(timezone.utc).isoformat(),
    }


async def get_fleet_locked_out_nodes(
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieves all locked-out and quarantined nodes in the tailnet fleet."""
    overview = await get_fleet_tailnet_lock_overview(session=session, tailnet=tailnet)
    combined = list(overview["quarantined_endpoints"])
    seen_ids = {e["id"] for e in combined}
    for item in overview["locked_out_endpoints"]:
        if item["id"] not in seen_ids:
            combined.append(item)
            seen_ids.add(item["id"])

    return {
        "tailnet": tailnet,
        "locked_out_count": len(combined),
        "endpoints": combined,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }


async def get_fleet_unsigned_nodes(
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieves all unsigned nodes awaiting Tailnet Lock signatures."""
    overview = await get_fleet_tailnet_lock_overview(session=session, tailnet=tailnet)
    return {
        "tailnet": tailnet,
        "unsigned_count": overview["unsigned_count"],
        "endpoints": overview["unsigned_endpoints"],
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }


async def get_fleet_signing_nodes(
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieves all trusted signing nodes possessing Tailnet Lock authority."""
    overview = await get_fleet_tailnet_lock_overview(session=session, tailnet=tailnet)
    return {
        "tailnet": tailnet,
        "signing_nodes_count": overview["signing_nodes_count"],
        "signing_nodes": overview["signing_nodes"],
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }


async def get_node_tailnet_lock_audit(
    session: AsyncSession,
    node_id: str,
) -> Dict[str, Any]:
    """Retrieves comprehensive Tailnet Lock status and historical audit for a specific node.

    Args:
        session: Active SQLAlchemy AsyncSession.
        node_id: Device ID or stable node ID.

    Returns:
        Dictionary containing current lock status, keys, errors, and recent lock audit logs.
    """
    stmt = select(Node).where((Node.id == node_id) | (Node.node_id == node_id))
    result = await session.execute(stmt)
    node = result.scalar_one_or_none()

    if node is None:
        return {"error": "node_not_found", "node_id": node_id}

    meta = node.telemetry_metadata or {}
    lock_info = meta.get("tailnet_lock", {})

    # Fetch recent audit logs for this node regarding Tailnet Lock
    lock_event_types = [
        AuditEventType.TAILNET_LOCK_LOCKED_OUT.value,
        AuditEventType.TAILNET_LOCK_UNSIGNED.value,
        AuditEventType.TAILNET_LOCK_QUARANTINED.value,
        AuditEventType.TAILNET_LOCK_KEY_CHANGED.value,
        AuditEventType.TAILNET_LOCK_SIGNATURE_VERIFIED.value,
        AuditEventType.TAILNET_LOCK_DISABLED.value,
    ]
    log_stmt = (
        select(AuditLog)
        .where(AuditLog.node_id == node.id)
        .where(AuditLog.event_type.in_(lock_event_types))
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
        "user": node.user,
        "tailnet": node.tailnet,
        "os": node.os,
        "is_online": node.is_online,
        "lock_status": lock_info.get("lock_status", node.tailnet_lock_status),
        "tailnet_lock_key": lock_info.get("tailnet_lock_key", node.tailnet_lock_key),
        "tailnet_lock_error": lock_info.get("tailnet_lock_error", node.tailnet_lock_error),
        "is_locked_out": lock_info.get("is_locked_out", node.is_locked_out),
        "is_quarantined": lock_info.get("is_quarantined", node.is_quarantined),
        "is_unsigned": lock_info.get("is_unsigned", False),
        "is_signing_node": lock_info.get("is_signing_node", node.is_signing_node),
        "is_exempt": lock_info.get("is_exempt", False),
        "has_valid_key": bool(lock_info.get("tailnet_lock_key", node.tailnet_lock_key)),
        "is_compliant": lock_info.get("is_compliant", not node.is_locked_out),
        "compliance_status": lock_info.get(
            "compliance_status",
            ComplianceStatus.NON_COMPLIANT.value if node.is_locked_out else ComplianceStatus.COMPLIANT.value,
        ),
        "audit_events": audit_history,
        "audited_at": datetime.now(timezone.utc).isoformat(),
    }
