from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.enums import (
    AuditSeverity,
    AuditEventType,
    ComplianceStatus,
    EventCategory,
)
from app.models.node import Node
from app.models.node_state import NodeState
from app.schemas.tailscale import TailscaleDevice

# Re-export version drift, key expiry, and posture monitor utilities for backward compatibility
from app.services.version_monitor import (
    calculate_key_expiry_countdown,
    evaluate_node_security_posture,
    evaluate_version_drift,
    format_countdown_human,
    get_fleet_key_expiry_overview,
    get_fleet_version_drift_overview,
    get_node_security_posture,
    parse_node_ts_version,
    parse_semver_tuple,
)

logger = logging.getLogger(__name__)

# Posture attribute keys standardized in Tailscale device posture
POSTURE_AUTO_UPDATE_ATTR: str = "node:tsAutoUpdate"
POSTURE_STATE_ENCRYPTED_ATTR: str = "node:tsStateEncrypted"

# Default tags that grant exemption from device posture requirements
DEFAULT_EXEMPT_POSTURE_TAGS: Set[str] = {
    "tag:posture-exempt",
    "tag:exempt-posture",
    "tag:compliance-exempt",
    "tag:dev-exempt",
}


def parse_posture_boolean(val: Any) -> Optional[bool]:
    """Parses various boolean representations into bool or None.

    Supports:
    - Booleans: True, False
    - Numbers: 1, 0
    - Strings: 'true', 'false', 'yes', 'no', '1', '0', 'enabled', 'disabled', 'on', 'off'
    - None / whitespace / unparseable -> None

    Examples:
        - parse_posture_boolean(True) -> True
        - parse_posture_boolean("true") -> True
        - parse_posture_boolean("False") -> False
        - parse_posture_boolean("enabled") -> True
        - parse_posture_boolean(None) -> None
    """
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        cleaned = val.strip().lower()
        if cleaned in ("true", "1", "yes", "y", "enabled", "on"):
            return True
        if cleaned in ("false", "0", "no", "n", "disabled", "off"):
            return False
    return None


def parse_node_auto_update(device: TailscaleDevice) -> Optional[bool]:
    """Extracts the 'node:tsAutoUpdate' posture attribute from a TailscaleDevice.

    Checks:
    1. device.get_node_auto_update_attribute() method if present.
    2. device.attributes for matching keys ('node:tsAutoUpdate', 'tsAutoUpdate', 'auto_update', etc.).
    3. device.tags for 'node:tsautoupdate:<val>', 'tag:auto-update', 'tag:no-auto-update'.

    Args:
        device: The TailscaleDevice payload.

    Returns:
        Boolean indicating if automatic updates are enabled, or None if unknown.
    """
    if hasattr(device, "get_node_auto_update_attribute"):
        val = device.get_node_auto_update_attribute()
        if val is not None:
            return val

    if device.attributes:
        for k, v in device.attributes.items():
            k_norm = k.lower().replace(":", "_").replace("-", "_")
            if k_norm in (
                "node_tsautoupdate",
                "node_ts_auto_update",
                "tsautoupdate",
                "ts_auto_update",
                "autoupdate",
                "auto_update",
            ) and v is not None:
                parsed = parse_posture_boolean(v)
                if parsed is not None:
                    return parsed

    for tag in device.tags:
        tag_lower = tag.lower().strip()
        if tag_lower.startswith("node:tsautoupdate:") or tag_lower.startswith("node:ts_auto_update:"):
            val_str = tag_lower.split(":", 2)[-1].strip()
            parsed = parse_posture_boolean(val_str)
            if parsed is not None:
                return parsed
        elif tag_lower in ("tag:auto-update", "tag:autoupdate", "tag:auto-update-enabled"):
            return True
        elif tag_lower in ("tag:no-auto-update", "tag:auto-update-disabled"):
            return False

    return None


def parse_node_state_encrypted(device: TailscaleDevice) -> Optional[bool]:
    """Extracts the 'node:tsStateEncrypted' posture attribute from a TailscaleDevice.

    Checks:
    1. device.get_node_state_encrypted_attribute() method if present.
    2. device.attributes for matching keys ('node:tsStateEncrypted', 'tsStateEncrypted', 'state_encrypted', etc.).
    3. device.tags for 'node:tsstateencrypted:<val>', 'tag:state-encrypted', 'tag:unencrypted-state'.

    Args:
        device: The TailscaleDevice payload.

    Returns:
        Boolean indicating if local state storage is encrypted, or None if unknown.
    """
    if hasattr(device, "get_node_state_encrypted_attribute"):
        val = device.get_node_state_encrypted_attribute()
        if val is not None:
            return val

    if device.attributes:
        for k, v in device.attributes.items():
            k_norm = k.lower().replace(":", "_").replace("-", "_")
            if k_norm in (
                "node_tsstateencrypted",
                "node_ts_state_encrypted",
                "tsstateencrypted",
                "ts_state_encrypted",
                "stateencrypted",
                "state_encrypted",
                "disk_encrypted",
                "disk_encryption",
            ) and v is not None:
                parsed = parse_posture_boolean(v)
                if parsed is not None:
                    return parsed

    for tag in device.tags:
        tag_lower = tag.lower().strip()
        if tag_lower.startswith("node:tsstateencrypted:") or tag_lower.startswith("node:ts_state_encrypted:"):
            val_str = tag_lower.split(":", 2)[-1].strip()
            parsed = parse_posture_boolean(val_str)
            if parsed is not None:
                return parsed
        elif tag_lower in ("tag:state-encrypted", "tag:disk-encrypted", "tag:encrypted-state"):
            return True
        elif tag_lower in ("tag:unencrypted-state", "tag:state-unencrypted", "tag:no-state-encryption"):
            return False

    return None


def is_device_posture_exempt(
    device: TailscaleDevice,
    exempt_tags: Optional[List[str]] = None,
) -> Tuple[bool, Optional[str]]:
    """Determines whether a device is explicitly exempt from posture compliance policies.

    Exemption criteria:
    1. Assigned an exemption tag (e.g., 'tag:posture-exempt', 'tag:compliance-exempt').
    2. Explicit attribute 'posture_exempt' or 'compliance_exempt' set to True.

    Args:
        device: TailscaleDevice payload.
        exempt_tags: List of tags granting exemption (defaults to settings.POSTURE_EXEMPT_TAGS).

    Returns:
        Tuple of (is_exempt: bool, reason: Optional[str]).
    """
    target_tags = {
        t.strip().lower()
        for t in (exempt_tags or getattr(settings, "POSTURE_EXEMPT_TAGS", None) or list(DEFAULT_EXEMPT_POSTURE_TAGS))
    }
    dev_tags = {t.strip().lower() for t in (device.tags or [])}

    matching = target_tags.intersection(dev_tags)
    if matching:
        tag_match = sorted(list(matching))[0]
        return True, f"Device has posture exemption tag '{tag_match}'"

    if device.attributes:
        for k, v in device.attributes.items():
            k_norm = k.lower().replace(":", "_").replace("-", "_")
            if k_norm in ("posture_exempt", "compliance_exempt", "is_exempt") and parse_posture_boolean(v):
                return True, f"Device has explicit exemption attribute '{k}'"

    return False, None


def audit_node_device_posture(
    device: TailscaleDevice,
    existing_node: Optional[Node] = None,
    require_auto_update: Optional[bool] = None,
    require_state_encrypted: Optional[bool] = None,
    exempt_tags: Optional[List[str]] = None,
    strict_mode: Optional[bool] = None,
    auto_update_severity: Optional[str] = None,
    state_encrypted_severity: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Audits device posture attributes `node:tsAutoUpdate` and `node:tsStateEncrypted`, flagging non-compliant endpoints.

    Evaluates:
    1. `node:tsAutoUpdate`: Verifies automatic client updates are enabled to prevent vulnerability drift.
    2. `node:tsStateEncrypted`: Verifies endpoint local state and cryptographic keys are encrypted at rest.
    3. Exemption policies: Detects exempt tags or attributes.
    4. State transitions: Detects changes in posture status against the database to trigger alerts.

    Args:
        device: Newly polled TailscaleDevice instance.
        existing_node: Optional existing Node ORM record for diffing.
        require_auto_update: Policy requirement for auto-update (defaults to settings.POSTURE_REQUIRE_AUTO_UPDATE).
        require_state_encrypted: Policy requirement for state encryption (defaults to settings.POSTURE_REQUIRE_STATE_ENCRYPTED).
        exempt_tags: Approved exemption tags.
        strict_mode: If True, missing/unknown attributes are treated as non-compliant rather than warning/unknown.
        auto_update_severity: Audit severity for auto-update violations.
        state_encrypted_severity: Audit severity for state encryption violations.
        now: Reference datetime.

    Returns:
        Structured posture evaluation report containing compliance status, violations, alerts, and state diffs.
    """
    eval_now = now or datetime.now(timezone.utc)
    req_auto_update = (
        require_auto_update
        if require_auto_update is not None
        else getattr(settings, "POSTURE_REQUIRE_AUTO_UPDATE", True)
    )
    req_state_encrypted = (
        require_state_encrypted
        if require_state_encrypted is not None
        else getattr(settings, "POSTURE_REQUIRE_STATE_ENCRYPTED", True)
    )
    is_strict = (
        strict_mode
        if strict_mode is not None
        else getattr(settings, "POSTURE_STRICT_MODE", False)
    )
    auto_sev = (
        auto_update_severity
        or getattr(settings, "POSTURE_AUTO_UPDATE_SEVERITY", AuditSeverity.HIGH.value)
    )
    state_sev = (
        state_encrypted_severity
        or getattr(settings, "POSTURE_STATE_ENCRYPTED_SEVERITY", AuditSeverity.CRITICAL.value)
    )

    # 1. Parse Posture Attributes
    ts_auto_update = parse_node_auto_update(device)
    ts_state_encrypted = parse_node_state_encrypted(device)

    # 2. Check Exemption
    is_exempt, exempt_reason = is_device_posture_exempt(device, exempt_tags=exempt_tags)

    violations: List[Dict[str, Any]] = []
    alerts: List[Dict[str, Any]] = []

    # 3. Evaluate Attribute Compliance
    auto_update_status: str
    state_encrypted_status: str

    if is_exempt:
        auto_update_status = ComplianceStatus.EXEMPT.value
        state_encrypted_status = ComplianceStatus.EXEMPT.value
        compliance_status = ComplianceStatus.EXEMPT.value
        is_compliant = True
    else:
        # Check node:tsAutoUpdate
        if ts_auto_update is True:
            auto_update_status = ComplianceStatus.COMPLIANT.value
        elif ts_auto_update is False:
            auto_update_status = ComplianceStatus.NON_COMPLIANT.value
            if req_auto_update:
                violations.append(
                    {
                        "attribute": POSTURE_AUTO_UPDATE_ATTR,
                        "status": ComplianceStatus.NON_COMPLIANT.value,
                        "severity": auto_sev,
                        "title": "Automatic Updates Disabled",
                        "description": (
                            f"Device '{device.hostname}' has automatic updates disabled "
                            f"({POSTURE_AUTO_UPDATE_ATTR}=False). Endpoint will not receive automated security patches."
                        ),
                        "current_value": False,
                        "required_value": True,
                        "remediation": "Run 'tailscale set --auto-update=true' on the endpoint or enforce auto-updates via MDM/policy.",
                    }
                )
        else:
            auto_update_status = ComplianceStatus.UNKNOWN.value
            if req_auto_update and is_strict:
                violations.append(
                    {
                        "attribute": POSTURE_AUTO_UPDATE_ATTR,
                        "status": ComplianceStatus.WARNING.value,
                        "severity": AuditSeverity.WARNING.value,
                        "title": "Automatic Update Status Unknown",
                        "description": (
                            f"Device '{device.hostname}' does not report the {POSTURE_AUTO_UPDATE_ATTR} attribute."
                        ),
                        "current_value": None,
                        "required_value": True,
                        "remediation": "Verify that the Tailscale client version supports reporting posture attributes.",
                    }
                )

        # Check node:tsStateEncrypted
        if ts_state_encrypted is True:
            state_encrypted_status = ComplianceStatus.COMPLIANT.value
        elif ts_state_encrypted is False:
            state_encrypted_status = ComplianceStatus.NON_COMPLIANT.value
            if req_state_encrypted:
                violations.append(
                    {
                        "attribute": POSTURE_STATE_ENCRYPTED_ATTR,
                        "status": ComplianceStatus.NON_COMPLIANT.value,
                        "severity": state_sev,
                        "title": "Unencrypted Tailscale State Storage",
                        "description": (
                            f"Device '{device.hostname}' has unencrypted state storage "
                            f"({POSTURE_STATE_ENCRYPTED_ATTR}=False). Sensitive node keys and state are stored in plaintext on disk."
                        ),
                        "current_value": False,
                        "required_value": True,
                        "remediation": "Enable disk encryption (BitLocker, FileVault, LUKS) or configure secure credential storage on the device.",
                    }
                )
        else:
            state_encrypted_status = ComplianceStatus.UNKNOWN.value
            if req_state_encrypted and is_strict:
                violations.append(
                    {
                        "attribute": POSTURE_STATE_ENCRYPTED_ATTR,
                        "status": ComplianceStatus.WARNING.value,
                        "severity": AuditSeverity.WARNING.value,
                        "title": "State Encryption Status Unknown",
                        "description": (
                            f"Device '{device.hostname}' does not report the {POSTURE_STATE_ENCRYPTED_ATTR} attribute."
                        ),
                        "current_value": None,
                        "required_value": True,
                        "remediation": "Ensure the Tailscale client version is capable of reporting encryption posture.",
                    }
                )

        # Determine Overall Compliance Status
        has_non_compliant = any(v["status"] == ComplianceStatus.NON_COMPLIANT.value for v in violations)
        has_warning = any(v["status"] == ComplianceStatus.WARNING.value for v in violations)

        if has_non_compliant:
            compliance_status = ComplianceStatus.NON_COMPLIANT.value
            is_compliant = False
        elif has_warning:
            compliance_status = ComplianceStatus.WARNING.value
            is_compliant = not is_strict
        else:
            compliance_status = ComplianceStatus.COMPLIANT.value
            is_compliant = True

    # 4. Compare with Existing Node Record for State Transition Alerts
    prev_metadata = (existing_node.telemetry_metadata or {}) if existing_node else {}
    prev_posture = prev_metadata.get("device_posture", {})
    prev_auto_update = prev_metadata.get("ts_auto_update") or prev_posture.get("ts_auto_update")
    prev_state_encrypted = prev_metadata.get("ts_state_encrypted") or prev_posture.get("ts_state_encrypted")
    prev_status = prev_posture.get("compliance_status", ComplianceStatus.COMPLIANT.value)

    state_changes = {
        "auto_update_changed": bool(existing_node and prev_auto_update != ts_auto_update),
        "state_encrypted_changed": bool(existing_node and prev_state_encrypted != ts_state_encrypted),
        "compliance_changed": bool(existing_node and prev_status != compliance_status),
        "previous_compliance_status": prev_status,
        "current_compliance_status": compliance_status,
    }

    # 5. Generate Alerts
    if not is_exempt:
        # Alert: Auto-update disabled
        if ts_auto_update is False and req_auto_update:
            alerts.append(
                {
                    "type": "auto_update_disabled",
                    "severity": auto_sev,
                    "title": f"Automatic updates disabled on '{device.hostname}'",
                    "message": (
                        f"Endpoint '{device.hostname}' has {POSTURE_AUTO_UPDATE_ATTR} disabled, "
                        f"violating fleet device posture policy."
                    ),
                    "event_type": AuditEventType.AUTO_UPDATE_DISABLED.value,
                    "event_category": EventCategory.POSTURE.value,
                    "details": {
                        "hostname": device.hostname,
                        "attribute": POSTURE_AUTO_UPDATE_ATTR,
                        "current_value": False,
                        "required_value": True,
                        "remediation": "Run 'tailscale set --auto-update=true' on the endpoint.",
                    },
                }
            )

        # Alert: State unencrypted
        if ts_state_encrypted is False and req_state_encrypted:
            alerts.append(
                {
                    "type": "state_unencrypted",
                    "severity": state_sev,
                    "title": f"Tailscale state storage unencrypted on '{device.hostname}'",
                    "message": (
                        f"Endpoint '{device.hostname}' has {POSTURE_STATE_ENCRYPTED_ATTR} disabled. "
                        f"Cryptographic node keys and state are stored in plaintext."
                    ),
                    "event_type": AuditEventType.STATE_UNENCRYPTED.value,
                    "event_category": EventCategory.POSTURE.value,
                    "details": {
                        "hostname": device.hostname,
                        "attribute": POSTURE_STATE_ENCRYPTED_ATTR,
                        "current_value": False,
                        "required_value": True,
                        "remediation": "Enable full disk encryption or secure OS credential storage.",
                    },
                }
            )

        # Alert: Previously non-compliant endpoint restored to compliance
        if existing_node and prev_status == ComplianceStatus.NON_COMPLIANT.value and is_compliant:
            alerts.append(
                {
                    "type": "posture_compliant",
                    "severity": AuditSeverity.INFO.value,
                    "title": f"Device posture compliance restored on '{device.hostname}'",
                    "message": (
                        f"Endpoint '{device.hostname}' now satisfies all required posture attributes "
                        f"({POSTURE_AUTO_UPDATE_ATTR}={ts_auto_update}, {POSTURE_STATE_ENCRYPTED_ATTR}={ts_state_encrypted})."
                    ),
                    "event_type": AuditEventType.POSTURE_COMPLIANT.value,
                    "event_category": EventCategory.POSTURE.value,
                    "details": {
                        "hostname": device.hostname,
                        "ts_auto_update": ts_auto_update,
                        "ts_state_encrypted": ts_state_encrypted,
                        "previous_status": prev_status,
                    },
                }
            )

    return {
        "node_id": device.stable_id,
        "hostname": device.hostname,
        "ts_auto_update": ts_auto_update,
        "ts_state_encrypted": ts_state_encrypted,
        "auto_update_status": auto_update_status,
        "state_encrypted_status": state_encrypted_status,
        "is_compliant": is_compliant,
        "compliance_status": compliance_status,
        "is_exempt": is_exempt,
        "exemption_reason": exempt_reason,
        "violations": violations,
        "violations_count": len(violations),
        "alerts": alerts,
        "state_changes": state_changes,
        "posture_attributes": {
            POSTURE_AUTO_UPDATE_ATTR: ts_auto_update,
            POSTURE_STATE_ENCRYPTED_ATTR: ts_state_encrypted,
        },
        "evaluated_at": eval_now.isoformat(),
    }


# ---------------------------------------------------------------------------
# Fleet-wide Aggregation Queries (Async Database Operations)
# ---------------------------------------------------------------------------


async def get_fleet_posture_compliance_overview(
    session: AsyncSession,
    tailnet: Optional[str] = None,
) -> Dict[str, Any]:
    """Aggregates fleet-wide device posture compliance for `node:tsAutoUpdate` and `node:tsStateEncrypted`.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet domain filter.

    Returns:
        Dictionary containing compliance percentage, attribute breakdowns, OS distribution, and flagged non-compliant endpoints.
    """
    stmt = select(Node).order_by(Node.hostname.asc())
    if tailnet:
        stmt = stmt.where(Node.tailnet == tailnet)

    result = await session.execute(stmt)
    nodes = list(result.scalars().all())

    total_devices = len(nodes)
    compliant_count = 0
    non_compliant_count = 0
    warning_count = 0
    exempt_count = 0

    auto_update_enabled = 0
    auto_update_disabled = 0
    auto_update_unknown = 0

    state_encrypted_count = 0
    state_unencrypted_count = 0
    state_encryption_unknown = 0

    os_breakdown: Dict[str, Dict[str, Any]] = {}
    flagged_endpoints: List[Dict[str, Any]] = []

    for node in nodes:
        meta = node.telemetry_metadata or {}
        posture_data = meta.get("device_posture", {})

        # Extract values from device_posture dict or fallback to top-level metadata
        ts_auto = posture_data.get("ts_auto_update", meta.get("ts_auto_update"))
        ts_enc = posture_data.get("ts_state_encrypted", meta.get("ts_state_encrypted"))
        is_comp = posture_data.get("is_compliant")
        comp_status = posture_data.get("compliance_status")
        is_ex = posture_data.get("is_exempt", False)
        violations = posture_data.get("violations", [])

        # Fallback to latest node_state if posture_data is absent
        if is_comp is None and "states" in node.__dict__ and node.states:
            latest_state = node.states[0]
            is_comp = latest_state.is_compliant
            comp_status = latest_state.compliance_status
            state_posture = (latest_state.posture_checks or {}).get("device_posture", {})
            if ts_auto is None:
                ts_auto = state_posture.get("ts_auto_update")
            if ts_enc is None:
                ts_enc = state_posture.get("ts_state_encrypted", latest_state.disk_encryption_enabled)
            if not violations:
                violations = state_posture.get("violations", [])

        # Default to compliant if no violations detected
        if comp_status is None:
            comp_status = ComplianceStatus.COMPLIANT.value
            is_comp = True

        if is_ex or comp_status == ComplianceStatus.EXEMPT.value:
            exempt_count += 1
            compliant_count += 1
        elif comp_status == ComplianceStatus.NON_COMPLIANT.value or is_comp is False:
            non_compliant_count += 1
        elif comp_status == ComplianceStatus.WARNING.value:
            warning_count += 1
        else:
            compliant_count += 1

        # Auto-update tally
        if ts_auto is True:
            auto_update_enabled += 1
        elif ts_auto is False:
            auto_update_disabled += 1
        else:
            auto_update_unknown += 1

        # State encrypted tally
        if ts_enc is True:
            state_encrypted_count += 1
        elif ts_enc is False:
            state_unencrypted_count += 1
        else:
            state_encryption_unknown += 1

        # OS Breakdown
        os_fam = (node.os or "unknown").lower()
        if os_fam not in os_breakdown:
            os_breakdown[os_fam] = {
                "total": 0,
                "compliant": 0,
                "non_compliant": 0,
                "auto_update_enabled": 0,
                "state_encrypted": 0,
            }
        os_breakdown[os_fam]["total"] += 1
        if comp_status == ComplianceStatus.COMPLIANT.value or is_ex:
            os_breakdown[os_fam]["compliant"] += 1
        elif comp_status == ComplianceStatus.NON_COMPLIANT.value or is_comp is False:
            os_breakdown[os_fam]["non_compliant"] += 1
        if ts_auto is True:
            os_breakdown[os_fam]["auto_update_enabled"] += 1
        if ts_enc is True:
            os_breakdown[os_fam]["state_encrypted"] += 1

        # Flagged Endpoints List
        if comp_status == ComplianceStatus.NON_COMPLIANT.value or is_comp is False or violations:
            flagged_endpoints.append(
                {
                    "id": node.id,
                    "node_id": node.node_id,
                    "hostname": node.hostname,
                    "user": node.user,
                    "os": node.os,
                    "os_version": node.os_version,
                    "client_version": node.client_version,
                    "is_online": node.is_online,
                    "compliance_status": comp_status,
                    "is_compliant": is_comp,
                    "is_exempt": is_ex,
                    "ts_auto_update": ts_auto,
                    "ts_state_encrypted": ts_enc,
                    "violations": violations,
                    "violations_count": len(violations),
                }
            )

    compliance_rate = (
        round((compliant_count / total_devices) * 100.0, 2)
        if total_devices > 0
        else 100.0
    )
    auto_update_rate = (
        round((auto_update_enabled / total_devices) * 100.0, 2)
        if total_devices > 0
        else 100.0
    )
    state_encrypted_rate = (
        round((state_encrypted_count / total_devices) * 100.0, 2)
        if total_devices > 0
        else 100.0
    )

    return {
        "total_endpoints": total_devices,
        "compliant_endpoints": compliant_count,
        "non_compliant_endpoints": non_compliant_count,
        "warning_endpoints": warning_count,
        "exempt_endpoints": exempt_count,
        "compliance_rate_percent": compliance_rate,
        "auto_update_summary": {
            "attribute": POSTURE_AUTO_UPDATE_ATTR,
            "enabled_count": auto_update_enabled,
            "disabled_count": auto_update_disabled,
            "unknown_count": auto_update_unknown,
            "compliance_percent": auto_update_rate,
        },
        "state_encrypted_summary": {
            "attribute": POSTURE_STATE_ENCRYPTED_ATTR,
            "encrypted_count": state_encrypted_count,
            "unencrypted_count": state_unencrypted_count,
            "unknown_count": state_encryption_unknown,
            "compliance_percent": state_encrypted_rate,
        },
        "os_breakdown": os_breakdown,
        "flagged_endpoints_count": len(flagged_endpoints),
        "flagged_endpoints": flagged_endpoints,
        "audited_at": datetime.now(timezone.utc).isoformat(),
    }


async def get_fleet_non_compliant_endpoints(
    session: AsyncSession,
    tailnet: Optional[str] = None,
    violation_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieves only the non-compliant endpoints with specific failure reasons and remediation steps.

    Args:
        session: Active SQLAlchemy AsyncSession.
        tailnet: Optional tailnet domain filter.
        violation_filter: Optional filter ('auto_update', 'state_encrypted', 'all').

    Returns:
        Dictionary containing list of non-compliant devices and action items.
    """
    overview = await get_fleet_posture_compliance_overview(session=session, tailnet=tailnet)
    all_flagged = overview["flagged_endpoints"]

    filtered: List[Dict[str, Any]] = []
    v_filt = (violation_filter or "all").lower().strip()

    for item in all_flagged:
        ts_auto = item.get("ts_auto_update")
        ts_enc = item.get("ts_state_encrypted")

        if v_filt in ("auto_update", "autoupdate", "auto-update"):
            if ts_auto is False:
                filtered.append(item)
        elif v_filt in ("state_encrypted", "stateencrypted", "state-encrypted", "disk_encryption"):
            if ts_enc is False:
                filtered.append(item)
        else:
            filtered.append(item)

    return {
        "total_non_compliant": len(filtered),
        "violation_filter": v_filt,
        "endpoints": filtered,
        "audited_at": datetime.now(timezone.utc).isoformat(),
    }


async def get_node_posture_compliance_audit(
    session: AsyncSession,
    node_id: str,
) -> Dict[str, Any]:
    """Returns a deep posture and compliance audit for a specific node, including historical checks.

    Args:
        session: Active SQLAlchemy AsyncSession.
        node_id: Target node primary ID or stable nodeId.

    Returns:
        Detailed posture audit dictionary, or an error dict if not found.
    """
    stmt = select(Node).where((Node.id == node_id) | (Node.node_id == node_id))
    result = await session.execute(stmt)
    node = result.scalar_one_or_none()

    if node is None:
        return {"error": "node_not_found", "node_id": node_id}

    meta = node.telemetry_metadata or {}
    posture_data = meta.get("device_posture", {})

    ts_auto = posture_data.get("ts_auto_update", meta.get("ts_auto_update"))
    ts_enc = posture_data.get("ts_state_encrypted", meta.get("ts_state_encrypted"))
    is_comp = posture_data.get("is_compliant", True)
    comp_status = posture_data.get("compliance_status", ComplianceStatus.COMPLIANT.value)
    is_ex = posture_data.get("is_exempt", False)
    violations = posture_data.get("violations", [])

    # Fetch recent node states for historical compliance snapshots
    state_stmt = (
        select(NodeState)
        .where(NodeState.node_id == node.id)
        .order_by(NodeState.recorded_at.desc())
        .limit(10)
    )
    state_res = await session.execute(state_stmt)
    states = list(state_res.scalars().all())

    history: List[Dict[str, Any]] = []
    for s in states:
        s_checks = s.posture_checks or {}
        s_posture = s_checks.get("device_posture", {})
        history.append(
            {
                "state_id": s.id,
                "recorded_at": s.recorded_at.isoformat() if s.recorded_at else None,
                "is_compliant": s.is_compliant,
                "compliance_status": s.compliance_status,
                "disk_encryption_enabled": s.disk_encryption_enabled,
                "ts_auto_update": s_checks.get("ts_auto_update", s_posture.get("ts_auto_update")),
                "ts_state_encrypted": s_checks.get("ts_state_encrypted", s_posture.get("ts_state_encrypted")),
            }
        )

    return {
        "node_id": node.node_id or node.id,
        "id": node.id,
        "hostname": node.hostname,
        "name": node.name,
        "user": node.user,
        "os": node.os,
        "os_version": node.os_version,
        "client_version": node.client_version,
        "is_online": node.is_online,
        "is_compliant": is_comp,
        "compliance_status": comp_status,
        "is_exempt": is_ex,
        "exemption_reason": posture_data.get("exemption_reason"),
        "ts_auto_update": ts_auto,
        "ts_state_encrypted": ts_enc,
        "violations": violations,
        "violations_count": len(violations),
        "posture_attributes": {
            POSTURE_AUTO_UPDATE_ATTR: ts_auto,
            POSTURE_STATE_ENCRYPTED_ATTR: ts_enc,
        },
        "history": history,
        "history_count": len(history),
        "audited_at": datetime.now(timezone.utc).isoformat(),
    }


__all__ = [
    "POSTURE_AUTO_UPDATE_ATTR",
    "POSTURE_STATE_ENCRYPTED_ATTR",
    "DEFAULT_EXEMPT_POSTURE_TAGS",
    "parse_posture_boolean",
    "parse_node_auto_update",
    "parse_node_state_encrypted",
    "is_device_posture_exempt",
    "audit_node_device_posture",
    "get_fleet_posture_compliance_overview",
    "get_fleet_non_compliant_endpoints",
    "get_node_posture_compliance_audit",
    # Re-exported from version_monitor
    "parse_semver_tuple",
    "parse_node_ts_version",
    "evaluate_version_drift",
    "format_countdown_human",
    "calculate_key_expiry_countdown",
    "evaluate_node_security_posture",
    "get_fleet_version_drift_overview",
    "get_fleet_key_expiry_overview",
    "get_node_security_posture",
]

