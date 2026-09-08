from enum import Enum


class ComplianceStatus(str, Enum):
    """Compliance status for device posture evaluations."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    WARNING = "warning"
    UNKNOWN = "unknown"
    EXEMPT = "exempt"


class AuditSeverity(str, Enum):
    """Severity levels for audit and network events."""
    INFO = "info"
    LOW = "low"
    WARNING = "warning"
    HIGH = "high"
    ERROR = "error"
    CRITICAL = "critical"


class EventCategory(str, Enum):
    """High-level category for audit log entries."""
    DEVICE = "device"
    POSTURE = "posture"
    SECURITY = "security"
    NETWORK = "network"
    ACL = "acl"
    SYSTEM = "system"


class AuditEventType(str, Enum):
    """Detailed event types for Tailscale telemetry, posture, and network events."""
    # Device lifecycle
    NODE_CREATED = "node.created"
    NODE_UPDATED = "node.updated"
    NODE_DELETED = "node.deleted"
    NODE_ONLINE = "node.online"
    NODE_OFFLINE = "node.offline"
    NODE_EXPIRED = "node.expired"
    NODE_OS_CHANGED = "node.os_changed"
    NODE_CLIENT_UPDATED = "node.client_updated"

    # Posture events
    POSTURE_COMPLIANT = "posture.compliant"
    POSTURE_NON_COMPLIANT = "posture.non_compliant"
    POSTURE_VIOLATION = "posture.violation"
    AUTO_UPDATE_DISABLED = "posture.auto_update_disabled"
    STATE_UNENCRYPTED = "posture.state_unencrypted"

    # Security & Key events
    SECURITY_ALERT = "security.alert"
    KEY_EXPIRY_WARNING = "security.key_expiry_warning"
    KEY_ROTATED = "security.key_rotated"
    VERSION_DRIFT_WARNING = "security.version_drift_warning"
    IMPOSSIBLE_TRAVEL = "security.impossible_travel"
    GEOLOCATION_ANOMALY = "security.geolocation_anomaly"
    TAILNET_LOCK_LOCKED_OUT = "security.tailnet_lock_locked_out"
    TAILNET_LOCK_UNSIGNED = "security.tailnet_lock_unsigned"
    TAILNET_LOCK_QUARANTINED = "security.tailnet_lock_quarantined"
    TAILNET_LOCK_KEY_CHANGED = "security.tailnet_lock_key_changed"
    TAILNET_LOCK_SIGNATURE_VERIFIED = "security.tailnet_lock_signature_verified"
    TAILNET_LOCK_DISABLED = "security.tailnet_lock_disabled"
    SSL_CERT_VALID = "security.ssl_cert_valid"
    SSL_CERT_EXPIRING = "security.ssl_cert_expiring"
    SSL_CERT_EXPIRED = "security.ssl_cert_expired"
    SSL_CERT_ERROR = "security.ssl_cert_error"
    SSL_CERT_UNREACHABLE = "security.ssl_cert_unreachable"

    # Network events
    LATENCY_SPIKE = "network.latency_spike"
    DERP_CHANGE = "network.derp_change"
    DERP_FALLBACK = "network.derp_fallback"
    ENDPOINT_CHANGE = "network.endpoint_change"
    PACKET_LOSS_ALERT = "network.packet_loss_alert"
    UNAUTHORIZED_EXIT_NODE = "network.unauthorized_exit_node"
    EXIT_NODE_ADVERTISED = "network.exit_node_advertised"
    ROUTE_CHANGE = "network.route_change"
    LOCATION_CHANGED = "network.location_changed"

    # ACL & Configuration events (Step 14)
    POLICY_UPDATE = "policy.update"
    ACL_UPDATED = "acl.updated"
    CONFIG_CHANGED = "tailnet.config_changed"
    WEBHOOK_TEST = "webhook.test"

    # Node Approval & Lifecycle
    NODE_NEEDS_APPROVAL = "node.needs_approval"
    NODE_APPROVED = "node.approved"

    # User Lifecycle events
    USER_CREATED = "user.created"
    USER_NEEDS_APPROVAL = "user.needs_approval"
    USER_APPROVED = "user.approved"
    USER_SUSPENDED = "user.suspended"
    USER_RESTORED = "user.restored"
    USER_DELETED = "user.deleted"
    USER_ROLE_UPDATED = "user.role_updated"

    # System & Sync
    SYNC_COMPLETED = "sync.completed"
    SYNC_FAILED = "sync.failed"
    CUSTOM = "custom"


class TailnetLockStatus(str, Enum):
    """Tailnet Lock posture status classification for fleet endpoints."""
    SIGNED = "signed"
    UNSIGNED = "unsigned"
    LOCKED_OUT = "locked_out"
    QUARANTINED = "quarantined"
    SIGNING_NODE = "signing_node"
    NOT_APPLICABLE = "not_applicable"
    EXEMPT = "exempt"
    UNKNOWN = "unknown"


class SSLCertificateStatus(str, Enum):
    """Status classification for MagicDNS TLS/SSL certificates."""
    VALID = "valid"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    UNREACHABLE = "unreachable"
    ERROR = "error"
    NOT_CONFIGURED = "not_configured"


