/**
 * Strict TypeScript Enum types and literals mirroring backend models and telemetry constants.
 */

export type ComplianceStatus =
  | 'compliant'
  | 'non_compliant'
  | 'warning'
  | 'unknown'
  | 'exempt';

export type AuditSeverity =
  | 'info'
  | 'low'
  | 'warning'
  | 'high'
  | 'error'
  | 'critical';

export type EventCategory =
  | 'device'
  | 'posture'
  | 'security'
  | 'network'
  | 'acl'
  | 'system';

export type AuditEventType =
  // Device lifecycle
  | 'node.created'
  | 'node.updated'
  | 'node.deleted'
  | 'node.online'
  | 'node.offline'
  | 'node.expired'
  | 'node.os_changed'
  | 'node.client_updated'
  // Posture events
  | 'posture.compliant'
  | 'posture.non_compliant'
  | 'posture.violation'
  | 'posture.auto_update_disabled'
  | 'posture.state_unencrypted'
  // Security & Key events
  | 'security.alert'
  | 'security.key_expiry_warning'
  | 'security.key_rotated'
  | 'security.version_drift_warning'
  | 'security.impossible_travel'
  | 'security.geolocation_anomaly'
  | 'security.tailnet_lock_locked_out'
  | 'security.tailnet_lock_unsigned'
  | 'security.tailnet_lock_quarantined'
  | 'security.tailnet_lock_key_changed'
  | 'security.tailnet_lock_signature_verified'
  | 'security.tailnet_lock_disabled'
  | 'security.ssl_cert_valid'
  | 'security.ssl_cert_expiring'
  | 'security.ssl_cert_expired'
  | 'security.ssl_cert_error'
  | 'security.ssl_cert_unreachable'
  // Network events
  | 'network.latency_spike'
  | 'network.derp_change'
  | 'network.derp_fallback'
  | 'network.endpoint_change'
  | 'network.packet_loss_alert'
  | 'network.unauthorized_exit_node'
  | 'network.exit_node_advertised'
  | 'network.route_change'
  | 'network.location_changed'
  // ACL & Configuration events
  | 'policy.update'
  | 'acl.updated'
  | 'tailnet.config_changed'
  | 'webhook.test'
  // Node Approval & Lifecycle
  | 'node.needs_approval'
  | 'node.approved'
  // User Lifecycle events
  | 'user.created'
  | 'user.needs_approval'
  | 'user.approved'
  | 'user.suspended'
  | 'user.restored'
  | 'user.deleted'
  | 'user.role_updated'
  // System & Sync
  | 'sync.completed'
  | 'sync.failed'
  | 'custom';

export type TailnetLockStatus =
  | 'signed'
  | 'unsigned'
  | 'locked_out'
  | 'quarantined'
  | 'signing_node'
  | 'not_applicable'
  | 'exempt'
  | 'unknown';

export type SSLCertificateStatus =
  | 'valid'
  | 'expiring_soon'
  | 'expired'
  | 'unreachable'
  | 'error'
  | 'not_configured';

export type HealthRating = 'healthy' | 'warning' | 'critical';

export type DeviceCategory =
  | 'server'
  | 'workstation'
  | 'mobile'
  | 'embedded'
  | 'unknown';

export type OsFamily =
  | 'linux'
  | 'macos'
  | 'windows'
  | 'ios'
  | 'android'
  | 'bsd'
  | 'other';

export type KeyExpiryStatus =
  | 'healthy'
  | 'warning'
  | 'critical'
  | 'expiring_soon'
  | 'expired'
  | 'disabled'
  | 'unknown';

export type VersionDriftType =
  | 'none'
  | 'patch'
  | 'minor'
  | 'major'
  | 'ahead'
  | 'unknown';
