import type {
  AuditEventType,
  AuditSeverity,
  ComplianceStatus,
  KeyExpiryStatus,
  SSLCertificateStatus,
  TailnetLockStatus,
  VersionDriftType,
} from './enums';

// ---------------------------------------------------------------------------
// Scheduler & Sync
// ---------------------------------------------------------------------------

export interface SchedulerJobDetail {
  id: string;
  name: string;
  next_run_time: string | null;
  trigger: string;
}

export interface SchedulerStatusResponse {
  scheduler_running: boolean;
  job_count: number;
  jobs: SchedulerJobDetail[];
  poll_interval_seconds: number;
  timestamp: string;
}

export interface TailscaleSyncResult {
  status: string;
  synced_at: string;
  devices_polled: number;
  changes_detected: number;
  created: number;
  updated: number;
  deleted: number;
  errors: string[];
}

// ---------------------------------------------------------------------------
// OS Distribution & Fleet Uptime
// ---------------------------------------------------------------------------

export interface OsDistributionEntry {
  count: number;
  percentage: number;
  online: number;
  offline: number;
  uptime_percentage: number;
  versions: Record<string, number>;
}

export interface FleetOsDistributionResponse {
  total_devices: number;
  online_devices: number;
  offline_devices: number;
  fleet_uptime_percentage: number;
  by_os: Record<string, OsDistributionEntry>;
  by_category: Record<string, number>;
  timestamp: string;
}

export interface FleetUptimeNodeItem {
  id: string;
  node_id: string | null;
  hostname: string;
  name: string;
  os: string;
  os_version: string | null;
  is_online: boolean;
  last_seen: string | null;
  streak_duration_seconds: number;
  streak_duration_human: string;
  addresses: string[];
}

export interface FleetUptimeOverviewResponse {
  total_nodes: number;
  online_nodes: number;
  offline_nodes: number;
  fleet_uptime_percentage: number;
  nodes: FleetUptimeNodeItem[];
  timestamp: string;
}

export interface NodeUptimeSnapshot {
  id: string;
  recorded_at: string | null;
  is_online: boolean;
  compliance_status: string;
  os_version: string | null;
  client_version: string | null;
  latency_ms: number | null;
  derp_region: string | null;
}

export interface NodeUptimeHistoryResponse {
  node_id: string;
  hostname: string;
  os: string;
  os_version: string | null;
  is_online: boolean;
  total_snapshots_evaluated: number;
  online_snapshots: number;
  uptime_percentage: number;
  history: NodeUptimeSnapshot[];
  error?: string;
}

// ---------------------------------------------------------------------------
// Version Drift & Key Expiry
// ---------------------------------------------------------------------------

export interface VersionDriftEvaluation {
  current_version: string | null;
  stable_version: string;
  is_valid: boolean;
  is_behind: boolean;
  is_ahead: boolean;
  is_stable: boolean;
  drift_type: VersionDriftType;
  major_behind: number;
  minor_behind: number;
  patch_behind: number;
  versions_behind: number;
  is_vulnerable: boolean;
  vulnerability_severity: AuditSeverity;
  vulnerability_summary: string;
}

export interface NodeVersionItem {
  id: string;
  node_id: string | null;
  hostname: string;
  name: string;
  os: string;
  is_online: boolean;
  node_ts_version: string;
  stable_version: string;
  is_vulnerable: boolean;
  vulnerability_severity: AuditSeverity;
  drift_type: VersionDriftType;
  versions_behind: number;
  summary: string;
  update_available: boolean;
}

export interface FleetVersionDriftOverviewResponse {
  stable_version: string;
  total_nodes: number;
  stable_nodes: number;
  outdated_nodes: number;
  vulnerable_nodes: number;
  vulnerability_rate_percentage: number;
  drift_breakdown: Record<string, number>;
  version_distribution: Record<string, number>;
  nodes: NodeVersionItem[];
  timestamp: string;
}

export interface KeyExpiryCountdown {
  expires_at: string | null;
  status: KeyExpiryStatus;
  severity: AuditSeverity;
  is_expired: boolean;
  is_expiring_soon: boolean;
  remaining_seconds: number | null;
  remaining_days: number | null;
  countdown_human: string;
  summary: string;
}

export interface NodeKeyExpiryItem {
  id: string;
  node_id: string | null;
  hostname: string;
  name: string;
  os: string;
  is_online: boolean;
  key_expiry_disabled: boolean;
  expires_at: string | null;
  status: KeyExpiryStatus;
  severity: AuditSeverity;
  is_expired: boolean;
  is_expiring_soon: boolean;
  remaining_seconds: number | null;
  remaining_days: number | null;
  countdown_human: string;
  summary: string;
}

export interface FleetKeyExpiryOverviewResponse {
  warning_threshold_days: number;
  critical_threshold_days: number;
  total_nodes: number;
  valid_keys: number;
  expiring_soon_keys: number;
  expired_keys: number;
  disabled_keys: number;
  unknown_keys: number;
  nodes: NodeKeyExpiryItem[];
  timestamp: string;
}

export interface VulnerabilityItem {
  type: string;
  severity: AuditSeverity | string;
  title: string;
  description: string;
  [key: string]: unknown;
}

export interface NodeSecurityPostureResponse {
  id: string;
  node_id: string | null;
  hostname: string;
  name: string;
  os: string;
  os_version: string | null;
  node_ts_version: string | null;
  is_online: boolean;
  is_compliant: boolean;
  compliance_status: ComplianceStatus;
  version_drift: VersionDriftEvaluation;
  key_expiry: KeyExpiryCountdown;
  vulnerabilities: VulnerabilityItem[];
  update_available: boolean;
  latest_state_recorded_at: string | null;
  timestamp: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Network & Routing
// ---------------------------------------------------------------------------

export interface DerpRegionStat {
  region: string;
  node_count: number;
  online_count: number;
  fallback_count: number;
  average_latency_ms: number | null;
  min_latency_ms: number | null;
  max_latency_ms: number | null;
}

export interface FleetDerpOverviewResponse {
  total_devices: number;
  online_devices: number;
  derp_fallback_devices: number;
  fleet_fallback_rate_percentage: number;
  regions_count: number;
  regions: DerpRegionStat[];
  timestamp: string;
}

export interface NetworkNodeItem {
  id: string;
  node_id: string | null;
  hostname: string;
  name: string;
  is_online: boolean;
  exposed_routes: string[];
  is_exit_node: boolean;
  is_unauthorized_exit_node: boolean;
  connection_type: 'direct' | 'derp_fallback' | 'offline' | string;
  derp_region: string | null;
  endpoints_count: number;
}

export interface SubnetNodeReference {
  node_id: string;
  hostname: string;
}

export interface FleetNetworkRoutingOverviewResponse {
  total_devices: number;
  devices_advertising_routes: number;
  exit_nodes_count: number;
  authorized_exit_nodes_count: number;
  unauthorized_exit_nodes_count: number;
  derp_fallback_count: number;
  direct_connection_count: number;
  unauthorized_alerts: Array<Record<string, unknown>>;
  derp_fallback_nodes: Array<Record<string, unknown>>;
  subnets_catalog: Record<string, SubnetNodeReference[]>;
  unique_subnets_count: number;
  derp_region_distribution: Record<string, number>;
  nodes: NetworkNodeItem[];
  timestamp: string;
}

export interface NodeNetworkRoutingAuditResponse {
  id: string;
  node_id: string | null;
  hostname: string;
  name: string;
  is_online: boolean;
  addresses: string[];
  tags: string[];
  is_exit_node: boolean;
  is_authorized_exit_node: boolean;
  is_unauthorized_exit_node: boolean;
  exposed_routes: string[];
  has_unauthorized_routes: boolean;
  unauthorized_routes: string[];
  derp_info: {
    is_derp_fallback: boolean;
    derp_region: string | null;
    latency_ms: number | null;
    fallback_reason?: string;
  };
  endpoints: string[];
  endpoints_count: number;
  error?: string;
}

// ---------------------------------------------------------------------------
// Posture Compliance
// ---------------------------------------------------------------------------

export interface FlaggedPostureEndpoint {
  id: string;
  node_id: string | null;
  hostname: string;
  name: string;
  user: string | null;
  os: string;
  client_version: string | null;
  is_online: boolean;
  ts_auto_update: boolean | null;
  ts_state_encrypted: boolean | null;
  is_compliant: boolean;
  compliance_status: ComplianceStatus;
  violations: string[];
}

export interface FleetPostureComplianceOverviewResponse {
  tailnet: string | null;
  total_endpoints: number;
  evaluated_count: number;
  compliant_count: number;
  non_compliant_count: number;
  exempt_count: number;
  compliance_percentage: number;
  auto_update_enabled_count: number;
  auto_update_disabled_count: number;
  state_encrypted_count: number;
  state_unencrypted_count: number;
  flagged_endpoints_count: number;
  flagged_endpoints: FlaggedPostureEndpoint[];
  audited_at: string;
}

export interface FleetNonCompliantEndpointsResponse {
  total_non_compliant: number;
  violation_filter: string;
  endpoints: FlaggedPostureEndpoint[];
  audited_at: string;
}

export interface PostureHistoryRecord {
  state_id: string;
  recorded_at: string | null;
  is_compliant: boolean;
  compliance_status: ComplianceStatus;
  disk_encryption_enabled: boolean | null;
  ts_auto_update: boolean | null;
  ts_state_encrypted: boolean | null;
}

export interface NodePostureComplianceAuditResponse {
  node_id: string;
  id: string;
  hostname: string;
  name: string;
  user: string | null;
  os: string;
  os_version: string | null;
  client_version: string | null;
  is_online: boolean;
  is_compliant: boolean;
  compliance_status: ComplianceStatus;
  is_exempt: boolean;
  exemption_reason: string | null;
  ts_auto_update: boolean | null;
  ts_state_encrypted: boolean | null;
  violations: string[];
  violations_count: number;
  posture_attributes: {
    'node:tsAutoUpdate': boolean | null;
    'node:tsStateEncrypted': boolean | null;
  };
  history: PostureHistoryRecord[];
  history_count: number;
  audited_at: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Geolocation & Impossible Travel
// ---------------------------------------------------------------------------

export interface CountryBreakdownItem {
  country_code: string;
  country_name: string;
  endpoint_count: number;
  percentage: number;
}

export interface FlaggedGeoEndpoint {
  id: string;
  node_id: string | null;
  hostname: string;
  name: string;
  user: string | null;
  country: string | null;
  country_name: string | null;
  public_address: string | null;
  distance_km: number | null;
  speed_kmh: number | null;
  anomaly_reason: string | null;
  audited_at: string | null;
}

export interface FleetGeolocationOverviewResponse {
  total_endpoints: number;
  endpoints_with_geolocation: number;
  unique_countries_count: number;
  country_distribution: Record<string, number>;
  country_breakdown: CountryBreakdownItem[];
  impossible_travel_events_count: number;
  flagged_endpoints_count: number;
  flagged_endpoints: FlaggedGeoEndpoint[];
  audited_at: string;
}

export interface ImpossibleTravelEventItem {
  id: string;
  node_id: string | null;
  hostname: string | null;
  event_type: AuditEventType | string;
  severity: AuditSeverity;
  message: string | null;
  details: Record<string, unknown>;
  created_at: string;
}

export interface FleetImpossibleTravelEventsResponse {
  tailnet: string | null;
  events_count: number;
  events: ImpossibleTravelEventItem[];
  retrieved_at: string;
}

export interface NodeGeolocationAuditResponse {
  is_compliant: boolean;
  compliance_status: ComplianceStatus;
  is_impossible_travel: boolean;
  country: string | null;
  country_name: string | null;
  public_address: string | null;
  latitude: number | null;
  longitude: number | null;
  distance_km: number | null;
  speed_kmh: number | null;
  anomaly_reason: string | null;
  location_history: Array<Record<string, unknown>>;
  audited_at: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Tailnet Lock
// ---------------------------------------------------------------------------

export interface TailnetLockNodeItem {
  id: string;
  node_id: string | null;
  hostname: string;
  name: string;
  user: string | null;
  os: string;
  is_online: boolean;
  tailnet_lock_key: string | null;
  tailnet_lock_error: string | null;
  lock_status: TailnetLockStatus;
  is_locked_out: boolean;
  is_quarantined: boolean;
  is_unsigned: boolean;
  is_signing_node: boolean;
  is_exempt: boolean;
}

export interface FleetTailnetLockOverviewResponse {
  tailnet: string | null;
  tailnet_lock_enabled: boolean;
  total_endpoints: number;
  signed_count: number;
  unsigned_count: number;
  locked_out_count: number;
  quarantined_count: number;
  signing_nodes_count: number;
  exempt_count: number;
  locked_out_endpoints: TailnetLockNodeItem[];
  unsigned_endpoints: TailnetLockNodeItem[];
  quarantined_endpoints: TailnetLockNodeItem[];
  signing_nodes: TailnetLockNodeItem[];
  audited_at: string;
}

export interface FleetLockedOutNodesResponse {
  tailnet: string | null;
  locked_out_count: number;
  endpoints: TailnetLockNodeItem[];
  retrieved_at: string;
}

export interface FleetUnsignedNodesResponse {
  tailnet: string | null;
  unsigned_count: number;
  endpoints: TailnetLockNodeItem[];
  retrieved_at: string;
}

export interface FleetSigningNodesResponse {
  tailnet: string | null;
  signing_nodes_count: number;
  signing_nodes: TailnetLockNodeItem[];
  retrieved_at: string;
}

export interface NodeTailnetLockAuditResponse {
  id: string;
  node_id: string | null;
  hostname: string;
  name: string;
  lock_status: TailnetLockStatus;
  is_compliant: boolean;
  compliance_status: ComplianceStatus;
  tailnet_lock_key: string | null;
  tailnet_lock_error: string | null;
  is_locked_out: boolean;
  is_quarantined: boolean;
  is_unsigned: boolean;
  is_signing_node: boolean;
  is_exempt: boolean;
  audited_at: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// MagicDNS SSL & TLS Certificates
// ---------------------------------------------------------------------------

export interface MagicDnsCertificateItem {
  node_id: string;
  hostname: string;
  domain: string;
  status: SSLCertificateStatus;
  expires_at: string | null;
  remaining_days: number | null;
  countdown_human: string;
  is_expired: boolean;
  is_expiring_soon: boolean;
  http_reachable: boolean;
  http_status_code: number | null;
  response_time_ms: number | null;
  tls_version: string | null;
  certificate: Record<string, unknown>;
  error: string | null;
  checked_at: string | null;
}

export interface FleetMagicDnsSslOverviewResponse {
  tailnet: string | null;
  total_fleet_nodes: number;
  monitored_domains_count: number;
  not_configured_count: number;
  valid_count: number;
  expiring_soon_count: number;
  expired_count: number;
  unreachable_count: number;
  expiring_soon_list: MagicDnsCertificateItem[];
  certificates: MagicDnsCertificateItem[];
  audited_at: string;
}

export type FleetExpiringCertificatesResponse = MagicDnsCertificateItem[];

export interface MagicDnsSslProbeResult {
  checked_nodes: number;
  valid_count: number;
  expiring_soon_count: number;
  expired_count: number;
  unreachable_count: number;
  error_count: number;
  alerts_logged: number;
  duration_seconds: number;
  results: Array<Record<string, unknown>>;
}

export interface NodeMagicDnsSslAuditResponse {
  id: string;
  node_id: string | null;
  hostname: string;
  name: string;
  domain: string | null;
  is_configured: boolean;
  status: SSLCertificateStatus;
  expires_at: string | null;
  remaining_days: number | null;
  countdown_human: string;
  is_expired: boolean;
  is_expiring_soon: boolean;
  http_reachable: boolean | null;
  http_status_code: number | null;
  response_time_ms: number | null;
  tls_version: string | null;
  certificate: Record<string, unknown>;
  error: string | null;
  checked_at: string | null;
  audit_events: Array<{
    id: string;
    event_type: string;
    severity: string;
    action: string;
    message: string | null;
    details: Record<string, unknown>;
    created_at: string | null;
  }>;
  audited_at: string;
}

// ---------------------------------------------------------------------------
// Webhook & ACL
// ---------------------------------------------------------------------------

export interface TailscaleWebhookActor {
  id?: string;
  loginName?: string;
  displayName?: string;
  type?: string;
  profilePicUrl?: string;
  [key: string]: unknown;
}

export interface TailscaleWebhookEvent {
  timestamp?: string;
  version?: number;
  type: string;
  tailnet?: string;
  message?: string;
  data: Record<string, unknown>;
  actor?: TailscaleWebhookActor | Record<string, unknown> | string;
}

export interface WebhookProcessedEvent {
  id: string;
  event_type: string;
  event_category: string;
  severity: string;
  action: string;
  actor?: string | null;
  node_id?: string | null;
  tailnet?: string | null;
  created_at: string;
}

export interface WebhookResponse {
  status: string;
  received_events: number;
  processed_events: number;
  ignored_events: number;
  events: WebhookProcessedEvent[];
  message?: string | null;
}

export interface WebhookStatusResponse {
  webhook_enabled: boolean;
  secret_configured: boolean;
  verify_signature_enabled: boolean;
  tolerance_seconds: number;
  total_webhook_events: number;
  last_event_received_at: string | null;
  event_types_breakdown: Record<string, number>;
  recent_events: Array<Record<string, unknown>>;
}

export interface AclAuditSummaryResponse {
  total_acl_events: number;
  last_policy_update_at: string | null;
  last_actor: string | null;
  recent_events: Array<Record<string, unknown>>;
}

export interface AclOverviewResponse {
  tailnet: string | null;
  total_events: number;
  policy_updates_count: number;
  last_policy_update: Record<string, unknown> | null;
  events_last_24h: number;
  recent_events: Array<Record<string, unknown>>;
  timestamp: string;
}

export interface TailscaleAclPolicy {
  acls?: Array<Record<string, unknown>>;
  groups?: Record<string, string[]>;
  hosts?: Record<string, string>;
  tagOwners?: Record<string, string[]>;
  autoApprovers?: Record<string, unknown>;
  nodeAttrs?: Array<Record<string, unknown>>;
  tests?: Array<Record<string, unknown>>;
  [key: string]: unknown;
}
