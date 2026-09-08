import type { HealthRating } from './enums';

export interface ActiveAlertItem {
  severity: 'critical' | 'warning' | 'info';
  category: 'security' | 'posture' | 'network' | 'key_expiry' | 'lock' | 'ssl' | string;
  source: string;
  message: string;
  node_id?: string | null;
  hostname?: string | null;
  created_at?: string | null;
  details: Record<string, unknown>;
}

export interface HealthSummaryFleet {
  total_devices: number;
  online_devices: number;
  offline_devices: number;
  fleet_uptime_percentage: number;
  healthy_devices: number;
  warning_devices: number;
  critical_devices: number;
}

export interface HealthSummaryPosture {
  total_evaluated: number;
  compliant_count: number;
  non_compliant_count: number;
  compliance_percentage: number;
  auto_update_enabled: number;
  auto_update_disabled: number;
  state_encrypted: number;
  state_unencrypted: number;
}

export interface HealthSummaryVersionDrift {
  target_stable_version: string;
  up_to_date_count: number;
  outdated_count: number;
  drift_percentage: number;
}

export interface HealthSummaryKeyExpiry {
  healthy_count: number;
  warning_count: number;
  critical_count: number;
  expired_count: number;
  disabled_count: number;
}

export interface HealthSummaryTailnetLock {
  total_nodes: number;
  signed_count: number;
  unsigned_count: number;
  locked_out_count: number;
  quarantined_count: number;
  signing_nodes_count: number;
}

export interface HealthSummaryCertificates {
  total_tracked: number;
  valid_count: number;
  expiring_soon_count: number;
  expired_count: number;
  not_configured_count: number;
}

export interface HealthSummaryNetwork {
  exit_nodes_count: number;
  derp_regions_count: number;
  avg_latency_ms: number | null;
}

export interface HealthSummaryGeolocation {
  total_countries: number;
  impossible_travel_alerts: number;
}

export interface HealthSummaryAuditAlerts {
  total_events: number;
  events_last_24h: number;
  critical_count: number;
  error_count: number;
  warning_count: number;
  info_count: number;
}

export interface BackgroundServicesStatus {
  scheduler_running?: boolean;
  jobs_count?: number;
  poller_interval_seconds?: number;
  ssl_monitor_interval_seconds?: number;
  jobs?: Array<{
    id: string;
    name: string;
    next_run_time: string | null;
    trigger: string;
  }>;
  [key: string]: unknown;
}

export interface AggregatedHealthStatsResponse {
  overall_status: HealthRating;
  health_score: number;
  tailnet: string | null;
  fleet: HealthSummaryFleet;
  posture: HealthSummaryPosture;
  version_drift: HealthSummaryVersionDrift;
  key_expiry: HealthSummaryKeyExpiry;
  tailnet_lock: HealthSummaryTailnetLock;
  certificates: HealthSummaryCertificates;
  network: HealthSummaryNetwork;
  geolocation: HealthSummaryGeolocation;
  audit_alerts: HealthSummaryAuditAlerts;
  services: BackgroundServicesStatus;
  active_alerts: ActiveAlertItem[];
  timestamp: string;
}

export interface HealthCheckResponse {
  status: string;
  service: string;
}
