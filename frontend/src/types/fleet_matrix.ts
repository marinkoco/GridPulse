import type {
  ComplianceStatus,
  DeviceCategory,
  HealthRating,
  KeyExpiryStatus,
  SSLCertificateStatus,
  TailnetLockStatus,
} from './enums';

export interface FleetMatrixColumn {
  key: string;
  label: string;
  category: string;
  type: 'string' | 'boolean' | 'number' | 'list' | 'datetime' | 'status';
  sortable: boolean;
  filterable: boolean;
}

export interface NodeMatrixItem {
  id: string;
  node_id: string | null;
  name: string;
  hostname: string;
  user: string | null;
  tailnet: string | null;
  addresses: string[];
  tags: string[];

  // System & OS
  os: string;
  os_raw: string | null;
  os_version: string | null;
  client_version: string | null;
  category: DeviceCategory | string;

  // Status & Uptime
  is_online: boolean;
  last_seen: string | null;
  streak_duration_seconds: number;
  streak_duration_human: string;

  // Security Posture & Compliance
  is_compliant: boolean;
  compliance_status: ComplianceStatus;
  violations: string[];
  update_available: boolean;

  // Key Lifecycle
  key_expiry_disabled: boolean;
  expires_at: string | null;
  key_expiry_status: KeyExpiryStatus;
  days_until_key_expiry: number | null;

  // Network & Routing
  is_exit_node: boolean;
  exposed_routes: string[];
  derp_region: string | null;
  latency_ms: number | null;

  // Geolocation
  country: string | null;
  public_address: string | null;
  country_name?: string | null;
  is_impossible_travel?: boolean;
  geo_anomaly_reason?: string | null;

  // Tailnet Lock
  tailnet_lock_status: TailnetLockStatus;
  is_locked_out: boolean;
  is_quarantined: boolean;
  is_signing_node: boolean;

  // MagicDNS & TLS
  magicdns_domain: string | null;
  ssl_cert_status: SSLCertificateStatus;
  ssl_cert_expires_at: string | null;
  is_ssl_cert_expiring: boolean;
  is_ssl_cert_expired: boolean;

  // Overall Node Health
  health_status: HealthRating;
  health_score: number;

  [key: string]: unknown;
}

export interface FleetMatrixCrossTabulation {
  os_by_status: Record<string, Record<string, number>>;
  os_by_compliance: Record<string, Record<string, number>>;
  category_by_status: Record<string, Record<string, number>>;
}

export interface FleetMatrixResponse {
  total_devices: number;
  filtered_devices: number;
  limit: number;
  offset: number;
  has_more: boolean;
  columns: FleetMatrixColumn[];
  cross_tabulation: FleetMatrixCrossTabulation;
  matrix: NodeMatrixItem[];
  timestamp: string;
}

export interface FleetMatrixSummaryResponse {
  total_devices: number;
  online_devices: number;
  offline_devices: number;
  cross_tabulation: FleetMatrixCrossTabulation;
  columns: FleetMatrixColumn[];
  timestamp: string;
}

export interface FleetMatrixQueryParams {
  tailnet?: string;
  status?: 'online' | 'offline' | 'all';
  os?: string;
  compliance?: 'compliant' | 'non_compliant';
  category?: DeviceCategory | string;
  locked_out?: boolean;
  quarantined?: boolean;
  geo_anomaly?: boolean;
  exit_node?: boolean;
  q?: string;
  sort_by?: string;
  order?: 'asc' | 'desc';
  limit?: number;
  offset?: number;
}
