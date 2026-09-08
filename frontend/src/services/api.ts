/**
 * Type-safe API Client for the GridPulse FastAPI backend (/api/v1).
 */

import type {
  AclAuditSummaryResponse,
  AclOverviewResponse,
  AggregatedHealthStatsResponse,
  AuditFeedQueryParams,
  AuditFeedResponse,
  FleetDerpOverviewResponse,
  FleetExpiringCertificatesResponse,
  FleetGeolocationOverviewResponse,
  FleetImpossibleTravelEventsResponse,
  FleetKeyExpiryOverviewResponse,
  FleetLockedOutNodesResponse,
  FleetMagicDnsSslOverviewResponse,
  FleetMatrixQueryParams,
  FleetMatrixResponse,
  FleetMatrixSummaryResponse,
  FleetNetworkRoutingOverviewResponse,
  FleetNonCompliantEndpointsResponse,
  FleetOsDistributionResponse,
  FleetPostureComplianceOverviewResponse,
  FleetSigningNodesResponse,
  FleetTailnetLockOverviewResponse,
  FleetUnsignedNodesResponse,
  FleetUptimeOverviewResponse,
  FleetVersionDriftOverviewResponse,
  HealthCheckResponse,
  MagicDnsSslProbeResult,
  NodeAuditFeedResponse,
  NodeGeolocationAuditResponse,
  NodeMagicDnsSslAuditResponse,
  NodeNetworkRoutingAuditResponse,
  NodePostureComplianceAuditResponse,
  NodeSecurityPostureResponse,
  NodeTailnetLockAuditResponse,
  NodeUptimeHistoryResponse,
  SchedulerStatusResponse,
  TailscaleSyncResult,
  WebhookStatusResponse,
} from '../types';

export const API_BASE_URL =
  (typeof import.meta !== 'undefined' && import.meta.env?.PUBLIC_API_URL) ||
  'http://localhost:8000';

export class ApiError extends Error {
  public status: number;
  public details?: unknown;

  constructor(message: string, status: number, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE_URL.replace(/\/$/, '')}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  if (!response.ok) {
    let errorDetail: unknown = null;
    try {
      errorDetail = await response.json();
    } catch {
      // Ignored if non-JSON error
    }
    const message =
      (typeof errorDetail === 'object' &&
        errorDetail !== null &&
        'detail' in errorDetail &&
        typeof (errorDetail as { detail: unknown }).detail === 'string' &&
        (errorDetail as { detail: string }).detail) ||
      `API request failed with status ${response.status} (${response.statusText})`;

    throw new ApiError(message, response.status, errorDetail);
  }

  return (await response.json()) as T;
}

function buildQuery(params?: Record<string, unknown>): string {
  if (!params) return '';
  const search = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') {
      search.set(k, String(v));
    }
  }
  const str = search.toString();
  return str ? `?${str}` : '';
}

export const api = {
  // Health & Scheduler
  getHealth: () => request<HealthCheckResponse>('/api/v1/health'),
  getSchedulerStatus: () => request<SchedulerStatusResponse>('/api/v1/scheduler/status'),
  triggerSync: () => request<TailscaleSyncResult>('/api/v1/tailscale/sync', { method: 'POST' }),

  // Aggregated Health Statistics (Step 16)
  getAggregatedHealthStats: (tailnet?: string) =>
    request<AggregatedHealthStatsResponse>(`/api/v1/fleet/health${buildQuery({ tailnet })}`),

  // Fleet Matrix (Step 16)
  getFleetMatrix: (params?: FleetMatrixQueryParams) =>
    request<FleetMatrixResponse>(
      `/api/v1/fleet/matrix${buildQuery(params as Record<string, unknown>)}`
    ),
  getFleetMatrixSummary: (tailnet?: string) =>
    request<FleetMatrixSummaryResponse>(`/api/v1/fleet/matrix/summary${buildQuery({ tailnet })}`),

  // Chronological Audit Feed (Step 16)
  getAuditFeed: (params?: AuditFeedQueryParams) =>
    request<AuditFeedResponse>(
      `/api/v1/audit/feed${buildQuery(params as Record<string, unknown>)}`
    ),
  getNodeAuditFeed: (nodeId: string, params?: AuditFeedQueryParams) =>
    request<NodeAuditFeedResponse>(
      `/api/v1/fleet/nodes/${encodeURIComponent(nodeId)}/audit-feed${buildQuery(
        params as Record<string, unknown>
      )}`
    ),

  // OS Distribution & Uptime
  getFleetOsDistribution: (tailnet?: string) =>
    request<FleetOsDistributionResponse>(`/api/v1/fleet/os-distribution${buildQuery({ tailnet })}`),
  getFleetUptime: (tailnet?: string) =>
    request<FleetUptimeOverviewResponse>(`/api/v1/fleet/uptime${buildQuery({ tailnet })}`),
  getNodeUptimeHistory: (nodeId: string, limit = 50) =>
    request<NodeUptimeHistoryResponse>(
      `/api/v1/fleet/nodes/${encodeURIComponent(nodeId)}/uptime${buildQuery({ limit })}`
    ),

  // Version Drift & Key Expiry
  getFleetVersionDrift: (params?: { tailnet?: string; stable_version?: string }) =>
    request<FleetVersionDriftOverviewResponse>(`/api/v1/fleet/version-drift${buildQuery(params)}`),
  getFleetKeyExpiry: (params?: {
    tailnet?: string;
    warning_days?: number;
    critical_days?: number;
  }) => request<FleetKeyExpiryOverviewResponse>(`/api/v1/fleet/key-expiry${buildQuery(params)}`),
  getNodeSecurityPosture: (nodeId: string, stable_version?: string) =>
    request<NodeSecurityPostureResponse>(
      `/api/v1/fleet/nodes/${encodeURIComponent(nodeId)}/security${buildQuery({
        stable_version,
      })}`
    ),

  // Network & Routing
  getFleetRoutes: (tailnet?: string) =>
    request<FleetNetworkRoutingOverviewResponse>(`/api/v1/fleet/routes${buildQuery({ tailnet })}`),
  getFleetDerpOverview: (tailnet?: string) =>
    request<FleetDerpOverviewResponse>(`/api/v1/fleet/derp${buildQuery({ tailnet })}`),
  getNodeNetworkAudit: (nodeId: string) =>
    request<NodeNetworkRoutingAuditResponse>(
      `/api/v1/fleet/nodes/${encodeURIComponent(nodeId)}/routes`
    ),

  // Posture Compliance
  getFleetPostureOverview: (tailnet?: string) =>
    request<FleetPostureComplianceOverviewResponse>(
      `/api/v1/fleet/posture${buildQuery({ tailnet })}`
    ),
  getFleetNonCompliantEndpoints: (params?: { tailnet?: string; violation_filter?: string }) =>
    request<FleetNonCompliantEndpointsResponse>(
      `/api/v1/fleet/posture/non-compliant${buildQuery(params)}`
    ),
  getNodePostureAudit: (nodeId: string) =>
    request<NodePostureComplianceAuditResponse>(
      `/api/v1/fleet/nodes/${encodeURIComponent(nodeId)}/compliance`
    ),

  // Geolocation
  getFleetGeolocation: (tailnet?: string) =>
    request<FleetGeolocationOverviewResponse>(
      `/api/v1/fleet/geolocation${buildQuery({ tailnet })}`
    ),
  getFleetImpossibleTravelEvents: (params?: { tailnet?: string; limit?: number }) =>
    request<FleetImpossibleTravelEventsResponse>(
      `/api/v1/fleet/geolocation/impossible-travel${buildQuery(params)}`
    ),
  getNodeGeolocationAudit: (nodeId: string) =>
    request<NodeGeolocationAuditResponse>(
      `/api/v1/fleet/nodes/${encodeURIComponent(nodeId)}/geolocation`
    ),

  // Tailnet Lock
  getFleetTailnetLock: (tailnet?: string) =>
    request<FleetTailnetLockOverviewResponse>(
      `/api/v1/fleet/tailnet-lock${buildQuery({ tailnet })}`
    ),
  getFleetLockedOutNodes: (tailnet?: string) =>
    request<FleetLockedOutNodesResponse>(
      `/api/v1/fleet/tailnet-lock/locked-out${buildQuery({ tailnet })}`
    ),
  getFleetUnsignedNodes: (tailnet?: string) =>
    request<FleetUnsignedNodesResponse>(
      `/api/v1/fleet/tailnet-lock/unsigned${buildQuery({ tailnet })}`
    ),
  getFleetSigningNodes: (tailnet?: string) =>
    request<FleetSigningNodesResponse>(
      `/api/v1/fleet/tailnet-lock/signing-nodes${buildQuery({ tailnet })}`
    ),
  getNodeTailnetLockAudit: (nodeId: string) =>
    request<NodeTailnetLockAuditResponse>(
      `/api/v1/fleet/nodes/${encodeURIComponent(nodeId)}/tailnet-lock`
    ),

  // MagicDNS SSL
  getFleetMagicDnsSslOverview: (tailnet?: string) =>
    request<FleetMagicDnsSslOverviewResponse>(
      `/api/v1/fleet/magicdns-ssl${buildQuery({ tailnet })}`
    ),
  getFleetExpiringCertificates: (params?: { tailnet?: string; days?: number }) =>
    request<FleetExpiringCertificatesResponse>(
      `/api/v1/fleet/magicdns-ssl/expiring${buildQuery(params)}`
    ),
  triggerMagicDnsSslProbe: () =>
    request<MagicDnsSslProbeResult>('/api/v1/fleet/magicdns-ssl/probe', { method: 'POST' }),
  getNodeMagicDnsSslAudit: (nodeId: string) =>
    request<NodeMagicDnsSslAuditResponse>(
      `/api/v1/fleet/nodes/${encodeURIComponent(nodeId)}/magicdns-ssl`
    ),

  // Webhooks & ACL
  getWebhookStatus: () => request<WebhookStatusResponse>('/api/v1/webhooks/status'),
  getFleetAclEvents: (params?: { tailnet?: string; limit?: number }) =>
    request<AclAuditSummaryResponse>(`/api/v1/fleet/acl/events${buildQuery(params)}`),
  getFleetAclOverview: (tailnet?: string) =>
    request<AclOverviewResponse>(`/api/v1/fleet/acl/overview${buildQuery({ tailnet })}`),
};
