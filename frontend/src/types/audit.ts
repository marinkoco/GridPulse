import type { AuditEventType, AuditSeverity, EventCategory } from './enums';

export interface AuditLogEventItem {
  id: string;
  node_id: string | null;
  hostname: string | null;
  device_name: string | null;
  os: string | null;
  tailnet: string | null;
  event_type: AuditEventType | string;
  event_category: EventCategory | string;
  severity: AuditSeverity;
  action: string;
  actor: string | null;
  message: string | null;
  details: Record<string, unknown>;
  ip_address: string | null;
  created_at: string;
}

export interface AuditFeedSummary {
  total_matching: number;
  by_severity: Record<AuditSeverity | string, number>;
  by_category: Record<EventCategory | string, number>;
}

export interface AuditFeedResponse {
  total: number;
  count: number;
  limit: number;
  offset: number;
  has_more: boolean;
  order: 'desc' | 'asc';
  summary: AuditFeedSummary;
  events: AuditLogEventItem[];
  timestamp: string;
}

export interface NodeAuditFeedResponse extends AuditFeedResponse {
  error?: string;
  node_id?: string;
}

export interface AuditFeedQueryParams {
  node_id?: string;
  tailnet?: string;
  severity?: AuditSeverity | string;
  category?: EventCategory | string;
  event_type?: AuditEventType | string;
  actor?: string;
  since?: string;
  until?: string;
  q?: string;
  order?: 'desc' | 'asc';
  limit?: number;
  offset?: number;
}
