import type { AuditLogEventItem, AuditSeverity, EventCategory } from '../types';

/**
 * Formats an ISO date string into a human-friendly relative time string.
 */
export function formatRelativeTime(dateInput?: string | Date | null): string {
  if (!dateInput) return 'Unknown';
  const date = typeof dateInput === 'string' ? new Date(dateInput) : dateInput;
  if (isNaN(date.getTime())) return 'Invalid date';

  const now = new Date();
  const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (diffInSeconds < 5) return 'Just now';
  if (diffInSeconds < 60) return `${diffInSeconds}s ago`;
  const diffInMinutes = Math.floor(diffInSeconds / 60);
  if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
  const diffInHours = Math.floor(diffInMinutes / 60);
  if (diffInHours < 24) return `${diffInHours}h ago`;
  const diffInDays = Math.floor(diffInHours / 24);
  if (diffInDays < 30) return `${diffInDays}d ago`;
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

/**
 * Formats an ISO date string into a clear UTC/localized string for tooltips.
 */
export function formatDateTime(dateInput?: string | Date | null): string {
  if (!dateInput) return 'N/A';
  const date = typeof dateInput === 'string' ? new Date(dateInput) : dateInput;
  if (isNaN(date.getTime())) return 'Invalid date';
  return date.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
}

/**
 * Determines whether an audit log event originated from a Tailscale real-time webhook.
 */
export function isWebhookEvent(
  event: Pick<AuditLogEventItem, 'actor' | 'event_category' | 'event_type' | 'details'>
): boolean {
  if (event.actor?.toLowerCase().includes('webhook')) return true;
  if (event.event_category === 'acl') return true;
  if (event.event_type.startsWith('policy.') || event.event_type.startsWith('webhook.')) return true;
  if (event.event_type === 'tailnet.config_changed') return true;
  if (
    event.details &&
    typeof event.details === 'object' &&
    ('webhook' in event.details ||
      'signature' in event.details ||
      'webhook_event' in event.details ||
      'tailscale_event' in event.details)
  ) {
    return true;
  }
  return false;
}

export interface SeverityStyle {
  badgeText: string;
  badgeClass: string;
  dotClass: string;
  borderClass: string;
  bgClass: string;
}

/**
 * Returns consistent Tailwind badge styles for an audit severity level.
 */
export function getSeverityStyle(severity: AuditSeverity | string): SeverityStyle {
  const s = severity.toLowerCase();
  switch (s) {
    case 'critical':
      return {
        badgeText: 'CRITICAL',
        badgeClass: 'bg-red-500/20 text-red-300 border-red-500/40',
        dotClass: 'bg-red-400 shadow-[0_0_8px_rgba(239,68,68,0.7)]',
        borderClass: 'border-red-500/30',
        bgClass: 'bg-red-950/20',
      };
    case 'error':
    case 'high':
      return {
        badgeText: 'ERROR',
        badgeClass: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
        dotClass: 'bg-rose-400 shadow-[0_0_8px_rgba(244,63,94,0.6)]',
        borderClass: 'border-rose-500/30',
        bgClass: 'bg-rose-950/15',
      };
    case 'warning':
      return {
        badgeText: 'WARNING',
        badgeClass: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
        dotClass: 'bg-amber-400',
        borderClass: 'border-amber-500/30',
        bgClass: 'bg-amber-950/15',
      };
    case 'low':
    case 'info':
    default:
      return {
        badgeText: 'INFO',
        badgeClass: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
        dotClass: 'bg-emerald-400',
        borderClass: 'border-slate-800',
        bgClass: 'bg-slate-900/40',
      };
  }
}

/**
 * Returns Tailwind tag styling for event categories.
 */
export function getCategoryStyle(category: EventCategory | string): { label: string; class: string } {
  const c = category.toLowerCase();
  switch (c) {
    case 'acl':
      return { label: 'ACL & Webhook', class: 'bg-violet-500/15 text-violet-300 border-violet-500/30' };
    case 'security':
      return { label: 'Security', class: 'bg-rose-500/15 text-rose-300 border-rose-500/30' };
    case 'posture':
      return { label: 'Posture', class: 'bg-purple-500/15 text-purple-300 border-purple-500/30' };
    case 'device':
      return { label: 'Device', class: 'bg-sky-500/15 text-sky-300 border-sky-500/30' };
    case 'network':
      return { label: 'Network', class: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30' };
    case 'system':
    default:
      return { label: 'System', class: 'bg-slate-500/15 text-slate-300 border-slate-500/30' };
  }
}

/**
 * Returns formatted OS icon, display name, and badge styling.
 */
export function getOsBadgeInfo(
  os?: string | null,
  osVersion?: string | null
): { icon: string; label: string; versionText: string; colorClass: string } {
  const norm = (os || 'unknown').toLowerCase();
  let icon = '🖥️';
  let label = os || 'Unknown';
  let colorClass = 'bg-slate-800 text-slate-300 border-slate-700';

  if (norm.includes('linux') || norm.includes('ubuntu') || norm.includes('debian') || norm.includes('fedora') || norm.includes('arch')) {
    icon = '🐧';
    label = 'Linux';
    colorClass = 'bg-amber-500/10 text-amber-300 border-amber-500/20';
  } else if (norm.includes('darwin') || norm.includes('mac') || norm.includes('apple') || norm.includes('sonoma') || norm.includes('ventura')) {
    icon = '🍎';
    label = 'macOS';
    colorClass = 'bg-slate-200/10 text-slate-200 border-slate-400/20';
  } else if (norm.includes('win')) {
    icon = '🪟';
    label = 'Windows';
    colorClass = 'bg-blue-500/10 text-blue-300 border-blue-500/20';
  } else if (norm.includes('android')) {
    icon = '🤖';
    label = 'Android';
    colorClass = 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20';
  } else if (norm.includes('ios') || norm.includes('ipad')) {
    icon = '📱';
    label = 'iOS';
    colorClass = 'bg-indigo-500/10 text-indigo-300 border-indigo-500/20';
  } else if (norm.includes('bsd')) {
    icon = '😈';
    label = 'FreeBSD';
    colorClass = 'bg-red-500/10 text-red-300 border-red-500/20';
  }

  const versionText = osVersion ? ` (${osVersion})` : '';
  return { icon, label, versionText, colorClass };
}

/**
 * Returns posture compliance badge styling and violation details.
 */
export function getPostureBadgeInfo(
  isCompliant: boolean,
  violations: string[] = []
): { label: string; badgeClass: string; dotClass: string; violationsCount: number } {
  if (isCompliant) {
    return {
      label: 'Compliant',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      dotClass: 'bg-emerald-400',
      violationsCount: 0,
    };
  }
  return {
    label: violations.length > 0 ? `Non-Compliant (${violations.length})` : 'Non-Compliant',
    badgeClass: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
    dotClass: 'bg-rose-400 animate-pulse',
    violationsCount: violations.length,
  };
}

/**
 * Returns Geolocation details, country flags, and impossible travel anomaly badges.
 */
export function getGeoBadgeInfo(
  country?: string | null,
  isAnomaly: boolean = false,
  anomalyReason?: string | null,
  countryName?: string | null
): {
  countryCode: string;
  countryDisplay: string;
  isAnomaly: boolean;
  anomalyReason: string | null;
  badgeClass: string;
} {
  const code = (country || 'N/A').toUpperCase();
  const display = countryName || code;

  if (isAnomaly) {
    return {
      countryCode: code,
      countryDisplay: display,
      isAnomaly: true,
      anomalyReason: anomalyReason || 'Impossible travel jump detected between consecutive sessions',
      badgeClass: 'bg-red-500/25 text-red-300 border-red-500/50 animate-pulse shadow-[0_0_12px_rgba(239,68,68,0.2)]',
    };
  }

  return {
    countryCode: code,
    countryDisplay: display,
    isAnomaly: false,
    anomalyReason: null,
    badgeClass: 'bg-slate-800/80 text-slate-300 border-slate-700/80',
  };
}

/**
 * Returns Tailnet Lock status badge styling, quarantine flags, and signing node pills.
 */
export function getTailnetLockBadgeInfo(
  status?: string | null,
  isLockedOut: boolean = false,
  isQuarantined: boolean = false,
  isSigningNode: boolean = false
): {
  label: string;
  badgeClass: string;
  dotClass: string;
  isQuarantined: boolean;
  isSigningNode: boolean;
} {
  const isQuarantineState = isLockedOut || isQuarantined || (status || '').toLowerCase().includes('quarantine') || (status || '').toLowerCase().includes('locked_out');

  if (isQuarantineState) {
    return {
      label: 'QUARANTINED',
      badgeClass: 'bg-red-500/25 text-red-300 border-red-500/50 animate-pulse shadow-[0_0_12px_rgba(239,68,68,0.25)] font-bold',
      dotClass: 'bg-red-400',
      isQuarantined: true,
      isSigningNode,
    };
  }

  const s = (status || 'unknown').toLowerCase();
  if (s === 'signed' || s === 'verified' || s === 'true') {
    return {
      label: 'Signed',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      dotClass: 'bg-emerald-400',
      isQuarantined: false,
      isSigningNode,
    };
  }

  if (s === 'unsigned' || s === 'untrusted') {
    return {
      label: 'Unsigned',
      badgeClass: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
      dotClass: 'bg-amber-400',
      isQuarantined: false,
      isSigningNode,
    };
  }

  return {
    label: status ? status.toUpperCase() : 'UNKNOWN',
    badgeClass: 'bg-slate-800 text-slate-400 border-slate-700',
    dotClass: 'bg-slate-500',
    isQuarantined: false,
    isSigningNode,
  };
}

/**
 * Returns key expiry badge styling and remaining days string.
 */
export function getKeyExpiryBadgeInfo(
  status?: string | null,
  daysLeft?: number | null,
  isDisabled: boolean = false
): { label: string; badgeClass: string; daysText: string } {
  if (isDisabled) {
    return {
      label: 'Disabled',
      badgeClass: 'bg-slate-800 text-slate-400 border-slate-700',
      daysText: 'Never expires',
    };
  }

  const s = (status || 'healthy').toLowerCase();
  const daysText = daysLeft !== null && daysLeft !== undefined ? `${Math.round(daysLeft)}d` : 'N/A';

  if (s === 'expired') {
    return {
      label: 'Expired',
      badgeClass: 'bg-red-500/20 text-red-300 border-red-500/40 animate-pulse',
      daysText: 'Expired',
    };
  }

  if (s === 'critical') {
    return {
      label: `Critical (${daysText})`,
      badgeClass: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
      daysText,
    };
  }

  if (s === 'warning') {
    return {
      label: `Expiring (${daysText})`,
      badgeClass: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
      daysText,
    };
  }

  return {
    label: `Valid (${daysText})`,
    badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    daysText,
  };
}

/**
 * Returns health score badge color class.
 */
export function getHealthScoreColor(score: number): {
  textClass: string;
  badgeClass: string;
  barGradient: string;
} {
  if (score >= 85) {
    return {
      textClass: 'text-emerald-400',
      badgeClass: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
      barGradient: 'from-emerald-500 to-teal-400',
    };
  }
  if (score >= 50) {
    return {
      textClass: 'text-amber-400',
      badgeClass: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
      barGradient: 'from-amber-500 to-yellow-400',
    };
  }
  return {
    textClass: 'text-red-400',
    badgeClass: 'bg-red-500/20 text-red-300 border-red-500/40',
    barGradient: 'from-red-600 to-rose-500',
  };
}

