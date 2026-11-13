import { format, formatDistanceToNow, parseISO, isValid } from 'date-fns';
import { AlertSeverity, DeviceStatus } from '../types';

// ─── Date / Time ─────────────────────────────────────────────

export function formatDate(dateStr: string | undefined | null): string {
  if (!dateStr) return '—';
  try {
    const d = parseISO(dateStr);
    return isValid(d) ? format(d, 'MMM dd, yyyy') : '—';
  } catch {
    return '—';
  }
}

export function formatDateTime(dateStr: string | undefined | null): string {
  if (!dateStr) return '—';
  try {
    const d = parseISO(dateStr);
    return isValid(d) ? format(d, 'MMM dd, yyyy HH:mm:ss') : '—';
  } catch {
    return '—';
  }
}

export function formatTimeAgo(dateStr: string | undefined | null): string {
  if (!dateStr) return '—';
  try {
    const d = parseISO(dateStr);
    return isValid(d) ? formatDistanceToNow(d, { addSuffix: true }) : '—';
  } catch {
    return '—';
  }
}

export function formatTime(dateStr: string | undefined | null): string {
  if (!dateStr) return '—';
  try {
    const d = parseISO(dateStr);
    return isValid(d) ? format(d, 'HH:mm:ss') : '—';
  } catch {
    return '—';
  }
}

// ─── Bytes ───────────────────────────────────────────────────

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

// ─── Severity ────────────────────────────────────────────────

export function severityToColor(severity: AlertSeverity): {
  text: string;
  bg: string;
  border: string;
  dot: string;
} {
  switch (severity) {
    case AlertSeverity.CRITICAL:
      return {
        text: 'text-red-400',
        bg: 'bg-red-900/20',
        border: 'border-red-700',
        dot: 'bg-red-400',
      };
    case AlertSeverity.HIGH:
      return {
        text: 'text-orange-400',
        bg: 'bg-orange-900/20',
        border: 'border-orange-700',
        dot: 'bg-orange-400',
      };
    case AlertSeverity.MEDIUM:
      return {
        text: 'text-yellow-400',
        bg: 'bg-yellow-900/20',
        border: 'border-yellow-700',
        dot: 'bg-yellow-400',
      };
    case AlertSeverity.LOW:
      return {
        text: 'text-blue-400',
        bg: 'bg-blue-900/20',
        border: 'border-blue-700',
        dot: 'bg-blue-400',
      };
    case AlertSeverity.INFO:
    default:
      return {
        text: 'text-gray-400',
        bg: 'bg-gray-800',
        border: 'border-gray-700',
        dot: 'bg-gray-400',
      };
  }
}

// ─── Device Status ───────────────────────────────────────────

export function deviceStatusToColor(status: DeviceStatus): {
  text: string;
  bg: string;
  dot: string;
} {
  switch (status) {
    case DeviceStatus.ONLINE:
      return { text: 'text-emerald-700', bg: 'bg-emerald-50', dot: 'bg-emerald-600' };
    case DeviceStatus.APPROVED:
      return { text: 'text-[#0078d4]', bg: 'bg-blue-50', dot: 'bg-[#0078d4]' };
    case DeviceStatus.PENDING:
      return { text: 'text-amber-800', bg: 'bg-amber-50', dot: 'bg-amber-600' };
    case DeviceStatus.REVOKED:
      return { text: 'text-red-700', bg: 'bg-red-50', dot: 'bg-red-600' };
    case DeviceStatus.OFFLINE:
    default:
      return { text: 'text-slate-600', bg: 'bg-slate-100', dot: 'bg-slate-400' };
  }
}

// ─── Risk Score ──────────────────────────────────────────────

export function riskScoreToColor(score: number): string {
  if (score >= 80) return 'text-red-700';
  if (score >= 60) return 'text-orange-700';
  if (score >= 40) return 'text-amber-800';
  if (score >= 20) return 'text-[#0078d4]';
  return 'text-emerald-700';
}

export function riskScoreToLabel(score: number): string {
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 40) return 'Medium';
  if (score >= 20) return 'Low';
  return 'Minimal';
}

// ─── OS Icons / Names ────────────────────────────────────────

export function osToIconName(osName: string): string {
  const lower = osName.toLowerCase();
  if (lower.includes('windows')) return 'windows';
  if (lower.includes('ubuntu') || lower.includes('debian') || lower.includes('linux')) return 'linux';
  if (lower.includes('mac') || lower.includes('darwin')) return 'macos';
  if (lower.includes('centos') || lower.includes('rhel') || lower.includes('fedora')) return 'linux';
  return 'unknown';
}

export function truncate(str: string, maxLen = 40): string {
  return str.length > maxLen ? `${str.slice(0, maxLen)}…` : str;
}

export function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
}

export function severityLabel(severity: AlertSeverity): string {
  return capitalize(severity);
}

export function statusLabel(status: string): string {
  return status.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}
