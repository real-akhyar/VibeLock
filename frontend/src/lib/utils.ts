import { clsx, type ClassValue } from 'clsx';

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

export function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'text-red-400';
    case 'high': return 'text-orange-400';
    case 'medium': return 'text-yellow-400';
    case 'low': return 'text-blue-400';
    default: return 'text-surface-400';
  }
}

export function severityBg(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-900/50 border-red-800 text-red-400';
    case 'high': return 'bg-orange-900/50 border-orange-800 text-orange-400';
    case 'medium': return 'bg-yellow-900/50 border-yellow-800 text-yellow-400';
    case 'low': return 'bg-blue-900/50 border-blue-800 text-blue-400';
    default: return 'bg-surface-800 border-surface-600 text-surface-400';
  }
}

export function statusColor(status: string): string {
  switch (status) {
    case 'resolved':
    case 'merged': return 'text-emerald-400';
    case 'pr_opened': return 'text-purple-400';
    case 'patching': return 'text-amber-400';
    case 'detected': return 'text-red-400';
    default: return 'text-surface-400';
  }
}

export function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}