import { useApi } from '@/hooks/useApi';
import api from '@/lib/api';
import { formatNumber } from '@/lib/utils';
import StatCard from './StatCard';
import LoadingSpinner from './LoadingSpinner';
import ErrorDisplay from './ErrorDisplay';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  GitBranch,
  Activity,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
} from 'recharts';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f87171',
  high: '#fb923c',
  medium: '#facc15',
  low: '#60a5fa',
};

export default function DashboardOverview() {
  const { data, loading, error, refetch } = useApi(
    () => api.getFullDashboard(undefined, 30),
    [],
  );

  if (loading) return <LoadingSpinner message="Loading dashboard..." />;
  if (error) return <ErrorDisplay message={error} onRetry={refetch} />;
  if (!data) return null;

  const { summary, trends, scans, top_repositories } = data;

  const severityData = Object.entries(summary.by_severity)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));

  return (
    <div className="space-y-6">
      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Vulnerabilities"
          value={formatNumber(summary.total)}
          icon={<Shield className="w-5 h-5 text-brand-400" />}
        />
        <StatCard
          label="Critical"
          value={formatNumber(summary.by_severity.critical || 0)}
          icon={<AlertTriangle className="w-5 h-5 text-red-400" />}
          className="border-red-900/30"
        />
        <StatCard
          label="Resolved"
          value={formatNumber(summary.by_status.resolved || 0)}
          icon={<CheckCircle className="w-5 h-5 text-emerald-400" />}
        />
        <StatCard
          label="Avg Scan Time"
          value={scans.avg_scan_duration_seconds ? `${scans.avg_scan_duration_seconds}s` : '—'}
          icon={<Clock className="w-5 h-5 text-amber-400" />}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Trend Chart */}
        <div className="card">
          <h3 className="text-sm font-semibold text-surface-300 mb-4">Vulnerability Trends (30 days)</h3>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={trends}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis
                dataKey="date"
                tick={{ fontSize: 11, fill: '#64748b' }}
                tickFormatter={(v: string) => v.slice(5)}
              />
              <YAxis tick={{ fontSize: 11, fill: '#64748b' }} />
              <Tooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
              />
              <Area type="monotone" dataKey="detected" stroke="#f87171" fill="#f8717120" strokeWidth={2} />
              <Area type="monotone" dataKey="resolved" stroke="#34d399" fill="#34d39920" strokeWidth={2} />
              <Area type="monotone" dataKey="open" stroke="#facc15" fill="#facc1520" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div className="card">
          <h3 className="text-sm font-semibold text-surface-300 mb-4">Severity Distribution</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: '#64748b' }} />
                <YAxis tick={{ fontSize: 11, fill: '#64748b' }} />
                <Tooltip
                  contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#6366f1'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[250px] text-surface-500 text-sm">
              No vulnerability data yet
            </div>
          )}
        </div>
      </div>

      {/* Scan Stats + Top Repos */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Scan Stats */}
        <div className="card">
          <h3 className="text-sm font-semibold text-surface-300 mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4" /> Scan Activity
          </h3>
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center">
              <p className="text-2xl font-bold">{formatNumber(scans.total_scans)}</p>
              <p className="text-xs text-surface-500 mt-1">Total</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-emerald-400">{formatNumber(scans.completed_scans)}</p>
              <p className="text-xs text-surface-500 mt-1">Completed</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-red-400">{formatNumber(scans.failed_scans)}</p>
              <p className="text-xs text-surface-500 mt-1">Failed</p>
            </div>
          </div>
        </div>

        {/* Top Repositories */}
        <div className="card">
          <h3 className="text-sm font-semibold text-surface-300 mb-4 flex items-center gap-2">
            <GitBranch className="w-4 h-4" /> Top Repositories
          </h3>
          {top_repositories.length > 0 ? (
            <div className="space-y-3">
              {top_repositories.slice(0, 5).map((repo) => (
                <div key={repo.repository} className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-surface-200 truncate">{repo.repository}</p>
                    <div className="flex gap-2 mt-1">
                      {repo.critical > 0 && (
                        <span className="text-xs text-red-400">{repo.critical} critical</span>
                      )}
                      {repo.high > 0 && (
                        <span className="text-xs text-orange-400">{repo.high} high</span>
                      )}
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-semibold">{formatNumber(repo.total_vulns)}</p>
                    {repo.open_prs > 0 && (
                      <p className="text-xs text-purple-400">{repo.open_prs} open PRs</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-surface-500 text-sm text-center py-8">No repositories scanned yet</p>
          )}
        </div>
      </div>
    </div>
  );
}