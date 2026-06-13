import { Activity, Database, Server, Clock, RefreshCw } from 'lucide-react';
import { usePolling } from '@/hooks/useApi';
import api from '@/lib/api';
import { formatDate } from '@/lib/utils';
import LoadingSpinner from '@/components/LoadingSpinner';
import ErrorDisplay from '@/components/ErrorDisplay';

export default function HealthPage() {
  const { data, loading, error, refetch } = usePolling(
    () => api.getDashboardHealth(),
    15000,
  );

  if (loading && !data) return <LoadingSpinner message="Checking system health..." />;
  if (error && !data) return <ErrorDisplay message={error} onRetry={refetch} />;
  if (!data) return null;

  const isHealthy = data.status === 'ok';

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">System Health</h2>
          <p className="text-surface-400 text-sm mt-1">Real-time service status</p>
        </div>
        <button onClick={refetch} className="btn-secondary text-sm">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Overall Status */}
      <div className={`card border-2 ${isHealthy ? 'border-emerald-800' : 'border-amber-800'}`}>
        <div className="flex items-center gap-4">
          <div className={`p-3 rounded-full ${isHealthy ? 'bg-emerald-900/50' : 'bg-amber-900/50'}`}>
            <Activity className={`w-8 h-8 ${isHealthy ? 'text-emerald-400' : 'text-amber-400'}`} />
          </div>
          <div>
            <h3 className="text-xl font-bold">{isHealthy ? 'All Systems Operational' : 'Degraded Service'}</h3>
            <p className="text-surface-400 text-sm">
              Last checked: {formatDate(data.timestamp)}
            </p>
          </div>
        </div>
      </div>

      {/* Service Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Supabase */}
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <Database className="w-5 h-5 text-brand-400" />
            <h3 className="font-semibold">Supabase</h3>
            <span className={`ml-auto px-2 py-0.5 rounded text-xs font-medium ${
              data.supabase?.connected
                ? 'bg-emerald-900/50 text-emerald-400 border border-emerald-800'
                : 'bg-red-900/50 text-red-400 border border-red-800'
            }`}>
              {data.supabase?.connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          {data.supabase?.error && (
            <p className="text-sm text-red-400 bg-red-900/20 rounded-lg p-3">{String(data.supabase.error)}</p>
          )}
          {data.supabase?.connected && (
            <p className="text-sm text-surface-500">Database connection is healthy</p>
          )}
        </div>

        {/* Redis */}
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <Server className="w-5 h-5 text-brand-400" />
            <h3 className="font-semibold">Redis</h3>
            <span className={`ml-auto px-2 py-0.5 rounded text-xs font-medium ${
              data.redis?.connected
                ? 'bg-emerald-900/50 text-emerald-400 border border-emerald-800'
                : 'bg-red-900/50 text-red-400 border border-red-800'
            }`}>
              {data.redis?.connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          {data.redis?.error && (
            <p className="text-sm text-red-400 bg-red-900/20 rounded-lg p-3">{String(data.redis.error)}</p>
          )}
          {data.redis?.connected && (
            <p className="text-sm text-surface-500">Message queue is operational</p>
          )}
        </div>
      </div>

      {/* Last Scan */}
      <div className="card">
        <div className="flex items-center gap-3">
          <Clock className="w-5 h-5 text-surface-400" />
          <div>
            <h3 className="font-semibold">Last Scan</h3>
            <p className="text-sm text-surface-400">
              {data.last_scan_at ? formatDate(data.last_scan_at) : 'No scans completed yet'}
            </p>
          </div>
        </div>
      </div>

      {/* Raw JSON for debugging */}
      <details className="card">
        <summary className="cursor-pointer text-sm font-medium text-surface-400">Raw Health Data</summary>
        <pre className="mt-3 text-xs font-mono text-surface-500 overflow-x-auto bg-surface-950 rounded-lg p-4">
          {JSON.stringify(data, null, 2)}
        </pre>
      </details>
    </div>
  );
}