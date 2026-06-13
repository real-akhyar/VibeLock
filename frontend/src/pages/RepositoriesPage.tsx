import { GitBranch, AlertTriangle, ExternalLink } from 'lucide-react';
import { useApi } from '@/hooks/useApi';
import api from '@/lib/api';
import { formatNumber } from '@/lib/utils';
import LoadingSpinner from '@/components/LoadingSpinner';
import ErrorDisplay from '@/components/ErrorDisplay';

export default function RepositoriesPage() {
  const { data, loading, error, refetch } = useApi(
    () => api.getRepositories(undefined, 50),
    [],
  );

  if (loading) return <LoadingSpinner />;
  if (error) return <ErrorDisplay message={error} onRetry={refetch} />;
  if (!data) return null;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Repositories</h2>
        <p className="text-surface-400 text-sm mt-1">Security overview per repository</p>
      </div>

      {data.length === 0 ? (
        <div className="card text-center py-16">
          <GitBranch className="w-12 h-12 text-surface-600 mx-auto mb-4" />
          <p className="text-surface-400">No repositories scanned yet</p>
          <p className="text-surface-500 text-sm mt-1">Install the GitHub App to start scanning</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {data.map((repo) => (
            <div key={repo.repository} className="card hover:border-surface-600 transition-colors">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <GitBranch className="w-4 h-4 text-brand-400" />
                  <h3 className="font-semibold text-surface-200 truncate">{repo.repository}</h3>
                </div>
                <a
                  href={`https://github.com/${repo.repository}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-surface-600 hover:text-surface-400"
                >
                  <ExternalLink className="w-4 h-4" />
                </a>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-2xl font-bold">{formatNumber(repo.total_vulns)}</p>
                  <p className="text-xs text-surface-500">Total</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-red-400">{formatNumber(repo.critical)}</p>
                  <p className="text-xs text-surface-500">Critical</p>
                </div>
              </div>

              <div className="mt-3 pt-3 border-t border-surface-700 flex items-center justify-between">
                <div className="flex gap-2">
                  {repo.critical > 0 && (
                    <span className="flex items-center gap-1 text-xs text-red-400">
                      <AlertTriangle className="w-3 h-3" /> {repo.critical}
                    </span>
                  )}
                  {repo.high > 0 && (
                    <span className="text-xs text-orange-400">{repo.high} high</span>
                  )}
                </div>
                {repo.open_prs > 0 && (
                  <span className="text-xs text-purple-400">{repo.open_prs} open PRs</span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}