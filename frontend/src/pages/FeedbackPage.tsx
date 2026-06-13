import { useState } from 'react';
import { Bug, Send, Loader2, AlertTriangle, CheckCircle, BarChart3 } from 'lucide-react';
import api from '@/lib/api';
import { useApi } from '@/hooks/useApi';
import { formatNumber } from '@/lib/utils';
import LoadingSpinner from '@/components/LoadingSpinner';
import ErrorDisplay from '@/components/ErrorDisplay';

export default function FeedbackPage() {
  const [vulnId, setVulnId] = useState('');
  const [repo, setRepo] = useState('');
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState(false);

  const { data: stats, loading, error, refetch } = useApi(
    () => api.getFeedbackStats(30),
    [],
  );

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vulnId.trim() || !repo.trim() || !reason.trim()) return;

    setSubmitting(true);
    setSubmitError(null);
    setSubmitSuccess(false);

    try {
      await api.submitFalsePositive({
        vulnerability_id: vulnId.trim(),
        repository: repo.trim(),
        reason: reason.trim(),
        marked_by: 'dashboard-user',
      });
      setSubmitSuccess(true);
      setVulnId('');
      setRepo('');
      setReason('');
      refetch();
    } catch (e: any) {
      setSubmitError(e.message || 'Failed to submit feedback');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-2xl font-bold">False Positive Feedback</h2>
        <p className="text-surface-400 text-sm mt-1">Mark vulnerabilities as false positives to improve detection accuracy</p>
      </div>

      {/* Submit Form */}
      <div className="card">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Bug className="w-5 h-5 text-brand-400" /> Report False Positive
        </h3>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium text-surface-300 mb-1.5 block">Vulnerability ID</label>
              <input
                className="input font-mono text-sm"
                placeholder="UUID of the vulnerability"
                value={vulnId}
                onChange={e => setVulnId(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="text-sm font-medium text-surface-300 mb-1.5 block">Repository</label>
              <input
                className="input"
                placeholder="owner/repo"
                value={repo}
                onChange={e => setRepo(e.target.value)}
                required
              />
            </div>
          </div>

          <div>
            <label className="text-sm font-medium text-surface-300 mb-1.5 block">Reason</label>
            <textarea
              className="input min-h-[100px] resize-y"
              placeholder="Explain why this is a false positive..."
              value={reason}
              onChange={e => setReason(e.target.value)}
              required
            />
          </div>

          <button type="submit" disabled={submitting} className="btn-primary">
            {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            Submit Feedback
          </button>
        </form>

        {submitSuccess && (
          <div className="mt-4 flex items-center gap-2 text-emerald-400 text-sm">
            <CheckCircle className="w-4 h-4" /> Feedback submitted successfully
          </div>
        )}
        {submitError && (
          <div className="mt-4 flex items-center gap-2 text-red-400 text-sm">
            <AlertTriangle className="w-4 h-4" /> {submitError}
          </div>
        )}
      </div>

      {/* Stats */}
      <div className="card">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <BarChart3 className="w-5 h-5 text-brand-400" /> Feedback Statistics
        </h3>

        {loading ? (
          <LoadingSpinner />
        ) : error ? (
          <ErrorDisplay message={error} onRetry={refetch} />
        ) : stats ? (
          <div className="space-y-6">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="bg-surface-800 rounded-lg p-4 text-center">
                <p className="text-2xl font-bold text-brand-400">{formatNumber(stats.total_false_positives)}</p>
                <p className="text-xs text-surface-500 mt-1">Total False Positives</p>
              </div>
              <div className="bg-surface-800 rounded-lg p-4 text-center">
                <p className="text-2xl font-bold">{Object.keys(stats.by_rule).length}</p>
                <p className="text-xs text-surface-500 mt-1">Affected Rules</p>
              </div>
              <div className="bg-surface-800 rounded-lg p-4 text-center">
                <p className="text-2xl font-bold">{Object.keys(stats.by_repository).length}</p>
                <p className="text-xs text-surface-500 mt-1">Affected Repos</p>
              </div>
            </div>

            {Object.keys(stats.by_rule).length > 0 && (
              <div>
                <h4 className="text-sm font-semibold text-surface-300 mb-3">By Detection Rule</h4>
                <div className="space-y-2">
                  {Object.entries(stats.by_rule)
                    .sort(([, a], [, b]) => b - a)
                    .map(([rule, count]) => (
                      <div key={rule} className="flex items-center justify-between p-2 bg-surface-800 rounded-lg">
                        <span className="text-sm font-mono text-surface-300">{rule}</span>
                        <span className="text-sm text-surface-400">{count}</span>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {stats.recent.length > 0 && (
              <div>
                <h4 className="text-sm font-semibold text-surface-300 mb-3">Recent Submissions</h4>
                <div className="space-y-2">
                  {stats.recent.map((entry: any, i: number) => (
                    <div key={i} className="p-3 bg-surface-800 rounded-lg">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-mono text-surface-300 text-xs">{entry.vulnerability_id?.slice(0, 12)}...</span>
                        <span className="text-xs text-surface-500">{entry.repository}</span>
                      </div>
                      <p className="text-xs text-surface-400 line-clamp-2">{entry.reason}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <p className="text-surface-500 text-sm text-center py-8">No feedback data available</p>
        )}
      </div>
    </div>
  );
}