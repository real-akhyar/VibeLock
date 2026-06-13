import { useState } from 'react';
import { Github, CheckCircle, Copy, ExternalLink, Loader2, AlertTriangle, ArrowRight } from 'lucide-react';
import api, { StartSetupResponse, CompleteSetupResponse, InstallationsResponse } from '@/lib/api';
import { useApi } from '@/hooks/useApi';
import LoadingSpinner from '@/components/LoadingSpinner';
import ErrorDisplay from '@/components/ErrorDisplay';

export default function GitHubSetupPage() {
  const [setupData, setSetupData] = useState<StartSetupResponse | null>(null);
  const [setupLoading, setSetupLoading] = useState(false);
  const [setupError, setSetupError] = useState<string | null>(null);

  const [code, setCode] = useState('');
  const [completeLoading, setCompleteLoading] = useState(false);
  const [completeResult, setCompleteResult] = useState<CompleteSetupResponse | null>(null);
  const [completeError, setCompleteError] = useState<string | null>(null);

  const { data: installations, loading: instLoading, error: instError, refetch: refetchInst } = useApi(
    () => api.getInstallations(),
    [],
  );

  const handleStartSetup = async () => {
    setSetupLoading(true);
    setSetupError(null);
    try {
      const result = await api.startSetup({});
      setSetupData(result);
    } catch (e: any) {
      setSetupError(e.message || 'Failed to start setup');
    } finally {
      setSetupLoading(false);
    }
  };

  const handleCompleteSetup = async () => {
    if (!code.trim()) return;
    setCompleteLoading(true);
    setCompleteError(null);
    try {
      const result = await api.completeSetup({ code: code.trim() });
      setCompleteResult(result);
      if (result.success) refetchInst();
    } catch (e: any) {
      setCompleteError(e.message || 'Failed to complete setup');
    } finally {
      setCompleteLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-2xl font-bold">GitHub App Setup</h2>
        <p className="text-surface-400 text-sm mt-1">Connect VibeLock to your GitHub repositories</p>
      </div>

      {/* Step 1: Start Setup */}
      <div className="card">
        <h3 className="text-lg font-semibold mb-1">Step 1: Create GitHub App</h3>
        <p className="text-surface-400 text-sm mb-4">
          This will open GitHub's app creation page with VibeLock's manifest pre-filled.
        </p>

        {!setupData ? (
          <button onClick={handleStartSetup} disabled={setupLoading} className="btn-primary">
            {setupLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Github className="w-4 h-4" />}
            Start GitHub App Setup
          </button>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-emerald-400">
              <CheckCircle className="w-4 h-4" />
              <span className="text-sm font-medium">Manifest created</span>
            </div>
            <a
              href={setupData.flow_url}
              target="_blank"
              rel="noopener noreferrer"
              className="btn-primary inline-flex"
            >
              <ExternalLink className="w-4 h-4" /> Open GitHub Setup Page
            </a>
            <div className="bg-surface-800 rounded-lg p-4">
              <p className="text-sm font-medium text-surface-300 mb-2">Instructions:</p>
              <ul className="space-y-1">
                {setupData.instructions.map((inst, i) => (
                  <li key={i} className="text-sm text-surface-400 flex items-start gap-2">
                    <ArrowRight className="w-3 h-3 mt-1 shrink-0" /> {inst}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {setupError && (
          <div className="mt-3 flex items-center gap-2 text-red-400 text-sm">
            <AlertTriangle className="w-4 h-4" /> {setupError}
          </div>
        )}
      </div>

      {/* Step 2: Complete Setup */}
      <div className="card">
        <h3 className="text-lg font-semibold mb-1">Step 2: Enter Setup Code</h3>
        <p className="text-surface-400 text-sm mb-4">
          After creating the app, GitHub redirects you with a code. Paste it here.
        </p>

        <div className="flex gap-3">
          <input
            className="input flex-1 font-mono"
            placeholder="Paste code from GitHub redirect..."
            value={code}
            onChange={e => setCode(e.target.value)}
          />
          <button onClick={handleCompleteSetup} disabled={completeLoading || !code.trim()} className="btn-primary">
            {completeLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Complete Setup'}
          </button>
        </div>

        {completeResult && (
          <div className={`mt-4 p-4 rounded-lg ${completeResult.success ? 'bg-emerald-900/30 border border-emerald-800' : 'bg-red-900/30 border border-red-800'}`}>
            {completeResult.success ? (
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-emerald-400">
                  <CheckCircle className="w-4 h-4" />
                  <span className="font-medium">Setup Complete!</span>
                </div>
                <div className="text-sm text-surface-300 space-y-1">
                  <p>App ID: <span className="font-mono">{completeResult.app_id}</span></p>
                  <p>App Name: {completeResult.app_name}</p>
                  <p>Owner: {completeResult.owner}</p>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-red-400">
                <AlertTriangle className="w-4 h-4" />
                <span>{completeResult.error}</span>
              </div>
            )}
          </div>
        )}

        {completeError && (
          <div className="mt-3 flex items-center gap-2 text-red-400 text-sm">
            <AlertTriangle className="w-4 h-4" /> {completeError}
          </div>
        )}
      </div>

      {/* Step 3: Installations */}
      <div className="card">
        <h3 className="text-lg font-semibold mb-1">Installed Organizations</h3>
        <p className="text-surface-400 text-sm mb-4">GitHub organizations where VibeLock is installed</p>

        {instLoading ? (
          <LoadingSpinner message="Loading installations..." />
        ) : instError ? (
          <ErrorDisplay message={instError} onRetry={refetchInst} />
        ) : installations && installations.count > 0 ? (
          <div className="space-y-2">
            {installations.installations.map((inst: any, i: number) => (
              <div key={i} className="flex items-center justify-between p-3 bg-surface-800 rounded-lg">
                <div className="flex items-center gap-3">
                  <Github className="w-5 h-5 text-surface-400" />
                  <div>
                    <p className="text-sm font-medium">{inst.account?.login || 'Unknown'}</p>
                    <p className="text-xs text-surface-500">ID: {inst.id}</p>
                  </div>
                </div>
                <span className="badge-success">Active</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8 text-surface-500">
            <Github className="w-10 h-10 mx-auto mb-3 opacity-50" />
            <p className="text-sm">No installations yet</p>
            <p className="text-xs mt-1">Complete Steps 1-2 to install VibeLock on your repositories</p>
          </div>
        )}
      </div>
    </div>
  );
}