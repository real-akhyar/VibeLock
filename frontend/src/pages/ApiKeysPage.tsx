import { useState } from 'react';
import { Key, Copy, Trash2, Shield, Loader2, AlertTriangle, CheckCircle, Eye, EyeOff } from 'lucide-react';
import api, { ApiKeyCreated, ApiKeyMetadata } from '@/lib/api';
import { useApi } from '@/hooks/useApi';
import { formatDate } from '@/lib/utils';
import LoadingSpinner from '@/components/LoadingSpinner';
import ErrorDisplay from '@/components/ErrorDisplay';

export default function ApiKeysPage() {
  const [orgId, setOrgId] = useState('');
  const [creating, setCreating] = useState(false);
  const [createdKey, setCreatedKey] = useState<ApiKeyCreated | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);
  const [showKey, setShowKey] = useState(false);

  const [revoking, setRevoking] = useState(false);
  const [revokeError, setRevokeError] = useState<string | null>(null);
  const [revokedMsg, setRevokedMsg] = useState<string | null>(null);

  const { data: keyMeta, loading, error, refetch } = useApi(
    () => orgId ? api.getApiKeyMetadata(orgId) : Promise.resolve(null),
    [orgId],
  );

  const handleCreate = async () => {
    if (!orgId.trim()) return;
    setCreating(true);
    setCreateError(null);
    setCreatedKey(null);
    try {
      const result = await api.createApiKey(orgId.trim());
      setCreatedKey(result);
      refetch();
    } catch (e: any) {
      setCreateError(e.message || 'Failed to create API key');
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async () => {
    if (!orgId.trim()) return;
    setRevoking(true);
    setRevokeError(null);
    setRevokedMsg(null);
    try {
      const result = await api.revokeApiKey(orgId.trim());
      setRevokedMsg(result.message);
      setCreatedKey(null);
      refetch();
    } catch (e: any) {
      setRevokeError(e.message || 'Failed to revoke API key');
    } finally {
      setRevoking(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-2xl font-bold">API Keys</h2>
        <p className="text-surface-400 text-sm mt-1">Manage organization-level API keys for CI/CD integration</p>
      </div>

      {/* Organization Selector */}
      <div className="card">
        <label className="text-sm font-medium text-surface-300 mb-2 block">Organization ID</label>
        <div className="flex gap-3">
          <input
            className="input flex-1 font-mono"
            placeholder="Enter organization UUID..."
            value={orgId}
            onChange={e => setOrgId(e.target.value)}
          />
          <button onClick={() => refetch()} className="btn-secondary" disabled={!orgId.trim()}>
            Load
          </button>
        </div>
      </div>

      {!orgId ? (
        <div className="card text-center py-16">
          <Key className="w-12 h-12 text-surface-600 mx-auto mb-4" />
          <p className="text-surface-400">Enter an organization ID to manage its API keys</p>
        </div>
      ) : loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorDisplay message={error} onRetry={refetch} />
      ) : (
        <>
          {/* Current Key Status */}
          <div className="card">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5 text-brand-400" /> Key Status
            </h3>

            {keyMeta ? (
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <div className={`w-3 h-3 rounded-full ${keyMeta.is_active ? 'bg-emerald-500' : 'bg-red-500'}`} />
                  <span className="text-sm font-medium">
                    {keyMeta.is_active ? 'Active' : 'Inactive'}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-surface-500">Prefix</p>
                    <p className="font-mono">{keyMeta.prefix}</p>
                  </div>
                  <div>
                    <p className="text-surface-500">Created</p>
                    <p>{formatDate(keyMeta.created_at)}</p>
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-surface-500 text-sm">No API key configured for this organization</p>
            )}
          </div>

          {/* Create Key */}
          <div className="card">
            <h3 className="text-lg font-semibold mb-4">Create / Rotate Key</h3>
            <p className="text-surface-400 text-sm mb-4">
              Creates a new <code className="bg-surface-800 px-1.5 py-0.5 rounded text-xs">vl_</code> prefixed key.
              If a key already exists, it will be rotated (old key invalidated).
            </p>

            <button onClick={handleCreate} disabled={creating} className="btn-primary">
              {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
              {keyMeta?.is_active ? 'Rotate Key' : 'Create Key'}
            </button>

            {createdKey && (
              <div className="mt-4 p-4 bg-emerald-900/30 border border-emerald-800 rounded-lg space-y-3">
                <div className="flex items-center gap-2 text-emerald-400">
                  <CheckCircle className="w-4 h-4" />
                  <span className="font-medium">Key Created!</span>
                </div>
                <div className="bg-surface-950 rounded-lg p-3 flex items-center justify-between">
                  <code className="text-sm font-mono text-surface-200 break-all">
                    {showKey ? createdKey.api_key : 'vl_' + '•'.repeat(40)}
                  </code>
                  <div className="flex gap-1 ml-2 shrink-0">
                    <button onClick={() => setShowKey(!showKey)} className="btn-ghost p-1.5">
                      {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                    <button onClick={() => copyToClipboard(createdKey.api_key)} className="btn-ghost p-1.5">
                      <Copy className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                <p className="text-xs text-amber-400 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" /> {createdKey.warning}
                </p>
              </div>
            )}

            {createError && (
              <div className="mt-3 flex items-center gap-2 text-red-400 text-sm">
                <AlertTriangle className="w-4 h-4" /> {createError}
              </div>
            )}
          </div>

          {/* Revoke Key */}
          {keyMeta?.is_active && (
            <div className="card border-red-900/30">
              <h3 className="text-lg font-semibold text-red-400 mb-4 flex items-center gap-2">
                <Trash2 className="w-5 h-5" /> Revoke Key
              </h3>
              <p className="text-surface-400 text-sm mb-4">
                This will immediately invalidate the current API key. All services using it will lose access.
              </p>

              <button onClick={handleRevoke} disabled={revoking} className="px-4 py-2 bg-red-900/50 hover:bg-red-800 text-red-400 rounded-lg font-medium transition-colors inline-flex items-center gap-2 disabled:opacity-50">
                {revoking ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                Revoke Key
              </button>

              {revokedMsg && (
                <div className="mt-3 flex items-center gap-2 text-emerald-400 text-sm">
                  <CheckCircle className="w-4 h-4" /> {revokedMsg}
                </div>
              )}

              {revokeError && (
                <div className="mt-3 flex items-center gap-2 text-red-400 text-sm">
                  <AlertTriangle className="w-4 h-4" /> {revokeError}
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}