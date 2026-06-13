const API_BASE = '/api/v1';

interface RequestOptions {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
}

class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
    this.name = 'ApiError';
  }
}

async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, headers = {} } = options;

  const token = localStorage.getItem('vibelock_token');
  const apiKey = localStorage.getItem('vibelock_api_key');

  const reqHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    ...headers,
  };

  if (token) {
    reqHeaders['Authorization'] = `Bearer ${token}`;
  }
  if (apiKey) {
    reqHeaders['X-VibeLock-API-Key'] = apiKey;
  }

  const res = await fetch(`${API_BASE}${endpoint}`, {
    method,
    headers: reqHeaders,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new ApiError(text || res.statusText, res.status);
  }

  return res.json();
}

// --- Dashboard ---

export interface VulnerabilitySummary {
  total: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
  by_status: Record<string, number>;
}

export interface TrendPoint {
  date: string;
  detected: number;
  resolved: number;
  open: number;
}

export interface ScanStats {
  total_scans: number;
  completed_scans: number;
  failed_scans: number;
  avg_scan_duration_seconds: number | null;
}

export interface RepositoryStats {
  repository: string;
  total_vulns: number;
  critical: number;
  high: number;
  open_prs: number;
}

export interface DashboardFull {
  summary: VulnerabilitySummary;
  trends: TrendPoint[];
  scans: ScanStats;
  top_repositories: RepositoryStats[];
  generated_at: string;
}

export interface PaginatedVulns {
  data: VulnItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface VulnItem {
  id: string;
  vulnerability_type: string;
  severity: string;
  file_path: string;
  line_number: number | null;
  description: string;
  code_snippet: string | null;
  remediation_status: string;
  created_at: string;
  repository: string;
  repository_id: string;
}

export interface VulnDetail {
  id: string;
  vulnerability_type: string;
  severity: string;
  file_path: string;
  line_number: number | null;
  description: string;
  code_snippet: string | null;
  remediation_status: string;
  created_at: string;
  repository: string;
  scan: Record<string, unknown> | null;
  pull_requests: Record<string, unknown>[];
}

export interface OrgSummary {
  id: string;
  org_name: string;
  plan_tier: string;
  repo_count: number;
  total_vulns: number;
  open_critical: number;
  last_scan_at: string | null;
}

export interface DashboardHealth {
  status: string;
  supabase: Record<string, unknown>;
  redis: Record<string, unknown>;
  last_scan_at: string | null;
  timestamp: string;
}

// --- GitHub Setup ---

export interface StartSetupResponse {
  setup_id: string | null;
  manifest: Record<string, unknown>;
  flow_url: string;
  instructions: string[];
}

export interface CompleteSetupResponse {
  success: boolean;
  app_id: number | null;
  app_name: string | null;
  owner: string | null;
  webhook_secret: string | null;
  error: string | null;
}

export interface SetupStatusResponse {
  setup_id: string;
  setup_complete: boolean;
  app_id: number | null;
  org_id: string | null;
  manifest_flow_url: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface InstallationsResponse {
  installations: Record<string, unknown>[];
  count: number;
}

// --- API Keys ---

export interface ApiKeyCreated {
  api_key: string;
  prefix: string;
  created_at: string;
  warning: string;
}

export interface ApiKeyMetadata {
  prefix: string;
  created_at: string | null;
  last_used_at: string | null;
  is_active: boolean;
}

export interface ApiKeyRevoked {
  message: string;
  org_id: string;
  revoked_at: string;
}

// --- Feedback ---

export interface FeedbackEntry {
  vulnerability_id: string;
  repository: string;
  reason: string;
  marked_by: string;
  pattern_signature?: string;
}

export interface FeedbackStats {
  total_false_positives: number;
  by_rule: Record<string, number>;
  by_repository: Record<string, number>;
  recent: Record<string, unknown>[];
}

// --- Auth ---

export interface LoginResponse {
  access_token: string;
  token_type: string;
}

// --- API Functions ---

export const api = {
  // Dashboard
  getSummary: (orgId?: string, days?: number) =>
    request<VulnerabilitySummary>(`/dashboard/summary?${qs({ organization_id: orgId, days })}`),

  getTrends: (orgId?: string, days?: number) =>
    request<TrendPoint[]>(`/dashboard/trends?${qs({ organization_id: orgId, days })}`),

  getScanStats: (orgId?: string, days?: number) =>
    request<ScanStats>(`/dashboard/scans?${qs({ organization_id: orgId, days })}`),

  getRepositories: (orgId?: string, limit?: number) =>
    request<RepositoryStats[]>(`/dashboard/repositories?${qs({ organization_id: orgId, limit })}`),

  getFullDashboard: (orgId?: string, days?: number) =>
    request<DashboardFull>(`/dashboard/full?${qs({ organization_id: orgId, days })}`),

  getVulnerabilities: (params: {
    page?: number;
    page_size?: number;
    severity?: string;
    type?: string;
    status?: string;
    repository_id?: string;
    organization_id?: string;
  }) => request<PaginatedVulns>(`/dashboard/vulnerabilities?${qs(params)}`),

  getVulnerabilityDetail: (id: string) =>
    request<VulnDetail>(`/dashboard/vulnerabilities/${id}`),

  getOrganizations: () =>
    request<OrgSummary[]>('/dashboard/organizations'),

  getDashboardHealth: () =>
    request<DashboardHealth>('/dashboard/health'),

  // Feedback
  submitFalsePositive: (entry: FeedbackEntry) =>
    request<Record<string, unknown>>('/dashboard/feedback/false-positive', { method: 'POST', body: entry }),

  getFeedbackStats: (days?: number) =>
    request<FeedbackStats>(`/dashboard/feedback/stats?${qs({ days })}`),

  // GitHub Setup
  startSetup: (body: { org_id?: string; webhook_url?: string; app_url?: string }) =>
    request<StartSetupResponse>('/github/setup/start', { method: 'POST', body }),

  completeSetup: (body: { code: string; setup_id?: string; org_id?: string }) =>
    request<CompleteSetupResponse>('/github/setup/complete', { method: 'POST', body }),

  getSetupStatus: (setupId: string) =>
    request<SetupStatusResponse>(`/github/setup/status/${setupId}`),

  getInstallations: (orgId?: string) =>
    request<InstallationsResponse>(`/github/installations?${qs({ org_id: orgId })}`),

  // API Keys
  createApiKey: (orgId: string) =>
    request<ApiKeyCreated>(`/orgs/${orgId}/api-keys`, { method: 'POST' }),

  getApiKeyMetadata: (orgId: string) =>
    request<ApiKeyMetadata>(`/orgs/${orgId}/api-keys`),

  revokeApiKey: (orgId: string) =>
    request<ApiKeyRevoked>(`/orgs/${orgId}/api-keys`, { method: 'DELETE' }),

  // Auth
  login: (username: string, password: string) =>
    request<LoginResponse>('/auth/login', { method: 'POST', body: { username, password } }),
};

function qs(params: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') {
      parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
    }
  }
  return parts.length ? `?${parts.join('&')}` : '';
}

export { ApiError };
export default api;