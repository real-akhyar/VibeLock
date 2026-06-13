-- VibeLock Database Schema (Supabase / PostgreSQL)
-- Tracks organizations, repositories, scans, vulnerabilities, and remediation PRs.

-- Core Accounts & Auth
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    github_installation_id BIGINT UNIQUE NOT NULL,
    org_name VARCHAR(255) NOT NULL,
    plan_tier VARCHAR(50) DEFAULT 'free', -- 'free', 'pro'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    github_repo_id BIGINT UNIQUE NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scans & Findings
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    commit_sha VARCHAR(40) NOT NULL,
    branch VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'queued', -- 'queued', 'scanning', 'completed', 'failed'
    vulnerabilities_count INT DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    vulnerability_type VARCHAR(100) NOT NULL, -- 'missing_rls', 'hardcoded_secret', 'sql_injection', etc.
    severity VARCHAR(20) NOT NULL, -- 'low', 'medium', 'high', 'critical'
    file_path TEXT NOT NULL,
    line_number INT,
    description TEXT NOT NULL,
    code_snippet TEXT,
    remediation_status VARCHAR(50) DEFAULT 'detected', -- 'detected', 'patching', 'pr_opened', 'resolved', 'ignored'
    remediation_attempts INT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Remediation Actions
CREATE TABLE IF NOT EXISTS pull_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    github_pr_number INT NOT NULL,
    pr_url TEXT NOT NULL,
    status VARCHAR(50) NOT NULL, -- 'open', 'merged', 'closed'
    patch_code TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repository_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(remediation_status);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_prs_vuln ON pull_requests(vulnerability_id);