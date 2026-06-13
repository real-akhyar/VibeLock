-- VIBE-030: Multi-Tenant Isolation — Row-Level Security Policies
-- Enables RLS on all tenant-scoped tables and creates isolation policies.
-- CRITICAL: The auth middleware MUST set app.current_org_id BEFORE these policies
-- are enabled, otherwise ALL queries will be blocked.
-- Run against Supabase PostgreSQL.

BEGIN;

-- ============================================================
-- Enable RLS on all tenant-scoped tables
-- ============================================================

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE pull_requests ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- Organizations: users can only see their own org
-- ============================================================

DROP POLICY IF EXISTS org_isolation ON organizations;
CREATE POLICY org_isolation ON organizations
    FOR ALL
    USING (id = current_setting('app.current_org_id')::uuid)
    WITH CHECK (id = current_setting('app.current_org_id')::uuid);

-- ============================================================
-- Repositories: scoped to organization_id
-- ============================================================

DROP POLICY IF EXISTS repo_isolation ON repositories;
CREATE POLICY repo_isolation ON repositories
    FOR ALL
    USING (organization_id = current_setting('app.current_org_id')::uuid)
    WITH CHECK (organization_id = current_setting('app.current_org_id')::uuid);

-- ============================================================
-- Scans: scoped via repository → organization
-- ============================================================

DROP POLICY IF EXISTS scan_isolation ON scans;
CREATE POLICY scan_isolation ON scans
    FOR SELECT
    USING (
        repository_id IN (
            SELECT id FROM repositories
            WHERE organization_id = current_setting('app.current_org_id')::uuid
        )
    );

DROP POLICY IF EXISTS scan_isolation_insert ON scans;
CREATE POLICY scan_isolation_insert ON scans
    FOR INSERT
    WITH CHECK (
        repository_id IN (
            SELECT id FROM repositories
            WHERE organization_id = current_setting('app.current_org_id')::uuid
        )
    );

DROP POLICY IF EXISTS scan_isolation_update ON scans;
CREATE POLICY scan_isolation_update ON scans
    FOR UPDATE
    USING (
        repository_id IN (
            SELECT id FROM repositories
            WHERE organization_id = current_setting('app.current_org_id')::uuid
        )
    );

DROP POLICY IF EXISTS scan_isolation_delete ON scans;
CREATE POLICY scan_isolation_delete ON scans
    FOR DELETE
    USING (
        repository_id IN (
            SELECT id FROM repositories
            WHERE organization_id = current_setting('app.current_org_id')::uuid
        )
    );

-- ============================================================
-- Vulnerabilities: scoped via scan → repository → organization
-- ============================================================

DROP POLICY IF EXISTS vuln_isolation ON vulnerabilities;
CREATE POLICY vuln_isolation ON vulnerabilities
    FOR SELECT
    USING (
        scan_id IN (
            SELECT s.id FROM scans s
            JOIN repositories r ON s.repository_id = r.id
            WHERE r.organization_id = current_setting('app.current_org_id')::uuid
        )
    );

DROP POLICY IF EXISTS vuln_isolation_insert ON vulnerabilities;
CREATE POLICY vuln_isolation_insert ON vulnerabilities
    FOR INSERT
    WITH CHECK (
        scan_id IN (
            SELECT s.id FROM scans s
            JOIN repositories r ON s.repository_id = r.id
            WHERE r.organization_id = current_setting('app.current_org_id')::uuid
        )
    );

DROP POLICY IF EXISTS vuln_isolation_update ON vulnerabilities;
CREATE POLICY vuln_isolation_update ON vulnerabilities
    FOR UPDATE
    USING (
        scan_id IN (
            SELECT s.id FROM scans s
            JOIN repositories r ON s.repository_id = r.id
            WHERE r.organization_id = current_setting('app.current_org_id')::uuid
        )
    );

DROP POLICY IF EXISTS vuln_isolation_delete ON vulnerabilities;
CREATE POLICY vuln_isolation_delete ON vulnerabilities
    FOR DELETE
    USING (
        scan_id IN (
            SELECT s.id FROM scans s
            JOIN repositories r ON s.repository_id = r.id
            WHERE r.organization_id = current_setting('app.current_org_id')::uuid
        )
    );

-- ============================================================
-- Pull Requests: scoped via vulnerability → scan → repo → org
-- ============================================================

DROP POLICY IF EXISTS pr_isolation ON pull_requests;
CREATE POLICY pr_isolation ON pull_requests
    FOR SELECT
    USING (
        vulnerability_id IN (
            SELECT v.id FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            JOIN repositories r ON s.repository_id = r.id
            WHERE r.organization_id = current_setting('app.current_org_id')::uuid
        )
    );

DROP POLICY IF EXISTS pr_isolation_insert ON pull_requests;
CREATE POLICY pr_isolation_insert ON pull_requests
    FOR INSERT
    WITH CHECK (
        vulnerability_id IN (
            SELECT v.id FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            JOIN repositories r ON s.repository_id = r.id
            WHERE r.organization_id = current_setting('app.current_org_id')::uuid
        )
    );

DROP POLICY IF EXISTS pr_isolation_update ON pull_requests;
CREATE POLICY pr_isolation_update ON pull_requests
    FOR UPDATE
    USING (
        vulnerability_id IN (
            SELECT v.id FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            JOIN repositories r ON s.repository_id = r.id
            WHERE r.organization_id = current_setting('app.current_org_id')::uuid
        )
    );

DROP POLICY IF EXISTS pr_isolation_delete ON pull_requests;
CREATE POLICY pr_isolation_delete ON pull_requests
    FOR DELETE
    USING (
        vulnerability_id IN (
            SELECT v.id FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            JOIN repositories r ON s.repository_id = r.id
            WHERE r.organization_id = current_setting('app.current_org_id')::uuid
        )
    );

-- ============================================================
-- Service role bypass: internal services use service_role key
-- and bypass RLS entirely. This is handled by Supabase's
-- built-in service_role bypass — no policy needed.
-- ============================================================

COMMIT;