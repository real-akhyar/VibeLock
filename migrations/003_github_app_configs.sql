-- VibeLock Migration 003: GitHub App Configs
-- Stores GitHub App credentials per organization with encryption at rest.
-- Depends on: 001_initial_schema.sql (organizations table)

CREATE TABLE IF NOT EXISTS github_app_configs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id) ON DELETE CASCADE,
    app_id          INTEGER,
    webhook_secret  TEXT,
    private_key_encrypted TEXT NOT NULL DEFAULT '',
    setup_complete  BOOLEAN NOT NULL DEFAULT FALSE,
    manifest_flow_url TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for fast lookup by org
CREATE INDEX IF NOT EXISTS idx_github_app_configs_org_id
    ON github_app_configs(org_id)
    WHERE setup_complete = TRUE;

-- Index for setup status lookups
CREATE INDEX IF NOT EXISTS idx_github_app_configs_setup_complete
    ON github_app_configs(setup_complete);

-- RLS: only allow access to own org's configs
ALTER TABLE github_app_configs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "org_isolation_github_app_configs"
    ON github_app_configs
    FOR ALL
    USING (org_id = current_setting('app.current_org_id', TRUE)::uuid)
    WITH CHECK (org_id = current_setting('app.current_org_id', TRUE)::uuid);

-- Trigger to auto-update updated_at
CREATE OR REPLACE FUNCTION update_github_app_configs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_github_app_configs_updated_at
    BEFORE UPDATE ON github_app_configs
    FOR EACH ROW
    EXECUTE FUNCTION update_github_app_configs_updated_at();