-- VIBE-030: Multi-Tenant Isolation — API Key Columns
-- Adds api_key_hash and api_key_created_at to organizations table.
-- Run against Supabase PostgreSQL.

BEGIN;

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS api_key_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS api_key_created_at TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN organizations.api_key_hash IS 'SHA-256 hex digest of the vl_ prefixed API key';
COMMENT ON COLUMN organizations.api_key_created_at IS 'Timestamp of last API key generation or rotation';

COMMIT;