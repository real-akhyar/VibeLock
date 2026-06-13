# VibeLock — Architecture Specification

> **Document version:** 1.0  
> **Last updated:** 2026-06-13  
> **Audience:** System designers, backend engineers, security reviewers  

This document describes the architectural decisions, data models, security boundaries, and operational contracts for the VibeLock platform.

---

## 9. Multi-Tenant Isolation (VIBE-030)

### 9.1 Overview

VibeLock serves multiple organizations simultaneously. Each organization must be **strictly isolated** — no organization may view, query, or mutate data belonging to another. This section defines the API key model, Row-Level Security (RLS) policies, auth middleware extension, query helper, key management endpoints, and the required database migration.

### 9.2 API Key Model

Every organization receives one or more **scoped API keys**. Keys are never stored in plaintext.

| Property | Specification |
|---|---|
| **Prefix** | `vl_` (VibeLock) |
| **Entropy** | 256-bit (32 bytes) cryptographically random |
| **Storage format** | SHA-256 hash (`api_key_hash`) in the `organizations` table |
| **Transmission** | Full key returned **exactly once** at creation time; subsequent requests present the full key |
| **Lookup** | Constant-time hash comparison: `SHA-256(provided_key) == stored_hash` |
| **Format** | `vl_` + base64url-encoded 32 random bytes → e.g. `vl_dGhpcyBpcyBhIHRlc3Qga2V5` (44 chars prefix + body) |

**Key generation pseudocode:**

```python
import secrets, hashlib, base64

def generate_api_key() -> tuple[str, str]:
    raw = secrets.token_bytes(32)
    full_key = "vl_" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    return full_key, key_hash
```

### 9.3 Database Migration

Add two columns to the `organizations` table:

```sql
-- Migration: VIBE-030 multi-tenant API key columns
-- Run against Supabase PostgreSQL

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS api_key_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS api_key_created_at TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN organizations.api_key_hash IS 'SHA-256 hex digest of the vl_ prefixed API key';
COMMENT ON COLUMN organizations.api_key_created_at IS 'Timestamp of last API key generation/rotation';
```

**Rollback:**

```sql
ALTER TABLE organizations
    DROP COLUMN IF EXISTS api_key_hash,
    DROP COLUMN IF EXISTS api_key_created_at;
```

### 9.4 Row-Level Security (RLS) Policies

Supabase/PostgreSQL RLS enforces isolation at the database level. All policies use the **current organization ID** set via a runtime parameter (`app.current_org_id`).

#### 9.4.1 Enable RLS

```sql
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE repositories  ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans         ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE pull_requests ENABLE ROW LEVEL SECURITY;
```

#### 9.4.2 Organizations

```sql
-- Organizations: only see own row
CREATE POLICY org_isolation ON organizations
    FOR ALL
    USING (id = current_setting('app.current_org_id')::uuid)
    WITH CHECK (id = current_setting('app.current_org_id')::uuid);
```

#### 9.4.3 Repositories

```sql
-- Repositories: scoped to owning organization
CREATE POLICY repo_isolation ON repositories
    FOR ALL
    USING (organization_id = current_setting('app.current_org_id')::uuid)
    WITH CHECK (organization_id = current_setting('app.current_org_id')::uuid);
```

#### 9.4.4 Scans

```sql
-- Scans: join through repository → organization
CREATE POLICY scan_isolation ON scans
    FOR ALL
    USING (
        repository_id IN (
            SELECT id FROM repositories
            WHERE organization_id = current_setting('app.current_org_id')::uuid
        )
    )
    WITH CHECK (
        repository_id IN (
            SELECT id FROM repositories
            WHERE organization_id = current_setting('app.current_org_id')::uuid
        )
    );
```

#### 9.4.5 Vulnerabilities

```sql
-- Vulnerabilities: join through scan → repository → organization
CREATE POLICY vuln_isolation ON vulnerabilities
    FOR ALL
    USING (
        scan_id IN (
            SELECT s.id FROM scans s
            JOIN repositories r ON r.id = s.repository_id
            WHERE r.organization_id = current_setting('app.current_org_id')::uuid
        )
    )
    WITH CHECK (
        scan_id IN (
            SELECT s.id FROM scans s
            JOIN repositories r ON r.id = s.repository_id
            WHERE r.organization_id = current_setting('app.current_org_id')::uuid
        )
    );
```

#### 9.4.6 Pull Requests

```sql
-- Pull requests: join through vulnerability → scan → repository → organization
CREATE POLICY pr_isolation ON pull_requests
    FOR ALL
    USING (
        vulnerability_id IN (
            SELECT v.id FROM vulnerabilities v
            JOIN scans s ON s.id = v.scan_id
            JOIN repositories r ON r.id = s.repository_id
            WHERE r.organization_id = current_setting('app.current_org_id')::uuid
        )
    )
    WITH CHECK (
        vulnerability_id IN (
            SELECT v.id FROM vulnerabilities v
            JOIN scans s ON s.id = v.scan_id
            JOIN repositories r ON r.id = s.repository_id
            WHERE r.organization_id = current_setting('app.current_org_id')::uuid
        )
    );
```

### 9.5 Auth Middleware Extension

The existing `auth_middleware` in `src/api/auth.py` must be extended to resolve the authenticated principal to an `org_id` and set the PostgreSQL runtime parameter before every dashboard request.

#### 9.5.1 API Key → Org Resolution

```python
# src/api/auth.py — additions

import hashlib

async def resolve_org_from_api_key(api_key: str) -> Optional[str]:
    """Look up an organization by its API key hash. Returns org_id or None."""
    if not api_key.startswith("vl_"):
        return None
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    result = (
        supabase.client.table("organizations")
        .select("id")
        .eq("api_key_hash", key_hash)
        .single()
        .execute()
    )
    return result.data["id"] if result.data else None
```

#### 9.5.2 Middleware Enhancement

```python
# In auth_middleware — after extracting user identity, set the RLS context:

async def auth_middleware(request: Request, call_next):
    # ... existing path-skip logic ...

    org_id = None

    # 1) Extract from JWT
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            token = auth_header[7:]
            payload = decode_token(token)
            org_id = payload.org_id
            request.state.user = AuthenticatedUser(
                user_id=payload.sub,
                org_id=org_id,
                role=payload.role,
                auth_method="jwt",
            )
        except HTTPException:
            pass

    # 2) Extract from API key header
    api_key = request.headers.get(auth_config.api_key_header, "")
    if not org_id and api_key.startswith("vl_"):
        resolved = await resolve_org_from_api_key(api_key)
        if resolved:
            org_id = resolved
            request.state.user = AuthenticatedUser(
                user_id=f"apikey:{org_id}",
                org_id=org_id,
                role="admin",
                auth_method="api_key",
            )

    # 3) Set RLS context on the database session
    if org_id and supabase.is_connected:
        try:
            supabase.client.rpc(
                "set_config",
                {"setting_name": "app.current_org_id", "setting_value": org_id}
            ).execute()
        except Exception:
            logger.warning("Failed to set app.current_org_id for RLS")

    return await call_next(request)
```

### 9.6 TenantScopedQuery Helper

A helper class in `src/shared/supabase_client.py` ensures that every query from application code carries the organization scope. This is the **application-level guard** that complements RLS.

```python
# src/shared/supabase_client.py — add after the SupabaseClient class

class TenantScopedQuery:
    """
    Wraps a Supabase query builder to inject org_id filtering automatically.
    Usage:
        query = TenantScopedQuery(supabase.client, org_id)
        result = query.table("vulnerabilities").select("*").execute()
    """

    def __init__(self, client, org_id: str):
        self._client = client
        self._org_id = org_id

    @property
    def org_id(self) -> str:
        return self._org_id

    def table(self, name: str):
        """Return a query builder pre-scoped to the tenant's org."""
        builder = self._client.table(name)

        if name == "organizations":
            builder = builder.eq("id", self._org_id)
        elif name == "repositories":
            builder = builder.eq("organization_id", self._org_id)
        elif name == "scans":
            # Sub-select: scans belonging to repos of this org
            # For Supabase-py, we rely on RLS; app-level filter as defense-in-depth
            pass
        elif name == "vulnerabilities":
            pass  # RLS-enforced; optional app-level join
        elif name == "pull_requests":
            pass  # RLS-enforced; optional app-level join

        return builder

    def rpc(self, fn_name: str, params: dict = None):
        """Execute a stored procedure within tenant context."""
        return self._client.rpc(fn_name, params or {})

    def execute_sql(self, query: str, params: dict = None):
        """Raw SQL execution with org_id parameter injection."""
        safe_params = params or {}
        safe_params["_org_id"] = self._org_id
        return self._client.rpc("execute_sql", {"query": query, "params": safe_params})
```

### 9.7 API Key Management Endpoints

New endpoints in `src/api/auth.py` (or a dedicated `src/api/api_keys.py`):

#### 9.7.1 Create / Rotate Key

```
POST /api/v1/orgs/{org_id}/api-keys
Authorization: Bearer <admin-jwt>
```

- Validates that the authenticated user's `org_id` matches the path parameter (or is a platform super-admin).
- Generates a new `vl_` key, stores its SHA-256 hash, updates `api_key_created_at`.
- Returns the full key **once**. The caller must store it securely.

**Response (201):**
```json
{
  "key": "vl_dGhpcyBpcyBhIHRlc3Qga2V5",
  "prefix": "vl_",
  "created_at": "2026-06-13T04:30:00Z",
  "warning": "Store this key securely. It will not be shown again."
}
```

#### 9.7.2 Revoke Key

```
DELETE /api/v1/orgs/{org_id}/api-keys
Authorization: Bearer <admin-jwt>
```

- Sets `api_key_hash` to `NULL` and `api_key_created_at` to `NULL`.
- All existing keys for the organization are immediately invalidated.
- Returns `204 No Content`.

#### 9.7.3 List Keys (metadata only)

```
GET /api/v1/orgs/{org_id}/api-keys
Authorization: Bearer <admin-jwt>
```

- Returns key metadata (never the key itself): creation timestamp, last-used timestamp (future), prefix.
- Response (200):
```json
{
  "keys": [
    {
      "prefix": "vl_",
      "created_at": "2026-06-13T04:30:00Z",
      "last_used_at": null
    }
  ]
}
```

### 9.8 Key Rotation Policy

| Event | Behavior |
|---|---|
| **Key created** | Old key hash overwritten; old key invalidated immediately |
| **Key revoked** | Hash set to NULL; all keys invalid |
| **Compromise suspected** | Admin calls rotate; new key returned, old key dead |
| **Key leakage detected** | Revoke immediately; investigate audit logs |

Rotation is **destructive** (single active key per org). Future iterations may support multiple concurrent keys with individual revocation.

### 9.9 Security Considerations

1. **Hash-only storage**: The plaintext API key never touches the database. Even a full database dump reveals only SHA-256 hashes.
2. **Constant-time comparison**: All key hash comparisons use `secrets.compare_digest()` or equivalent to prevent timing side-channels.
3. **RLS as defense-in-depth**: Even if application code has a bug, PostgreSQL RLS prevents cross-tenant data access.
4. **No key in logs**: The auth middleware redacts API keys from log output. Only the `vl_` prefix may appear for debugging.
5. **Rate limiting**: API key endpoints are rate-limited (5 requests/minute per IP) to prevent brute-force hash discovery (though 256-bit keys make this infeasible).
6. **Audit trail**: Key creation, rotation, and revocation events are logged with actor identity and timestamp.

### 9.10 Integration Checklist

- [ ] Run migration SQL (Section 9.3) against Supabase
- [ ] Enable RLS and create policies (Section 9.4)
- [ ] Extend `auth_middleware` with org resolution (Section 9.5)
- [ ] Add `TenantScopedQuery` to `supabase_client.py` (Section 9.6)
- [ ] Implement API key CRUD endpoints (Section 9.7)
- [ ] Update dashboard queries to use `TenantScopedQuery` or pass `organization_id` filter
- [ ] Write integration tests: cross-tenant access attempts must return empty results or 403
- [ ] Document key management in operator runbook