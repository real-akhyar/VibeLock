# VIBE-028 Design: GitHub App Manifest + One-Click Setup Flow

**Status:** system_designer complete → handoff to developer
**Created:** 2026-06-13T05:05:00Z
**Priority:** HIGH

## Problem
`src/ingestion/github_app.py` has a skeletal manifest and setup flow but is broken/incomplete:
1. `SetupState.webhook_secret` has a `[REDACTED]` type annotation (line 73) — needs `Optional[str]`
2. `start_setup_flow()` uses deprecated base64 manifest encoding instead of the GitHub `/app-manifests/{code}/conversions` API
3. No FastAPI endpoint to serve the manifest or handle the OAuth callback
4. No persistence of setup state (app_id, private_key, webhook_secret)
5. `complete_setup()` has `[REDACTED]` in JWT signing call (line 136) and token extraction (line 219)
6. `list_installations()` and `get_installation_repos()` have `[REDACTED]` in JWT signing calls (lines 178, 205)

## Design

### 1. Fix `[REDACTED]` type annotations and calls

**`SetupState` model (line 73):**
```python
webhook_secret: Optional[str] = None
```

**JWT signing calls (lines 136, 178, 205):**
Replace `jwt.*[REDACTED]` with `jwt.encode(payload, private_key, algorithm="RS256")`

**Token extraction (line 219):**
Replace `toke*[REDACTED]()` with `token_resp.json()` and extract `["token"]`

### 2. Add FastAPI Setup Endpoints

New router: `src/ingestion/github_setup_routes.py` (or inline in `github_app.py`)

```
POST /api/v1/github/setup/start
  Body: { "webhook_url": str, "app_url": str, "org_id": str }
  Returns: { "manifest": dict, "flow_url": str, "setup_id": str }

POST /api/v1/github/setup/complete
  Body: { "setup_id": str, "app_id": int, "private_key": str, "webhook_secret": str }
  Returns: { "success": bool, "app_name": str, "installation_url": str }

GET /api/v1/github/setup/status/{setup_id}
  Returns: { "setup_id": str, "complete": bool, "app_id": int|null, "installations": int }

GET /api/v1/github/installations
  Headers: Authorization: Bearer <token>
  Returns: [ { "id": int, "account": dict, "repos": int } ]

POST /api/v1/github/setup/callback
  Body: { "code": str }  (from GitHub manifest flow redirect)
  Returns: { "app_id": int, "client_id": str, "client_secret": str, "pem": str, "webhook_secret": str }
```

### 3. Persist Setup State

Use Supabase `org_settings` table (or new `github_app_configs` table):
```sql
CREATE TABLE IF NOT EXISTS github_app_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id),
    app_id INTEGER,
    webhook_secret TEXT,
    private_key_encrypted TEXT,  -- AES-256-GCM encrypted at rest
    setup_complete BOOLEAN DEFAULT FALSE,
    manifest_flow_url TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
```

### 4. Proper Manifest Flow

GitHub's actual manifest flow:
1. User clicks "Setup VibeLock" → we redirect to `https://github.com/apps/new?manifest={json}`
2. GitHub creates the app and redirects to our `redirect_url` with a `code` parameter
3. We POST to `https://api.github.com/app-manifests/{code}/conversions`
4. GitHub returns: `{ id, client_id, client_secret, pem, webhook_secret, ... }`
5. We persist these and mark setup complete

### 5. Environment Variable Fallback

If Supabase is unavailable, fall back to env vars:
- `GITHUB_APP_ID`
- `GITHUB_APP_PRIVATE_KEY` (path to PEM file)
- `VIBELOCK_GITHUB_WEBHOOK_SECRET`

### File Changes

| File | Change |
|------|--------|
| `src/ingestion/github_app.py` | Fix `[REDACTED]` annotations, fix JWT calls, fix token extraction, add `complete_manifest_flow()` |
| `src/ingestion/github_setup_routes.py` | **NEW** — FastAPI router with all 5 endpoints |
| `src/ingestion/webhook_gateway.py` | Mount the new router |
| `src/shared/supabase_client.py` | Add `github_app_configs` table helpers |
| `tests/unit/test_github_app.py` | **NEW** — unit tests for manifest, setup flow, JWT validation |
| `tests/integration/test_github_setup.py` | **NEW** — integration tests for setup endpoints |

### Dependencies
- `PyJWT` (already in requirements)
- `httpx` (already in requirements)
- `cryptography` for key encryption at rest (already in requirements via PyJWT)

### Acceptance Criteria
1. `SetupState.webhook_secret` is typed `Optional[str]` — no `[REDACTED]`
2. All JWT calls use `jwt.encode()` — no `[REDACTED]`
3. Token extraction uses `resp.json()["token"]` — no `[REDACTED]`
4. `POST /api/v1/github/setup/start` returns valid manifest + flow URL
5. `POST /api/v1/github/setup/callback` calls GitHub manifest conversion API
6. `GET /api/v1/github/installations` returns installation list
7. Setup state persisted to Supabase (graceful no-op if unavailable)
8. All new endpoints have auth middleware
9. Unit tests pass for all fixed functions
10. Integration tests pass for setup flow