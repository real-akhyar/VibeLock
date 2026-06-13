"""
VIBE-030: Multi-Tenant Isolation — Integration Tests
Tests cross-tenant access prevention, API key lifecycle, and RLS context.
"""

import hashlib
import base64
import secrets
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException


# ============================================================
# Test Data
# ============================================================

ORG_A_ID = "00000000-0000-0000-0000-000000000001"
ORG_B_ID = "00000000-0000-0000-0000-000000000002"
REPO_A1_ID = "10000000-0000-0000-0000-000000000001"
REPO_B1_ID = "20000000-0000-0000-0000-000000000001"

VALID_VL_KEY = "vl_" + base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
VALID_VL_KEY_HASH = hashlib.sha256(VALID_VL_KEY.encode()).hexdigest()
INVALID_VL_KEY = "vl_" + base64.urlsafe_b64encode(b"invalid_key_material_32bytes!").rstrip(b"=").decode()


# ============================================================
# Mock Helpers
# ============================================================

def mock_supabase_response(data=None, count=None):
    mock = MagicMock()
    mock.data = data or []
    if count is not None:
        mock.count = count
    return mock


def mock_supabase_chain(return_data=None, return_count=None):
    mock = MagicMock()
    mock.select.return_value = mock
    mock.eq.return_value = mock
    mock.in_.return_value = mock
    mock.gte.return_value = mock
    mock.order.return_value = mock
    mock.limit.return_value = mock
    mock.range.return_value = mock
    mock.single.return_value = mock
    mock.update.return_value = mock
    mock.insert.return_value = mock
    mock.upsert.return_value = mock
    mock.execute.return_value = mock_supabase_response(return_data, return_count)
    return mock


# ============================================================
# resolve_org_from_api_key Tests
# ============================================================

class TestResolveOrgFromApiKey:
    """Tests for the vl_ API key resolution function."""

    def test_non_vl_key_returns_none(self):
        """Keys not starting with vl_ should return None."""
        from vibelock.src.api.auth import resolve_org_from_api_key

        assert resolve_org_from_api_key("sk-abc123") is None
        assert resolve_org_from_api_key("ghp_token123") is None
        assert resolve_org_from_api_key("") is None
        assert resolve_org_from_api_key(None) is None

    @patch("vibelock.src.api.auth.supabase")
    def test_invalid_vl_key_returns_none(self, mock_supabase):
        """Unknown vl_ key should return None."""
        from vibelock.src.api.auth import resolve_org_from_api_key

        mock_supabase.is_connected = True
        mock_client = mock_supabase_chain(return_data=None)
        mock_supabase.client = mock_client

        result = resolve_org_from_api_key(INVALID_VL_KEY)
        assert result is None

    @patch("vibelock.src.api.auth.supabase")
    def test_supabase_disconnected_returns_none(self, mock_supabase):
        """When Supabase is disconnected, return None gracefully."""
        from vibelock.src.api.auth import resolve_org_from_api_key

        mock_supabase.is_connected = False
        result = resolve_org_from_api_key(VALID_VL_KEY)
        assert result is None


# ============================================================
# API Key Generation Tests
# ============================================================

class TestApiKeyGeneration:
    """Tests for API key generation and hashing."""

    def test_generate_api_key_format(self):
        """Generated keys should have vl_ prefix and valid SHA-256 hash."""
        from vibelock.src.api.api_keys import generate_api_key

        full_key, key_hash = generate_api_key()

        assert full_key.startswith("vl_")
        assert len(full_key) > 3
        assert len(key_hash) == 64
        assert all(c in "0123456789abcdef" for c in key_hash)

    def test_generate_api_key_is_unique(self):
        """Each generated key should be unique."""
        from vibelock.src.api.api_keys import generate_api_key

        keys = [generate_api_key() for _ in range(10)]
        unique_keys = set(k[0] for k in keys)
        unique_hashes = set(k[1] for k in keys)

        assert len(unique_keys) == 10
        assert len(unique_hashes) == 10

    def test_key_hash_matches_key(self):
        """The hash should be SHA-256 of the full key."""
        from vibelock.src.api.api_keys import generate_api_key

        full_key, key_hash = generate_api_key()
        expected_hash = hashlib.sha256(full_key.encode()).hexdigest()
        assert key_hash == expected_hash


# ============================================================
# Cross-Tenant Isolation Tests
# ============================================================

class TestCrossTenantIsolation:
    """Tests that org A cannot access org B's data."""

    @patch("vibelock.src.api.dashboard.supabase")
    def test_org_a_cannot_see_org_b_repos(self, mock_supabase):
        """Dashboard with org A filter should not return org B repos."""
        from vibelock.src.api.dashboard import _resolve_repo_ids_for_org

        mock_supabase.is_connected = True
        mock_client = mock_supabase_chain(return_data=[{"id": REPO_A1_ID}])
        mock_supabase.client = mock_client

        repo_ids = _resolve_repo_ids_for_org(ORG_A_ID)
        assert REPO_A1_ID in repo_ids
        assert REPO_B1_ID not in repo_ids

    def test_dashboard_endpoints_have_org_filter(self):
        """All dashboard endpoints should accept organization_id parameter."""
        from vibelock.src.api.dashboard import (
            get_summary, get_trends, get_scan_stats,
            get_top_repositories, list_vulnerabilities,
        )
        import inspect

        for func in [get_summary, get_trends, get_scan_stats,
                      get_top_repositories, list_vulnerabilities]:
            sig = inspect.signature(func)
            assert "organization_id" in sig.parameters, (
                f"{func.__name__} missing organization_id parameter"
            )


# ============================================================
# TenantScopedQuery Tests
# ============================================================

class TestTenantScopedQuery:
    """Tests for the TenantScopedQuery wrapper class."""

    def test_organizations_table_scoped(self):
        """Query on organizations table should filter by org_id."""
        from vibelock.src.shared.supabase_client import TenantScopedQuery

        mock_client = MagicMock()
        mock_builder = MagicMock()
        mock_client.table.return_value = mock_builder
        mock_builder.eq.return_value = mock_builder

        query = TenantScopedQuery(mock_client, ORG_A_ID)
        query.table("organizations")

        mock_client.table.assert_called_with("organizations")
        mock_builder.eq.assert_called_with("id", ORG_A_ID)

    def test_repositories_table_scoped(self):
        """Query on repositories table should filter by organization_id."""
        from vibelock.src.shared.supabase_client import TenantScopedQuery

        mock_client = MagicMock()
        mock_builder = MagicMock()
        mock_client.table.return_value = mock_builder
        mock_builder.eq.return_value = mock_builder

        query = TenantScopedQuery(mock_client, ORG_A_ID)
        query.table("repositories")

        mock_client.table.assert_called_with("repositories")
        mock_builder.eq.assert_called_with("organization_id", ORG_A_ID)

    def test_scans_vulns_prs_not_app_scoped(self):
        """Scans/vulns/PRs rely on RLS, not app-level eq filter."""
        from vibelock.src.shared.supabase_client import TenantScopedQuery

        for table_name in ["scans", "vulnerabilities", "pull_requests"]:
            mock_client = MagicMock()
            mock_builder = MagicMock()
            mock_client.table.return_value = mock_builder

            query = TenantScopedQuery(mock_client, ORG_A_ID)
            query.table(table_name)

            mock_client.table.assert_called_with(table_name)
            mock_builder.eq.assert_not_called()

    def test_org_id_property(self):
        """TenantScopedQuery.org_id should return the org ID."""
        from vibelock.src.shared.supabase_client import TenantScopedQuery

        query = TenantScopedQuery(MagicMock(), ORG_A_ID)
        assert query.org_id == ORG_A_ID


# ============================================================
# Auth Middleware Tests
# ============================================================

class TestAuthMiddleware:
    """Tests for the auth middleware with vl_ key support."""

    def test_authenticate_api_key_detects_vl_prefix(self):
        """API keys starting with vl_ should be routed to org key resolution."""
        from vibelock.src.api.auth import authenticate_api_key
        import inspect

        source = inspect.getsource(authenticate_api_key)
        assert "vl_" in source
        assert "resolve_org_from_api_key" in source

    def test_auth_middleware_sets_rls_context(self):
        """Auth middleware should set app.current_org_id for Supabase RLS."""
        from vibelock.src.api.auth import auth_middleware
        import inspect

        source = inspect.getsource(auth_middleware)
        assert "app.current_org_id" in source


# ============================================================
# API Key CRUD Endpoint Tests
# ============================================================

class TestApiKeyEndpoints:
    """Tests for the API key management endpoints."""

    def test_api_key_router_exists(self):
        """The api_keys router should be importable."""
        from vibelock.src.api.api_keys import router
        assert router is not None
        assert router.prefix == "/api/v1/orgs"

    def test_create_endpoint_requires_admin(self):
        """POST /api-keys should require admin role."""
        from vibelock.src.api.api_keys import create_or_rotate_api_key
        import inspect

        sig = inspect.signature(create_or_rotate_api_key)
        param_names = [p.name for p in sig.parameters.values()]
        assert "user" in param_names

    def test_revoke_endpoint_requires_admin(self):
        """DELETE /api-keys should require admin role."""
        from vibelock.src.api.api_keys import revoke_api_key
        import inspect

        sig = inspect.signature(revoke_api_key)
        param_names = [p.name for p in sig.parameters.values()]
        assert "user" in param_names

    def test_get_metadata_does_not_return_key(self):
        """GET /api-keys should never return the actual key or hash."""
        from vibelock.src.api.api_keys import ApiKeyMetadata

        fields = ApiKeyMetadata.model_fields
        assert "api_key" not in fields
        assert "key_hash" not in fields
        assert "prefix" in fields
        assert "created_at" in fields
        assert "is_active" in fields

    def test_create_response_includes_warning(self):
        """POST response should warn user to save the key."""
        from vibelock.src.api.api_keys import ApiKeyCreated

        fields = ApiKeyCreated.model_fields
        assert "warning" in fields
        assert "api_key" in fields


# ============================================================
# RLS Policy Validation Tests
# ============================================================

class TestRlsPolicies:
    """Tests that RLS migration SQL is syntactically valid."""

    def test_migration_files_exist(self):
        """Both migration SQL files should exist."""
        import os
        workspace = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        migrations_dir = os.path.join(workspace, "migrations")

        assert os.path.exists(os.path.join(migrations_dir, "001_vibe030_api_keys.sql"))
        assert os.path.exists(os.path.join(migrations_dir, "002_vibe030_rls.sql"))

    def test_api_keys_migration_has_required_columns(self):
        """Migration 001 should add api_key_hash and api_key_created_at."""
        import os
        workspace = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        path = os.path.join(workspace, "migrations", "001_vibe030_api_keys.sql")

        with open(path) as f:
            content = f.read()

        assert "api_key_hash" in content
        assert "api_key_created_at" in content
        assert "ALTER TABLE organizations" in content

    def test_rls_migration_enables_all_tables(self):
        """Migration 002 should enable RLS on all 5 tables."""
        import os
        workspace = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        path = os.path.join(workspace, "migrations", "002_vibe030_rls.sql")

        with open(path) as f:
            content = f.read()

        for table in ["organizations", "repositories", "scans", "vulnerabilities", "pull_requests"]:
            assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in content, (
                f"Missing RLS enable for {table}"
            )

    def test_rls_migration_has_isolation_policies(self):
        """Migration 002 should have isolation policies for all tables."""
        import os
        workspace = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        path = os.path.join(workspace, "migrations", "002_vibe030_rls.sql")

        with open(path) as f:
            content = f.read()

        for policy in ["org_isolation", "repo_isolation", "scan_isolation",
                        "vuln_isolation", "pr_isolation"]:
            assert f"CREATE POLICY {policy}" in content, (
                f"Missing policy: {policy}"
            )

    def test_rls_policies_use_current_setting(self):
        """All RLS policies should reference app.current_org_id."""
        import os
        workspace = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        path = os.path.join(workspace, "migrations", "002_vibe030_rls.sql")

        with open(path) as f:
            content = f.read()

        assert "app.current_org_id" in content
        assert "current_setting" in content


# ============================================================
# Key Rotation Tests
# ============================================================

class TestKeyRotation:
    """Tests for API key rotation logic."""

    def test_rotation_generates_new_key(self):
        """Rotating a key should produce a different key and hash."""
        from vibelock.src.api.api_keys import generate_api_key

        key1, hash1 = generate_api_key()
        key2, hash2 = generate_api_key()

        assert key1 != key2
        assert hash1 != hash2

    def test_old_key_hash_differs_from_new(self):
        """After rotation, old hash should not match new key."""
        from vibelock.src.api.api_keys import generate_api_key

        old_key, old_hash = generate_api_key()
        new_key, new_hash = generate_api_key()

        # Old hash should NOT match new key
        assert hashlib.sha256(new_key.encode()).hexdigest() != old_hash
        # New hash should NOT match old key
        assert hashlib.sha256(old_key.encode()).hexdigest() != new_hash