"""
VibeLock — Organization API Key Management
CRUD endpoints for vl_ prefixed org-level API keys.
Used for CI/CD integrations and external service authentication.
"""

import hashlib
import secrets
import base64
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from vibelock.src.api.auth import (
    AuthenticatedUser,
    authenticate_any,
    require_admin,
)
from vibelock.src.shared.supabase_client import supabase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/orgs", tags=["api-keys"])


# --- Models ---

class ApiKeyCreated(BaseModel):
    """Response when a new API key is created. The full key is shown ONCE."""
    api_key: str = Field(description="Full API key — save this now, it won't be shown again")
    prefix: str = Field(description="Key prefix for identification")
    created_at: str
    warning: str = "Store this key securely. It will not be displayed again."


class ApiKeyMetadata(BaseModel):
    """Metadata about an API key — never includes the actual key or hash."""
    prefix: str = "vl_"
    created_at: Optional[str] = None
    last_used_at: Optional[str] = None
    is_active: bool = True


class ApiKeyRevoked(BaseModel):
    """Response when an API key is revoked."""
    message: str
    org_id: str
    revoked_at: str


# --- Key Generation ---

def generate_api_key() -> tuple[str, str]:
    """
    Generate a new vl_ prefixed API key.
    Returns (full_key, sha256_hash).
    """
    raw = secrets.token_bytes(32)
    full_key = "vl_" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    return full_key, key_hash


# --- Helpers ---

async def _get_org_or_403(org_id: str, user: AuthenticatedUser) -> dict:
    """Fetch org and verify user has access. Returns org dict or raises 403."""
    if not supabase.is_connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    # Users can only manage keys for their own org (unless super-admin)
    if user.org_id and user.org_id != org_id and user.role != "internal":
        raise HTTPException(status_code=403, detail="Cannot manage keys for another organization")

    try:
        result = (
            supabase.client.table("organizations")
            .select("*")
            .eq("id", org_id)
            .single()
            .execute()
        )
        if not result.data:
            raise HTTPException(status_code=404, detail="Organization not found")
        return result.data
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch org {org_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error")


# --- Endpoints ---

@router.post("/{org_id}/api-keys", response_model=ApiKeyCreated)
async def create_or_rotate_api_key(
    org_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin),
):
    """
    Create a new API key or rotate an existing one for an organization.
    If a key already exists, it is replaced (rotation).
    Requires admin role.
    """
    org = await _get_org_or_403(org_id, user)

    full_key, key_hash = generate_api_key()
    now = datetime.now(timezone.utc)

    try:
        supabase.client.table("organizations").update({
            "api_key_hash": key_hash,
            "api_key_created_at": now.isoformat(),
        }).eq("id", org_id).execute()

        logger.info(f"API key {'rotated' if org.get('api_key_hash') else 'created'} for org {org_id}")

        return ApiKeyCreated(
            api_key=full_key,
            prefix="vl_",
            created_at=now.isoformat(),
        )
    except Exception as e:
        logger.error(f"Failed to create/rotate API key for org {org_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to store API key: {str(e)}")


@router.delete("/{org_id}/api-keys", response_model=ApiKeyRevoked)
async def revoke_api_key(
    org_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin),
):
    """
    Revoke an organization's API key.
    After revocation, the key can no longer be used for authentication.
    Requires admin role.
    """
    org = await _get_org_or_403(org_id, user)

    if not org.get("api_key_hash"):
        raise HTTPException(status_code=404, detail="No API key exists for this organization")

    now = datetime.now(timezone.utc)

    try:
        supabase.client.table("organizations").update({
            "api_key_hash": None,
            "api_key_created_at": None,
        }).eq("id", org_id).execute()

        logger.info(f"API key revoked for org {org_id}")

        return ApiKeyRevoked(
            message="API key revoked successfully",
            org_id=org_id,
            revoked_at=now.isoformat(),
        )
    except Exception as e:
        logger.error(f"Failed to revoke API key for org {org_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to revoke API key: {str(e)}")


@router.get("/{org_id}/api-keys", response_model=ApiKeyMetadata)
async def get_api_key_metadata(
    org_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(authenticate_any),
):
    """
    Get API key metadata for an organization.
    Never returns the actual key or its hash — only prefix, timestamps, and status.
    """
    org = await _get_org_or_403(org_id, user)

    return ApiKeyMetadata(
        prefix="vl_",
        created_at=org.get("api_key_created_at"),
        last_used_at=None,  # TODO: track last usage in future iteration
        is_active=org.get("api_key_hash") is not None,
    )