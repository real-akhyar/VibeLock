"""
VibeLock — Auth Routes
Provides /auth/login endpoint for dashboard authentication.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from vibelock.src.api.auth import create_token, auth_config
from vibelock.src.shared.supabase_client import supabase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


# --- Models ---

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# --- Endpoint ---

@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest):
    """
    Authenticate a user and return a JWT access token.

    Supports two auth methods:
    1. Supabase-backed org lookup (username = org_id, password = API key)
    2. Internal admin login (configured via VIBELOCK_ADMIN_USERNAME / VIBELOCK_ADMIN_PASSWORD env vars)
    """
    import os

    # --- Internal admin login ---
    admin_user = os.getenv("VIBELOCK_ADMIN_USERNAME", "admin")
    admin_pass = os.getenv("VIBELOCK_ADMIN_PASSWORD", "")

    if body.username == admin_user and admin_pass and body.password == admin_pass:
        token = create_token(
            user_id="admin",
            org_id=None,
            role="admin",
        )
        logger.info("admin_login_success")
        return LoginResponse(access_token=token)

    # --- Supabase org-based login ---
    if supabase.is_connected:
        try:
            import hashlib

            # Look up org by name
            org_result = (
                supabase.client.table("organizations")
                .select("id, org_name, api_key_hash")
                .eq("org_name", body.username)
                .single()
                .execute()
            )

            if org_result.data:
                org = org_result.data
                # Password should match the org's API key hash
                provided_hash = hashlib.sha256(body.password.encode()).hexdigest()

                if org.get("api_key_hash") == provided_hash:
                    token = create_token(
                        user_id=f"org:{org['id']}",
                        org_id=org["id"],
                        role="admin",
                    )
                    logger.info("org_login_success", org_id=org["id"])
                    return LoginResponse(access_token=token)

        except Exception as e:
            logger.warning(f"org_login_lookup_failed: {e}")

    raise HTTPException(status_code=401, detail="Invalid username or password")