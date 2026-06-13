"""
VibeLock — GitHub App Setup API Routes
Provides endpoints for the GitHub App manifest flow:
  1. POST /api/v1/github/setup/start — starts manifest flow, returns setup URL
  2. POST /api/v1/github/setup/complete — exchanges code for app credentials
  3. GET  /api/v1/github/setup/status/{setup_id} — check setup progress
  4. GET  /api/v1/github/installations — list all installations
  5. POST /api/v1/github/setup/callback — OAuth callback handler
"""

import os
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field

from vibelock.src.ingestion.github_app import (
    start_setup_flow,
    complete_manifest_flow,
    complete_setup,
    list_installations,
    get_manifest,
    get_app_credentials_from_env,
)
from vibelock.src.db.supabase_github import github_app_config_store
from vibelock.src.api.auth import authenticate_any, AuthenticatedUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/github", tags=["github-setup"])


# --- Request / Response Models ---

class StartSetupRequest(BaseModel):
    org_id: Optional[str] = Field(None, description="Organization UUID to associate the app with")
    webhook_url: Optional[str] = Field(None, description="Override default webhook URL")
    app_url: Optional[str] = Field(None, description="Override default app homepage URL")


class StartSetupResponse(BaseModel):
    setup_id: Optional[str] = None
    manifest: dict
    flow_url: str
    instructions: list[str]


class CompleteSetupRequest(BaseModel):
    code: str = Field(..., description="Temporary code from GitHub manifest redirect")
    setup_id: Optional[str] = Field(None, description="Config record ID from /start response")
    org_id: Optional[str] = Field(None, description="Organization UUID (required if no setup_id)")


class CompleteSetupResponse(BaseModel):
    success: bool
    app_id: Optional[int] = None
    app_name: Optional[str] = None
    owner: Optional[str] = None
    webhook_secret: Optional[str] = None
    error: Optional[str] = None


class SetupStatusResponse(BaseModel):
    setup_id: str
    setup_complete: bool
    app_id: Optional[int] = None
    org_id: Optional[str] = None
    manifest_flow_url: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class InstallationsResponse(BaseModel):
    installations: list[dict]
    count: int


class CallbackRequest(BaseModel):
    code: str = Field(..., description="Temporary code from GitHub OAuth redirect")
    state: Optional[str] = Field(None, description="OAuth state parameter")


class CallbackResponse(BaseModel):
    success: bool
    app_id: Optional[int] = None
    app_name: Optional[str] = None
    error: Optional[str] = None


# --- Endpoints ---

@router.post("/setup/start", response_model=StartSetupResponse)
async def start_github_setup(
    body: StartSetupRequest,
    user: AuthenticatedUser = Depends(authenticate_any),
):
    """
    Start the GitHub App manifest flow.

    Returns a one-click GitHub URL that the user opens to create the VibeLock
    GitHub App. A setup_id is returned for tracking the flow progress.
    """
    webhook_url = body.webhook_url or os.getenv("VIBELOCK_WEBHOOK_URL", "")
    app_url = body.app_url or os.getenv("VIBELOCK_APP_URL", "")

    result = await start_setup_flow(webhook_url, app_url)

    # Persist setup state in Supabase if available
    setup_id = None
    org_id = body.org_id or user.org_id
    if org_id and github_app_config_store.is_available:
        setup_id = github_app_config_store.create_config(
            org_id=org_id,
            manifest_flow_url=result["flow_url"],
        )

    return StartSetupResponse(
        setup_id=setup_id,
        manifest=result["manifest"],
        flow_url=result["flow_url"],
        instructions=result["instructions"],
    )


@router.post("/setup/complete", response_model=CompleteSetupResponse)
async def complete_github_setup(
    body: CompleteSetupRequest,
    user: AuthenticatedUser = Depends(authenticate_any),
):
    """
    Complete the GitHub App manifest flow by exchanging the temporary code
    for full app credentials.

    The code is obtained from GitHub's redirect after the user creates the app.
    Credentials (app_id, private_key, webhook_secret) are persisted in Supabase.
    """
    result = await complete_manifest_flow(body.code)

    if not result.get("success"):
        return CompleteSetupResponse(
            success=False,
            error=result.get("error", "Unknown error during manifest conversion"),
        )

    app_id = result.get("id")
    private_key = result.get("pem", "")
    webhook_secret = result.get("webhook_secret", "")

    if not app_id or not private_key:
        return CompleteSetupResponse(
            success=False,
            error="GitHub response missing required fields (id or pem)",
        )

    # Verify credentials work by fetching app info
    verify_result = await complete_setup(
        app_id=app_id,
        private_key=private_key,
        webhook_secret=webhook_secret,
    )

    if not verify_result.get("success"):
        return CompleteSetupResponse(
            success=False,
            app_id=app_id,
            error=f"Credential verification failed: {verify_result.get('error')}",
        )

    # Persist credentials in Supabase
    setup_id = body.setup_id
    org_id = body.org_id or user.org_id

    if setup_id and github_app_config_store.is_available:
        github_app_config_store.complete_config(
            setup_id=setup_id,
            app_id=app_id,
            private_key=private_key,
            webhook_secret=webhook_secret,
        )
    elif org_id and github_app_config_store.is_available:
        new_id = github_app_config_store.create_config(org_id=org_id)
        if new_id:
            github_app_config_store.complete_config(
                setup_id=new_id,
                app_id=app_id,
                private_key=private_key,
                webhook_secret=webhook_secret,
            )

    return CompleteSetupResponse(
        success=True,
        app_id=app_id,
        app_name=verify_result.get("app_name"),
        owner=verify_result.get("owner"),
        webhook_secret=webhook_secret,
    )


@router.get("/setup/status/{setup_id}", response_model=SetupStatusResponse)
async def get_setup_status(
    setup_id: str,
    user: AuthenticatedUser = Depends(authenticate_any),
):
    """
    Check the progress of a GitHub App setup flow.

    Returns whether setup is complete and the app_id if credentials have been stored.
    """
    config = github_app_config_store.get_config(setup_id)

    if not config:
        raise HTTPException(status_code=404, detail="Setup ID not found")

    return SetupStatusResponse(
        setup_id=setup_id,
        setup_complete=config.get("setup_complete", False),
        app_id=config.get("app_id"),
        org_id=config.get("org_id"),
        manifest_flow_url=config.get("manifest_flow_url"),
        created_at=config.get("created_at"),
        updated_at=config.get("updated_at"),
    )


@router.get("/installations", response_model=InstallationsResponse)
async def get_installations(
    org_id: Optional[str] = Query(None, description="Organization UUID"),
    user: AuthenticatedUser = Depends(authenticate_any),
):
    """
    List all GitHub App installations.

    Requires valid GitHub App credentials (from Supabase or environment variables).
    """
    target_org = org_id or user.org_id
    creds = None

    if target_org and github_app_config_store.is_available:
        creds = github_app_config_store.get_credentials(target_org)

    if not creds:
        creds = get_app_credentials_from_env()

    if not creds:
        raise HTTPException(
            status_code=400,
            detail="No GitHub App credentials configured. Complete setup first.",
        )

    installations = await list_installations(
        app_id=creds["app_id"],
        private_key=creds["private_key"],
    )

    return InstallationsResponse(
        installations=installations,
        count=len(installations),
    )


@router.post("/setup/callback", response_model=CallbackResponse)
async def setup_callback(body: CallbackRequest):
    """
    OAuth callback handler for the GitHub App manifest flow.

    GitHub redirects here after the user creates the app, with a `code` parameter.
    This endpoint exchanges the code and persists credentials.

    This endpoint does NOT require authentication — it's called by GitHub's redirect.
    """
    if not body.code:
        raise HTTPException(status_code=400, detail="Missing 'code' parameter")

    result = await complete_manifest_flow(body.code)

    if not result.get("success"):
        return CallbackResponse(
            success=False,
            error=result.get("error", "Unknown error during manifest conversion"),
        )

    app_id = result.get("id")
    private_key = result.get("pem", "")
    webhook_secret = result.get("webhook_secret", "")

    if not app_id or not private_key:
        return CallbackResponse(
            success=False,
            error="GitHub response missing required fields",
        )

    # Verify credentials
    verify_result = await complete_setup(
        app_id=app_id,
        private_key=private_key,
        webhook_secret=webhook_secret,
    )

    # Try to persist if Supabase is available
    if github_app_config_store.is_available:
        setup_id = github_app_config_store.create_config(
            org_id=None,
            manifest_flow_url=None,
        )
        if setup_id:
            github_app_config_store.complete_config(
                setup_id=setup_id,
                app_id=app_id,
                private_key=private_key,
                webhook_secret=webhook_secret,
            )

    return CallbackResponse(
        success=True,
        app_id=app_id,
        app_name=verify_result.get("app_name") if verify_result.get("success") else None,
        error=None if verify_result.get("success") else verify_result.get("error"),
    )