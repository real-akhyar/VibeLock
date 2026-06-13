"""
VibeLock — GitHub App Setup
Provides GitHub App manifest, setup flow, and one-click installation.
"""

import os
import logging
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger(__name__)


# --- GitHub App Manifest ---

GITHUB_APP_MANIFEST = {
    "name": "VibeLock",
    "url": "https://vibelock.dev",
    "hook_attributes": {
        "url": "https://api.vibelock.dev/webhook/github",
    },
    "redirect_url": "",
    "description": "Autonomous security remediation — detects vulnerabilities and opens auto-fix PRs.",
    "public": True,
    "default_events": [
        "push",
        "pull_request",
    ],
    "default_permissions": {
        "contents": "read",
        "pull_requests": "write",
        "metadata": "read",
        "checks": "write",
        "commit_statuses": "write",
    },
}


def get_manifest(webhook_url: Optional[str] = None, app_url: Optional[str] = None) -> dict:
    """
    Get the GitHub App manifest with configurable URLs.
    
    Args:
        webhook_url: Override webhook URL (default: from env VIBELOCK_WEBHOOK_URL)
        app_url: Override app homepage URL (default: from env VIBELOCK_APP_URL)
    """
    manifest = GITHUB_APP_MANIFEST.copy()
    
    if webhook_url:
        manifest["hook_attributes"]["url"] = webhook_url
    elif os.getenv("VIBELOCK_WEBHOOK_URL"):
        manifest["hook_attributes"]["url"] = os.getenv("VIBELOCK_WEBHOOK_URL")
    
    if app_url:
        manifest["url"] = app_url
    elif os.getenv("VIBELOCK_APP_URL"):
        manifest["url"] = os.getenv("VIBELOCK_APP_URL")
    
    redirect_url = os.getenv("VIBELOCK_REDIRECT_URL", "")
    if redirect_url:
        manifest["redirect_url"] = redirect_url
    
    return manifest


# --- Setup Flow ---

class SetupState(BaseModel):
    """Tracks the GitHub App setup flow state."""
    manifest_flow_url: Optional[str] = None
    app_id: Optional[int] = None
    installation_id: Optional[int] = None
    webhook_secret: Optional[str] = None
    private_key_path: Optional[str] = None
    setup_complete: bool = False


async def start_setup_flow(webhook_url: str, app_url: str) -> dict:
    """
    Start the GitHub App setup flow.
    Returns the manifest flow URL for the user to complete installation.
    """
    manifest = get_manifest(webhook_url, app_url)
    
    # In production, this would POST to GitHub's manifest endpoint:
    # POST https://api.github.com/app-manifests/{code}/conversions
    # For now, return the manifest for manual setup
    
    manifest_json = __import__("json").dumps(manifest, indent=2)
    
    # Generate the one-click setup URL
    manifest_encoded = __import__("base64").b64encode(
        manifest_json.encode()
    ).decode()
    
    flow_url = f"https://github.com/apps/new?manifest={manifest_encoded}"
    
    return {
        "manifest": manifest,
        "flow_url": flow_url,
        "instructions": [
            "1. Open the flow_url in your browser",
            "2. Review and accept the permissions",
            "3. GitHub will create the app and provide: App ID, Private Key, Webhook Secret",
            "4. Set these as environment variables:",
            "   - GITHUB_APP_ID=<app_id>",
            "   - GITHUB_APP_PRIVATE_KEY=<path_to_pem>",
            "   - VIBELOCK_GITHUB_WEBHOOK_SECRET=<webhook_secret>",
            "5. Restart VibeLock to apply",
        ],
    }


async def complete_setup(
    app_id: int,
    private_key: str,
    webhook_secret: str,
    installation_id: Optional[int] = None,
) -> dict:
    """
    Complete the GitHub App setup by validating credentials.
    """
    import jwt
    import time
    import httpx
    
    # Generate JWT for GitHub App authentication
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 600,
        "iss": str(app_id),
    }
    
    try:
        app_token = jwt.encode(payload, private_key, algorithm="RS256")
    except Exception as e:
        return {"success": False, "error": f"Invalid private key: {str(e)}"}
    
    # Verify by fetching app info
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                "https://api.github.com/app",
                headers={
                    "Authorization": f"Bearer {app_token}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            if resp.status_code == 200:
                app_info = resp.json()
                return {
                    "success": True,
                    "app_name": app_info.get("name"),
                    "app_id": app_id,
                    "owner": app_info.get("owner", {}).get("login"),
                    "installation_id": installation_id,
                }
            else:
                return {
                    "success": False,
                    "error": f"GitHub API returned {resp.status_code}: {resp.text}",
                }
        except Exception as e:
            return {"success": False, "error": f"Connection failed: {str(e)}"}


# --- Installation Management ---

async def list_installations(app_id: int, private_key: str) -> list[dict]:
    """List all GitHub App installations."""
    import jwt
    import time
    import httpx
    
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": str(app_id)}
    app_token = jwt.encode(payload, private_key, algorithm="RS256")
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.github.com/app/installations",
            headers={
                "Authorization": f"Bearer {app_token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        if resp.status_code == 200:
            return resp.json()
        return []


async def get_installation_repos(
    installation_id: int,
    app_id: int,
    private_key: str,
) -> list[dict]:
    """List repositories accessible to an installation."""
    import jwt
    import time
    import httpx
    
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": str(app_id)}
    app_token = jwt.encode(payload, private_key, algorithm="RS256")
    
    # Get installation token
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        if token_resp.status_code != 201:
            return []
        
        installation_token = token_resp.json().get("token")
        
        # List repos
        repos_resp = await client.get(
            "https://api.github.com/installation/repositories",
            headers={
                "Authorization": f"Bearer {installation_token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        if repos_resp.status_code == 200:
            return repos_resp.json().get("repositories", [])
        return []