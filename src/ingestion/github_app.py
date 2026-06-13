"""
VibeLock — GitHub App Setup
Provides GitHub App manifest, setup flow, and one-click installation.
Implements the GitHub App manifest flow:
  1. User clicks "Setup VibeLock" → redirect to https://github.com/apps/new?manifest={json}
  2. GitHub creates the app and redirects to our redirect_url with a `code` parameter
  3. We POST to https://api.github.com/app-manifests/{code}/conversions
  4. GitHub returns: { id, client_id, client_secret, pem, webhook_secret, ... }
  5. We persist these and mark setup complete
"""

import os
import json
import logging
from typing import Optional

import jwt
import httpx
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

    Returns the manifest (as JSON string for URL encoding) and the one-click
    GitHub flow URL. The user opens this URL to create the app on GitHub.
    """
    manifest = get_manifest(webhook_url, app_url)

    manifest_json = json.dumps(manifest, indent=2)

    # Generate the one-click setup URL using the manifest parameter
    flow_url = f"https://github.com/apps/new?manifest={manifest_json}"

    return {
        "manifest": manifest,
        "flow_url": flow_url,
        "instructions": [
            "1. Open the flow_url in your browser",
            "2. Review and accept the permissions",
            "3. GitHub will create the app and redirect you back with a setup code",
            "4. The callback endpoint will complete the setup automatically",
            "5. Alternatively, set these as environment variables:",
            "   - GITHUB_APP_ID=<app_id>",
            "   - GITHUB_APP_PRIVATE_KEY=<path_to_pem>",
            "   - VIBELOCK_GITHUB_WEBHOOK_SECRET=<webhook_secret>",
        ],
    }


async def complete_manifest_flow(code: str) -> dict:
    """
    Complete the GitHub App manifest flow by exchanging the temporary code
    for the full app credentials.

    Calls POST https://api.github.com/app-manifests/{code}/conversions
    Returns: { id, client_id, client_secret, pem, webhook_secret, slug, ... }

    Args:
        code: The temporary code from GitHub's redirect after app creation.

    Returns:
        dict with app credentials from GitHub.
    """
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"https://api.github.com/app-manifests/{code}/conversions",
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            if resp.status_code == 201:
                data = resp.json()
                logger.info("manifest_flow_completed", app_id=data.get("id"))
                return {"success": True, **data}
            else:
                error_detail = resp.text
                logger.error("manifest_flow_failed", status=resp.status_code, detail=error_detail)
                return {"success": False, "error": f"GitHub returned {resp.status_code}: {error_detail}"}
        except Exception as e:
            logger.error("manifest_flow_exception", error=str(e))
            return {"success": False, "error": f"Connection failed: {str(e)}"}


def _generate_jwt(app_id: int, private_key: str) -> str:
    """
    Generate a short-lived JWT for GitHub App authentication.

    Args:
        app_id: GitHub App ID (integer).
        private_key: PEM-encoded RSA private key string.

    Returns:
        JWT token string signed with RS256.
    """
    import time

    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 600,
        "iss": str(app_id),
    }

    return jwt.encode(payload, private_key, algorithm="RS256")


async def complete_setup(
    app_id: int,
    private_key: str,
    webhook_secret: str,
    installation_id: Optional[int] = None,
) -> dict:
    """
    Complete the GitHub App setup by validating credentials.

    Args:
        app_id: GitHub App ID.
        private_key: PEM-encoded RSA private key.
        webhook_secret: Webhook secret for validating incoming hooks.
        installation_id: Optional known installation ID.

    Returns:
        dict with success status and app info.
    """
    try:
        app_token = _generate_jwt(app_id, private_key)
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
    """
    List all GitHub App installations.

    Args:
        app_id: GitHub App ID.
        private_key: PEM-encoded RSA private key.

    Returns:
        List of installation dicts from GitHub API.
    """
    app_token = _generate_jwt(app_id, private_key)

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
        logger.warning("list_installations_failed", status=resp.status_code)
        return []


async def get_installation_repos(
    installation_id: int,
    app_id: int,
    private_key: str,
) -> list[dict]:
    """
    List repositories accessible to an installation.

    Args:
        installation_id: GitHub App installation ID.
        app_id: GitHub App ID.
        private_key: PEM-encoded RSA private key.

    Returns:
        List of repository dicts.
    """
    app_token = _generate_jwt(app_id, private_key)

    # Get installation access token
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        if token_resp.status_code != 201:
            logger.warning("installation_token_failed", status=token_resp.status_code)
            return []

        installation_token = token_resp.json()["token"]

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


# --- Environment Variable Fallback ---

def get_app_credentials_from_env() -> Optional[dict]:
    """
    Load GitHub App credentials from environment variables.

    Reads:
        GITHUB_APP_ID
        GITHUB_APP_PRIVATE_KEY (path to PEM file)
        VIBELOCK_GITHUB_WEBHOOK_SECRET

    Returns:
        dict with app_id, private_key, webhook_secret, or None if not configured.
    """
    app_id_str = os.getenv("GITHUB_APP_ID")
    private_key_path = os.getenv("GITHUB_APP_PRIVATE_KEY")
    webhook_secret = os.getenv("VIBELOCK_GITHUB_WEBHOOK_SECRET")

    if not app_id_str or not private_key_path:
        return None

    try:
        app_id = int(app_id_str)
    except (ValueError, TypeError):
        logger.error("GITHUB_APP_ID is not a valid integer")
        return None

    try:
        with open(private_key_path, "r") as f:
            private_key = f.read()
    except FileNotFoundError:
        logger.error(f"GITHUB_APP_PRIVATE_KEY file not found: {private_key_path}")
        return None
    except Exception as e:
        logger.error(f"Failed to read private key: {e}")
        return None

    return {
        "app_id": app_id,
        "private_key": private_key,
        "webhook_secret": webhook_secret or "",
    }