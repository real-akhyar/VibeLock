"""
VibeLock Supabase Client
Centralized Supabase integration for database reads/writes.
Used by scanner, remediation engine, and API gateway.
"""

import os
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class SupabaseClient:
    """Singleton Supabase client wrapper for VibeLock."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.url = os.getenv("SUPABASE_URL")
        self.service_key = os.getenv("SUPABASE_SERVICE_KEY")
        self.anon_key = os.getenv("SUPABASE_ANON_KEY")
        self._client = None

        if not self.url or not self.service_key:
            logger.warning(
                "SUPABASE_URL or SUPABASE_SERVICE_KEY not set — "
                "Supabase integration disabled. Set env vars to enable."
            )
        else:
            self._connect()

    def _connect(self):
        """Initialize the Supabase client."""
        try:
            from supabase import create_client

            self._client = create_client(self.url, self.service_key)
            logger.info(f"Supabase connected: {self.url}")
        except ImportError:
            logger.error(
                "supabase-py not installed. Run: pip install supabase"
            )
        except Exception as e:
            logger.error(f"Supabase connection failed: {e}")

    @property
    def client(self):
        return self._client

    @property
    def is_connected(self) -> bool:
        return self._client is not None

    # --- Organizations ---

    def get_organization(self, installation_id: int) -> Optional[Dict]:
        """Get organization by GitHub installation ID."""
        if not self._client:
            return None
        try:
            result = (
                self._client.table("organizations")
                .select("*")
                .eq("github_installation_id", installation_id)
                .single()
                .execute()
            )
            return result.data
        except Exception as e:
            logger.error(f"get_organization failed: {e}")
            return None

    def upsert_organization(
        self, installation_id: int, org_name: str, plan_tier: str = "free"
    ) -> Optional[Dict]:
        """Create or update an organization."""
        if not self._client:
            return None
        try:
            result = (
                self._client.table("organizations")
                .upsert({
                    "github_installation_id": installation_id,
                    "org_name": org_name,
                    "plan_tier": plan_tier,
                })
                .execute()
            )
            return result.data[0] if result.data else None
        except Exception as e:
            logger.error(f"upsert_organization failed: {e}")
            return None

    # --- Repositories ---

    def get_repository(self, github_repo_id: int) -> Optional[Dict]:
        """Get repository by GitHub repo ID."""
        if not self._client:
            return None
        try:
            result = (
                self._client.table("repositories")
                .select("*")
                .eq("github_repo_id", github_repo_id)
                .single()
                .execute()
            )
            return result.data
        except Exception as e:
            logger.error(f"get_repository failed: {e}")
            return None

    def upsert_repository(
        self, organization_id: str, github_repo_id: int, full_name: str
    ) -> Optional[Dict]:
        """Create or update a repository."""
        if not self._client:
            return None
        try:
            result = (
                self._client.table("repositories")
                .upsert({
                    "organization_id": organization_id,
                    "github_repo_id": github_repo_id,
                    "full_name": full_name,
                    "is_active": True,
                })
                .execute()
            )
            return result.data[0] if result.data else None
        except Exception as e:
            logger.error(f"upsert_repository failed: {e}")
            return None

    def get_active_repositories(self, organization_id: str) -> List[Dict]:
        """Get all active repositories for an organization."""
        if not self._client:
            return []
        try:
            result = (
                self._client.table("repositories")
                .select("*")
                .eq("organization_id", organization_id)
                .eq("is_active", True)
                .execute()
            )
            return result.data or []
        except Exception as e:
            logger.error(f"get_active_repositories failed: {e}")
            return []

    # --- Scans ---

    def create_scan(
        self,
        repository_id: str,
        commit_sha: str,
        branch: str,
    ) -> Optional[str]:
        """Create a new scan record. Returns scan ID."""
        if not self._client:
            return None
        try:
            result = (
                self._client.table("scans")
                .insert({
                    "repository_id": repository_id,
                    "commit_sha": commit_sha,
                    "branch": branch,
                    "status": "queued",
                    "started_at": datetime.now(timezone.utc).isoformat(),
                })
                .execute()
            )
            return result.data[0]["id"] if result.data else None
        except Exception as e:
            logger.error(f"create_scan failed: {e}")
            return None

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        vulnerabilities_count: int = 0,
    ):
        """Update scan status and completion time."""
        if not self._client:
            return
        try:
            update_data = {
                "status": status,
                "vulnerabilities_count": vulnerabilities_count,
            }
            if status in ("completed", "failed"):
                update_data["completed_at"] = datetime.now(timezone.utc).isoformat()
            (
                self._client.table("scans")
                .update(update_data)
                .eq("id", scan_id)
                .execute()
            )
        except Exception as e:
            logger.error(f"update_scan_status failed: {e}")

    # --- Vulnerabilities ---

    def create_vulnerability(self, vuln: Dict) -> Optional[str]:
        """Create a vulnerability record. Returns vuln ID."""
        if not self._client:
            return None
        try:
            result = (
                self._client.table("vulnerabilities")
                .insert({
                    "scan_id": vuln.get("scan_id"),
                    "vulnerability_type": vuln.get("type", "unknown"),
                    "severity": vuln.get("severity", "medium"),
                    "file_path": vuln.get("file_path", ""),
                    "line_number": vuln.get("line_number"),
                    "description": vuln.get("description", ""),
                    "code_snippet": vuln.get("code_snippet", ""),
                    "remediation_status": "detected",
                })
                .execute()
            )
            return result.data[0]["id"] if result.data else None
        except Exception as e:
            logger.error(f"create_vulnerability failed: {e}")
            return None

    def update_vulnerability_status(
        self, vuln_id: str, status: str, extra: Dict = None
    ):
        """Update vulnerability remediation status."""
        if not self._client:
            return
        try:
            update_data = {"remediation_status": status}
            if extra:
                update_data.update(extra)
            (
                self._client.table("vulnerabilities")
                .update(update_data)
                .eq("id", vuln_id)
                .execute()
            )
        except Exception as e:
            logger.error(f"update_vulnerability_status failed: {e}")

    def get_pending_vulnerabilities(self, limit: int = 10) -> List[Dict]:
        """Get vulnerabilities awaiting remediation."""
        if not self._client:
            return []
        try:
            result = (
                self._client.table("vulnerabilities")
                .select("*")
                .eq("remediation_status", "detected")
                .in_("severity", ["high", "critical"])
                .order("created_at", desc=False)
                .limit(limit)
                .execute()
            )
            return result.data or []
        except Exception as e:
            logger.error(f"get_pending_vulnerabilities failed: {e}")
            return []

    # --- Pull Requests ---

    def create_pr_record(self, pr_data: Dict) -> Optional[str]:
        """Record a created pull request."""
        if not self._client:
            return None
        try:
            result = (
                self._client.table("pull_requests")
                .insert({
                    "vulnerability_id": pr_data.get("vulnerability_id"),
                    "github_pr_number": pr_data.get("github_pr_number"),
                    "pr_url": pr_data.get("pr_url", ""),
                    "status": "open",
                    "patch_code": pr_data.get("patch_code", ""),
                })
                .execute()
            )
            return result.data[0]["id"] if result.data else None
        except Exception as e:
            logger.error(f"create_pr_record failed: {e}")
            return None

    def update_pr_status(self, pr_id: str, status: str):
        """Update PR status (merged, closed)."""
        if not self._client:
            return
        try:
            (
                self._client.table("pull_requests")
                .update({"status": status})
                .eq("id", pr_id)
                .execute()
            )
        except Exception as e:
            logger.error(f"update_pr_status failed: {e}")

    # --- Health Check ---

    def health_check(self) -> Dict[str, Any]:
        """Check Supabase connectivity."""
        if not self._client:
            return {"connected": False, "error": "SUPABASE_URL not configured"}
        try:
            result = self._client.table("organizations").select("id").limit(1).execute()
            return {"connected": True, "latency_ms": None}
        except Exception as e:
            return {"connected": False, "error": str(e)}


# Module-level singleton
supabase = SupabaseClient()