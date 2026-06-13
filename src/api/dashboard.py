"""
VibeLock — Dashboard API
Provides vulnerability stats, trends, and history endpoints
for the user-facing dashboard.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from collections import Counter

from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from vibelock.src.shared.supabase_client import supabase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


# --- Response Models ---

class VulnerabilitySummary(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_type: dict[str, int]
    by_status: dict[str, int]


class TrendPoint(BaseModel):
    date: str
    detected: int
    resolved: int
    open: int


class ScanStats(BaseModel):
    total_scans: int
    completed_scans: int
    failed_scans: int
    avg_scan_duration_seconds: Optional[float] = None


class RepositoryStats(BaseModel):
    repository: str
    total_vulns: int
    critical: int
    high: int
    open_prs: int


class DashboardResponse(BaseModel):
    summary: VulnerabilitySummary
    trends: list[TrendPoint]
    scans: ScanStats
    top_repositories: list[RepositoryStats]
    generated_at: str


class PaginatedVulns(BaseModel):
    data: list[dict]
    total: int
    page: int
    page_size: int


class VulnDetail(BaseModel):
    id: str
    vulnerability_type: str
    severity: str
    file_path: str
    line_number: Optional[int] = None
    description: str
    code_snippet: Optional[str] = None
    remediation_status: str
    created_at: str
    repository: str
    scan: Optional[dict] = None
    pull_requests: list[dict] = []


class OrgSummary(BaseModel):
    id: str
    org_name: str
    plan_tier: str
    repo_count: int
    total_vulns: int
    open_critical: int
    last_scan_at: Optional[str] = None


class DashboardHealth(BaseModel):
    status: str
    supabase: dict
    redis: dict
    last_scan_at: Optional[str] = None
    timestamp: str


# --- Helpers ---

def _resolve_repo_ids_for_org(organization_id: str) -> list[str]:
    if not supabase.is_connected:
        return []
    try:
        result = (
            supabase.client.table("repositories")
            .select("id")
            .eq("organization_id", organization_id)
            .eq("is_active", True)
            .execute()
        )
        return [r["id"] for r in (result.data or [])]
    except Exception as e:
        logger.error(f"Failed to resolve repo IDs for org {organization_id}: {e}")
        return []


def _resolve_repo_name(repository_id: str) -> str:
    if not supabase.is_connected:
        return repository_id
    try:
        result = (
            supabase.client.table("repositories")
            .select("full_name")
            .eq("id", repository_id)
            .single()
            .execute()
        )
        return result.data.get("full_name", repository_id) if result.data else repository_id
    except Exception:
        return repository_id


# --- Endpoints ---

@router.get("/summary", response_model=VulnerabilitySummary)
async def get_summary(
    organization_id: Optional[str] = Query(None),
    days: int = Query(default=30, ge=1, le=365),
):
    if not supabase.is_connected:
        return _mock_summary()
    
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        query = (
            supabase.client.table("vulnerabilities")
            .select("severity, vulnerability_type, remediation_status")
            .gte("created_at", since)
        )
        if organization_id:
            repo_ids = _resolve_repo_ids_for_org(organization_id)
            if repo_ids:
                query = query.in_("repository_id", repo_ids)
            else:
                return VulnerabilitySummary(total=0, by_severity={}, by_type={}, by_status={})

        result = query.execute()
        vulns = result.data or []
        by_severity = dict(Counter(v.get("severity", "unknown") for v in vulns))
        by_type = dict(Counter(v.get("vulnerability_type", "unknown") for v in vulns))
        by_status = dict(Counter(v.get("remediation_status", "unknown") for v in vulns))
        
        return VulnerabilitySummary(total=len(vulns), by_severity=by_severity, by_type=by_type, by_status=by_status)
    except Exception as e:
        logger.error(f"Dashboard summary failed: {e}")
        return _mock_summary()


@router.get("/trends", response_model=list[TrendPoint])
async def get_trends(
    organization_id: Optional[str] = Query(None),
    days: int = Query(default=30, ge=1, le=365),
):
    if not supabase.is_connected:
        return _mock_trends(days)
    
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        query = (
            supabase.client.table("vulnerabilities")
            .select("created_at, remediation_status, repository_id")
            .gte("created_at", since)
            .order("created_at", desc=False)
        )
        if organization_id:
            repo_ids = _resolve_repo_ids_for_org(organization_id)
            if repo_ids:
                query = query.in_("repository_id", repo_ids)
            else:
                return _mock_trends(days)

        result = query.execute()
        vulns = result.data or []
        daily: dict[str, dict[str, int]] = {}
        for v in vulns:
            date = v["created_at"][:10] if v.get("created_at") else "unknown"
            if date not in daily:
                daily[date] = {"detected": 0, "resolved": 0, "open": 0}
            daily[date]["detected"] += 1
            if v.get("remediation_status") in ("resolved", "pr_opened", "merged"):
                daily[date]["resolved"] += 1
            else:
                daily[date]["open"] += 1
        
        return [TrendPoint(date=date, **counts) for date, counts in sorted(daily.items())]
    except Exception as e:
        logger.error(f"Dashboard trends failed: {e}")
        return _mock_trends(days)


@router.get("/scans", response_model=ScanStats)
async def get_scan_stats(
    organization_id: Optional[str] = Query(None),
    days: int = Query(default=30, ge=1, le=365),
):
    if not supabase.is_connected:
        return ScanStats(total_scans=0, completed_scans=0, failed_scans=0)
    
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        query = (
            supabase.client.table("scans")
            .select("status, started_at, completed_at, repository_id")
            .gte("started_at", since)
        )
        if organization_id:
            repo_ids = _resolve_repo_ids_for_org(organization_id)
            if repo_ids:
                query = query.in_("repository_id", repo_ids)
            else:
                return ScanStats(total_scans=0, completed_scans=0, failed_scans=0)

        result = query.execute()
        scans = result.data or []
        total = len(scans)
        completed = sum(1 for s in scans if s.get("status") == "completed")
        failed = sum(1 for s in scans if s.get("status") == "failed")
        
        durations = []
        for s in scans:
            if s.get("started_at") and s.get("completed_at"):
                try:
                    start = datetime.fromisoformat(s["started_at"].replace("Z", "+00:00"))
                    end = datetime.fromisoformat(s["completed_at"].replace("Z", "+00:00"))
                    durations.append((end - start).total_seconds())
                except (ValueError, TypeError):
                    pass
        
        avg_duration = sum(durations) / len(durations) if durations else None
        return ScanStats(
            total_scans=total, completed_scans=completed, failed_scans=failed,
            avg_scan_duration_seconds=round(avg_duration, 1) if avg_duration else None,
        )
    except Exception as e:
        logger.error(f"Dashboard scan stats failed: {e}")
        return ScanStats(total_scans=0, completed_scans=0, failed_scans=0)


@router.get("/repositories", response_model=list[RepositoryStats])
async def get_top_repositories(
    organization_id: Optional[str] = Query(None),
    limit: int = Query(default=10, ge=1, le=50),
):
    if not supabase.is_connected:
        return []
    
    try:
        query = supabase.client.table("vulnerabilities").select("repository_id, severity, remediation_status")
        if organization_id:
            repo_ids = _resolve_repo_ids_for_org(organization_id)
            if repo_ids:
                query = query.in_("repository_id", repo_ids)
            else:
                return []

        result = query.execute()
        vulns = result.data or []
        repo_data: dict[str, dict] = {}
        for v in vulns:
            rid = v.get("repository_id", "unknown")
            if rid not in repo_data:
                repo_data[rid] = {"repository": _resolve_repo_name(rid), "total_vulns": 0, "critical": 0, "high": 0, "open_prs": 0}
            repo_data[rid]["total_vulns"] += 1
            if v.get("severity") == "critical":
                repo_data[rid]["critical"] += 1
            if v.get("severity") == "high":
                repo_data[rid]["high"] += 1
            if v.get("remediation_status") == "pr_opened":
                repo_data[rid]["open_prs"] += 1
        
        sorted_repos = sorted(repo_data.values(), key=lambda r: r["total_vulns"], reverse=True)[:limit]
        return [RepositoryStats(**r) for r in sorted_repos]
    except Exception as e:
        logger.error(f"Dashboard repositories failed: {e}")
        return []


@router.get("/full", response_model=DashboardResponse)
async def get_full_dashboard(
    organization_id: Optional[str] = Query(None),
    days: int = Query(default=30, ge=1, le=365),
):
    summary, trends, scans, repos = await asyncio.gather(
        get_summary(organization_id, days),
        get_trends(organization_id, days),
        get_scan_stats(organization_id, days),
        get_top_repositories(organization_id),
    )
    return DashboardResponse(
        summary=summary, trends=trends, scans=scans, top_repositories=repos,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/vulnerabilities", response_model=PaginatedVulns)
async def list_vulnerabilities(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    severity: Optional[str] = Query(None),
    vulnerability_type: Optional[str] = Query(None, alias="type"),
    status: Optional[str] = Query(None),
    repository_id: Optional[str] = Query(None),
    organization_id: Optional[str] = Query(None),
):
    if not supabase.is_connected:
        return PaginatedVulns(data=[], total=0, page=page, page_size=page_size)

    try:
        query = supabase.client.table("vulnerabilities").select(
            "id, vulnerability_type, severity, file_path, line_number, "
            "description, code_snippet, remediation_status, created_at, repository_id",
            count="exact",
        )
        if severity:
            query = query.eq("severity", severity)
        if vulnerability_type:
            query = query.eq("vulnerability_type", vulnerability_type)
        if status:
            query = query.eq("remediation_status", status)
        if repository_id:
            query = query.eq("repository_id", repository_id)
        if organization_id:
            repo_ids = _resolve_repo_ids_for_org(organization_id)
            if repo_ids:
                query = query.in_("repository_id", repo_ids)
            else:
                return PaginatedVulns(data=[], total=0, page=page, page_size=page_size)

        start = (page - 1) * page_size
        end = start + page_size - 1
        query = query.order("created_at", desc=True).range(start, end)
        result = query.execute()
        vulns = result.data or []
        total = result.count if hasattr(result, "count") else len(vulns)

        for v in vulns:
            v["repository"] = _resolve_repo_name(v.get("repository_id", ""))

        return PaginatedVulns(data=vulns, total=total, page=page, page_size=page_size)
    except Exception as e:
        logger.error(f"Dashboard vulnerabilities list failed: {e}")
        return PaginatedVulns(data=[], total=0, page=page, page_size=page_size)


@router.get("/vulnerabilities/{vuln_id}", response_model=VulnDetail)
async def get_vulnerability_detail(vuln_id: str):
    if not supabase.is_connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        result = supabase.client.table("vulnerabilities").select("*").eq("id", vuln_id).single().execute()
        if not result.data:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        vuln = result.data

        prs_result = supabase.client.table("pull_requests").select("*").eq("vulnerability_id", vuln_id).execute()
        prs = prs_result.data or []

        scan = None
        if vuln.get("scan_id"):
            scan_result = supabase.client.table("scans").select(
                "id, status, commit_sha, branch, started_at, completed_at"
            ).eq("id", vuln["scan_id"]).single().execute()
            scan = scan_result.data

        return VulnDetail(
            id=vuln["id"],
            vulnerability_type=vuln.get("vulnerability_type", "unknown"),
            severity=vuln.get("severity", "unknown"),
            file_path=vuln.get("file_path", ""),
            line_number=vuln.get("line_number"),
            description=vuln.get("description", ""),
            code_snippet=vuln.get("code_snippet"),
            remediation_status=vuln.get("remediation_status", "unknown"),
            created_at=vuln.get("created_at", ""),
            repository=_resolve_repo_name(vuln.get("repository_id", "")),
            scan=scan,
            pull_requests=prs,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Dashboard vulnerability detail failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/organizations", response_model=list[OrgSummary])
async def list_organizations():
    if not supabase.is_connected:
        return []

    try:
        orgs_result = supabase.client.table("organizations").select("*").execute()
        orgs = orgs_result.data or []
        summaries = []

        for org in orgs:
            org_id = org["id"]
            repos_result = supabase.client.table("repositories").select("id").eq("organization_id", org_id).eq("is_active", True).execute()
            repo_ids = [r["id"] for r in (repos_result.data or [])]
            repo_count = len(repo_ids)

            total_vulns = 0
            open_critical = 0
            last_scan_at = None

            if repo_ids:
                vulns_result = supabase.client.table("vulnerabilities").select("severity, remediation_status").in_("repository_id", repo_ids).execute()
                for v in (vulns_result.data or []):
                    total_vulns += 1
                    if v.get("severity") == "critical" and v.get("remediation_status") not in ("resolved", "merged"):
                        open_critical += 1

                scans_result = supabase.client.table("scans").select("completed_at").in_("repository_id", repo_ids).order("completed_at", desc=True).limit(1).execute()
                if scans_result.data:
                    last_scan_at = scans_result.data[0].get("completed_at")

            summaries.append(OrgSummary(
                id=org_id,
                org_name=org.get("org_name", "unknown"),
                plan_tier=org.get("plan_tier", "free"),
                repo_count=repo_count,
                total_vulns=total_vulns,
                open_critical=open_critical,
                last_scan_at=last_scan_at,
            ))

        return summaries
    except Exception as e:
        logger.error(f"Dashboard organizations failed: {e}")
        return []


@router.get("/health", response_model=DashboardHealth)
async def dashboard_health():
    """Dashboard-specific health check."""
    supabase_health = supabase.health_check() if supabase.is_connected else {"connected": False, "error": "not configured"}

    redis_health = {"connected": False}
    try:
        import redis.asyncio as aioredis
        import os
        r = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        await r.ping()
        redis_health = {"connected": True}
        await r.close()
    except Exception as e:
        redis_health = {"connected": False, "error": str(e)}

    last_scan_at = None
    if supabase.is_connected:
        try:
            scan_result = supabase.client.table("scans").select("completed_at").order("completed_at", desc=True).limit(1).execute()
            if scan_result.data:
                last_scan_at = scan_result.data[0].get("completed_at")
        except Exception:
            pass

    return DashboardHealth(
        status="ok" if supabase_health.get("connected") else "degraded",
        supabase=supabase_health,
        redis=redis_health,
        last_scan_at=last_scan_at,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# --- Mock Data ---

def _mock_summary() -> VulnerabilitySummary:
    return VulnerabilitySummary(
        total=0,
        by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0},
        by_type={},
        by_status={"detected": 0, "patching": 0, "pr_opened": 0, "resolved": 0},
    )


def _mock_trends(days: int) -> list[TrendPoint]:
    return [
        TrendPoint(
            date=(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d"),
            detected=0,
            resolved=0,
            open=0,
        )
        for i in range(days)
    ]