"""
VibeLock — Dashboard API
Provides vulnerability stats, trends, and history endpoints
for the user-facing dashboard.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from collections import Counter

from fastapi import APIRouter, Query, HTTPException
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


# --- Endpoints ---

@router.get("/summary", response_model=VulnerabilitySummary)
async def get_summary(
    organization_id: Optional[str] = Query(None),
    days: int = Query(default=30, ge=1, le=365),
):
    """Get vulnerability summary counts."""
    if not supabase.is_connected:
        return _mock_summary()
    
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        
        result = (
            supabase.client.table("vulnerabilities")
            .select("severity, vulnerability_type, remediation_status")
            .gte("created_at", since)
            .execute()
        )
        
        vulns = result.data or []
        
        by_severity = dict(Counter(v.get("severity", "unknown") for v in vulns))
        by_type = dict(Counter(v.get("vulnerability_type", "unknown") for v in vulns))
        by_status = dict(Counter(v.get("remediation_status", "unknown") for v in vulns))
        
        return VulnerabilitySummary(
            total=len(vulns),
            by_severity=by_severity,
            by_type=by_type,
            by_status=by_status,
        )
    except Exception as e:
        logger.error(f"Dashboard summary failed: {e}")
        return _mock_summary()


@router.get("/trends", response_model=list[TrendPoint])
async def get_trends(
    days: int = Query(default=30, ge=1, le=365),
):
    """Get daily vulnerability trends."""
    if not supabase.is_connected:
        return _mock_trends(days)
    
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        
        result = (
            supabase.client.table("vulnerabilities")
            .select("created_at, remediation_status")
            .gte("created_at", since)
            .order("created_at", desc=False)
            .execute()
        )
        
        vulns = result.data or []
        
        # Group by date
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
        
        return [
            TrendPoint(date=date, **counts)
            for date, counts in sorted(daily.items())
        ]
    except Exception as e:
        logger.error(f"Dashboard trends failed: {e}")
        return _mock_trends(days)


@router.get("/scans", response_model=ScanStats)
async def get_scan_stats(
    days: int = Query(default=30, ge=1, le=365),
):
    """Get scan statistics."""
    if not supabase.is_connected:
        return ScanStats(total_scans=0, completed_scans=0, failed_scans=0)
    
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        
        result = (
            supabase.client.table("scans")
            .select("status, started_at, completed_at")
            .gte("started_at", since)
            .execute()
        )
        
        scans = result.data or []
        
        total = len(scans)
        completed = sum(1 for s in scans if s.get("status") == "completed")
        failed = sum(1 for s in scans if s.get("status") == "failed")
        
        # Average duration
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
            total_scans=total,
            completed_scans=completed,
            failed_scans=failed,
            avg_scan_duration_seconds=round(avg_duration, 1) if avg_duration else None,
        )
    except Exception as e:
        logger.error(f"Dashboard scan stats failed: {e}")
        return ScanStats(total_scans=0, completed_scans=0, failed_scans=0)


@router.get("/repositories", response_model=list[RepositoryStats])
async def get_top_repositories(
    limit: int = Query(default=10, ge=1, le=50),
):
    """Get top repositories by vulnerability count."""
    if not supabase.is_connected:
        return []
    
    try:
        # Get repos with vuln counts
        result = (
            supabase.client.table("vulnerabilities")
            .select("repository_id, severity, remediation_status")
            .execute()
        )
        
        vulns = result.data or []
        
        # Group by repo
        repo_data: dict[str, dict] = {}
        for v in vulns:
            rid = v.get("repository_id", "unknown")
            if rid not in repo_data:
                repo_data[rid] = {
                    "repository": rid,
                    "total_vulns": 0,
                    "critical": 0,
                    "high": 0,
                    "open_prs": 0,
                }
            repo_data[rid]["total_vulns"] += 1
            if v.get("severity") == "critical":
                repo_data[rid]["critical"] += 1
            if v.get("severity") == "high":
                repo_data[rid]["high"] += 1
            if v.get("remediation_status") == "pr_opened":
                repo_data[rid]["open_prs"] += 1
        
        # Sort by total and limit
        sorted_repos = sorted(
            repo_data.values(),
            key=lambda r: r["total_vulns"],
            reverse=True,
        )[:limit]
        
        return [RepositoryStats(**r) for r in sorted_repos]
    except Exception as e:
        logger.error(f"Dashboard repositories failed: {e}")
        return []


@router.get("/full", response_model=DashboardResponse)
async def get_full_dashboard(
    organization_id: Optional[str] = Query(None),
    days: int = Query(default=30, ge=1, le=365),
):
    """Get complete dashboard data in one call."""
    summary = await get_summary(organization_id, days)
    trends = await get_trends(days)
    scans = await get_scan_stats(days)
    repos = await get_top_repositories()
    
    return DashboardResponse(
        summary=summary,
        trends=trends,
        scans=scans,
        top_repositories=repos,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


# --- Mock Data (when Supabase is not connected) ---

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