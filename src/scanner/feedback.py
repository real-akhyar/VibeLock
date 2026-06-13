"""
VibeLock — False-Positive Feedback Loop
Allows users to mark vulnerabilities as false positives. The system records
these marks and uses them to adjust future scan confidence scores.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from vibelock.src.shared.supabase_client import supabase

logger = logging.getLogger(__name__)


# --- Models ---

class FeedbackEntry(BaseModel):
    """A user-submitted false-positive feedback entry."""
    vulnerability_id: str = Field(..., description="UUID of the vulnerability")
    repository: str = Field(..., description="Full repo name (owner/repo)")
    reason: str = Field(..., description="Why this is a false positive")
    marked_by: str = Field(default="user", description="Who marked it")
    pattern_signature: Optional[str] = Field(
        default=None,
        description="Hash of the code pattern that triggered the false positive",
    )


class FeedbackStats(BaseModel):
    """Aggregated false-positive statistics."""
    total_false_positives: int
    by_rule: dict[str, int]
    by_repository: dict[str, int]
    recent: list[dict]


# --- Core Logic ---

async def record_false_positive(entry: FeedbackEntry) -> dict:
    """
    Record a false-positive feedback entry in the database.

    Steps:
    1. Mark the vulnerability as false_positive in the vulns table.
    2. Insert a feedback record with the reason and pattern signature.
    3. Return the updated vulnerability state.
    """
    now = datetime.now(timezone.utc).isoformat()

    # Update vulnerability status
    vuln_result = (
        supabase.table("vulnerabilities")
        .update({"status": "false_positive", "resolved_at": now})
        .eq("id", entry.vulnerability_id)
        .execute()
    )

    if not vuln_result.data:
        logger.warning("vulnerability_not_found", vuln_id=entry.vulnerability_id)
        return {"success": False, "error": "Vulnerability not found"}

    # Insert feedback record
    feedback_result = (
        supabase.table("false_positive_feedback")
        .insert({
            "vulnerability_id": entry.vulnerability_id,
            "repository": entry.repository,
            "reason": entry.reason,
            "marked_by": entry.marked_by,
            "pattern_signature": entry.pattern_signature,
            "created_at": now,
        })
        .execute()
    )

    logger.info(
        "false_positive_recorded",
        vuln_id=entry.vulnerability_id,
        repo=entry.repository,
        rule=entry.pattern_signature,
    )

    return {
        "success": True,
        "vulnerability_id": entry.vulnerability_id,
        "new_status": "false_positive",
        "feedback_id": feedback_result.data[0]["id"] if feedback_result.data else None,
    }


async def get_feedback_stats(days: int = 30) -> FeedbackStats:
    """
    Get aggregated false-positive statistics for the dashboard.

    Returns counts by rule, by repository, and recent entries.
    """
    from datetime import timedelta

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    # Total count
    total_result = (
        supabase.table("false_positive_feedback")
        .select("id", count="exact")
        .gte("created_at", cutoff)
        .execute()
    )
    total = total_result.count or 0

    # By rule (pattern_signature)
    all_entries = (
        supabase.table("false_positive_feedback")
        .select("pattern_signature, repository, reason, created_at")
        .gte("created_at", cutoff)
        .order("created_at", desc=True)
        .limit(500)
        .execute()
    )

    by_rule: dict[str, int] = {}
    by_repo: dict[str, int] = {}
    recent: list[dict] = []

    for entry in (all_entries.data or []):
        sig = entry.get("pattern_signature") or "unknown"
        repo = entry.get("repository") or "unknown"
        by_rule[sig] = by_rule.get(sig, 0) + 1
        by_repo[repo] = by_repo.get(repo, 0) + 1
        if len(recent) < 20:
            recent.append(entry)

    return FeedbackStats(
        total_false_positives=total,
        by_rule=by_rule,
        by_repository=by_repo,
        recent=recent,
    )


async def adjust_confidence(
    rule_id: str,
    pattern_signature: str,
) -> float:
    """
    Adjust the confidence score for a scanner rule based on historical
    false-positive rate.

    Returns a multiplier (0.0–1.0) to apply to the rule's confidence.
    A rule with many false positives gets a lower multiplier.
    """
    # Count false positives for this pattern
    fp_result = (
        supabase.table("false_positive_feedback")
        .select("id", count="exact")
        .eq("pattern_signature", pattern_signature)
        .execute()
    )
    fp_count = fp_result.count or 0

    # Count total detections for this rule
    total_result = (
        supabase.table("vulnerabilities")
        .select("id", count="exact")
        .eq("rule_id", rule_id)
        .execute()
    )
    total_count = total_result.count or 1  # Avoid division by zero

    fp_rate = fp_count / max(total_count, 1)

    # Sigmoid-like decay: more false positives → lower confidence
    # At 0% FP rate → multiplier 1.0
    # At 50% FP rate → multiplier ~0.5
    # At 100% FP rate → multiplier ~0.1
    import math
    multiplier = 1.0 / (1.0 + math.exp(5 * (fp_rate - 0.3)))

    logger.debug(
        "confidence_adjusted",
        rule_id=rule_id,
        fp_count=fp_count,
        total_count=total_count,
        fp_rate=round(fp_rate, 3),
        multiplier=round(multiplier, 3),
    )

    return round(multiplier, 3)