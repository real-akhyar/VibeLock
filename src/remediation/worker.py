"""
VibeLock Celery Worker — Remediation
Consumes remediation jobs, runs the agentic fix loop (max 3 attempts),
verifies patches, and dispatches PR creation.
"""

import os
import json
import logging
from datetime import datetime, timezone
from celery import Celery

from vibelock.src.remediation.engine import RemediationEngine
from vibelock.src.verifier.patch_verifier import PatchVerifier
from vibelock.src.shared.sanitizer import TokenSanitizer
from vibelock.src.shared.budget import BudgetGuard

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
app = Celery("vibelock_remediation", broker=REDIS_URL, backend=REDIS_URL)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_default_queue="vibelock.remediate",
)

_supabase = None


def get_supabase():
    global _supabase
    if _supabase is None:
        from supabase import create_client

        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_KEY")
        if not url or not key:
            logger.warning("SUPABASE_URL or SUPABASE_SERVICE_KEY not set")
            return None
        _supabase = create_client(url, key)
    return _supabase


engine = RemediationEngine()
verifier = PatchVerifier()
sanitizer = TokenSanitizer()
budget = BudgetGuard()


@app.task(bind=True, name="vibelock.remediate.vulnerability", max_retries=0)
def remediate_vulnerability(self, vuln: dict):
    """
    Run the agentic remediation loop for a single vulnerability.

    vuln dict:
    {
        "id": "<uuid>",
        "scan_id": "<uuid>",
        "vulnerability_type": "hardcoded_secret",
        "severity": "high",
        "file_path": "src/auth.py",
        "line_number": 42,
        "description": "...",
        "code_snippet": "...",
        "repository_id": "<uuid>",
        "commit_sha": "abc123",
        "full_name": "owner/repo",
        "installation_id": 12345
    }
    """
    vuln_id = vuln.get("id", "unknown")
    vuln_type = vuln.get("vulnerability_type", "unknown")
    file_path = vuln.get("file_path", "")
    severity = vuln.get("severity", "medium")

    logger.info(f"Remediation started: {vuln_id} ({vuln_type}) in {file_path}")

    supabase = get_supabase()

    # Update status to 'patching'
    if supabase:
        try:
            supabase.table("vulnerabilities").update(
                {"remediation_status": "patching"}
            ).eq("id", vuln_id).execute()
        except Exception as e:
            logger.error(f"Failed to update vuln status: {e}")

    # --- Read the vulnerable file ---
    try:
        with open(file_path, "r") as fh:
            original_code = fh.read()
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        _mark_failed(supabase, vuln_id, f"File not found: {file_path}")
        return {"status": "failed", "reason": "file_not_found"}

    # --- Agentic loop: max 3 attempts ---
    MAX_ATTEMPTS = 3
    patch_code = None
    last_error = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        if budget.is_exhausted():
            logger.warning("Budget exhausted — aborting remediation")
            _mark_failed(supabase, vuln_id, "Budget exhausted")
            return {"status": "failed", "reason": "budget_exhausted"}

        logger.info(f"Attempt {attempt}/{MAX_ATTEMPTS} for {vuln_id}")

        # Sanitize code before sending to LLM
        clean_code = sanitizer.sanitize(original_code)

        # Generate patch
        patch_code = engine.generate_patch(
            vulnerability=vuln,
            original_code=clean_code,
            attempt=attempt,
        )

        if not patch_code:
            last_error = "Patch generator returned empty result"
            logger.warning(f"Attempt {attempt}: {last_error}")
            continue

        # Verify patch
        verification = verifier.verify(
            original_code=original_code,
            patched_code=patch_code,
            file_path=file_path,
            vulnerability=vuln,
        )

        budget.record_attempt()

        if verification["passed"]:
            logger.info(f"Patch verified on attempt {attempt}")
            break
        else:
            last_error = verification.get("errors", ["Unknown verification failure"])
            logger.warning(f"Attempt {attempt} failed verification: {last_error}")
            patch_code = None

    # --- All attempts exhausted ---
    if patch_code is None:
        _mark_failed(
            supabase, vuln_id,
            f"All {MAX_ATTEMPTS} attempts failed. Last error: {last_error}"
        )
        return {
            "status": "failed",
            "reason": "max_attempts_exhausted",
            "last_error": last_error,
        }

    # --- Patch verified — create PR ---
    try:
        from vibelock.src.remediation.github_pr import create_fix_pr

        pr_result = create_fix_pr(
            vulnerability=vuln,
            patched_code=patch_code,
            original_code=original_code,
            file_path=file_path,
        )

        if supabase:
            supabase.table("vulnerabilities").update(
                {"remediation_status": "pr_opened"}
            ).eq("id", vuln_id).execute()

            supabase.table("pull_requests").insert({
                "vulnerability_id": vuln_id,
                "github_pr_number": pr_result.get("number"),
                "pr_url": pr_result.get("html_url", ""),
                "status": "open",
                "patch_code": patch_code,
            }).execute()

        logger.info(f"PR opened for {vuln_id}: {pr_result.get('html_url')}")
        return {"status": "pr_opened", "pr_url": pr_result.get("html_url")}

    except Exception as e:
        logger.error(f"PR creation failed: {e}")
        _mark_failed(supabase, vuln_id, f"PR creation failed: {str(e)}")
        return {"status": "failed", "reason": "pr_creation_failed", "error": str(e)}


def _mark_failed(supabase, vuln_id: str, reason: str):
    """Mark vulnerability as failed and log reason."""
    logger.error(f"Remediation failed for {vuln_id}: {reason}")
    if supabase:
        try:
            supabase.table("vulnerabilities").update({
                "remediation_status": "failed",
                "description": supabase.raw(
                    f"description || '\n[FAILED] {reason}'"
                ),
            }).eq("id", vuln_id).execute()
        except Exception as e:
            logger.error(f"Failed to update failure status: {e}")