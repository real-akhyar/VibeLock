"""
VibeLock Celery Worker — Remediation
Consumes remediation jobs, runs the agentic fix loop (max 3 attempts),
verifies patches, and dispatches PR creation.
"""

import os
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from celery import Celery

from vibelock.src.remediation.engine import remediate_finding, generate_patch
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
    vuln_type = vuln.get("vulnerability_type", vuln.get("type", "unknown"))
    file_path_str = vuln.get("file_path", "")
    severity = vuln.get("severity", "medium")

    logger.info(f"Remediation started: {vuln_id} ({vuln_type}) in {file_path_str}")

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
    file_path = Path(file_path_str)
    try:
        original_code = file_path.read_text(encoding="utf-8", errors="ignore")
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

        # Generate patch using the engine's generate_patch function
        # Build a Finding-like dict for the engine
        finding_dict = {
            "vulnerability_type": vuln_type,
            "severity": severity,
            "file_path": file_path_str,
            "line_number": vuln.get("line_number", 1),
            "description": vuln.get("description", ""),
            "code_snippet": vuln.get("code_snippet", clean_code[:500]),
        }

        try:
            patch_result = generate_patch(
                finding=finding_dict,
                file_path=file_path,
                llm_call=_llm_call_sync,
            )
            patch_code = patch_result.patch_code if hasattr(patch_result, 'patch_code') else patch_result.get("patch_code", "")
        except Exception as e:
            last_error = f"Patch generation failed: {e}"
            logger.warning(f"Attempt {attempt}: {last_error}")
            continue

        if not patch_code:
            last_error = "Patch generator returned empty result"
            logger.warning(f"Attempt {attempt}: {last_error}")
            continue

        # Verify patch
        verification = verifier.verify(
            original_code=original_code,
            patched_code=patch_code,
            file_path=file_path_str,
            vulnerability={"vulnerability_type": vuln_type},
        )

        budget.record_attempt()

        if verification.get("passed"):
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
            "last_error": str(last_error),
        }

    # --- Patch verified — create PR ---
    try:
        from vibelock.src.remediation.github_pr import create_fix_pr

        pr_result = create_fix_pr(
            vulnerability=vuln,
            patched_code=patch_code,
            original_code=original_code,
            file_path=file_path_str,
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

        # --- Send PR notification ---
        try:
            from vibelock.src.notifications import dispatch_notification
            from vibelock.src.notifications.models import NotificationEvent

            full_name = vuln.get("full_name", "unknown")
            dispatch_notification(NotificationEvent.PR_OPENED, {
                "org": full_name.split("/")[0] if "/" in full_name else full_name,
                "repo": full_name,
                "pr_url": pr_result.get("html_url", ""),
                "vuln_type": vuln_type,
                "severity": severity,
                "file_path": file_path,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except ImportError:
            logger.info("notifications_module_not_available")
        except Exception as e:
            logger.error(f"PR notification failed: {e}")

        return {"status": "pr_opened", "pr_url": pr_result.get("html_url")}

    except Exception as e:
        logger.error(f"PR creation failed: {e}")
        _mark_failed(supabase, vuln_id, f"PR creation failed: {str(e)}")
        return {"status": "failed", "reason": "pr_creation_failed", "error": str(e)}


def _llm_call_sync(prompt: str) -> str:
    """
    Synchronous LLM call wrapper for Celery tasks.
    Uses DeepSeek API via HTTP request.
    """
    import os
    import json
    from urllib.request import Request, urlopen
    from urllib.error import URLError

    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        logger.warning("DEEPSEEK_API_KEY not set — using mock response")
        return json.dumps({
            "patch": "# [VibeLock] Patch generation requires DEEPSEEK_API_KEY",
            "explanation": "No API key configured"
        })

    try:
        body = json.dumps({
            "model": "deepseek-coder",
            "messages": [
                {"role": "system", "content": "You are a security-focused code fixer. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "max_tokens": 2000,
        }).encode()

        req = Request(
            "https://api.deepseek.com/v1/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
        )

        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"]

    except Exception as e:
        logger.error(f"LLM call failed: {e}")
        raise


def _mark_failed(supabase, vuln_id: str, reason: str):
    """Mark vulnerability as failed and log reason."""
    logger.error(f"Remediation failed for {vuln_id}: {reason}")
    if supabase:
        try:
            supabase.table("vulnerabilities").update({
                "remediation_status": "failed",
            }).eq("id", vuln_id).execute()
        except Exception as e:
            logger.error(f"Failed to update failure status: {e}")

    # --- Send failure notification ---
    try:
        from vibelock.src.notifications import dispatch_notification
        from vibelock.src.notifications.models import NotificationEvent

        dispatch_notification(NotificationEvent.REMEDIATION_FAILED, {
            "org": "unknown",
            "repo": "unknown",
            "vuln_id": vuln_id,
            "vuln_type": "unknown",
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except ImportError:
        pass
    except Exception as e:
        logger.error(f"Failure notification failed: {e}")