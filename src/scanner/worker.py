"""
VibeLock Celery Worker — Scanner
Consumes scan jobs from Redis queue, runs heuristic + semantic scans,
persists findings to Supabase.
"""

import os
import json
import logging
from datetime import datetime, timezone
from celery import Celery
from celery.signals import worker_ready

from vibelock.src.scanner.heuristic import HeuristicScanner
from vibelock.src.scanner.semantic import SemanticScanner
from vibelock.src.shared.sanitizer import TokenSanitizer
from vibelock.src.shared.loop_state import LoopStateManager

logger = logging.getLogger(__name__)

# --- Celery App ---
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
app = Celery("vibelock_scanner", broker=REDIS_URL, backend=REDIS_URL)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_default_queue="vibelock.scan",
)

# --- Supabase Client (lazy init) ---
_supabase = None


def get_supabase():
    global _supabase
    if _supabase is None:
        from supabase import create_client

        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_KEY")
        if not url or not key:
            logger.warning("SUPABASE_URL or SUPABASE_SERVICE_KEY not set — DB writes disabled")
            return None
        _supabase = create_client(url, key)
    return _supabase


# --- Workers ---
heuristic = HeuristicScanner()
semantic = SemanticScanner()
sanitizer = TokenSanitizer()
loop_state = LoopStateManager()


@app.task(bind=True, name="vibelock.scan.repository")
def scan_repository(self, payload: dict):
    """
    Main scan task. Payload from webhook:
    {
        "repository_id": "<uuid>",
        "full_name": "owner/repo",
        "commit_sha": "abc123...",
        "branch": "main",
        "changed_files": ["path/to/file.py", ...],
        "installation_id": 12345
    }
    """
    repo_id = payload["repository_id"]
    commit_sha = payload["commit_sha"]
    branch = payload["branch"]
    changed_files = payload.get("changed_files", [])
    full_name = payload.get("full_name", "unknown")

    logger.info(f"Scan started: {full_name}@{commit_sha} ({len(changed_files)} files)")

    supabase = get_supabase()

    # --- Create scan record ---
    scan_id = None
    if supabase:
        try:
            result = (
                supabase.table("scans")
                .insert({
                    "repository_id": repo_id,
                    "commit_sha": commit_sha,
                    "branch": branch,
                    "status": "scanning",
                    "started_at": datetime.now(timezone.utc).isoformat(),
                })
                .execute()
            )
            scan_id = result.data[0]["id"] if result.data else None
        except Exception as e:
            logger.error(f"Failed to create scan record: {e}")

    all_vulnerabilities = []

    # --- Stage 1: Heuristic scan (all files) ---
    for file_path in changed_files:
        try:
            findings = heuristic.scan_file(file_path)
            for finding in findings:
                finding["scan_id"] = scan_id
                finding["repository_id"] = repo_id
                finding["commit_sha"] = commit_sha
                finding["file_path"] = file_path
                finding["scanner"] = "heuristic"
                all_vulnerabilities.append(finding)
        except FileNotFoundError:
            logger.warning(f"File not found (may be deleted): {file_path}")
        except Exception as e:
            logger.error(f"Heuristic scan failed for {file_path}: {e}")

    # --- Stage 2: Semantic scan (critical files only) ---
    critical_patterns = [
        "schema.sql", "*.supabase.ts", "middleware", "auth", "route",
        "api/", "controller", "handler", "service",
    ]
    critical_files = [
        f for f in changed_files
        if any(pattern.replace("*", "") in f.lower() for pattern in critical_patterns)
    ]

    for file_path in critical_files:
        try:
            with open(file_path, "r") as fh:
                code = fh.read()
            # Sanitize before sending to LLM
            clean_code = sanitizer.sanitize(code)
            findings = semantic.scan_code(clean_code, file_path)
            for finding in findings:
                finding["scan_id"] = scan_id
                finding["repository_id"] = repo_id
                finding["commit_sha"] = commit_sha
                finding["file_path"] = file_path
                finding["scanner"] = "semantic"
                all_vulnerabilities.append(finding)
        except FileNotFoundError:
            logger.warning(f"Critical file not found: {file_path}")
        except Exception as e:
            logger.error(f"Semantic scan failed for {file_path}: {e}")

    # --- Persist vulnerabilities ---
    if supabase and all_vulnerabilities:
        try:
            for vuln in all_vulnerabilities:
                supabase.table("vulnerabilities").insert({
                    "scan_id": scan_id,
                    "vulnerability_type": vuln.get("type", "unknown"),
                    "severity": vuln.get("severity", "medium"),
                    "file_path": vuln.get("file_path", ""),
                    "line_number": vuln.get("line_number"),
                    "description": vuln.get("description", ""),
                    "code_snippet": vuln.get("code_snippet", ""),
                    "remediation_status": "detected",
                }).execute()
        except Exception as e:
            logger.error(f"Failed to persist vulnerabilities: {e}")

    # --- Update scan record ---
    if supabase and scan_id:
        try:
            supabase.table("scans").update({
                "status": "completed",
                "vulnerabilities_count": len(all_vulnerabilities),
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", scan_id).execute()
        except Exception as e:
            logger.error(f"Failed to update scan record: {e}")

    # --- Dispatch remediation for high/critical findings ---
    critical_findings = [
        v for v in all_vulnerabilities
        if v.get("severity") in ("high", "critical")
    ]
    if critical_findings:
        from vibelock.src.remediation.worker import remediate_vulnerability

        for vuln in critical_findings:
            remediate_vulnerability.delay(vuln)

    logger.info(
        f"Scan complete: {full_name}@{commit_sha} — "
        f"{len(all_vulnerabilities)} vulns ({len(critical_findings)} critical)"
    )

    return {
        "scan_id": str(scan_id) if scan_id else None,
        "vulnerabilities_count": len(all_vulnerabilities),
        "critical_count": len(critical_findings),
    }


@worker_ready.connect
def on_worker_ready(**kwargs):
    logger.info("VibeLock Scanner worker ready — listening on queue 'vibelock.scan'")