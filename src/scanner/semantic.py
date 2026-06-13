"""
VibeLock — Semantic AI Scanner (Context-Aware)
Triggers on critical files. Uses DeepSeek-Coder to detect logic flaws
like missing RLS policies, unvalidated inputs, and architectural vulnerabilities.
"""
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import structlog

from ..shared.sanitizer import sanitize_code
from ..scanner.heuristic import Finding, Severity, VulnType, ScanResult

logger = structlog.get_logger(__name__)

# Files that trigger semantic scanning (critical paths)
CRITICAL_FILE_PATTERNS = [
    "schema.sql", "migration", "migrations/",
    "middleware", "middleware/",
    "route", "routes/", "router",
    "auth", "authorization",
    "*.supabase.ts",
    "policy", "policies/",
    "guard", "guards/",
]

SEMANTIC_SCAN_PROMPT = """You are a security auditor. Analyze this code for logic-level vulnerabilities.

Focus on:
1. Missing Supabase Row-Level Security (RLS) policies — any table creation without "alter table ... enable row level security" or missing "create policy" statements
2. Unvalidated user inputs — any endpoint that takes user input without validation/sanitization
3. Authorization bypass — endpoints that don't check user ownership before returning/modifying data
4. Missing authentication checks — routes without auth middleware
5. Insecure defaults — permissive CORS, debug mode enabled, exposed admin endpoints

Respond with a JSON array of findings:
[{"vulnerability_type": "missing_rls|unvalidated_input|auth_bypass|missing_auth|insecure_default",
  "severity": "low|medium|high|critical",
  "file_path": "...",
  "line_number": null,
  "description": "...",
  "code_snippet": "...",
  "remediation_hint": "..."}]

If no issues found, return empty array [].

Code to analyze:
```
{code}
```"""


def is_critical_file(file_path: str) -> bool:
    """Check if a file matches critical patterns for semantic scanning."""
    path_lower = file_path.lower()
    for pattern in CRITICAL_FILE_PATTERNS:
        if pattern.replace("*", "") in path_lower:
            return True
    return False


def filter_critical_files(files: List[str]) -> List[str]:
    """Filter a list of changed files to only critical ones."""
    return [f for f in files if is_critical_file(f)]


@dataclass
class SemanticScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_analyzed: int = 0
    skipped_files: int = 0
    errors: List[str] = field(default_factory=list)


async def semantic_scan_file(
    file_path: Path,
    content: str,
    llm_call: callable,  # async function that takes prompt and returns response text
) -> List[Finding]:
    """Run semantic AI analysis on a single critical file."""
    sanitized = sanitize_code(content)
    prompt = SEMANTIC_SCAN_PROMPT.format(code=sanitized[:8000])  # Truncate for token budget
    
    try:
        response = await llm_call(prompt)
        raw_findings = json.loads(response)
        
        findings = []
        for f in raw_findings:
            findings.append(Finding(
                vulnerability_type=VulnType(f.get("vulnerability_type", "unvalidated_input")),
                severity=Severity(f.get("severity", "medium")),
                file_path=str(file_path),
                line_number=f.get("line_number"),
                description=f.get("description", ""),
                code_snippet=f.get("code_snippet", ""),
                remediation_hint=f.get("remediation_hint", ""),
            ))
        return findings
    except json.JSONDecodeError as e:
        logger.error("semantic_parse_error", file=str(file_path), error=str(e))
        return []
    except Exception as e:
        logger.error("semantic_scan_error", file=str(file_path), error=str(e))
        return []


async def semantic_scan_directory(
    root: Path,
    changed_files: List[str],
    llm_call: callable,
) -> SemanticScanResult:
    """Run semantic scan on critical files only."""
    result = SemanticScanResult()
    critical = filter_critical_files(changed_files)
    result.skipped_files = len(changed_files) - len(critical)
    result.files_analyzed = len(critical)
    
    for file_rel in critical:
        file_path = root / file_rel
        if not file_path.exists():
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            findings = await semantic_scan_file(file_path, content, llm_call)
            result.findings.extend(findings)
        except Exception as e:
            result.errors.append(f"Failed to analyze {file_rel}: {e}")
    
    logger.info(
        "semantic_scan_complete",
        analyzed=result.files_analyzed,
        skipped=result.skipped_files,
        findings=len(result.findings),
    )
    return result