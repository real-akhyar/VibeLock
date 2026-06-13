"""
VibeLock — Remediation Engine: Context Assembler + Patch Generator
Assembles context from vulnerable files, generates isolated patches via LLM,
and enforces the 3-attempt guardrail.
"""
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import structlog

from ..scanner.heuristic import Finding, Severity
from ..shared.sanitizer import sanitize_code

logger = structlog.get_logger(__name__)

MAX_REMEDIATION_ATTEMPTS = 3

PATCH_GENERATOR_PROMPT = """You are a security-focused code fixer. Generate ONLY the exact code change needed to fix this vulnerability.

Vulnerability: {vuln_type} ({severity})
File: {file_path}
Line: {line_number}
Issue: {description}

Current code:
```
{code_snippet}
```

File context (surrounding code):
```
{file_context}
```

Rules:
1. Return ONLY valid JSON: {{"patch": "<the exact replacement code>", "explanation": "<brief>"}}
2. The patch must be a drop-in replacement for the vulnerable lines
3. Do NOT modify anything outside the vulnerable section
4. Do NOT add new imports or dependencies unless absolutely required
5. Preserve existing formatting and indentation
6. If the fix requires adding RLS policies, include the full SQL statement
7. For hardcoded secrets, replace with environment variable access pattern

Return your response as valid JSON only, no markdown wrapping."""


@dataclass
class PatchAttempt:
    attempt_number: int
    patch_code: str
    explanation: str
    verification_passed: bool = False
    error_message: Optional[str] = None


@dataclass
class RemediationResult:
    finding: Finding
    attempts: List[PatchAttempt] = field(default_factory=list)
    success: bool = False
    final_patch: Optional[str] = None


def assemble_context(finding: Finding, file_path: Path, context_lines: int = 10) -> str:
    """Extract surrounding code context around the vulnerable line."""
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").split("\n")
        start = max(0, finding.line_number - context_lines - 1)
        end = min(len(lines), finding.line_number + context_lines)
        return "\n".join(lines[start:end])
    except Exception:
        return finding.code_snippet


async def generate_patch(
    finding: Finding,
    file_path: Path,
    llm_call: callable,
) -> PatchAttempt:
    """Generate a single patch attempt via LLM."""
    file_context = assemble_context(finding, file_path)
    sanitized_snippet = sanitize_code(finding.code_snippet)
    sanitized_context = sanitize_code(file_context)
    
    prompt = PATCH_GENERATOR_PROMPT.format(
        vuln_type=finding.vulnerability_type.value,
        severity=finding.severity.value,
        file_path=str(file_path),
        line_number=finding.line_number,
        description=finding.description,
        code_snippet=sanitized_snippet,
        file_context=sanitized_context[:6000],
    )
    
    try:
        response = await llm_call(prompt)
        data = json.loads(response)
        return PatchAttempt(
            attempt_number=1,
            patch_code=data.get("patch", ""),
            explanation=data.get("explanation", ""),
        )
    except json.JSONDecodeError as e:
        return PatchAttempt(
            attempt_number=1,
            patch_code="",
            explanation="",
            error_message=f"Failed to parse LLM response: {e}",
        )
    except Exception as e:
        return PatchAttempt(
            attempt_number=1,
            patch_code="",
            explanation="",
            error_message=str(e),
        )


async def remediate_finding(
    finding: Finding,
    file_path: Path,
    llm_call: callable,
    verifier: callable,  # async function that takes (file_path, patch) -> (bool, str)
) -> RemediationResult:
    """Run the full remediation loop: generate → verify → retry up to 3 times."""
    result = RemediationResult(finding=finding)
    
    for attempt_num in range(1, MAX_REMEDIATION_ATTEMPTS + 1):
        logger.info(
            "remediation_attempt",
            vuln_id=finding.vulnerability_type.value,
            file=str(file_path),
            attempt=attempt_num,
        )
        
        patch = await generate_patch(finding, file_path, llm_call)
        patch.attempt_number = attempt_num
        result.attempts.append(patch)
        
        if patch.error_message:
            logger.warning("patch_generation_failed", error=patch.error_message)
            continue
        
        # Verify the patch
        passed, error = await verifier(file_path, patch.patch_code)
        patch.verification_passed = passed
        patch.error_message = error if not passed else None
        
        if passed:
            result.success = True
            result.final_patch = patch.patch_code
            logger.info("remediation_success", attempt=attempt_num)
            break
        else:
            logger.warning("verification_failed", attempt=attempt_num, error=error)
    
    if not result.success:
        logger.error(
            "remediation_exhausted",
            vuln_id=finding.vulnerability_type.value,
            attempts=MAX_REMEDIATION_ATTEMPTS,
        )
    
    return result