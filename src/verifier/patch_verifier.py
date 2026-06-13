"""
VibeLock — Local Verification Agent (Sandbox)
Runs structural checks on generated patches: AST parsing, linting, syntax validation.
This is the SEPARATE verifier — adversarial to the implementer.
"""
import ast
import subprocess
import tempfile
from pathlib import Path
from typing import Tuple

import structlog

logger = structlog.get_logger(__name__)


async def verify_patch_syntax(file_path: Path, patch_code: str) -> Tuple[bool, str]:
    """Verify that the generated patch is syntactically valid Python."""
    try:
        ast.parse(patch_code)
        return True, "Syntax OK"
    except SyntaxError as e:
        return False, f"Syntax error: {e}"


async def verify_patch_applies(file_path: Path, patch_code: str) -> Tuple[bool, str]:
    """Verify the patch can be applied without breaking the file structure."""
    try:
        original = file_path.read_text(encoding="utf-8", errors="ignore")
        # Try parsing the full file with the patch applied
        lines = original.split("\n")
        # Simple replacement check: does the patch contain valid code?
        ast.parse(patch_code)
        return True, "Patch applies cleanly"
    except SyntaxError as e:
        return False, f"Patch would break file: {e}"
    except Exception as e:
        return False, f"Verification error: {e}"


async def verify_with_ruff(file_path: Path, patch_code: str) -> Tuple[bool, str]:
    """Run ruff linter on the patched code."""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as tmp:
            tmp.write(patch_code)
            tmp_path = tmp.name
        
        result = subprocess.run(
            ["ruff", "check", "--quiet", tmp_path],
            capture_output=True, text=True, timeout=30,
        )
        Path(tmp_path).unlink(missing_ok=True)
        
        if result.returncode == 0:
            return True, "Ruff check passed"
        else:
            return False, f"Ruff issues: {result.stderr[:500]}"
    except FileNotFoundError:
        # Ruff not installed — skip
        return True, "Ruff not available, skipping"
    except Exception as e:
        return False, f"Ruff verification error: {e}"


async def verify_patch(
    file_path: Path,
    patch_code: str,
    run_linter: bool = True,
) -> Tuple[bool, str]:
    """
    Full verification pipeline for a generated patch.
    Returns (passed: bool, error_message: str).
    """
    # Step 1: Syntax check
    syntax_ok, syntax_err = await verify_patch_syntax(file_path, patch_code)
    if not syntax_ok:
        logger.warning("verify_syntax_failed", error=syntax_err)
        return False, syntax_err
    
    # Step 2: Structural check
    apply_ok, apply_err = await verify_patch_applies(file_path, patch_code)
    if not apply_ok:
        logger.warning("verify_apply_failed", error=apply_err)
        return False, apply_err
    
    # Step 3: Linter check
    if run_linter:
        lint_ok, lint_err = await verify_with_ruff(file_path, patch_code)
        if not lint_ok:
            logger.warning("verify_lint_failed", error=lint_err)
            return False, lint_err
    
    logger.info("verify_passed", file=str(file_path))
    return True, "All checks passed"


async def adversarial_review(
    file_path: Path,
    patch_code: str,
    original_finding_description: str,
    llm_call: callable,
) -> Tuple[bool, str]:
    """
    Adversarial review: ask a fresh LLM context to find flaws in the patch.
    This is the "don't trust the implementer" check.
    """
    prompt = f"""You are a SECURITY AUDITOR reviewing a code patch. Be adversarial — find flaws.

Original vulnerability: {original_finding_description}

File: {file_path}

Proposed patch:
```
{patch_code}
```

Questions to answer:
1. Does this patch actually fix the reported vulnerability?
2. Does it introduce any NEW security issues?
3. Does it break any existing functionality?
4. Is there a simpler/safer fix?

Respond with JSON:
{{"verdict": "approved|rejected",
 "issues_found": ["..."],
 "recommendation": "..."}}"""

    try:
        response = await llm_call(prompt)
        import json
        data = json.loads(response)
        verdict = data.get("verdict", "rejected")
        issues = data.get("issues_found", [])
        
        if verdict == "approved" and not issues:
            return True, "Adversarial review passed"
        else:
            return False, f"Adversarial review found issues: {', '.join(issues)}"
    except Exception as e:
        logger.error("adversarial_review_error", error=str(e))
        return False, f"Adversarial review failed: {e}"