"""
VibeLock — Semgrep Runner
Integrates Semgrep CLI for rule-based static analysis.
Used by the heuristic scanner to run the VibeLock rule pack.
"""
import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Path to the VibeLock Semgrep rule pack
RULES_PATH = Path(__file__).parent.parent.parent / "config" / "semgrep_rules.yml"


def run_semgrep(
    target_path: str,
    rules_path: Optional[str] = None,
    languages: Optional[list[str]] = None,
) -> list[dict]:
    """
    Run Semgrep against a file or directory using the VibeLock rule pack.
    Returns list of findings as dicts.
    """
    rules = rules_path or str(RULES_PATH)

    if not Path(rules).exists():
        logger.warning(f"Semgrep rules file not found: {rules}")
        return []

    cmd = ["semgrep", "--config", rules, "--json", "--quiet", "--no-git-ignore"]

    if languages:
        cmd.extend(["--lang", ",".join(languages)])

    cmd.append(target_path)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode not in (0, 1):
            # Exit code 0 = no findings, 1 = findings found (both OK)
            logger.error(f"Semgrep failed with code {result.returncode}: {result.stderr[:500]}")
            return []

        data = json.loads(result.stdout)
        findings = []

        for entry in data.get("results", []):
            findings.append({
                "vulnerability_type": entry.get("check_id", "unknown"),
                "severity": _map_severity(entry.get("extra", {}).get("severity", "WARNING")),
                "file_path": entry.get("path", ""),
                "line_number": entry.get("start", {}).get("line"),
                "description": entry.get("extra", {}).get("message", ""),
                "code_snippet": entry.get("extra", {}).get("lines", ""),
                "scanner": "semgrep",
                "rule_id": entry.get("check_id", ""),
                "metadata": entry.get("extra", {}).get("metadata", {}),
            })

        logger.info(f"Semgrep scan complete: {len(findings)} findings in {target_path}")
        return findings

    except subprocess.TimeoutExpired:
        logger.error(f"Semgrep timed out on {target_path}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Semgrep output parse failed: {e}")
        return []
    except FileNotFoundError:
        logger.error("Semgrep CLI not found. Install: pip install semgrep")
        return []
    except Exception as e:
        logger.error(f"Semgrep run failed: {e}")
        return []


def run_semgrep_on_files(
    file_paths: list[str],
    rules_path: Optional[str] = None,
) -> list[dict]:
    """
    Run Semgrep against multiple specific files.
    Uses a temp file list to avoid shell argument limits.
    """
    if not file_paths:
        return []

    # Filter to files that exist
    existing = [f for f in file_paths if Path(f).exists()]
    if not existing:
        return []

    # Write file list to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        for path in existing:
            f.write(f"{path}\n")
        temp_path = f.name

    try:
        rules = rules_path or str(RULES_PATH)
        cmd = [
            "semgrep", "--config", rules,
            "--json", "--quiet", "--no-git-ignore",
            f"--targets={temp_path}",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode not in (0, 1):
            logger.error(f"Semgrep batch failed: {result.stderr[:500]}")
            return []

        data = json.loads(result.stdout)
        findings = []

        for entry in data.get("results", []):
            findings.append({
                "vulnerability_type": entry.get("check_id", "unknown"),
                "severity": _map_severity(entry.get("extra", {}).get("severity", "WARNING")),
                "file_path": entry.get("path", ""),
                "line_number": entry.get("start", {}).get("line"),
                "description": entry.get("extra", {}).get("message", ""),
                "code_snippet": entry.get("extra", {}).get("lines", ""),
                "scanner": "semgrep",
                "rule_id": entry.get("check_id", ""),
                "metadata": entry.get("extra", {}).get("metadata", {}),
            })

        return findings

    except Exception as e:
        logger.error(f"Semgrep batch run failed: {e}")
        return []
    finally:
        Path(temp_path).unlink(missing_ok=True)


def _map_severity(semgrep_severity: str) -> str:
    """Map Semgrep severity levels to VibeLock severity."""
    mapping = {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
    }
    return mapping.get(semgrep_severity.upper(), "medium")