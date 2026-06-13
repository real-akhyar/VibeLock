"""
VibeLock — Heuristic Scanner (Fast / Low Cost)
AST matching + regex checks for hardcoded secrets, SQL injection, and obvious flaws.
"""
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional

import structlog

logger = structlog.get_logger(__name__)


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnType(str, Enum):
    HARDCODED_SECRET = "hardcoded_secret"
    SQL_INJECTION = "sql_injection"
    MISSING_RLS = "missing_rls"
    UNVALIDATED_INPUT = "unvalidated_input"
    XSS = "xss"


@dataclass
class Finding:
    vulnerability_type: VulnType
    severity: Severity
    file_path: str
    line_number: int
    description: str
    code_snippet: str
    remediation_hint: str = ""


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    errors: List[str] = field(default_factory=list)


# --- Regex-based detection patterns ---

SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey|secret|password|passwd|token)\s*[:=]\s*["\'][^"\']{8,}["\']',
     VulnType.HARDCODED_SECRET, Severity.CRITICAL,
     "Hardcoded secret/credential detected. Use environment variables instead."),
    (r'(?i)aws_access_key_id\s*[:=]\s*["\']AKIA[0-9A-Z]{16}["\']',
     VulnType.HARDCODED_SECRET, Severity.CRITICAL,
     "AWS access key hardcoded. Use IAM roles or environment variables."),
    (r'(?i)github[_-]?token\s*[:=]\s*["\']gh[pousr]_[A-Za-z0-9_]{20,}["\']',
     VulnType.HARDCODED_SECRET, Severity.CRITICAL,
     "GitHub token hardcoded. Use secrets manager or environment variables."),
    (r'(?i)supabase[_-]?(url|key|anon[_-]?key|service[_-]?role[_-]?key)\s*[:=]\s*["\'][^"\']{20,}["\']',
     VulnType.HARDCODED_SECRET, Severity.CRITICAL,
     "Supabase credentials hardcoded. Use environment variables."),
]

SQL_INJECTION_PATTERNS = [
    (r'(?i)(execute|cursor\.execute|raw)\s*\(\s*(f["\']|["\'].*%.*["\']|["\'].*\{.*\}.*["\'])',
     VulnType.SQL_INJECTION, Severity.HIGH,
     "Potential SQL injection: string formatting in SQL query. Use parameterized queries."),
    (r'(?i)\.format\(.*\)\s*.*SELECT|INSERT|UPDATE|DELETE',
     VulnType.SQL_INJECTION, Severity.HIGH,
     "SQL query built with .format(). Use parameterized queries instead."),
    (r'(?i)\+\s*["\'].*SELECT|INSERT|UPDATE|DELETE',
     VulnType.SQL_INJECTION, Severity.MEDIUM,
     "String concatenation in SQL query. Use parameterized queries."),
]

XSS_PATTERNS = [
    (r'(?i)innerHTML\s*=|dangerouslySetInnerHTML',
     VulnType.XSS, Severity.HIGH,
     "Potential XSS: direct innerHTML assignment. Use textContent or sanitize input."),
    (r'(?i)document\.write\s*\(|eval\s*\(.*\+',
     VulnType.XSS, Severity.HIGH,
     "Potential XSS: document.write or eval with dynamic input."),
]

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".sql", ".supabase.ts",
    ".go", ".rs", ".java", ".rb", ".php", ".env", ".yaml", ".yml",
}


def scan_file(file_path: Path, content: str) -> List[Finding]:
    """Run all heuristic checks on a single file."""
    findings: List[Finding] = []
    lines = content.split("\n")
    
    for line_num, line in enumerate(lines, start=1):
        # Check secrets
        for pattern, vuln_type, severity, hint in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    vulnerability_type=vuln_type,
                    severity=severity,
                    file_path=str(file_path),
                    line_number=line_num,
                    description=hint,
                    code_snippet=line.strip()[:200],
                    remediation_hint=hint,
                ))
        
        # Check SQL injection
        for pattern, vuln_type, severity, hint in SQL_INJECTION_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    vulnerability_type=vuln_type,
                    severity=severity,
                    file_path=str(file_path),
                    line_number=line_num,
                    description=hint,
                    code_snippet=line.strip()[:200],
                    remediation_hint=hint,
                ))
        
        # Check XSS
        for pattern, vuln_type, severity, hint in XSS_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    vulnerability_type=vuln_type,
                    severity=severity,
                    file_path=str(file_path),
                    line_number=line_num,
                    description=hint,
                    code_snippet=line.strip()[:200],
                    remediation_hint=hint,
                ))
    
    return findings


def scan_directory(root: Path, changed_files: Optional[List[str]] = None) -> ScanResult:
    """Scan a directory (or specific changed files) for vulnerabilities."""
    result = ScanResult()
    
    targets = []
    if changed_files:
        targets = [Path(f) for f in changed_files if Path(f).suffix in SCAN_EXTENSIONS]
    else:
        for ext in SCAN_EXTENSIONS:
            targets.extend(root.rglob(f"*{ext}"))
    
    result.files_scanned = len(targets)
    
    for file_path in targets:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            findings = scan_file(file_path, content)
            result.findings.extend(findings)
            if findings:
                logger.info("findings_in_file", file=str(file_path), count=len(findings))
        except Exception as e:
            result.errors.append(f"Failed to scan {file_path}: {e}")
            logger.error("scan_error", file=str(file_path), error=str(e))
    
    logger.info(
        "scan_complete",
        files_scanned=result.files_scanned,
        findings=len(result.findings),
        errors=len(result.errors),
    )
    return result