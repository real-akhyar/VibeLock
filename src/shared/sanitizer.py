"""
VibeLock — Token Sanitizer
Deterministic regex pre-filter to mask high-entropy strings before LLM dispatch.
"""
import re
from typing import List, Tuple

# Patterns to mask before sending code to external LLM
SANITIZE_PATTERNS: List[Tuple[str, str]] = [
    # AWS keys
    (r'AKIA[0-9A-Z]{16}', '[AWS_ACCESS_KEY_REDACTED]'),
    (r'(?i)aws_secret_access_key["\']?\s*[:=]\s*["\'][^"\']+["\']', 'aws_secret_access_key="[REDACTED]"'),
    # Generic API keys / tokens (high entropy)
    (r'(?i)(api[_-]?key|apikey|secret|token|password|passwd)["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
     r'\1="[REDACTED]"'),
    # JWT tokens
    (r'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}', '[JWT_REDACTED]'),
    # GitHub tokens
    (r'gh[pousr]_[A-Za-z0-9_]{20,}', '[GITHUB_TOKEN_REDACTED]'),
    # Database connection strings
    (r'(?i)(postgres|mysql|mongodb|redis)://[^@]+@[^\s]+', r'\1://[CREDENTIALS_REDACTED]@[HOST_REDACTED]'),
    # Private keys
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----.*?-----END \1 PRIVATE KEY-----',
     '[PRIVATE_KEY_REDACTED]', re.DOTALL),
    # Generic high-entropy base64 strings (likely secrets)
    (r'(?i)(secret|key|token|auth)["\']?\s*[:=]\s*["\'][A-Za-z0-9+/=]{32,}["\']',
     r'\1="[HIGH_ENTROPY_REDACTED]"'),
]

def sanitize_code(code: str) -> str:
    """Strip sensitive values before sending to external LLM."""
    sanitized = code
    for pattern, replacement, *flags in SANITIZE_PATTERNS:
        flag = flags[0] if flags else 0
        sanitized = re.sub(pattern, replacement, sanitized, flags=flag)
    return sanitized

def has_sensitive_data(code: str) -> bool:
    """Check if code contains patterns that would be redacted."""
    for pattern, _, *flags in SANITIZE_PATTERNS:
        flag = flags[0] if flags else 0
        if re.search(pattern, code, flags=flag):
            return True
    return False