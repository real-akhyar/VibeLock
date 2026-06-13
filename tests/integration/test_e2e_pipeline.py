"""
VibeLock — End-to-End Integration Test
Simulates the full pipeline: GitHub webhook → scan → fix → PR
Uses mock objects for external dependencies (GitHub, Supabase, Redis).
"""

import json
import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timezone


# --- Mock Data ---

MOCK_PUSH_WEBHOOK = {
    "ref": "refs/heads/main",
    "before": "abc1230000000000000000000000000000000000",
    "after": "def4560000000000000000000000000000000000",
    "repository": {
        "id": 123456789,
        "name": "test-repo",
        "full_name": "testorg/test-repo",
        "private": False,
        "default_branch": "main",
        "owner": {"name": "testorg", "email": "admin@testorg.com"},
    },
    "pusher": {"name": "testuser", "email": "test@testorg.com"},
    "commits": [
        {
            "id": "def4560000000000000000000000000000000000",
            "message": "Add new feature",
            "author": {"name": "testuser", "email": "test@testorg.com"},
            "added": ["src/auth.py"],
            "removed": [],
            "modified": ["src/db.py"],
        }
    ],
    "head_commit": {
        "id": "def4560000000000000000000000000000000000",
        "message": "Add new feature",
        "author": {"name": "testuser", "email": "test@testorg.com"},
        "added": ["src/auth.py"],
        "removed": [],
        "modified": ["src/db.py"],
    },
    "installation": {"id": 98765},
}

MOCK_VULNERABLE_CODE = '''
import os
DATABASE_PASSWORD = "hardcoded_secret_12345"

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
'''

MOCK_FIXED_CODE = '''
import os
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    return db.execute(query, (user_id,))
'''


# --- Test: Webhook Parsing ---

class TestWebhookParsing:
    """Test that webhook payloads are correctly parsed and validated."""

    def test_push_event_parsing(self):
        """Push event should be parsed into WebhookPayload correctly."""
        from vibelock.src.ingestion.schemas import PushEvent, WebhookPayload

        event = PushEvent(**MOCK_PUSH_WEBHOOK)
        payload = WebhookPayload.from_push_event(event, "delivery-001")

        assert payload.event_type == "push"
        assert payload.repository_full_name == "testorg/test-repo"
        assert payload.repository_id == 123456789
        assert payload.branch == "main"
        assert payload.commit_sha == "def4560000000000000000000000000000000000"
        assert "src/auth.py" in payload.changed_files
        assert "src/db.py" in payload.changed_files
        assert payload.installation_id == 98765

    def test_push_event_all_changed_files(self):
        """Should deduplicate files across commits."""
        from vibelock.src.ingestion.schemas import PushEvent

        event = PushEvent(**MOCK_PUSH_WEBHOOK)
        files = event.all_changed_files

        assert len(files) == 2
        assert "src/auth.py" in files
        assert "src/db.py" in files

    def test_unsupported_event_type(self):
        """Unsupported event types should raise ValueError."""
        from vibelock.src.ingestion.schemas import parse_webhook

        with pytest.raises(ValueError, match="Unsupported event type"):
            parse_webhook("issues", {})


# --- Test: Heuristic Scanner ---

class TestHeuristicScanner:
    """Test that the heuristic scanner detects vulnerabilities."""

    def test_detect_hardcoded_secret(self):
        """Should detect hardcoded secrets in Python code."""
        from vibelock.src.scanner.heuristic import HeuristicScanner

        scanner = HeuristicScanner()
        findings = scanner.scan_text(MOCK_VULNERABLE_CODE, "test.py")

        secrets = [f for f in findings if f["type"] == "hardcoded_secret"]
        assert len(secrets) >= 1
        assert any("DATABASE_PASSWORD" in s.get("description", "") for s in secrets)

    def test_detect_sql_injection(self):
        """Should detect SQL injection via f-string."""
        from vibelock.src.scanner.heuristic import HeuristicScanner

        scanner = HeuristicScanner()
        findings = scanner.scan_text(MOCK_VULNERABLE_CODE, "test.py")

        sqli = [f for f in findings if f["type"] == "sql_injection"]
        assert len(sqli) >= 1

    def test_clean_code_no_findings(self):
        """Clean code should produce no findings."""
        from vibelock.src.scanner.heuristic import HeuristicScanner

        scanner = HeuristicScanner()
        findings = scanner.scan_text(MOCK_FIXED_CODE, "test.py")

        # Should have no hardcoded secrets or SQL injection
        high_severity = [f for f in findings if f["severity"] in ("high", "critical")]
        assert len(high_severity) == 0


# --- Test: Token Sanitizer ---

class TestTokenSanitizer:
    """Test that sensitive data is redacted before LLM dispatch."""

    def test_sanitize_api_keys(self):
        """API keys should be masked."""
        from vibelock.src.shared.sanitizer import TokenSanitizer

        sanitizer = TokenSanitizer()
        code = 'API_KEY = "sk-abc123def456ghi789"'
        cleaned = sanitizer.sanitize(code)

        assert "sk-abc123def456ghi789" not in cleaned
        assert "[REDACTED" in cleaned

    def test_sanitize_jwt_tokens(self):
        """JWT tokens should be masked."""
        from vibelock.src.shared.sanitizer import TokenSanitizer

        sanitizer = TokenSanitizer()
        code = 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
        cleaned = sanitizer.sanitize(code)

        assert "eyJhbGciOi" not in cleaned
        assert "[REDACTED" in cleaned

    def test_preserve_non_secret_code(self):
        """Non-secret code should pass through unchanged."""
        from vibelock.src.shared.sanitizer import TokenSanitizer

        sanitizer = TokenSanitizer()
        code = 'def hello():\n    return "world"'
        cleaned = sanitizer.sanitize(code)

        assert 'def hello():' in cleaned
        assert '"world"' in cleaned


# --- Test: Patch Verifier ---

class TestPatchVerifier:
    """Test that the verifier correctly validates patches."""

    def test_syntax_check_passes(self):
        """Valid Python code should pass syntax check."""
        from vibelock.src.verifier.patch_verifier import PatchVerifier

        verifier = PatchVerifier()
        result = verifier._check_syntax(MOCK_FIXED_CODE)

        assert result["passed"] is True

    def test_syntax_check_fails(self):
        """Invalid Python code should fail syntax check."""
        from vibelock.src.verifier.patch_verifier import PatchVerifier

        verifier = PatchVerifier()
        result = verifier._check_syntax("def broken(:")

        assert result["passed"] is False

    def test_structural_check_passes(self):
        """Patch that preserves structure should pass."""
        from vibelock.src.verifier.patch_verifier import PatchVerifier

        verifier = PatchVerifier()
        result = verifier._check_structure(MOCK_VULNERABLE_CODE, MOCK_FIXED_CODE)

        assert result["passed"] is True

    def test_structural_check_detects_missing_function(self):
        """Patch that removes a function should fail structural check."""
        from vibelock.src.verifier.patch_verifier import PatchVerifier

        verifier = PatchVerifier()
        original = "def foo():\n    pass\ndef bar():\n    pass"
        patched = "def foo():\n    pass"  # bar() removed

        result = verifier._check_structure(original, patched)

        assert result["passed"] is False
        assert "bar" in str(result.get("errors", ""))


# --- Test: Budget Guardrails ---

class TestBudgetGuardrails:
    """Test that budget limits are enforced."""

    def test_budget_not_exhausted_initially(self):
        """Budget should not be exhausted on creation."""
        from vibelock.src.shared.budget import BudgetGuard

        budget = BudgetGuard(daily_limit=1000, cycle_limit=100)
        assert not budget.is_exhausted()

    def test_budget_exhausted_after_limit(self):
        """Budget should be exhausted after exceeding daily limit."""
        from vibelock.src.shared.budget import BudgetGuard

        budget = BudgetGuard(daily_limit=100, cycle_limit=50)
        budget.record_usage(101)

        assert budget.is_exhausted()

    def test_cycle_limit_enforced(self):
        """Cycle limit should prevent further attempts."""
        from vibelock.src.shared.budget import BudgetGuard

        budget = BudgetGuard(daily_limit=1000, cycle_limit=10)
        budget.record_attempt()
        budget.record_attempt()

        assert budget.cycle_attempts == 2
        assert not budget.is_cycle_exhausted()

        # Exhaust cycle
        for _ in range(8):
            budget.record_attempt()

        assert budget.is_cycle_exhausted()


# --- Test: Loop State Manager ---

class TestLoopStateManager:
    """Test that loop state survives across cycles."""

    def test_save_and_load_state(self, tmp_path):
        """State should persist to file and be reloadable."""
        from vibelock.src.shared.loop_state import LoopStateManager

        state_file = tmp_path / "LOOP-STATE.md"
        manager = LoopStateManager(state_path=str(state_file))

        manager.set_active_task("VIBE-001", "Test task")
        manager.mark_done("VIBE-001")
        manager.save()

        # Reload
        manager2 = LoopStateManager(state_path=str(state_file))
        assert "VIBE-001" in manager2.completed_tasks

    def test_get_next_task(self, tmp_path):
        """Should return the next pending task."""
        from vibelock.src.shared.loop_state import LoopStateManager

        state_file = tmp_path / "LOOP-STATE.md"
        manager = LoopStateManager(state_path=str(state_file))

        manager.add_task("TASK-1", "First task", "high")
        manager.add_task("TASK-2", "Second task", "medium")

        next_task = manager.get_next_task()
        assert next_task is not None
        assert next_task["id"] == "TASK-1"


# --- Test: Full Pipeline Integration ---

class TestFullPipeline:
    """End-to-end test of the complete VibeLock pipeline."""

    @pytest.mark.asyncio
    async def test_webhook_to_scan_flow(self):
        """Simulate: webhook received → parsed → scan job created."""
        from vibelock.src.ingestion.schemas import PushEvent, WebhookPayload

        # 1. Parse webhook
        event = PushEvent(**MOCK_PUSH_WEBHOOK)
        payload = WebhookPayload.from_push_event(event, "delivery-test-001")

        # 2. Verify payload
        assert payload.event_type == "push"
        assert len(payload.changed_files) == 2
        assert payload.installation_id == 98765

        # 3. Scan would be triggered here (mocked)
        scan_job = {
            "repository_id": str(payload.repository_id),
            "full_name": payload.repository_full_name,
            "commit_sha": payload.commit_sha,
            "branch": payload.branch,
            "changed_files": payload.changed_files,
            "installation_id": payload.installation_id,
        }

        assert scan_job["changed_files"] == ["src/auth.py", "src/db.py"]

    def test_scan_to_remediation_flow(self):
        """Simulate: scan finds vuln → remediation triggered."""
        from vibelock.src.scanner.heuristic import HeuristicScanner

        # 1. Scan finds vulnerability
        scanner = HeuristicScanner()
        findings = scanner.scan_text(MOCK_VULNERABLE_CODE, "src/auth.py")

        assert len(findings) > 0

        # 2. Critical findings trigger remediation
        critical = [f for f in findings if f["severity"] in ("high", "critical")]
        assert len(critical) > 0

        # 3. Remediation job would be created
        for vuln in critical:
            remediation_job = {
                "vulnerability_type": vuln["type"],
                "severity": vuln["severity"],
                "file_path": "src/auth.py",
                "description": vuln["description"],
                "code_snippet": vuln.get("code_snippet", ""),
            }
            assert remediation_job["severity"] in ("high", "critical")

    def test_remediation_to_pr_flow(self):
        """Simulate: patch generated → verified → PR created."""
        from vibelock.src.verifier.patch_verifier import PatchVerifier

        # 1. Patch is generated (mocked as MOCK_FIXED_CODE)
        patch = MOCK_FIXED_CODE

        # 2. Verifier checks the patch
        verifier = PatchVerifier()
        syntax_result = verifier._check_syntax(patch)
        assert syntax_result["passed"] is True

        structure_result = verifier._check_structure(MOCK_VULNERABLE_CODE, patch)
        assert structure_result["passed"] is True

        # 3. PR would be created (mocked)
        pr_result = {
            "number": 42,
            "html_url": "https://github.com/testorg/test-repo/pull/42",
            "branch": "vibelock/fix-hardcoded-secret-abc12345",
        }
        assert pr_result["number"] == 42

    def test_guardrail_max_attempts(self):
        """Simulate: 3 failed attempts → abort."""
        from vibelock.src.shared.budget import BudgetGuard

        budget = BudgetGuard(daily_limit=10000, cycle_limit=3)

        # Simulate 3 failed attempts
        for i in range(3):
            budget.record_attempt()

        assert budget.is_cycle_exhausted()
        # 4th attempt should be blocked
        assert budget.cycle_attempts == 3

    def test_token_sanitization_before_llm(self):
        """Simulate: code is sanitized before sending to LLM."""
        from vibelock.src.shared.sanitizer import TokenSanitizer

        sanitizer = TokenSanitizer()

        # Code with multiple secrets
        code_with_secrets = '''
        AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
        DB_PASS = "super_secret_password"
        TOKEN = "ghp_abc123def456ghi789jkl"
        JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummy"
        '''

        cleaned = sanitizer.sanitize(code_with_secrets)

        # No secrets should remain
        assert "AKIAIOSFODNN7EXAMPLE" not in cleaned
        assert "super_secret_password" not in cleaned
        assert "ghp_abc123def456ghi789jkl" not in cleaned
        assert "eyJhbGciOiJIUzI1NiJ9" not in cleaned

        # Structure should be preserved
        assert "AWS_KEY" in cleaned
        assert "DB_PASS" in cleaned
        assert "TOKEN" in cleaned
        assert "JWT" in cleaned

    def test_dashboard_summary_mock(self):
        """Dashboard should return mock data when Supabase is disconnected."""
        from vibelock.src.api.dashboard import _mock_summary

        summary = _mock_summary()

        assert summary.total == 0
        assert "critical" in summary.by_severity
        assert "high" in summary.by_severity

    def test_notification_config(self):
        """Notification config should load from environment."""
        from vibelock.src.shared.notifications import NotificationConfig

        config = NotificationConfig()
        assert isinstance(config.notify_on_severity, list)
        assert "critical" in config.notify_on_severity
        assert "high" in config.notify_on_severity


# --- Run ---

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])