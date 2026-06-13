"""Tests for VibeLock heuristic scanner."""
import tempfile
from pathlib import Path

import pytest

from src.scanner.heuristic import (
    scan_file,
    scan_directory,
    Finding,
    Severity,
    VulnType,
    SECRET_PATTERNS,
    SQL_INJECTION_PATTERNS,
)


class TestSecretDetection:
    def test_detects_hardcoded_api_key(self):
        code = 'API_KEY = "sk-1234567890abcdefghij"'
        findings = scan_file(Path("test.py"), code)
        assert len(findings) >= 1
        assert any(f.vulnerability_type == VulnType.HARDCODED_SECRET for f in findings)

    def test_detects_aws_key(self):
        code = 'aws_access_key_id = "AKIA1234567890ABCDEF"'
        findings = scan_file(Path("test.py"), code)
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_github_token(self):
        code = 'github_token = "ghp_1234567890abcdefghijklmnop"'
        findings = scan_file(Path("test.py"), code)
        assert len(findings) >= 1

    def test_detects_supabase_key(self):
        code = 'SUPABASE_SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."'
        findings = scan_file(Path("test.py"), code)
        assert len(findings) >= 1

    def test_no_false_positive_on_safe_code(self):
        code = 'name = "hello world"\nvalue = 42\nresult = compute()'
        findings = scan_file(Path("test.py"), code)
        assert len(findings) == 0


class TestSQLInjection:
    def test_detects_fstring_sql(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        findings = scan_file(Path("test.py"), code)
        assert len(findings) >= 1
        assert any(f.vulnerability_type == VulnType.SQL_INJECTION for f in findings)

    def test_detects_format_sql(self):
        code = 'db.raw("SELECT * FROM users WHERE name = '{}'".format(name))'
        findings = scan_file(Path("test.py"), code)
        assert len(findings) >= 1

    def test_detects_concatenation_sql(self):
        code = 'query = "SELECT * FROM users WHERE id = " + user_id'
        findings = scan_file(Path("test.py"), code)
        assert len(findings) >= 1

    def test_parameterized_query_is_safe(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        findings = scan_file(Path("test.py"), code)
        sql_findings = [f for f in findings if f.vulnerability_type == VulnType.SQL_INJECTION]
        assert len(sql_findings) == 0


class TestXSS:
    def test_detects_innerhtml(self):
        code = 'element.innerHTML = userInput;'
        findings = scan_file(Path("test.js"), code)
        assert len(findings) >= 1
        assert any(f.vulnerability_type == VulnType.XSS for f in findings)

    def test_detects_dangerously_set_inner_html(self):
        code = '<div dangerouslySetInnerHTML={{__html: userInput}} />'
        findings = scan_file(Path("test.jsx"), code)
        assert len(findings) >= 1


class TestScanDirectory:
    def test_scans_python_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "safe.py").write_text("x = 1\ny = 2")
            (tmp / "secret.py").write_text('password = "super-secret-123"')
            
            result = scan_directory(tmp)
            assert result.files_scanned >= 2
            assert len(result.findings) >= 1

    def test_scans_only_changed_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "a.py").write_text("x = 1")
            (tmp / "b.py").write_text('API_KEY = "sk-exposed"')
            
            result = scan_directory(tmp, changed_files=["a.py"])
            assert result.files_scanned == 1
            assert len(result.findings) == 0