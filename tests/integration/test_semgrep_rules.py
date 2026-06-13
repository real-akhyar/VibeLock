"""
Integration tests for Semgrep rule pack.
Tests that rules fire correctly on vulnerable code samples.
"""
import pytest
import tempfile
from pathlib import Path

# Mark as integration tests
pytestmark = pytest.mark.integration


def _write_temp_file(content: str, suffix: str = ".py") -> Path:
    """Write content to a temp file and return its path."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    tmp.write(content)
    tmp.close()
    return Path(tmp.name)


class TestSemgrepPythonRules:
    """Test Python-specific Semgrep rules."""

    def test_hardcoded_secret_detected(self):
        """Rule should detect hardcoded API keys."""
        from vibelock.src.scanner.semgrep_runner import run_semgrep

        code = '''
API_KEY = "sk-1234567890abcdefghij"
SECRET_KEY = "my-super-secret-password"
'''
        tmp = _write_temp_file(code, ".py")
        try:
            findings = run_semgrep(str(tmp))
            assert len(findings) > 0, "Should detect hardcoded secrets"
            assert any("hardcoded" in f["vulnerability_type"].lower() for f in findings)
        finally:
            tmp.unlink(missing_ok=True)

    def test_sql_injection_fstring_detected(self):
        """Rule should detect SQL injection via f-strings."""
        from vibelock.src.scanner.semgrep_runner import run_semgrep

        code = '''
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        tmp = _write_temp_file(code, ".py")
        try:
            findings = run_semgrep(str(tmp))
            assert len(findings) > 0, "Should detect SQL injection"
            assert any("sql" in f["vulnerability_type"].lower() for f in findings)
        finally:
            tmp.unlink(missing_ok=True)

    def test_subprocess_shell_true_detected(self):
        """Rule should detect shell=True in subprocess calls."""
        from vibelock.src.scanner.semgrep_runner import run_semgrep

        code = '''
import subprocess
subprocess.call("ls -la", shell=True)
'''
        tmp = _write_temp_file(code, ".py")
        try:
            findings = run_semgrep(str(tmp))
            assert len(findings) > 0, "Should detect shell injection"
        finally:
            tmp.unlink(missing_ok=True)

    def test_pickle_deserialization_detected(self):
        """Rule should detect unsafe pickle usage."""
        from vibelock.src.scanner.semgrep_runner import run_semgrep

        code = '''
import pickle
data = pickle.loads(user_input)
'''
        tmp = _write_temp_file(code, ".py")
        try:
            findings = run_semgrep(str(tmp))
            assert len(findings) > 0, "Should detect pickle deserialization"
        finally:
            tmp.unlink(missing_ok=True)

    def test_eval_detected(self):
        """Rule should detect eval() usage."""
        from vibelock.src.scanner.semgrep_runner import run_semgrep

        code = '''
result = eval(user_input)
'''
        tmp = _write_temp_file(code, ".py")
        try:
            findings = run_semgrep(str(tmp))
            assert len(findings) > 0, "Should detect eval"
        finally:
            tmp.unlink(missing_ok=True)

    def test_clean_code_no_findings(self):
        """Clean code should produce no findings."""
        from vibelock.src.scanner.semgrep_runner import run_semgrep

        code = '''
import os
database_url = os.getenv("DATABASE_URL")

def get_user(user_id: int):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
'''
        tmp = _write_temp_file(code, ".py")
        try:
            findings = run_semgrep(str(tmp))
            assert len(findings) == 0, f"Clean code should have no findings, got: {findings}"
        finally:
            tmp.unlink(missing_ok=True)


class TestSemgrepJSRules:
    """Test JavaScript/TypeScript-specific Semgrep rules."""

    def test_js_eval_detected(self):
        """Rule should detect eval() in JS."""
        from vibelock.src.scanner.semgrep_runner import run_semgrep

        code = '''
const result = eval(userInput);
'''
        tmp = _write_temp_file(code, ".js")
        try:
            findings = run_semgrep(str(tmp))
            assert len(findings) > 0, "Should detect JS eval"
        finally:
            tmp.unlink(missing_ok=True)

    def test_js_innerhtml_xss_detected(self):
        """Rule should detect innerHTML XSS."""
        from vibelock.src.scanner.semgrep_runner import run_semgrep

        code = '''
document.getElementById("app").innerHTML = userInput;
'''
        tmp = _write_temp_file(code, ".js")
        try:
            findings = run_semgrep(str(tmp))
            assert len(findings) > 0, "Should detect XSS"
        finally:
            tmp.unlink(missing_ok=True)

    def test_js_sql_injection_detected(self):
        """Rule should detect SQL injection in JS."""
        from vibelock.src.scanner.semgrep_runner import run_semgrep

        code = '''
const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);
'''
        tmp = _write_temp_file(code, ".js")
        try:
            findings = run_semgrep(str(tmp))
            assert len(findings) > 0, "Should detect JS SQL injection"
        finally:
            tmp.unlink(missing_ok=True)

    def test_js_jwt_none_algorithm_detected(self):
        """Rule should detect JWT none algorithm."""
        from vibelock.src.scanner.semgrep_runner import run_semgrep

        code = '''
jwt.verify(token, secret, {algorithms: ["none"]});
'''
        tmp = _write_temp_file(code, ".js")
        try:
            findings = run_semgrep(str(tmp))
            assert len(findings) > 0, "Should detect JWT none algo"
        finally:
            tmp.unlink(missing_ok=True)


class TestSemgrepBatchRunner:
    """Test batch file scanning."""

    def test_run_on_multiple_files(self):
        """Should scan multiple files at once."""
        from vibelock.src.scanner.semgrep_runner import run_semgrep_on_files

        code1 = 'API_KEY = "sk-secret-key-12345"'
        code2 = 'const result = eval(userInput);'

        tmp1 = _write_temp_file(code1, ".py")
        tmp2 = _write_temp_file(code2, ".js")

        try:
            findings = run_semgrep_on_files([str(tmp1), str(tmp2)])
            assert len(findings) >= 2, f"Should find at least 2 issues, got {len(findings)}"
        finally:
            tmp1.unlink(missing_ok=True)
            tmp2.unlink(missing_ok=True)

    def test_empty_file_list(self):
        """Should handle empty file list gracefully."""
        from vibelock.src.scanner.semgrep_runner import run_semgrep_on_files

        findings = run_semgrep_on_files([])
        assert findings == []

    def test_nonexistent_files(self):
        """Should handle nonexistent files gracefully."""
        from vibelock.src.scanner.semgrep_runner import run_semgrep_on_files

        findings = run_semgrep_on_files(["/nonexistent/path/file.py"])
        assert findings == []