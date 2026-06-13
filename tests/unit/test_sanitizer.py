"""Tests for VibeLock token sanitizer."""
import pytest

from src.shared.sanitizer import sanitize_code, has_sensitive_data


class TestSanitizer:
    def test_redacts_aws_key(self):
        code = 'aws_access_key_id = "AKIA1234567890ABCDEF"'
        result = sanitize_code(code)
        assert "AKIA" not in result
        assert "REDACTED" in result

    def test_redacts_api_key(self):
        code = 'API_KEY = "sk-this-is-a-secret-key-12345"'
        result = sanitize_code(code)
        assert "sk-this-is-a-secret-key" not in result
        assert "REDACTED" in result

    def test_redacts_jwt(self):
        code = 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
        result = sanitize_code(code)
        assert "eyJ" not in result
        assert "JWT_REDACTED" in result

    def test_redacts_github_token(self):
        code = 'GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuv"'
        result = sanitize_code(code)
        assert "ghp_" not in result
        assert "GITHUB_TOKEN_REDACTED" in result

    def test_redacts_db_connection_string(self):
        code = 'DATABASE_URL = "postgres://user:password@host:5432/db"'
        result = sanitize_code(code)
        assert "password" not in result
        assert "CREDENTIALS_REDACTED" in result

    def test_preserves_safe_code(self):
        code = 'x = 1\ny = "hello world"\nz = compute(x, y)'
        result = sanitize_code(code)
        assert result == code

    def test_has_sensitive_data_detects(self):
        assert has_sensitive_data('password = "secret123"')
        assert has_sensitive_data('AWS key: AKIA1234567890ABCDEF')

    def test_has_sensitive_data_clean(self):
        assert not has_sensitive_data("x = 1\ny = 2")
        assert not has_sensitive_data("def foo(): return 42")