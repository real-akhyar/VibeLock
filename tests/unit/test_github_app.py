"""Tests for VibeLock GitHub App setup module."""
import os
import json
from unittest.mock import patch, AsyncMock, MagicMock

import pytest

from src.ingestion.github_app import (
    get_manifest,
    start_setup_flow,
    complete_manifest_flow,
    _generate_jwt,
    complete_setup,
    list_installations,
    get_app_credentials_from_env,
    SetupState,
    GITHUB_APP_MANIFEST,
)


class TestGetManifest:
    def test_default_manifest(self):
        manifest = get_manifest()
        assert manifest["name"] == "VibeLock"
        assert "hook_attributes" in manifest
        assert "default_permissions" in manifest
        assert manifest["public"] is True

    def test_custom_webhook_url(self):
        manifest = get_manifest(webhook_url="https://custom.example.com/webhook")
        assert manifest["hook_attributes"]["url"] == "https://custom.example.com/webhook"

    def test_custom_app_url(self):
        manifest = get_manifest(app_url="https://custom.example.com")
        assert manifest["url"] == "https://custom.example.com"

    def test_env_var_webhook_url(self, monkeypatch):
        monkeypatch.setenv("VIBELOCK_WEBHOOK_URL", "https://env.example.com/webhook")
        manifest = get_manifest()
        assert manifest["hook_attributes"]["url"] == "https://env.example.com/webhook"

    def test_env_var_redirect_url(self, monkeypatch):
        monkeypatch.setenv("VIBELOCK_REDIRECT_URL", "https://app.example.com/callback")
        manifest = get_manifest()
        assert manifest["redirect_url"] == "https://app.example.com/callback"


class TestSetupState:
    def test_default_state(self):
        state = SetupState()
        assert state.setup_complete is False
        assert state.app_id is None
        assert state.installation_id is None

    def test_completed_state(self):
        state = SetupState(
            app_id=12345,
            installation_id=67890,
            webhook_secret="wh_secret_test_123",
            setup_complete=True,
        )
        assert state.setup_complete is True
        assert state.app_id == 12345


class TestStartSetupFlow:
    @pytest.mark.asyncio
    async def test_returns_manifest_and_url(self):
        result = await start_setup_flow(
            webhook_url="https://hooks.example.com",
            app_url="https://app.example.com",
        )
        assert "manifest" in result
        assert "flow_url" in result
        assert "instructions" in result
        assert result["flow_url"].startswith("https://github.com/apps/new?manifest=")
        assert len(result["instructions"]) == 5


class TestCompleteManifestFlow:
    @pytest.mark.asyncio
    async def test_successful_conversion(self):
        mock_response = AsyncMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": 12345,
            "client_id": "Iv1.abc123",
            "client_secret": "test_client_secret_456",
            "pem": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
            "webhook_secret": "wh_test_secret_789",
            "slug": "vibelock",
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
            result = await complete_manifest_flow("test-code-123")
            assert result["success"] is True
            assert result["id"] == 12345
            assert "pem" in result

    @pytest.mark.asyncio
    async def test_failed_conversion(self):
        mock_response = AsyncMock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
            result = await complete_manifest_flow("bad-code")
            assert result["success"] is False
            assert "error" in result


class TestGenerateJWT:
    def test_generates_valid_jwt_structure(self):
        token = _generate_jwt(12345, "fake-key")
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    def test_different_app_ids_produce_different_tokens(self):
        token1 = _generate_jwt(111, "key-a")
        token2 = _generate_jwt(222, "key-a")
        assert token1 != token2


class TestCompleteSetup:
    @pytest.mark.asyncio
    async def test_successful_verification(self):
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "name": "VibeLock",
            "owner": {"login": "test-org"},
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response
            result = await complete_setup(
                app_id=12345,
                private_key="fake-key",
                webhook_secret="secret",
            )
            assert result["success"] is True
            assert result["app_name"] == "VibeLock"
            assert result["owner"] == "test-org"

    @pytest.mark.asyncio
    async def test_invalid_private_key(self):
        result = await complete_setup(
            app_id=12345,
            private_key="not-a-valid-pem-key",
            webhook_secret="secret",
        )
        assert result["success"] is False
        assert "error" in result


class TestListInstallations:
    @pytest.mark.asyncio
    async def test_returns_installations(self):
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"id": 1, "account": {"login": "org1"}},
            {"id": 2, "account": {"login": "org2"}},
        ]

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response
            result = await list_installations(app_id=12345, private_key="key")
            assert len(result) == 2
            assert result[0]["id"] == 1

    @pytest.mark.asyncio
    async def test_returns_empty_on_failure(self):
        mock_response = AsyncMock()
        mock_response.status_code = 401

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response
            result = await list_installations(app_id=12345, private_key="bad-key")
            assert result == []


class TestGetAppCredentialsFromEnv:
    def test_returns_none_when_not_configured(self):
        result = get_app_credentials_from_env()
        assert result is None

    def test_returns_credentials_when_configured(self, monkeypatch, tmp_path):
        key_file = tmp_path / "test-key.pem"
        key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")

        monkeypatch.setenv("GITHUB_APP_ID", "12345")
        monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", str(key_file))
        monkeypatch.setenv("VIBELOCK_GITHUB_WEBHOOK_SECRET", "wh_secret")

        result = get_app_credentials_from_env()
        assert result is not None
        assert result["app_id"] == 12345
        assert "test" in result["private_key"]
        assert result["webhook_secret"] == "wh_secret"

    def test_returns_none_for_missing_key_file(self, monkeypatch):
        monkeypatch.setenv("GITHUB_APP_ID", "12345")
        monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "/nonexistent/key.pem")

        result = get_app_credentials_from_env()
        assert result is None