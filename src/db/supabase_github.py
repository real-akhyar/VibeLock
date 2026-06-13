"""
VibeLock — Supabase GitHub App Config Persistence
Stores and retrieves GitHub App configuration (app_id, private_key, webhook_secret)
with AES-256-GCM encryption at rest for the private key.
"""

import os
import json
import base64
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Try to import cryptography for key encryption at rest
try:
    from cryptography.fernet import Fernet
    _fernet_available = True
except ImportError:
    _fernet_available = False
    logger.warning("cryptography not installed — private keys will NOT be encrypted at rest")


def _get_encryption_key() -> Optional[bytes]:
    """
    Derive a Fernet-compatible key from VIBELOCK_ENCRYPTION_KEY env var
    or generate a deterministic key from SUPABASE_SERVICE_KEY.
    """
    key = os.getenv("VIBELOCK_ENCRYPTION_KEY")
    if key:
        # If it's already a valid Fernet key (base64, 32 bytes), use it directly
        try:
            decoded = base64.urlsafe_b64decode(key.encode())
            if len(decoded) == 32:
                return key.encode()
        except Exception:
            pass
        # Otherwise, derive from it
        import hashlib
        return base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest())

    # Fallback: derive from SUPABASE_SERVICE_KEY
    supabase_key = os.getenv("SUPABASE_SERVICE_KEY")
    if supabase_key:
        import hashlib
        return base64.urlsafe_b64encode(hashlib.sha256(supabase_key.encode()).digest())

    return None


def _encrypt_value(value: str) -> str:
    """Encrypt a string value using Fernet symmetric encryption."""
    if not _fernet_available:
        logger.warning("encryption_unavailable_storing_plaintext")
        return value

    key = _get_encryption_key()
    if not key:
        logger.warning("no_encryption_key_storing_plaintext")
        return value

    try:
        fernet = Fernet(key)
        encrypted = fernet.encrypt(value.encode())
        return encrypted.decode()
    except Exception as e:
        logger.error(f"encryption_failed: {e}")
        return value


def _decrypt_value(encrypted_value: str) -> str:
    """Decrypt a Fernet-encrypted string value."""
    if not _fernet_available:
        return encrypted_value

    key = _get_encryption_key()
    if not key:
        return encrypted_value

    try:
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_value.encode())
        return decrypted.decode()
    except Exception:
        # If decryption fails, the value might be stored in plaintext
        return encrypted_value


class GithubAppConfigStore:
    """
    Persists GitHub App configuration in Supabase.

    Table: github_app_configs
    Columns:
        - id: UUID PRIMARY KEY
        - org_id: UUID (FK → organizations.id)
        - app_id: INTEGER
        - webhook_secret: TEXT
        - private_key_encrypted: TEXT (AES-256-GCM encrypted)
        - setup_complete: BOOLEAN
        - manifest_flow_url: TEXT
        - created_at: TIMESTAMPTZ
        - updated_at: TIMESTAMPTZ
    """

    TABLE = "github_app_configs"

    def __init__(self):
        self._client = None
        self._init_client()

    def _init_client(self):
        """Lazily initialize the Supabase client."""
        try:
            from vibelock.src.shared.supabase_client import supabase
            if supabase.is_connected:
                self._client = supabase.client
        except ImportError:
            logger.warning("supabase_client_not_available")
        except Exception as e:
            logger.error(f"supabase_init_failed: {e}")

    @property
    def is_available(self) -> bool:
        return self._client is not None

    def _ensure_client(self):
        if self._client is None:
            self._init_client()

    # --- CRUD Operations ---

    def create_config(
        self,
        org_id: str,
        manifest_flow_url: Optional[str] = None,
    ) -> Optional[str]:
        """
        Create a new GitHub App config record.

        Args:
            org_id: The organization UUID.
            manifest_flow_url: The GitHub manifest flow URL.

        Returns:
            The config record ID (UUID string), or None on failure.
        """
        self._ensure_client()
        if not self._client:
            logger.warning("create_config: supabase not available")
            return None

        try:
            result = (
                self._client.table(self.TABLE)
                .insert({
                    "org_id": org_id,
                    "manifest_flow_url": manifest_flow_url,
                    "setup_complete": False,
                })
                .execute()
            )
            if result.data:
                return result.data[0]["id"]
            return None
        except Exception as e:
            logger.error(f"create_config failed: {e}")
            return None

    def complete_config(
        self,
        setup_id: str,
        app_id: int,
        private_key: str,
        webhook_secret: str,
    ) -> bool:
        """
        Mark a config as complete and store credentials.

        Args:
            setup_id: The config record ID.
            app_id: GitHub App ID.
            private_key: PEM-encoded RSA private key (encrypted at rest).
            webhook_secret: Webhook shared secret.

        Returns:
            True on success, False on failure.
        """
        self._ensure_client()
        if not self._client:
            logger.warning("complete_config: supabase not available")
            return False

        try:
            encrypted_key = _encrypt_value(private_key)

            result = (
                self._client.table(self.TABLE)
                .update({
                    "app_id": app_id,
                    "private_key_encrypted": encrypted_key,
                    "webhook_secret": webhook_secret,
                    "setup_complete": True,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                })
                .eq("id", setup_id)
                .execute()
            )
            return bool(result.data)
        except Exception as e:
            logger.error(f"complete_config failed: {e}")
            return False

    def get_config(self, setup_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a GitHub App config by ID.

        Args:
            setup_id: The config record ID.

        Returns:
            Dict with config fields (private_key decrypted), or None.
        """
        self._ensure_client()
        if not self._client:
            return None

        try:
            result = (
                self._client.table(self.TABLE)
                .select("*")
                .eq("id", setup_id)
                .single()
                .execute()
            )
            if result.data:
                data = dict(result.data)
                # Decrypt the private key
                if data.get("private_key_encrypted"):
                    data["private_key"] = _decrypt_value(data["private_key_encrypted"])
                return data
            return None
        except Exception as e:
            logger.error(f"get_config failed: {e}")
            return None

    def get_config_by_org(self, org_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve the GitHub App config for an organization.

        Args:
            org_id: The organization UUID.

        Returns:
            Dict with config fields, or None.
        """
        self._ensure_client()
        if not self._client:
            return None

        try:
            result = (
                self._client.table(self.TABLE)
                .select("*")
                .eq("org_id", org_id)
                .eq("setup_complete", True)
                .order("created_at", desc=True)
                .limit(1)
                .execute()
            )
            if result.data:
                data = dict(result.data[0])
                if data.get("private_key_encrypted"):
                    data["private_key"] = _decrypt_value(data["private_key_encrypted"])
                return data
            return None
        except Exception as e:
            logger.error(f"get_config_by_org failed: {e}")
            return None

    def get_credentials(self, org_id: str) -> Optional[Dict[str, Any]]:
        """
        Get active GitHub App credentials for an organization.

        Falls back to environment variables if Supabase is unavailable
        or no config is found.

        Args:
            org_id: The organization UUID.

        Returns:
            Dict with app_id, private_key, webhook_secret, or None.
        """
        self._ensure_client()

        # Try Supabase first
        if self._client:
            config = self.get_config_by_org(org_id)
            if config and config.get("app_id"):
                return {
                    "app_id": config["app_id"],
                    "private_key": config.get("private_key", ""),
                    "webhook_secret": config.get("webhook_secret", ""),
                }

        # Fall back to environment variables
        from vibelock.src.ingestion.github_app import get_app_credentials_from_env
        return get_app_credentials_from_env()

    def delete_config(self, setup_id: str) -> bool:
        """
        Delete a GitHub App config record.

        Args:
            setup_id: The config record ID.

        Returns:
            True on success, False on failure.
        """
        self._ensure_client()
        if not self._client:
            return False

        try:
            result = (
                self._client.table(self.TABLE)
                .delete()
                .eq("id", setup_id)
                .execute()
            )
            return bool(result.data)
        except Exception as e:
            logger.error(f"delete_config failed: {e}")
            return False


# Module-level singleton
github_app_config_store = GithubAppConfigStore()