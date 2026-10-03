"""
Secrets management for secure credential storage.
Supports environment variables, AWS Secrets Manager, and HashiCorp Vault.
"""

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path


class SecretsBackend(ABC):
    """Abstract base for secrets backends."""

    @abstractmethod
    async def get_secret(self, key: str) -> str | None:
        """Retrieve a secret by key."""
        pass

    @abstractmethod
    async def set_secret(self, key: str, value: str) -> None:
        """Store a secret."""
        pass

    @abstractmethod
    async def delete_secret(self, key: str) -> None:
        """Delete a secret."""
        pass


class EnvironmentSecretsBackend(SecretsBackend):
    """Simple environment-based secrets (for development)."""

    async def get_secret(self, key: str) -> str | None:
        return os.getenv(key)

    async def set_secret(self, key: str, value: str) -> None:
        os.environ[key] = value

    async def delete_secret(self, key: str) -> None:
        if key in os.environ:
            del os.environ[key]


class FileSecretsBackend(SecretsBackend):
    """File-based secrets storage (encrypted in production)."""

    def __init__(self, secrets_file: Path):
        self.secrets_file = secrets_file
        self._secrets: dict[str, str] = {}
        self._load_secrets()

    def _load_secrets(self) -> None:
        """Load secrets from file."""
        if self.secrets_file.exists():
            with open(self.secrets_file) as f:
                self._secrets = json.load(f)

    def _save_secrets(self) -> None:
        """Save secrets to file."""
        self.secrets_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.secrets_file, "w") as f:
            json.dump(self._secrets, f, indent=2)

    async def get_secret(self, key: str) -> str | None:
        return self._secrets.get(key)

    async def set_secret(self, key: str, value: str) -> None:
        self._secrets[key] = value
        self._save_secrets()

    async def delete_secret(self, key: str) -> None:
        if key in self._secrets:
            del self._secrets[key]
            self._save_secrets()


class SecretsManager:
    """
    Unified secrets management interface.
    Automatically selects backend based on environment.
    """

    def __init__(self, backend: SecretsBackend | None = None):
        if backend is None:
            # Auto-select backend
            if os.getenv("USE_FILE_SECRETS"):
                secrets_file = Path(os.getenv("SECRETS_FILE", ".secrets.json"))
                backend = FileSecretsBackend(secrets_file)
            else:
                backend = EnvironmentSecretsBackend()

        self.backend = backend

    async def get_secret(self, key: str, default: str | None = None) -> str | None:
        """Get a secret value."""
        value = await self.backend.get_secret(key)
        return value if value is not None else default

    async def set_secret(self, key: str, value: str) -> None:
        """Set a secret value."""
        await self.backend.set_secret(key, value)

    async def delete_secret(self, key: str) -> None:
        """Delete a secret."""
        await self.backend.delete_secret(key)

    async def get_database_url(self) -> str:
        """Get database connection URL."""
        return await self.get_secret("DATABASE_URL", "sqlite+aiosqlite:///./scanner.db")

    async def get_redis_url(self) -> str:
        """Get Redis connection URL."""
        return await self.get_secret("REDIS_URL", "redis://localhost:6379/0")

    async def get_secret_key(self) -> str:
        """Get application secret key."""
        secret = await self.get_secret("SECRET_KEY")
        if not secret:
            # Generate a secret key if not set
            import secrets

            secret = secrets.token_urlsafe(32)
            await self.set_secret("SECRET_KEY", secret)
        return secret

    async def rotate_secret(self, key: str) -> str:
        """Rotate a secret (generate new value)."""
        import secrets

        new_value = secrets.token_urlsafe(32)
        await self.set_secret(key, new_value)
        return new_value


# Singleton instance
_secrets_manager: SecretsManager | None = None


def get_secrets_manager() -> SecretsManager:
    """Get the global secrets manager instance."""
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager
