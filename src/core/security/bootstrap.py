"""Admin bootstrap.

Self-registration only ever creates a low-privilege ``viewer`` (see the register
route), so there is no way to get the first admin through the API. This creates
that admin from environment variables at startup, once, without ever weakening an
account that already exists.

Set, in the environment / secret manager:

    SENTINEL_ADMIN_USERNAME=...
    SENTINEL_ADMIN_PASSWORD=...        # >= 8 chars
    SENTINEL_ADMIN_EMAIL=...           # optional

It is a no-op when those are unset, when an admin already exists, or when the
username is already taken.
"""

import os

import structlog
from sqlalchemy import select

from src.core.database import UserModel, get_db_manager
from src.core.security.auth import AuthenticationManager
from src.core.security.secrets import get_secrets_manager

logger = structlog.get_logger()

ADMIN_USERNAME_ENV = "SENTINEL_ADMIN_USERNAME"
ADMIN_PASSWORD_ENV = "SENTINEL_ADMIN_PASSWORD"
ADMIN_EMAIL_ENV = "SENTINEL_ADMIN_EMAIL"
_MIN_PASSWORD_LEN = 8


async def ensure_admin() -> bool:
    """Create the bootstrap admin if configured and none exists. Returns True when
    an admin was created, False otherwise. Safe to call on every startup."""
    username = os.getenv(ADMIN_USERNAME_ENV)
    password = os.getenv(ADMIN_PASSWORD_ENV)
    if not username or not password:
        return False
    if len(password) < _MIN_PASSWORD_LEN:
        logger.warning("Bootstrap admin password too short; skipping", min_length=_MIN_PASSWORD_LEN)
        return False

    db_manager = get_db_manager()
    async with db_manager.session() as db:
        existing_admin = await db.execute(select(UserModel).where(UserModel.role == "admin"))
        if existing_admin.scalar_one_or_none() is not None:
            return False

        taken = await db.execute(select(UserModel).where(UserModel.username == username))
        if taken.scalar_one_or_none() is not None:
            logger.warning("Bootstrap admin username already taken; not modifying it", username=username)
            return False

        secrets = get_secrets_manager()
        secret_key = await secrets.get_secret_key()
        auth = AuthenticationManager(secret_key)
        admin = UserModel(
            username=username,
            email=os.getenv(ADMIN_EMAIL_ENV, f"{username}@local"),
            hashed_password=auth.get_password_hash(password),
            role="admin",
        )
        db.add(admin)
        await db.commit()
        logger.info("Bootstrap admin created", username=username)
        return True
