"""RBAC enforcement and admin bootstrap tests."""

from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from src.api.dependencies import require_permission
from src.core.database import UserModel
from src.core.security.auth import Permission


def _req(role):
    return SimpleNamespace(state=SimpleNamespace(role=role))


@pytest.mark.asyncio
async def test_require_permission_enforces_role_permissions():
    # viewer cannot create scans; analyst can.
    with pytest.raises(HTTPException) as exc:
        await require_permission(Permission.SCAN_CREATE)(_req("viewer"))
    assert exc.value.status_code == 403
    assert await require_permission(Permission.SCAN_CREATE)(_req("analyst"))

    # viewer can read scans.
    assert await require_permission(Permission.SCAN_READ)(_req("viewer"))

    # only admin manages users.
    assert await require_permission(Permission.USER_MANAGE)(_req("admin"))
    with pytest.raises(HTTPException) as exc:
        await require_permission(Permission.USER_MANAGE)(_req("analyst"))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_require_permission_rejects_missing_or_unknown_role():
    # No role on request state -> 401.
    with pytest.raises(HTTPException) as exc:
        await require_permission(Permission.SCAN_READ)(SimpleNamespace(state=SimpleNamespace()))
    assert exc.value.status_code == 401
    # Unknown role string -> 403.
    with pytest.raises(HTTPException) as exc:
        await require_permission(Permission.SCAN_READ)(_req("wizard"))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_ensure_admin_creates_once_and_is_idempotent(db_session, monkeypatch):
    import src.core.security.bootstrap as boot

    @asynccontextmanager
    async def fake_session():
        yield db_session

    async def fake_secret_key():
        return "x" * 32

    monkeypatch.setattr(boot, "get_db_manager", lambda: SimpleNamespace(session=fake_session))
    monkeypatch.setattr(boot, "get_secrets_manager", lambda: SimpleNamespace(get_secret_key=fake_secret_key))
    monkeypatch.setenv("SENTINEL_ADMIN_USERNAME", "root")
    monkeypatch.setenv("SENTINEL_ADMIN_PASSWORD", "supersecret123")

    assert await boot.ensure_admin() is True  # created
    assert await boot.ensure_admin() is False  # already exists -> no-op

    result = await db_session.execute(select(UserModel).where(UserModel.role == "admin"))
    admin = result.scalar_one_or_none()
    assert admin is not None and admin.username == "root"


@pytest.mark.asyncio
async def test_ensure_admin_noop_without_env(monkeypatch):
    import src.core.security.bootstrap as boot

    monkeypatch.delenv("SENTINEL_ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("SENTINEL_ADMIN_PASSWORD", raising=False)
    assert await boot.ensure_admin() is False


def test_oob_callback_is_public_but_siblings_are_protected():
    from unittest.mock import MagicMock

    from src.api.middleware.auth import AuthMiddleware

    mw = AuthMiddleware(app=MagicMock())
    # The callback sink is public: external targets hit it without credentials.
    assert mw._is_public("/api/v1/oob/callback/abc123")
    assert mw._is_public("/api/v1/oob/callback/deadbeef")
    # Sibling / management routes stay authenticated.
    assert not mw._is_public("/api/v1/oob/listeners")
    assert not mw._is_public("/api/v1/oob/callbacks")  # trailing-slash boundary
    assert not mw._is_public("/api/v1/oob/callback")  # needs an id segment
    assert not mw._is_public("/api/v1/scans")
    # Existing exact publics still work.
    assert mw._is_public("/health")
    assert mw._is_public("/api/v1/auth/login")
