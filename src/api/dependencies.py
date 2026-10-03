"""Shared API dependencies.

``require_permission`` enforces the global RBAC model (ROLE_PERMISSIONS) on an
endpoint. It reads the role the auth middleware put on ``request.state`` and
rejects the request when that role lacks the permission. This is the coarse,
account-level gate ("may this user create scans at all?"); campaign access is a
separate, finer check (_check_campaign_membership).
"""

from fastapi import HTTPException, Request, status

from src.core.security.auth import ROLE_PERMISSIONS, Permission, Role


def require_permission(permission: Permission):
    """FastAPI dependency factory: allow the request only if the caller's role
    grants ``permission``."""

    async def checker(request: Request) -> Role:
        role_value = getattr(request.state, "role", None)
        if role_value is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        try:
            role = Role(role_value)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unknown role") from exc
        if permission not in ROLE_PERMISSIONS.get(role, []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires the '{permission.value}' permission.",
            )
        return role

    return checker
