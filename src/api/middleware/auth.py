"""
Authentication middleware for API requests.
"""

import structlog
from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.security import AuthenticationManager
from src.core.security.secrets import get_secrets_manager

logger = structlog.get_logger()


class AuthMiddleware(BaseHTTPMiddleware):
    """JWT authentication middleware."""

    # Public endpoints. Exact match only: a prefix test would make every
    # path public, since all paths start with "/".
    PUBLIC_PATHS = frozenset(
        {
            "/",
            "/health",
            "/ready",
            "/metrics",
            "/api/docs",
            "/api/redoc",
            "/api/openapi.json",
            "/api/v1/auth/login",
            "/api/v1/auth/register",
        }
    )

    # Public path prefixes. Kept deliberately narrow: only the OOB callback sink,
    # which external targets hit without credentials for blind-vuln (SSRF/XXE/OAST)
    # verification. The trailing slash prevents matching sibling routes like
    # "/api/v1/oob/callbacks" or "/api/v1/oob/listeners".
    PUBLIC_PREFIXES = ("/api/v1/oob/callback/",)

    def __init__(self, app):
        super().__init__(app)
        self.auth_manager = None

    async def _get_auth_manager(self) -> AuthenticationManager:
        """Lazy load auth manager."""
        if self.auth_manager is None:
            secrets = get_secrets_manager()
            secret_key = await secrets.get_secret_key()
            self.auth_manager = AuthenticationManager(secret_key)
        return self.auth_manager

    def _is_public(self, path: str) -> bool:
        """Public when it matches a public path exactly, or a narrow public prefix.
        Exact match is the default because a blanket startswith would expose every
        route; prefixes are listed one by one and kept tight."""
        return path in self.PUBLIC_PATHS or any(path.startswith(prefix) for prefix in self.PUBLIC_PREFIXES)

    async def dispatch(self, request: Request, call_next):
        """Process request with authentication."""
        if self._is_public(request.url.path):
            return await call_next(request)

        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header.split(" ", 1)[1]

        # Verify token
        auth_manager = await self._get_auth_manager()
        token_data = auth_manager.verify_token(token)

        if token_data is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Add user info to request state
        request.state.user_id = token_data.sub
        request.state.username = token_data.username
        request.state.role = token_data.role

        logger.info(
            "Authenticated request",
            user_id=token_data.sub,
            username=token_data.username,
            path=request.url.path,
        )

        return await call_next(request)
