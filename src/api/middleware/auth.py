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

    # Public endpoints that don't require authentication
    PUBLIC_PATHS = [
        "/",
        "/health",
        "/ready",
        "/metrics",
        "/api/docs",
        "/api/redoc",
        "/api/openapi.json",
        "/api/v1/auth/login",
        "/api/v1/auth/register",
    ]

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

    async def dispatch(self, request: Request, call_next):
        """Process request with authentication."""
        # Check if path requires authentication
        if any(request.url.path.startswith(path) for path in self.PUBLIC_PATHS):
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
