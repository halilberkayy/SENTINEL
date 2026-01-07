"""
Authentication and authorization module with JWT and RBAC.
"""

from datetime import datetime, timedelta
from enum import Enum

import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Role(str, Enum):
    """User roles for RBAC."""

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    API_USER = "api_user"


class Permission(str, Enum):
    """Granular permissions."""

    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_UPDATE = "scan:update"
    SCAN_DELETE = "scan:delete"
    REPORT_READ = "report:read"
    REPORT_EXPORT = "report:export"
    CONFIG_UPDATE = "config:update"
    USER_MANAGE = "user:manage"
    PLUGIN_MANAGE = "plugin:manage"


# RBAC permission mapping
ROLE_PERMISSIONS: dict[Role, list[Permission]] = {
    Role.ADMIN: list(Permission),  # All permissions
    Role.ANALYST: [
        Permission.SCAN_CREATE,
        Permission.SCAN_READ,
        Permission.SCAN_UPDATE,
        Permission.REPORT_READ,
        Permission.REPORT_EXPORT,
    ],
    Role.VIEWER: [
        Permission.SCAN_READ,
        Permission.REPORT_READ,
    ],
    Role.API_USER: [
        Permission.SCAN_CREATE,
        Permission.SCAN_READ,
        Permission.REPORT_READ,
    ],
}


class User(BaseModel):
    """User model."""

    id: str
    username: str
    email: EmailStr
    role: Role
    is_active: bool = True
    created_at: datetime
    last_login: datetime | None = None


class Token(BaseModel):
    """JWT token model."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    """Token payload data."""

    sub: str  # user_id
    username: str
    role: Role
    exp: datetime


class AuthenticationManager:
    """Manages authentication and authorization."""

    def __init__(self, secret_key: str, algorithm: str = "HS256", access_token_expire_minutes: int = 30):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str) -> str:
        """Hash a password."""
        return pwd_context.hash(password)

    def create_access_token(self, user: User) -> Token:
        """Create a JWT access token."""
        expires_delta = timedelta(minutes=self.access_token_expire_minutes)
        expire = datetime.utcnow() + expires_delta

        payload = {
            "sub": user.id,
            "username": user.username,
            "role": user.role.value,
            "exp": expire,
            "iat": datetime.utcnow(),
        }

        encoded_jwt = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        return Token(access_token=encoded_jwt, expires_in=int(expires_delta.total_seconds()))

    def verify_token(self, token: str) -> TokenData | None:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            token_data = TokenData(
                sub=payload.get("sub"),
                username=payload.get("username"),
                role=Role(payload.get("role")),
                exp=datetime.fromtimestamp(payload.get("exp")),
            )
            return token_data
        except jwt.PyJWTError:
            return None

    def has_permission(self, user: User, permission: Permission) -> bool:
        """Check if user has a specific permission."""
        role_permissions = ROLE_PERMISSIONS.get(user.role, [])
        return permission in role_permissions

    def authorize(self, user: User, required_permissions: list[Permission]) -> bool:
        """Check if user has all required permissions."""
        if not user.is_active:
            return False

        role_permissions = ROLE_PERMISSIONS.get(user.role, [])
        return all(perm in role_permissions for perm in required_permissions)


class APIKeyManager:
    """Manages API keys for programmatic access."""

    def __init__(self, secret_key: str):
        self.secret_key = secret_key

    def generate_api_key(self, user_id: str, prefix: str = "sk") -> str:
        """Generate an API key for a user."""
        import hashlib
        import secrets

        # Generate a random secret
        random_secret = secrets.token_urlsafe(32)

        # Create a hash with user_id and secret
        data = f"{user_id}:{random_secret}:{self.secret_key}"
        api_key_hash = hashlib.sha256(data.encode()).hexdigest()

        # Format: prefix_hash (first 32 chars of hash)
        return f"{prefix}_{api_key_hash[:32]}"

    def verify_api_key(self, api_key: str) -> bool:
        """Verify an API key."""
        # In production, this would check against a database
        # For now, just validate format
        return api_key.startswith("sk_") and len(api_key) == 35


class SecurityHeaders:
    """Security headers for HTTP responses."""

    @staticmethod
    def get_security_headers() -> dict[str, str]:
        """Get recommended security headers."""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self'"
            ),
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        }
