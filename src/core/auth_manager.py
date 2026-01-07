"""
Authentication Manager Module

Provides session management and authentication injection for authenticated scanning.
Supports multiple authentication methods: Basic, Form, JWT, OAuth2, Cookie.
"""

import base64
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class AuthType(Enum):
    """Supported authentication types"""

    BASIC = "basic"
    FORM = "form"
    JWT = "jwt"
    OAUTH2 = "oauth2"
    COOKIE = "cookie"
    API_KEY = "api_key"


@dataclass
class AuthConfig:
    """Authentication configuration"""

    auth_type: AuthType
    credentials: dict[str, str] = field(default_factory=dict)

    # For form-based auth
    login_url: str | None = None
    logout_url: str | None = None
    username_field: str = "username"
    password_field: str = "password"

    # For OAuth2
    token_endpoint: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scope: str | None = None

    # For API Key
    api_key_header: str = "X-API-Key"
    api_key_param: str | None = None

    # Session settings
    session_timeout: int = 3600  # seconds
    auto_refresh: bool = True
    verify_ssl: bool = True


@dataclass
class Session:
    """Authenticated session state"""

    session_id: str
    auth_type: AuthType
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    token: str | None = None
    token_type: str = "Bearer"
    expires_at: datetime | None = None
    refresh_token: str | None = None
    is_valid: bool = True
    created_at: datetime = field(default_factory=datetime.now)

    def is_expired(self) -> bool:
        """Check if session has expired"""
        if self.expires_at is None:
            return False
        return datetime.now() >= self.expires_at

    def get_auth_header(self) -> tuple[str, str] | None:
        """Get authorization header tuple"""
        if self.token:
            return ("Authorization", f"{self.token_type} {self.token}")
        return None

    def to_dict(self) -> dict[str, Any]:
        """Serialize session to dict"""
        return {
            "session_id": self.session_id,
            "auth_type": self.auth_type.value,
            "headers": self.headers,
            "cookies": self.cookies,
            "token": self.token,
            "token_type": self.token_type,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_valid": self.is_valid,
            "created_at": self.created_at.isoformat(),
        }


class AuthManager:
    """
    Manage authenticated sessions for security scanning.

    Handles authentication flows and session injection for HTTP requests.
    """

    def __init__(self, http_client: Any):
        """
        Initialize AuthManager.

        Args:
            http_client: HTTP client instance for making requests
        """
        self.http_client = http_client
        self.active_sessions: dict[str, Session] = {}
        self._session_counter = 0

    async def authenticate(self, config: AuthConfig) -> Session:
        """
        Authenticate using the specified method.

        Args:
            config: Authentication configuration

        Returns:
            Session object with auth tokens/cookies
        """
        auth_methods = {
            AuthType.BASIC: self._basic_auth,
            AuthType.FORM: self._form_auth,
            AuthType.JWT: self._jwt_auth,
            AuthType.OAUTH2: self._oauth2_auth,
            AuthType.COOKIE: self._cookie_auth,
            AuthType.API_KEY: self._api_key_auth,
        }

        auth_method = auth_methods.get(config.auth_type)
        if not auth_method:
            raise ValueError(f"Unsupported auth type: {config.auth_type}")

        session = await auth_method(config)
        self.active_sessions[session.session_id] = session

        logger.info(f"Authentication successful: {config.auth_type.value}")
        return session

    async def refresh_session(self, session: Session, config: AuthConfig) -> Session:
        """
        Refresh an expired session.

        Args:
            session: Expired session to refresh
            config: Original auth config

        Returns:
            New session with fresh tokens
        """
        if session.auth_type == AuthType.OAUTH2 and session.refresh_token:
            return await self._oauth2_refresh(session, config)

        # For other auth types, re-authenticate
        return await self.authenticate(config)

    async def inject_auth(self, session: Session, headers: dict[str, str]) -> dict[str, str]:
        """
        Inject authentication into request headers.

        Args:
            session: Active session
            headers: Original request headers

        Returns:
            Headers with authentication injected
        """
        auth_headers = headers.copy()

        # Add session headers
        auth_headers.update(session.headers)

        # Add auth header
        auth_header = session.get_auth_header()
        if auth_header:
            auth_headers[auth_header[0]] = auth_header[1]

        return auth_headers

    def get_cookies(self, session: Session) -> dict[str, str]:
        """Get cookies from session"""
        return session.cookies.copy()

    async def invalidate_session(self, session: Session, config: AuthConfig | None = None):
        """
        Invalidate and logout session.

        Args:
            session: Session to invalidate
            config: Original auth config (for logout URL)
        """
        session.is_valid = False

        # Perform logout if configured
        if config and config.logout_url:
            try:
                await self.http_client.get(config.logout_url, headers=await self.inject_auth(session, {}))
            except Exception as e:
                logger.warning(f"Logout request failed: {e}")

        # Remove from active sessions
        if session.session_id in self.active_sessions:
            del self.active_sessions[session.session_id]

        logger.info(f"Session invalidated: {session.session_id}")

    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        self._session_counter += 1
        return f"session_{self._session_counter}_{datetime.now().strftime('%Y%m%d%H%M%S')}"

    # === Authentication Methods ===

    async def _basic_auth(self, config: AuthConfig) -> Session:
        """HTTP Basic Authentication"""
        username = config.credentials.get("username", "")
        password = config.credentials.get("password", "")

        # Create Basic auth header
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode()

        return Session(
            session_id=self._generate_session_id(), auth_type=AuthType.BASIC, token=encoded, token_type="Basic"
        )

    async def _form_auth(self, config: AuthConfig) -> Session:
        """Form-based authentication with CSRF token support"""
        if not config.login_url:
            raise ValueError("Login URL required for form authentication")

        username = config.credentials.get("username", "")
        password = config.credentials.get("password", "")

        # Step 1: Get login page to extract CSRF token
        login_page = await self.http_client.get(config.login_url)
        csrf_token = await self._extract_csrf_token(login_page)

        # Step 2: Prepare login data
        login_data = {
            config.username_field: username,
            config.password_field: password,
        }

        # Add CSRF token if found
        if csrf_token:
            login_data["_token"] = csrf_token[1]
            login_data[csrf_token[0]] = csrf_token[1]

        # Step 3: Submit login form
        response = await self.http_client.post(config.login_url, data=login_data, allow_redirects=False)

        # Extract session cookies
        cookies = self._extract_cookies(response)

        # Check for authentication success
        if response.status in [200, 302, 303]:
            return Session(
                session_id=self._generate_session_id(),
                auth_type=AuthType.FORM,
                cookies=cookies,
                expires_at=datetime.now() + timedelta(seconds=config.session_timeout),
            )

        raise ValueError(f"Form authentication failed: {response.status}")

    async def _jwt_auth(self, config: AuthConfig) -> Session:
        """JWT Bearer token authentication"""
        token = config.credentials.get("token", "")

        if not token:
            # Try to obtain token from endpoint
            if config.token_endpoint:
                token = await self._obtain_jwt_token(config)
            else:
                raise ValueError("JWT token or token endpoint required")

        # Parse token to extract expiration
        expires_at = self._parse_jwt_expiry(token)

        return Session(
            session_id=self._generate_session_id(),
            auth_type=AuthType.JWT,
            token=token,
            token_type="Bearer",
            expires_at=expires_at,
        )

    async def _oauth2_auth(self, config: AuthConfig) -> Session:
        """OAuth2 Client Credentials flow"""
        if not config.token_endpoint:
            raise ValueError("Token endpoint required for OAuth2")

        # Request token
        auth_data = {
            "grant_type": "client_credentials",
            "client_id": config.client_id or config.credentials.get("client_id", ""),
            "client_secret": config.client_secret or config.credentials.get("client_secret", ""),
        }

        if config.scope:
            auth_data["scope"] = config.scope

        response = await self.http_client.post(
            config.token_endpoint, data=auth_data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if response.status != 200:
            raise ValueError(f"OAuth2 token request failed: {response.status}")

        token_data = json.loads(await response.text())

        expires_in = token_data.get("expires_in", 3600)

        return Session(
            session_id=self._generate_session_id(),
            auth_type=AuthType.OAUTH2,
            token=token_data.get("access_token"),
            token_type=token_data.get("token_type", "Bearer"),
            refresh_token=token_data.get("refresh_token"),
            expires_at=datetime.now() + timedelta(seconds=expires_in),
        )

    async def _oauth2_refresh(self, session: Session, config: AuthConfig) -> Session:
        """Refresh OAuth2 token"""
        if not session.refresh_token or not config.token_endpoint:
            raise ValueError("Cannot refresh: no refresh token or endpoint")

        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": session.refresh_token,
            "client_id": config.client_id or config.credentials.get("client_id", ""),
            "client_secret": config.client_secret or config.credentials.get("client_secret", ""),
        }

        response = await self.http_client.post(
            config.token_endpoint, data=refresh_data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if response.status != 200:
            raise ValueError("Token refresh failed")

        token_data = json.loads(await response.text())
        expires_in = token_data.get("expires_in", 3600)

        # Update session
        session.token = token_data.get("access_token")
        session.refresh_token = token_data.get("refresh_token", session.refresh_token)
        session.expires_at = datetime.now() + timedelta(seconds=expires_in)
        session.is_valid = True

        return session

    async def _cookie_auth(self, config: AuthConfig) -> Session:
        """Manual cookie injection"""
        cookie_string = config.credentials.get("cookies", "")

        cookies = {}
        for cookie in cookie_string.split(";"):
            cookie = cookie.strip()
            if "=" in cookie:
                name, value = cookie.split("=", 1)
                cookies[name.strip()] = value.strip()

        return Session(
            session_id=self._generate_session_id(),
            auth_type=AuthType.COOKIE,
            cookies=cookies,
            expires_at=datetime.now() + timedelta(seconds=config.session_timeout),
        )

    async def _api_key_auth(self, config: AuthConfig) -> Session:
        """API Key authentication"""
        api_key = config.credentials.get("api_key", "")

        headers = {}
        if config.api_key_header:
            headers[config.api_key_header] = api_key

        return Session(
            session_id=self._generate_session_id(),
            auth_type=AuthType.API_KEY,
            headers=headers,
            token=api_key if not config.api_key_header else None,
        )

    # === Helper Methods ===

    async def _extract_csrf_token(self, response: Any) -> tuple[str, str] | None:
        """Extract CSRF token from HTML response"""
        try:
            html = await response.text()

            # Common CSRF token patterns
            patterns = [
                r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
                r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
                r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']',
                r'name=["\']_csrf["\'][^>]*value=["\']([^"\']+)["\']',
                r'<meta name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
            ]

            token_names = ["_token", "csrf_token", "csrfmiddlewaretoken", "_csrf", "csrf-token"]

            for pattern, name in zip(patterns, token_names, strict=False):
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    return (name, match.group(1))

        except Exception as e:
            logger.debug(f"CSRF token extraction failed: {e}")

        return None

    def _extract_cookies(self, response: Any) -> dict[str, str]:
        """Extract cookies from response headers"""
        cookies = {}

        try:
            for cookie in response.cookies:
                cookies[cookie.key] = cookie.value
        except Exception:
            # Fallback: parse Set-Cookie headers
            try:
                set_cookie = response.headers.getall("Set-Cookie", [])
                for cookie_header in set_cookie:
                    parts = cookie_header.split(";")[0]
                    if "=" in parts:
                        name, value = parts.split("=", 1)
                        cookies[name.strip()] = value.strip()
            except Exception as e:
                logger.debug(f"Error parsing cookie header: {e}")

        return cookies

    async def _obtain_jwt_token(self, config: AuthConfig) -> str:
        """Obtain JWT token from endpoint"""
        username = config.credentials.get("username", "")
        password = config.credentials.get("password", "")

        response = await self.http_client.post(
            config.token_endpoint,
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"},
        )

        if response.status != 200:
            raise ValueError("JWT token request failed")

        data = json.loads(await response.text())
        return data.get("access_token") or data.get("token") or data.get("jwt")

    def _parse_jwt_expiry(self, token: str) -> datetime | None:
        """Parse JWT token to extract expiration"""
        try:
            # JWT format: header.payload.signature
            parts = token.split(".")
            if len(parts) != 3:
                return None

            # Decode payload (add padding if needed)
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding

            decoded = base64.urlsafe_b64decode(payload)
            claims = json.loads(decoded)

            exp = claims.get("exp")
            if exp:
                return datetime.fromtimestamp(exp)

        except Exception as e:
            logger.debug(f"JWT parsing failed: {e}")

        return None


# Convenience function for CLI usage
def create_auth_config(
    auth_type: str,
    username: str | None = None,
    password: str | None = None,
    token: str | None = None,
    cookies: str | None = None,
    login_url: str | None = None,
    token_endpoint: str | None = None,
    api_key: str | None = None,
) -> AuthConfig:
    """
    Create AuthConfig from CLI arguments.

    Args:
        auth_type: 'basic', 'form', 'jwt', 'oauth2', 'cookie', 'api_key'
        username: Username for basic/form auth
        password: Password for basic/form auth
        token: JWT token
        cookies: Cookie string
        login_url: Form login URL
        token_endpoint: JWT/OAuth2 token endpoint
        api_key: API key

    Returns:
        AuthConfig ready for use
    """
    auth_type_enum = AuthType(auth_type.lower())

    credentials = {}
    if username:
        credentials["username"] = username
    if password:
        credentials["password"] = password
    if token:
        credentials["token"] = token
    if cookies:
        credentials["cookies"] = cookies
    if api_key:
        credentials["api_key"] = api_key

    return AuthConfig(
        auth_type=auth_type_enum, credentials=credentials, login_url=login_url, token_endpoint=token_endpoint
    )
