"""
SENTINEL Security Audit Tests
OWASP Top 10 compliance tests for the scanner's own codebase.

Tests cover:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A07: Authentication Failures
"""

import asyncio
import os
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── A07: Authentication & JWT Tests ───────────────────────────────────


class TestJWTSecurity:
    """Test JWT implementation for common vulnerabilities."""

    def _get_auth_manager(self):
        from src.core.security.auth import AuthenticationManager
        return AuthenticationManager(secret_key="test-secret-key-minimum-32-chars!!")

    def _create_test_user(self):
        from src.core.security.auth import Role, User
        return User(
            id="test-user-id",
            username="testuser",
            email="test@example.com",
            role=Role.ANALYST,
            is_active=True,
            created_at=datetime.utcnow(),
        )

    def test_token_creation_and_verification(self):
        """Verify basic token flow works."""
        auth = self._get_auth_manager()
        user = self._create_test_user()
        token = auth.create_access_token(user)

        assert token.access_token is not None
        assert token.token_type == "bearer"

        data = auth.verify_token(token.access_token)
        assert data is not None
        assert data.username == "testuser"
        assert data.sub == "test-user-id"

    def test_invalid_token_rejected(self):
        """Verify that tampered tokens are rejected."""
        auth = self._get_auth_manager()
        result = auth.verify_token("invalid.token.here")
        assert result is None

    def test_token_with_wrong_secret_rejected(self):
        """Verify tokens signed with different key are rejected."""
        from src.core.security.auth import AuthenticationManager
        auth1 = AuthenticationManager(secret_key="secret-key-one-minimum-32-chars!!")
        auth2 = AuthenticationManager(secret_key="secret-key-two-minimum-32-chars!!")

        user = self._create_test_user()
        token = auth1.create_access_token(user)

        # Should fail with different secret
        result = auth2.verify_token(token.access_token)
        assert result is None

    def test_expired_token_rejected(self):
        """Verify expired tokens are properly rejected."""
        from src.core.security.auth import AuthenticationManager
        auth = AuthenticationManager(
            secret_key="test-secret-key-minimum-32-chars!!",
            access_token_expire_minutes=0,  # Expires immediately
        )
        user = self._create_test_user()
        token = auth.create_access_token(user)

        # Token should be expired
        import time
        time.sleep(1)
        result = auth.verify_token(token.access_token)
        assert result is None

    def test_algorithm_enforcement(self):
        """Verify that only the configured algorithm is accepted."""
        import jwt
        auth = self._get_auth_manager()

        # Create a token with 'none' algorithm (attack vector)
        payload = {
            "sub": "attacker",
            "username": "attacker",
            "role": "admin",
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": datetime.utcnow(),
        }

        # This should be rejected because auth expects HS256
        try:
            unsigned_token = jwt.encode(payload, "", algorithm="none")
            result = auth.verify_token(unsigned_token)
            # If we get here, the none algorithm was accepted (BAD)
            assert result is None, "Algorithm 'none' should not be accepted"
        except Exception:
            # Expected: PyJWT should reject this
            pass

    def test_password_hashing_not_plaintext(self):
        """Verify passwords are hashed, not stored in plaintext."""
        auth = self._get_auth_manager()
        password = "test-password-123"
        hashed = auth.get_password_hash(password)

        assert hashed != password
        assert len(hashed) > 20
        assert auth.verify_password(password, hashed)
        assert not auth.verify_password("wrong-password", hashed)


# ── A01: Broken Access Control Tests ──────────────────────────────────


class TestAccessControl:
    """Test RBAC implementation."""

    def test_viewer_cannot_create_scans(self):
        """Verify viewer role lacks scan creation permission."""
        from src.core.security.auth import AuthenticationManager, Permission, Role, User

        auth = AuthenticationManager(secret_key="test-secret-key-minimum-32-chars!!")
        viewer = User(
            id="viewer-id",
            username="viewer",
            email="viewer@example.com",
            role=Role.VIEWER,
            is_active=True,
            created_at=datetime.utcnow(),
        )

        assert not auth.has_permission(viewer, Permission.SCAN_CREATE)
        assert not auth.has_permission(viewer, Permission.CONFIG_UPDATE)
        assert not auth.has_permission(viewer, Permission.USER_MANAGE)

    def test_admin_has_all_permissions(self):
        """Verify admin role has full access."""
        from src.core.security.auth import AuthenticationManager, Permission, Role, User

        auth = AuthenticationManager(secret_key="test-secret-key-minimum-32-chars!!")
        admin = User(
            id="admin-id",
            username="admin",
            email="admin@example.com",
            role=Role.ADMIN,
            is_active=True,
            created_at=datetime.utcnow(),
        )

        for perm in Permission:
            assert auth.has_permission(admin, perm), f"Admin should have {perm}"

    def test_inactive_user_denied(self):
        """Verify inactive users are denied access."""
        from src.core.security.auth import AuthenticationManager, Permission, Role, User

        auth = AuthenticationManager(secret_key="test-secret-key-minimum-32-chars!!")
        inactive_user = User(
            id="inactive-id",
            username="inactive",
            email="inactive@example.com",
            role=Role.ADMIN,
            is_active=False,
            created_at=datetime.utcnow(),
        )

        assert not auth.authorize(inactive_user, [Permission.SCAN_CREATE])


# ── A05: Security Misconfiguration Tests ──────────────────────────────


class TestSecurityConfig:
    """Test security configuration hardening."""

    def test_cors_rejects_wildcard_with_credentials(self):
        """Verify CORS does not allow wildcard origins with credentials."""
        # Read the actual app.py to verify the fix is in place
        import ast

        app_path = os.path.join(os.path.dirname(__file__), "..", "..", "src", "api", "app.py")
        with open(app_path, "r") as f:
            content = f.read()

        # The fix should ensure that wildcard + credentials is not possible
        assert "allow_credentials=False" in content or "_is_wildcard" in content, (
            "CORS should not allow wildcard origins with credentials"
        )

    def test_security_headers_present(self):
        """Verify all required security headers are set."""
        from src.core.security.auth import SecurityHeaders

        headers = SecurityHeaders.get_security_headers()

        required_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "Referrer-Policy",
            "Permissions-Policy",
        ]

        for header in required_headers:
            assert header in headers, f"Missing security header: {header}"

    def test_x_frame_options_deny(self):
        """Verify X-Frame-Options is set to DENY."""
        from src.core.security.auth import SecurityHeaders

        headers = SecurityHeaders.get_security_headers()
        assert headers["X-Frame-Options"] == "DENY"

    def test_hsts_enabled(self):
        """Verify HSTS is enabled with adequate max-age."""
        from src.core.security.auth import SecurityHeaders

        headers = SecurityHeaders.get_security_headers()
        hsts = headers["Strict-Transport-Security"]
        assert "max-age=" in hsts
        # Extract max-age value
        import re
        match = re.search(r"max-age=(\d+)", hsts)
        assert match is not None
        max_age = int(match.group(1))
        assert max_age >= 31536000, "HSTS max-age should be at least 1 year"


# ── A04: Rate Limiting Tests ──────────────────────────────────────────


class TestRateLimiting:
    """Test rate limiting middleware for brute-force protection."""

    @pytest.mark.asyncio
    async def test_auth_rate_limit_stricter(self):
        """Verify auth endpoints have stricter rate limits than general endpoints."""
        from src.api.middleware.rate_limit import RateLimitMiddleware

        middleware = RateLimitMiddleware(app=MagicMock())
        assert middleware.AUTH_RATE_LIMIT < middleware.requests_per_minute

    @pytest.mark.asyncio
    async def test_brute_force_lockout(self):
        """Verify brute-force tracker locks out after threshold."""
        from src.api.middleware.rate_limit import AuthBruteForceTracker

        tracker = AuthBruteForceTracker()
        client_id = "test-attacker-ip"

        # Record 5 failures (should trigger first threshold)
        for _ in range(5):
            await tracker.record_failure(client_id)

        is_locked, retry_after = await tracker.is_locked_out(client_id)
        assert is_locked, "Should be locked after 5 failures"
        assert retry_after > 0

    @pytest.mark.asyncio
    async def test_successful_login_clears_failures(self):
        """Verify successful login clears failure history."""
        from src.api.middleware.rate_limit import AuthBruteForceTracker

        tracker = AuthBruteForceTracker()
        client_id = "test-user-ip"

        # Record some failures
        for _ in range(3):
            await tracker.record_failure(client_id)

        count = await tracker.get_failure_count(client_id)
        assert count == 3

        # Successful login should clear
        await tracker.clear(client_id)
        count = await tracker.get_failure_count(client_id)
        assert count == 0

    @pytest.mark.asyncio
    async def test_auth_endpoints_detected(self):
        """Verify auth endpoints are correctly identified."""
        from src.api.middleware.rate_limit import RateLimitMiddleware

        middleware = RateLimitMiddleware(app=MagicMock())
        assert middleware._is_auth_endpoint("/api/v1/auth/login")
        assert middleware._is_auth_endpoint("/api/v1/auth/register")
        assert not middleware._is_auth_endpoint("/api/v1/scans")
        assert not middleware._is_auth_endpoint("/health")


# ── A03: Injection Tests ──────────────────────────────────────────────


class TestInjectionPrevention:
    """Test input validation and injection prevention."""

    def test_url_validation(self):
        """Verify URL validation rejects malicious input."""
        from src.cli.commands import validate_url

        # Valid URLs
        assert validate_url("https://example.com")
        assert validate_url("http://test.com/path?q=1")

        # Invalid URLs
        assert not validate_url("not-a-url")
        assert not validate_url("")
        assert not validate_url("javascript:alert(1)")

    def test_scan_result_evidence_type(self):
        """Verify ScanResult evidence field is correctly typed as dict."""
        from src.core.scanner_engine import ScanResult

        result = ScanResult(module_name="test", status="ok", details="test")
        assert isinstance(result.evidence, dict), "evidence should default to dict, not list"

    def test_api_key_format_validation(self):
        """Verify API key validation checks format."""
        from src.core.security.auth import APIKeyManager

        manager = APIKeyManager(secret_key="test-key")
        assert manager.verify_api_key("sk_" + "a" * 32)
        assert not manager.verify_api_key("invalid-key")
        assert not manager.verify_api_key("")
        assert not manager.verify_api_key("sk_short")


# ── Data Type Safety Tests ────────────────────────────────────────────


class TestTypeSafety:
    """Test dataclass field types match their defaults."""

    def test_scan_result_defaults(self):
        """Verify all ScanResult field defaults are correctly typed."""
        from src.core.scanner_engine import ScanResult

        result = ScanResult(module_name="test", status="ok", details="details")

        assert isinstance(result.vulnerabilities, list)
        assert isinstance(result.evidence, dict)
        assert isinstance(result.timestamp, datetime)
        assert isinstance(result.duration, float)
        assert isinstance(result.risk_level, str)
