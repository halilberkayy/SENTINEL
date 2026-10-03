"""
Unit tests for authentication system.
"""

from datetime import datetime

from src.core.security import AuthenticationManager, Permission, Role, User


class TestAuthenticationManager:
    """Test authentication functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.auth_manager = AuthenticationManager(secret_key="test-secret-key")
        self.test_user = User(
            id="test-123",
            username="testuser",
            email="test@example.com",
            role=Role.ANALYST,
            is_active=True,
            created_at=datetime.now(),
        )

    def test_password_hashing(self):
        """Test password hashing and verification."""
        password = "secure_password_123"
        hashed = self.auth_manager.get_password_hash(password)

        assert hashed != password
        assert self.auth_manager.verify_password(password, hashed)
        assert not self.auth_manager.verify_password("wrong_password", hashed)

    def test_token_creation_and_verification(self):
        """Test JWT token creation and verification."""
        token = self.auth_manager.create_access_token(self.test_user)

        assert token.access_token is not None
        assert token.token_type == "bearer"
        assert token.expires_in > 0

        # Verify token
        token_data = self.auth_manager.verify_token(token.access_token)

        assert token_data is not None
        assert token_data.sub == self.test_user.id
        assert token_data.username == self.test_user.username
        assert token_data.role == self.test_user.role

    def test_invalid_token_verification(self):
        """Test verification of invalid tokens."""
        invalid_token = "invalid.jwt.token"
        token_data = self.auth_manager.verify_token(invalid_token)

        assert token_data is None

    def test_permission_checking(self):
        """Test RBAC permission checking."""
        # Analyst should have scan permissions
        assert self.auth_manager.has_permission(self.test_user, Permission.SCAN_CREATE)
        assert self.auth_manager.has_permission(self.test_user, Permission.SCAN_READ)
        assert self.auth_manager.has_permission(self.test_user, Permission.REPORT_READ)

        # Analyst should NOT have admin permissions
        assert not self.auth_manager.has_permission(self.test_user, Permission.USER_MANAGE)
        assert not self.auth_manager.has_permission(self.test_user, Permission.PLUGIN_MANAGE)

    def test_authorization_with_multiple_permissions(self):
        """Test authorization with multiple required permissions."""
        required_permissions = [Permission.SCAN_READ, Permission.REPORT_READ]

        assert self.auth_manager.authorize(self.test_user, required_permissions)

        # Should fail if one permission is missing
        required_permissions.append(Permission.USER_MANAGE)
        assert not self.auth_manager.authorize(self.test_user, required_permissions)

    def test_inactive_user_authorization(self):
        """Test that inactive users are denied."""
        inactive_user = User(
            id="inactive-123",
            username="inactiveuser",
            email="inactive@example.com",
            role=Role.ADMIN,  # Even admin
            is_active=False,  # But inactive
            created_at=datetime.now(),
        )

        assert not self.auth_manager.authorize(inactive_user, [Permission.SCAN_READ])
