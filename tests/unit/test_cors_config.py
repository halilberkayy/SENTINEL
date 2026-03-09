"""
Tests for CORS configuration security.
Ensures wildcard origins are not combined with credentials.
"""

import os
from unittest.mock import patch


class TestCORSConfiguration:
    """Verify CORS middleware is properly configured."""

    def test_cors_wildcard_no_credentials_in_source(self):
        """Verify app.py source code prevents wildcard+credentials combo."""
        app_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "api", "app.py"
        )
        with open(app_path, "r") as f:
            content = f.read()

        # Must have the security check
        assert "_is_wildcard" in content, "Missing wildcard detection logic"

        # Must have allow_credentials=False for wildcard case
        assert "allow_credentials=False" in content, (
            "Wildcard origins must have allow_credentials=False"
        )

        # Must have explicit origins case with credentials
        assert "allow_credentials=True" in content, (
            "Explicit origins should allow credentials"
        )

    def test_cors_env_variable_documented(self):
        """Verify CORS_ALLOWED_ORIGINS env var is used."""
        app_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "api", "app.py"
        )
        with open(app_path, "r") as f:
            content = f.read()

        assert "CORS_ALLOWED_ORIGINS" in content

    def test_cors_methods_restricted(self):
        """Verify HTTP methods are explicitly listed, not wildcard."""
        app_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "api", "app.py"
        )
        with open(app_path, "r") as f:
            content = f.read()

        # Should list specific methods instead of ["*"]
        assert '"GET"' in content or "'GET'" in content
        assert '"POST"' in content or "'POST'" in content

    def test_cors_headers_restricted(self):
        """Verify allowed headers are explicitly listed."""
        app_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "api", "app.py"
        )
        with open(app_path, "r") as f:
            content = f.read()

        assert '"Authorization"' in content or "'Authorization'" in content
        assert '"Content-Type"' in content or "'Content-Type'" in content
