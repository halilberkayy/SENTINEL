"""
Custom exceptions for the vulnerability scanner.
"""

from typing import Any, Dict, Optional


class ScannerException(Exception):
    """
    Base exception for scanner errors.

    All custom exceptions inherit from this class.
    """

    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        self.message = message
        self.context = context or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.context:
            context_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            return f"{self.message} (Context: {context_str})"
        return self.message


class ConfigurationError(ScannerException):
    """
    Configuration related errors.

    Raised when there are issues with configuration files,
    missing required settings, or invalid configuration values.
    """

    pass


class ValidationError(ScannerException):
    """
    Input validation errors.

    Raised when user input or data fails validation checks,
    such as invalid URLs, malformed payloads, or constraint violations.
    """

    pass


class HTTPError(ScannerException):
    """
    HTTP request related errors.

    Raised when HTTP requests fail, timeout, or return unexpected responses.
    Includes connection errors, SSL errors, and HTTP status code errors.
    """

    pass


class ModuleError(ScannerException):
    """
    Module execution errors.

    Raised when a scanner module fails to execute properly,
    encounters runtime errors, or produces invalid results.
    """

    pass


class ReportError(ScannerException):
    """
    Report generation errors.

    Raised when report generation fails, output formatting errors occur,
    or there are issues writing reports to disk.
    """

    pass


class PayloadError(ScannerException):
    """
    Payload related errors.

    Raised when payload generation, encoding, or validation fails,
    or when payloads produce unexpected results during testing.
    """

    pass


class DatabaseError(ScannerException):
    """
    Database operation errors.

    Raised when database operations fail, including connection errors,
    query execution failures, or transaction rollback issues.
    """

    pass


class CacheError(ScannerException):
    """
    Cache operation errors.

    Raised when cache operations fail, including Redis connection errors,
    serialization failures, or cache invalidation issues.
    """

    pass


class AuthenticationError(ScannerException):
    """
    Authentication and authorization errors.

    Raised when authentication fails, tokens are invalid or expired,
    or users lack required permissions.
    """

    pass


class RateLimitError(ScannerException):
    """
    Rate limiting errors.

    Raised when rate limits are exceeded or rate limiting
    configuration is invalid.
    """

    pass
