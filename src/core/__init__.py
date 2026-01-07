"""
Core components for the vulnerability scanner.

This package contains the core functionality including configuration,
HTTP client, scanner engine, authentication, CVSS scoring, and exception handling.
"""

from .auth_manager import AuthConfig, AuthManager, AuthType, Session, create_auth_config
from .config import Config, LoggingConfig, NetworkConfig, OutputConfig, ScannerConfig, SecurityConfig
from .cvss import CVSSCalculator, CVSSResult, CVSSVector, get_cvss_for_vulnerability, get_cwe_for_vulnerability
from .exceptions import ConfigurationError, HTTPError, ModuleError, ScannerException, ValidationError
from .http_client import HTTPClient, RateLimiter
from .scanner_engine import ScannerEngine, ScanResult

__all__ = [
    # Configuration
    "Config",
    "NetworkConfig",
    "ScannerConfig",
    "OutputConfig",
    "LoggingConfig",
    "SecurityConfig",
    # HTTP
    "HTTPClient",
    "RateLimiter",
    # Scanner
    "ScannerEngine",
    "ScanResult",
    # CVSS
    "CVSSCalculator",
    "CVSSVector",
    "CVSSResult",
    "get_cvss_for_vulnerability",
    "get_cwe_for_vulnerability",
    # Authentication
    "AuthManager",
    "AuthConfig",
    "AuthType",
    "Session",
    "create_auth_config",
    # Exceptions
    "ScannerException",
    "HTTPError",
    "ConfigurationError",
    "ModuleError",
    "ValidationError",
]
