"""
Configuration management for the vulnerability scanner.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .exceptions import ConfigurationError


@dataclass
class NetworkConfig:
    """Network configuration settings."""

    timeout: int = 30
    verify_ssl: bool = True
    max_retries: int = 3
    retry_delay: float = 1.0
    max_redirects: int = 5
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    rate_limit: float = 1.0  # requests per second


@dataclass
class ScannerConfig:
    """Scanner configuration settings."""

    concurrent_requests: int = 10
    max_payloads_per_module: int = 100
    enable_advanced_detection: bool = True
    enable_waf_bypass: bool = False
    enable_false_positive_reduction: bool = True
    scan_depth: int = 3


@dataclass
class OutputConfig:
    """Output configuration settings."""

    format: str = "txt"  # txt, json, html, pdf
    output_dir: str = "output/reports"
    include_timestamps: bool = True
    include_evidence: bool = True
    severity_threshold: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class LoggingConfig:
    """Logging configuration settings."""

    level: str = "INFO"
    file: str = "output/logs/scanner.log"
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


@dataclass
class SecurityConfig:
    """Security configuration settings."""

    enable_ethical_checks: bool = True
    require_consent: bool = True
    blacklisted_domains: list[str] = field(default_factory=list)
    whitelisted_domains: list[str] = field(default_factory=list)
    max_requests_per_domain: int = 1000


class Config:
    """Main configuration class."""

    def __init__(self, config_file: str | None = None):
        """
        Initialize configuration.

        Args:
            config_file: Path to configuration file
        """
        self.config_file = config_file or "config/scanner_config.json"
        self.network = NetworkConfig()
        self.scanner = ScannerConfig()
        self.output = OutputConfig()
        self.logging = LoggingConfig()
        self.security = SecurityConfig()

        self._load_config()
        self._setup_logging()

    def _load_config(self) -> None:
        """Load configuration from file."""
        config_path = Path(self.config_file)

        if config_path.exists():
            try:
                with open(config_path, encoding="utf-8") as f:
                    data = json.load(f)

                # Update configurations from file
                if "network" in data:
                    self._update_network_config(data["network"])
                if "scanner" in data:
                    self._update_scanner_config(data["scanner"])
                if "output" in data:
                    self._update_output_config(data["output"])
                if "logging" in data:
                    self._update_logging_config(data["logging"])
                if "security" in data:
                    self._update_security_config(data["security"])

            except (json.JSONDecodeError, KeyError) as e:
                raise ConfigurationError(f"Invalid configuration file: {e}")
        else:
            # Create default configuration
            self._create_default_config()

    def _update_network_config(self, data: dict[str, Any]) -> None:
        """Update network configuration from data."""
        for key, value in data.items():
            if hasattr(self.network, key):
                setattr(self.network, key, value)

    def _update_scanner_config(self, data: dict[str, Any]) -> None:
        """Update scanner configuration from data."""
        for key, value in data.items():
            if hasattr(self.scanner, key):
                setattr(self.scanner, key, value)

    def _update_output_config(self, data: dict[str, Any]) -> None:
        """Update output configuration from data."""
        for key, value in data.items():
            if hasattr(self.output, key):
                setattr(self.output, key, value)

    def _update_logging_config(self, data: dict[str, Any]) -> None:
        """Update logging configuration from data."""
        for key, value in data.items():
            if hasattr(self.logging, key):
                setattr(self.logging, key, value)

    def _update_security_config(self, data: dict[str, Any]) -> None:
        """Update security configuration from data."""
        for key, value in data.items():
            if hasattr(self.security, key):
                setattr(self.security, key, value)

    def _create_default_config(self) -> None:
        """Create default configuration file."""
        config_path = Path(self.config_file)
        config_path.parent.mkdir(parents=True, exist_ok=True)

        default_config = {
            "network": {
                "timeout": 30,
                "verify_ssl": True,
                "max_retries": 3,
                "retry_delay": 1.0,
                "max_redirects": 5,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "rate_limit": 1.0,
            },
            "scanner": {
                "concurrent_requests": 10,
                "max_payloads_per_module": 100,
                "enable_advanced_detection": True,
                "enable_waf_bypass": False,
                "enable_false_positive_reduction": True,
                "scan_depth": 3,
            },
            "output": {
                "format": "txt",
                "output_dir": "output/reports",
                "include_timestamps": True,
                "include_evidence": True,
                "severity_threshold": "LOW",
            },
            "logging": {
                "level": "INFO",
                "file": "output/logs/scanner.log",
                "max_file_size": 10485760,
                "backup_count": 5,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            },
            "security": {
                "enable_ethical_checks": True,
                "require_consent": True,
                "blacklisted_domains": [],
                "whitelisted_domains": [],
                "max_requests_per_domain": 1000,
            },
        }

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=2, ensure_ascii=False)

    def _setup_logging(self) -> None:
        """Setup logging configuration."""
        log_path = Path(self.logging.file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        logging.basicConfig(
            level=getattr(logging, self.logging.level.upper()),
            format=self.logging.format,
            handlers=[logging.FileHandler(log_path), logging.StreamHandler()],
        )

    def save(self) -> None:
        """Save current configuration to file."""
        config_data = {
            "network": self.network.__dict__,
            "scanner": self.scanner.__dict__,
            "output": self.output.__dict__,
            "logging": self.logging.__dict__,
            "security": self.security.__dict__,
        }

        config_path = Path(self.config_file)
        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)

    def validate_target(self, url: str) -> bool:
        """
        Validate if target is allowed for scanning.

        Args:
            url: Target URL to validate

        Returns:
            True if target is allowed, False otherwise
        """
        from urllib.parse import urlparse

        # Basic URL format validation
        if not url or not url.strip():
            return False

        try:
            parsed = urlparse(url)

            # Check if URL has required components
            if not parsed.scheme or not parsed.netloc:
                return False

            # Check if scheme is supported
            if parsed.scheme not in ["http", "https"]:
                return False

            domain = parsed.netloc

            # Check blacklist
            if domain in self.security.blacklisted_domains:
                return False

            # Check whitelist (if enabled)
            if self.security.whitelisted_domains and domain not in self.security.whitelisted_domains:
                return False

            return True

        except Exception:
            return False
