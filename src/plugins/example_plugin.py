"""
Example custom scan plugin.
This serves as a template for creating new scanner plugins.
"""

from typing import Any

from src.plugins.manager import PluginCapability, PluginInterface


class ExampleScannerPlugin(PluginInterface):
    """Example custom vulnerability scanner plugin."""

    @property
    def name(self) -> str:
        return "example_scanner"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Security Team"

    @property
    def description(self) -> str:
        return "Example scanner plugin demonstrating the plugin architecture"

    async def initialize(self, config: dict[str, Any]) -> None:
        """Initialize the plugin with configuration."""
        self.config = config
        self.timeout = config.get("timeout", 30)
        self.max_requests = config.get("max_requests", 100)
        print(f"{self.name} initialized with config: {config}")

    async def scan(self, target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Perform custom security scan.

        Args:
            target: Target URL
            options: Scan options

        Returns:
            Standardized scan results
        """
        # Custom scan logic: Check for security headers and information disclosure

        results = {
            "status": "completed",
            "target": target,
            "vulnerabilities": [
                {
                    "title": "Example Vulnerability",
                    "type": "custom_check",
                    "severity": "medium",
                    "description": "This is an example vulnerability found by the custom plugin",
                    "evidence": {
                        "url": target,
                        "method": "GET",
                    },
                    "remediation": "Example remediation steps",
                }
            ],
            "scan_metadata": {
                "plugin": self.name,
                "version": self.version,
                "requests_made": 1,
            },
        }

        return results

    def get_capabilities(self) -> list[PluginCapability]:
        """Get plugin capabilities."""
        return [
            PluginCapability(
                name="custom_vulnerability_detection",
                description="Detects custom vulnerabilities specific to this plugin",
                supported_platforms=["web"],
            ),
        ]

    def validate_config(self, config: dict[str, Any]) -> bool:
        """Validate plugin configuration."""
        required_keys = ["timeout"]
        return all(key in config for key in required_keys)

    async def cleanup(self) -> None:
        """Cleanup resources."""
        print(f"{self.name} cleanup complete")
