# SENTINEL Plugin Development Guide

**Version 5.0.0 | OWASP Top 10 2025 Compliant | 48 Modules**

This guide explains how to create custom plugins for the SENTINEL vulnerability scanner.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Plugin Architecture](#plugin-architecture)
3. [Creating Your First Plugin](#creating-your-first-plugin)
4. [Plugin Interface](#plugin-interface)
5. [Best Practices](#best-practices)
6. [Testing Plugins](#testing-plugins)
7. [Distribution](#distribution)

---

## Introduction

The SENTINEL plugin system allows you to extend the scanner with custom vulnerability checks, integrations, and reporting capabilities. Plugins are Python modules that follow a defined interface.

### Plugin Capabilities

- **Custom Scanners**: Add new vulnerability detection modules
- **Integrations**: Connect with external tools and services
- **Reporters**: Create custom report formats
- **Processors**: Add pre/post processing steps

---

## Plugin Architecture

```
src/plugins/
├── __init__.py
├── manager.py          # Plugin management
├── interface.py        # Base interfaces
└── examples/
    └── example_plugin.py
```

### Plugin Lifecycle

1. **Discovery**: Plugins are discovered at startup
2. **Validation**: Plugin structure is validated
3. **Loading**: Plugin is imported and instantiated
4. **Initialization**: `initialize()` method is called
5. **Execution**: Plugin methods are called during scans
6. **Cleanup**: `cleanup()` method is called on shutdown

---

## Creating Your First Plugin

### Step 1: Create Plugin File

Create a new Python file in `src/plugins/`:

```python
# src/plugins/my_custom_plugin.py

from .interface import PluginInterface, PluginCapability

class MyCustomPlugin(PluginInterface):
    """Example custom scanner plugin."""
    
    # Plugin metadata
    name = "My Custom Plugin"
    version = "1.0.0"
    author = "Your Name"
    description = "Detects custom vulnerabilities"
    
    # Capabilities this plugin provides
    capabilities = [PluginCapability.SCANNER]
    
    def __init__(self):
        super().__init__()
        self.enabled = True
    
    def initialize(self, config):
        """Initialize the plugin with configuration."""
        self.config = config
        self.logger.info(f"{self.name} initialized")
        return True
    
    async def scan(self, target_url, http_client):
        """Perform custom scan logic."""
        vulnerabilities = []
        
        # Your custom scanning logic here
        response = await http_client.get(target_url)
        
        if self._check_vulnerability(response):
            vulnerabilities.append({
                'title': 'Custom Vulnerability Found',
                'severity': 'medium',
                'description': 'Description of the vulnerability',
                'url': target_url,
                'remediation': 'How to fix this issue'
            })
        
        return vulnerabilities
    
    def _check_vulnerability(self, response):
        """Custom vulnerability check logic."""
        if response and response.status == 200:
            content = response.text
            # Your detection logic
            return 'vulnerable_pattern' in content
        return False
    
    def cleanup(self):
        """Cleanup resources."""
        self.logger.info(f"{self.name} cleaned up")
```

### Step 2: Register Plugin

Plugins are automatically discovered, but you can also manually register:

```python
from src.plugins.manager import PluginManager

manager = PluginManager()
manager.register_plugin(MyCustomPlugin())
```

---

## Plugin Interface

### Base Interface

```python
from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Dict, Any, Optional

class PluginCapability(Enum):
    """Plugin capability types."""
    SCANNER = "scanner"
    REPORTER = "reporter"
    PROCESSOR = "processor"
    INTEGRATION = "integration"

class PluginInterface(ABC):
    """Base interface for all plugins."""
    
    # Required attributes
    name: str = "BasePlugin"
    version: str = "0.0.0"
    author: str = "Unknown"
    description: str = ""
    capabilities: List[PluginCapability] = []
    
    # Optional attributes
    enabled: bool = True
    priority: int = 100  # Lower = higher priority
    
    @abstractmethod
    def initialize(self, config: Dict) -> bool:
        """Initialize the plugin."""
        pass
    
    @abstractmethod
    async def scan(self, target_url: str, http_client) -> List[Dict]:
        """Perform scanning (for SCANNER capability)."""
        pass
    
    def cleanup(self):
        """Optional cleanup method."""
        pass
    
    def get_info(self) -> Dict:
        """Return plugin information."""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'capabilities': [c.value for c in self.capabilities],
            'enabled': self.enabled
        }
```

### Scanner Plugin Methods

For scanner plugins, implement these methods:

```python
async def scan(self, target_url: str, http_client) -> List[Dict]:
    """
    Main scanning method.
    
    Args:
        target_url: The target URL to scan
        http_client: HTTP client for making requests
    
    Returns:
        List of vulnerability dictionaries
    """
    pass

async def pre_scan(self, target_url: str) -> None:
    """Called before scanning starts."""
    pass

async def post_scan(self, results: List[Dict]) -> List[Dict]:
    """Called after scanning, can modify results."""
    return results
```

### Reporter Plugin Methods

For reporter plugins:

```python
def generate_report(self, scan_results: Dict, format: str) -> str:
    """
    Generate a report from scan results.
    
    Args:
        scan_results: Complete scan results dictionary
        format: Report format (html, pdf, json, etc.)
    
    Returns:
        Report content as string
    """
    pass
```

---

## Best Practices

### 1. Error Handling

Always handle exceptions gracefully:

```python
async def scan(self, target_url, http_client):
    try:
        response = await http_client.get(target_url)
        # Process response
    except Exception as e:
        self.logger.error(f"Scan failed: {e}")
        return []
```

### 2. Configuration

Use configuration for customizable settings:

```python
def initialize(self, config):
    self.timeout = config.get('timeout', 30)
    self.max_depth = config.get('max_depth', 3)
    self.custom_patterns = config.get('patterns', [])
    return True
```

### 3. Logging

Use the built-in logger:

```python
import logging

class MyPlugin(PluginInterface):
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(f"plugin.{self.name}")
    
    async def scan(self, target_url, http_client):
        self.logger.info(f"Starting scan on {target_url}")
        self.logger.debug(f"Using timeout: {self.timeout}")
```

### 4. Async/Await

Use async properly for network operations:

```python
import asyncio

async def scan(self, target_url, http_client):
    # Run multiple checks concurrently
    tasks = [
        self._check_endpoint(http_client, f"{target_url}/api"),
        self._check_endpoint(http_client, f"{target_url}/admin"),
        self._check_endpoint(http_client, f"{target_url}/login"),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    vulnerabilities = []
    for result in results:
        if isinstance(result, list):
            vulnerabilities.extend(result)
    
    return vulnerabilities
```

### 5. Resource Management

Clean up resources properly:

```python
def __init__(self):
    self.session = None
    self.cache = {}

def initialize(self, config):
    self.session = aiohttp.ClientSession()
    return True

def cleanup(self):
    if self.session:
        asyncio.run(self.session.close())
    self.cache.clear()
```

---

## Testing Plugins

### Unit Tests

```python
# tests/plugins/test_my_plugin.py

import pytest
from unittest.mock import Mock, AsyncMock
from src.plugins.my_custom_plugin import MyCustomPlugin

class TestMyCustomPlugin:
    
    @pytest.fixture
    def plugin(self):
        plugin = MyCustomPlugin()
        plugin.initialize({})
        return plugin
    
    def test_plugin_info(self, plugin):
        info = plugin.get_info()
        assert info['name'] == "My Custom Plugin"
        assert info['version'] == "1.0.0"
    
    @pytest.mark.asyncio
    async def test_scan_returns_vulnerabilities(self, plugin):
        mock_client = Mock()
        mock_response = Mock()
        mock_response.status = 200
        mock_response.text = "vulnerable_pattern"
        mock_client.get = AsyncMock(return_value=mock_response)
        
        results = await plugin.scan("http://example.com", mock_client)
        
        assert len(results) > 0
        assert results[0]['severity'] == 'medium'
```

### Integration Tests

```python
@pytest.mark.asyncio
async def test_plugin_with_scanner_engine():
    from src.core.scanner_engine import ScannerEngine
    from src.core.config import Config
    from src.plugins.manager import PluginManager
    
    config = Config()
    engine = ScannerEngine(config)
    
    # Register plugin
    plugin_manager = PluginManager()
    plugin_manager.register_plugin(MyCustomPlugin())
    
    # Run scan
    results = await engine.scan("http://testsite.com", ["my_custom_plugin"])
    
    assert results is not None
```

---

## Distribution

### Package Structure

```
my-sentinel-plugin/
├── setup.py
├── README.md
├── LICENSE
├── my_plugin/
│   ├── __init__.py
│   └── plugin.py
└── tests/
    └── test_plugin.py
```

### setup.py

```python
from setuptools import setup, find_packages

setup(
    name="sentinel-my-plugin",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "sentinel-scanner>=1.0.0",
    ],
    entry_points={
        'sentinel.plugins': [
            'my_plugin = my_plugin.plugin:MyCustomPlugin',
        ],
    },
)
```

### Installation

```bash
pip install sentinel-my-plugin
```

Or from source:

```bash
pip install -e ./my-sentinel-plugin
```

---

## Example Plugins

### Rate Limiting Checker

```python
class RateLimitChecker(PluginInterface):
    name = "Rate Limit Checker"
    capabilities = [PluginCapability.SCANNER]
    
    async def scan(self, target_url, http_client):
        vulnerabilities = []
        
        # Send burst of requests
        responses = []
        for i in range(20):
            response = await http_client.get(target_url)
            responses.append(response.status)
            await asyncio.sleep(0.05)
        
        # Check if any were rate limited
        if 429 not in responses:
            vulnerabilities.append({
                'title': 'Missing Rate Limiting',
                'severity': 'medium',
                'description': 'Endpoint does not implement rate limiting'
            })
        
        return vulnerabilities
```

### Custom Header Checker

```python
class SecurityHeaderChecker(PluginInterface):
    name = "Security Header Checker"
    capabilities = [PluginCapability.SCANNER]
    
    REQUIRED_HEADERS = [
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Content-Security-Policy',
        'Strict-Transport-Security'
    ]
    
    async def scan(self, target_url, http_client):
        response = await http_client.get(target_url)
        vulnerabilities = []
        
        for header in self.REQUIRED_HEADERS:
            if header.lower() not in [h.lower() for h in response.headers]:
                vulnerabilities.append({
                    'title': f'Missing Security Header: {header}',
                    'severity': 'low',
                    'description': f'The {header} header is not set'
                })
        
        return vulnerabilities
```

---

## Support

For questions and support:
- GitHub Issues: [Create an issue](https://github.com/yourusername/sentinel-scanner/issues)
- Documentation: [Full documentation](https://docs.sentinel-scanner.dev)
