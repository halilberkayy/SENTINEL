"""
SENTINEL — Red Team Platform
Professional security scanning and red team operations for authorized testing.

Developed by: Halil Berkay Şahin
Version: 6.0.0
License: MIT
"""

import datetime as _datetime

if not hasattr(_datetime, "UTC"):
    _datetime.UTC = _datetime.timezone.utc  # Python 3.10

__version__ = "6.0.0"
__author__ = "Halil Berkay Şahin"
__email__ = "halilberkaysahin@gmail.com"
__license__ = "MIT"

from .core.config import Config
from .core.scanner_engine import ScannerEngine

__all__ = ["ScannerEngine", "Config", "__version__", "__author__", "__email__", "__license__"]
