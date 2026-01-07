"""
Enterprise Web Vulnerability Scanner
A professional-grade security scanning tool for educational and authorized testing purposes.

Developed by: Halil Berkay Şahin
Version: 5.0.0
License: MIT
"""

__version__ = "5.0.0"
__author__ = "Halil Berkay Şahin"
__email__ = "halilberkaysahin@gmail.com"
__license__ = "MIT"

from .core.config import Config
from .core.scanner_engine import ScannerEngine

__all__ = ["ScannerEngine", "Config", "__version__", "__author__", "__email__", "__license__"]
