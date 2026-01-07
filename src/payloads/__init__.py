"""
Payload databases for vulnerability testing.

This package contains payloads for various vulnerability types including
XSS, SQL injection, directory traversal, and other attack vectors.
"""

from .sqli_payloads import SQLIPayloads
from .wordlists import Wordlists
from .xss_payloads import XSSPayloads

__all__ = ["XSSPayloads", "SQLIPayloads", "Wordlists"]
