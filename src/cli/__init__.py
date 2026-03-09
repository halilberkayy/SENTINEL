"""
SENTINEL CLI package.
Provides the command-line interface for the vulnerability scanner.
"""

from .commands import main
from .redteam import campaign, payload, redteam_scan

__all__ = ["main", "campaign", "payload", "redteam_scan"]
