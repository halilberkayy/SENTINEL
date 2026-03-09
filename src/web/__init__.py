"""
SENTINEL Web UI package.
Provides the FastAPI web dashboard with WebSocket progress reporting.
"""

from .app import app, scan_manager

__all__ = ["app", "scan_manager"]
