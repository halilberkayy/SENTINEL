"""
Scan state management for the SENTINEL web UI.
"""

import asyncio
import logging
import os
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from src.core.config import Config
from src.core.scanner_engine import ScannerEngine

logger = logging.getLogger(__name__)


class ScanManager:
    """Manages scan state, WebSocket clients, and result storage."""

    def __init__(self) -> None:
        self.active_scans: dict[str, dict[str, Any]] = {}
        self.config = Config()
        self.engine = ScannerEngine(self.config)
        self.connected_clients: list[WebSocket] = []
        self.last_scan_results: dict[str, dict[str, Any]] = {}

        # Initialize persistent storage
        from src.core.scan_repository import get_memory_store

        self.store = get_memory_store()

    async def broadcast(self, data: dict[str, Any]) -> None:
        """Broadcast data to all connected WebSocket clients."""
        disconnected_clients = []
        for client in self.connected_clients:
            try:
                await client.send_json(data)
            except (WebSocketDisconnect, RuntimeError, Exception) as e:
                logger.debug(f"Failed to send data to client: {e}")
                disconnected_clients.append(client)

        for client in disconnected_clients:
            if client in self.connected_clients:
                self.connected_clients.remove(client)

    def save_scan_results(
        self, scan_id: str, url: str, modules: list[str], results: list[dict[str, Any]]
    ) -> None:
        """Save scan results to persistent storage."""
        scan_data = {
            "scan_id": scan_id,
            "url": url,
            "modules": modules,
            "results": results,
            "vulnerability_count": sum(len(r.get("vulnerabilities", [])) for r in results),
            "completed_at": asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0,
        }
        self.store.save_scan(scan_id, scan_data)
        self.last_scan_results[scan_id] = scan_data

    def get_scan_results(self, scan_id: str) -> dict[str, Any] | None:
        """Get scan results from storage."""
        return self.store.get_scan(scan_id) or self.last_scan_results.get(scan_id)

    def get_recent_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent scans."""
        return self.store.get_recent_scans(limit)
