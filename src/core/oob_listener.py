"""
Out-of-Band (OOB) Callback Listener for blind vulnerability verification.
Manages listeners that receive HTTP/DNS callbacks from blind SSRF, XXE, and OAST payloads.
"""

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)


class OOBListenerManager:
    """
    Manages OOB callback listeners and their interactions.
    Listeners generate unique callback URLs that are injected into scan payloads.
    When a callback is received, it is stored and correlated with active scans.
    """

    def __init__(self, base_url: str = "http://localhost:8000") -> None:
        self.base_url = base_url.rstrip("/")
        self._active_listeners: dict[str, dict[str, Any]] = {}

    def create_listener(
        self,
        campaign_id: str,
        types: list[str] | None = None,
        ttl_hours: int = 24,
    ) -> dict[str, Any]:
        """
        Create a new OOB listener for a campaign.

        Args:
            campaign_id: Campaign to associate the listener with
            types: Listener types (http, dns)
            ttl_hours: Time-to-live in hours before auto-expiry

        Returns:
            Listener details including callback URL and ID
        """
        listener_id = f"oob_{secrets.token_urlsafe(16)}"
        now = datetime.now(timezone.utc)

        listener = {
            "listener_id": listener_id,
            "campaign_id": campaign_id,
            "types": types or ["http"],
            "active": True,
            "created_at": now,
            "expires_at": now + timedelta(hours=ttl_hours),
            "callback_url": f"{self.base_url}/api/v1/oob/callback/{listener_id}",
            "dns_subdomain": f"{listener_id}.oob.sentinel.local" if "dns" in (types or []) else None,
        }

        self._active_listeners[listener_id] = listener

        logger.info(
            "OOB listener created",
            listener_id=listener_id,
            campaign_id=campaign_id,
            types=types,
        )

        return listener

    def get_listener(self, listener_id: str) -> dict[str, Any] | None:
        """Get a listener by ID."""
        listener = self._active_listeners.get(listener_id)
        if listener is None:
            return None

        # Check expiry
        if datetime.now(timezone.utc) > listener["expires_at"]:
            listener["active"] = False

        return listener

    def deactivate_listener(self, listener_id: str) -> bool:
        """Deactivate a listener."""
        listener = self._active_listeners.get(listener_id)
        if listener is None:
            return False

        listener["active"] = False
        logger.info("OOB listener deactivated", listener_id=listener_id)
        return True

    def list_listeners(self, campaign_id: str | None = None) -> list[dict[str, Any]]:
        """List active listeners, optionally filtered by campaign."""
        now = datetime.now(timezone.utc)
        results = []
        for listener in self._active_listeners.values():
            # Auto-expire
            if now > listener["expires_at"]:
                listener["active"] = False

            if campaign_id and listener["campaign_id"] != campaign_id:
                continue

            results.append(listener)

        return results

    def generate_correlation_id(self, listener_id: str, context: str = "") -> str:
        """
        Generate a unique correlation ID for a specific payload/scan.
        This ID is embedded in the callback URL to trace back to the source.
        """
        short_id = secrets.token_urlsafe(8)
        return f"{listener_id}:{short_id}"

    def validate_callback(self, listener_id: str) -> dict[str, Any] | None:
        """
        Validate an incoming callback against active listeners.

        Returns:
            Listener details if valid and active, None otherwise
        """
        listener = self.get_listener(listener_id)
        if listener is None:
            logger.warning("OOB callback for unknown listener", listener_id=listener_id)
            return None

        if not listener["active"]:
            logger.warning("OOB callback for expired/inactive listener", listener_id=listener_id)
            return None

        return listener

    def cleanup_expired(self) -> int:
        """Remove expired listeners. Returns count of removed listeners."""
        now = datetime.now(timezone.utc)
        expired = [
            lid for lid, l in self._active_listeners.items()
            if now > l["expires_at"]
        ]
        for lid in expired:
            del self._active_listeners[lid]

        if expired:
            logger.info(f"Cleaned up {len(expired)} expired OOB listeners")

        return len(expired)


# Module-level singleton
_oob_manager: OOBListenerManager | None = None


def get_oob_manager(base_url: str = "http://localhost:8000") -> OOBListenerManager:
    """Get or create the global OOB listener manager."""
    global _oob_manager
    if _oob_manager is None:
        _oob_manager = OOBListenerManager(base_url=base_url)
    return _oob_manager
