"""
Proxy Management utility.
Refactored from root modules/proxy_manager.py
"""

import socket

import aiohttp


class ProxyManager:
    """Advanced proxy management with TOR support and proxy rotation."""

    def __init__(self, proxy_list=None, use_tor=False):
        self.proxy_list = proxy_list or []
        self.use_tor = use_tor
        self.current_proxy_index = 0
        self.failed_proxies = set()
        self.tor_proxy = "socks5://127.0.0.1:9050"

    def check_tor_availability(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(("127.0.0.1", 9050))
            sock.close()
            return result == 0
        except Exception:
            return False

    def get_next_proxy(self) -> str | None:
        if self.use_tor and self.check_tor_availability():
            return self.tor_proxy
        if not self.proxy_list:
            return None
        proxy = self.proxy_list[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
        return proxy

    async def create_session_with_proxy(self, timeout=30):
        proxy_url = self.get_next_proxy()
        timeout_config = aiohttp.ClientTimeout(total=timeout)
        return aiohttp.ClientSession(timeout=timeout_config), proxy_url
