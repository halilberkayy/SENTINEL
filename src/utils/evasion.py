"""
Anti-Forensics and Evasion utility.
Refactored from root modules/anti_forensics.py
"""

from dataclasses import dataclass
from enum import Enum

import aiohttp


class EvasionLevel(Enum):
    """Evasion sophistication levels."""

    LOW = "Low Evasion"
    MEDIUM = "Medium Evasion"
    HIGH = "High Evasion"
    EXTREME = "Extreme Evasion"


class TrafficProfile(Enum):
    """Traffic behavior profiles."""

    NORMAL_USER = "Normal User"
    POWER_USER = "Power User"
    BOT_CRAWLER = "Bot Crawler"
    SECURITY_SCANNER = "Security Scanner"
    RANDOM_BROWSING = "Random Browsing"


@dataclass
class EvasionConfig:
    """Anti-forensics configuration."""

    evasion_level: EvasionLevel
    traffic_profile: TrafficProfile
    use_tor: bool = True
    use_proxy_chain: bool = True
    randomize_timing: bool = True
    spoof_headers: bool = True
    use_decoy_requests: bool = True
    clear_logs: bool = False


@dataclass
class ProxyChain:
    """Proxy chain configuration."""

    proxies: list[dict[str, str]]
    rotation_interval: int = 300
    max_failures: int = 3
    current_index: int = 0


class AntiForensicsEngine:
    """Advanced anti-forensics and evasion system."""

    def __init__(self, evasion_config: EvasionConfig = None, proxy_manager=None):
        self.config = evasion_config or EvasionConfig(
            evasion_level=EvasionLevel.HIGH, traffic_profile=TrafficProfile.NORMAL_USER
        )
        self.proxy_manager = proxy_manager
        self._init_user_agents()
        self._init_headers_profiles()
        self._init_timing_profiles()
        self._init_tor_configuration()
        self.session_history = []
        self.current_identity = None
        self.proxy_chains = []
        self.session = None

    def _init_user_agents(self):
        self.user_agents = {
            "windows_chrome": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
            ],
            "windows_firefox": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"],
            "mac_safari": [
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
            ],
            "security_tools": ["Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"],
        }

    def _init_headers_profiles(self):
        self.header_profiles = {
            TrafficProfile.NORMAL_USER: {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
            },
            TrafficProfile.SECURITY_SCANNER: {"Accept": "*/*", "Connection": "close", "X-Scanner": "security-audit"},
        }

    def _init_timing_profiles(self):
        self.timing_profiles = {
            EvasionLevel.LOW: {"request_delay": (0.1, 0.5)},
            EvasionLevel.HIGH: {"request_delay": (1.0, 5.0)},
        }

    def _init_tor_configuration(self):
        self.tor_config = {"socks_proxy": "socks5://127.0.0.1:9050"}

    async def initialize_stealth_session(self) -> aiohttp.ClientSession:
        self.current_identity = self._generate_identity()
        headers = self._build_stealth_headers()
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(headers=headers, timeout=timeout)
        return self.session

    def _generate_identity(self) -> dict:
        ua = self.user_agents["windows_chrome"][0]
        return {"user_agent": ua, "platform": "Windows", "do_not_track": "1"}

    def _build_stealth_headers(self) -> dict[str, str]:
        return self.header_profiles[TrafficProfile.NORMAL_USER]

    async def cleanup(self):
        if self.session:
            await self.session.close()


async def create_stealth_session(evasion_level: EvasionLevel = EvasionLevel.HIGH) -> AntiForensicsEngine:
    engine = AntiForensicsEngine(EvasionConfig(evasion_level=evasion_level, traffic_profile=TrafficProfile.NORMAL_USER))
    await engine.initialize_stealth_session()
    return engine
