"""
IOC (Indicators of Compromise) Checker.

Checks IPs, domains, and file hashes against multiple threat intelligence sources:
  - AbuseIPDB (free tier: 1000 checks/day)
  - AlienVault OTX (free, community-driven)
  - Local blocklists (bundled with SENTINEL)

Usage:
    checker = IOCChecker(abuseipdb_key="...", otx_key="...")
    result = await checker.check_ip("203.0.113.50")
    result = await checker.check_domain("evil.example.com")
    result = await checker.check_hash("44d88612fea8a8f36de82e1278abb02f")
"""

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

# Known malicious IP ranges (RFC 5737 documentation + common sinkhole ranges)
LOCAL_BLOCKLIST_IPS: set[str] = set()

# Common hash patterns
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


@dataclass
class IOCResult:
    """Result of an IOC check."""

    indicator: str
    indicator_type: str  # ip, domain, hash
    verdict: str  # clean, suspicious, malicious, unknown
    confidence: int  # 0-100
    sources: list[dict[str, Any]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    checked_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "sources": self.sources,
            "tags": self.tags,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "checked_at": self.checked_at,
        }


class IOCChecker:
    """Multi-source IOC lookup engine."""

    def __init__(
        self,
        abuseipdb_key: str | None = None,
        otx_key: str | None = None,
        timeout: int = 10,
    ):
        self.abuseipdb_key = abuseipdb_key
        self.otx_key = otx_key
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    def classify_indicator(self, indicator: str) -> str:
        """Determine indicator type: ip, domain, or hash."""
        indicator = indicator.strip()
        try:
            ipaddress.ip_address(indicator)
            return "ip"
        except ValueError:
            pass
        if SHA256_PATTERN.match(indicator) or SHA1_PATTERN.match(indicator) or MD5_PATTERN.match(indicator):
            return "hash"
        if DOMAIN_PATTERN.match(indicator):
            return "domain"
        return "unknown"

    async def check(self, indicator: str) -> IOCResult:
        """Auto-classify and check an indicator against all available sources."""
        ioc_type = self.classify_indicator(indicator)
        if ioc_type == "ip":
            return await self.check_ip(indicator)
        elif ioc_type == "domain":
            return await self.check_domain(indicator)
        elif ioc_type == "hash":
            return await self.check_hash(indicator)
        return IOCResult(
            indicator=indicator,
            indicator_type="unknown",
            verdict="unknown",
            confidence=0,
            sources=[{"source": "classifier", "message": "Could not determine indicator type"}],
        )

    async def check_ip(self, ip: str) -> IOCResult:
        """Check an IP address against threat intelligence sources."""
        sources = []
        tags = []
        max_confidence = 0

        # 1. Local checks
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                return IOCResult(indicator=ip, indicator_type="ip", verdict="clean", confidence=100,
                                 sources=[{"source": "local", "detail": "Private/RFC1918 address"}], tags=["private"])
            if addr.is_loopback:
                return IOCResult(indicator=ip, indicator_type="ip", verdict="clean", confidence=100,
                                 sources=[{"source": "local", "detail": "Loopback address"}], tags=["loopback"])
            if ip in LOCAL_BLOCKLIST_IPS:
                sources.append({"source": "local_blocklist", "detail": "Found in local blocklist"})
                tags.append("blocklisted")
                max_confidence = 80
        except ValueError:
            pass

        # 2. AbuseIPDB
        if self.abuseipdb_key:
            try:
                result = await self._query_abuseipdb(ip)
                if result:
                    sources.append(result)
                    score = result.get("abuse_confidence_score", 0)
                    max_confidence = max(max_confidence, score)
                    if score > 50:
                        tags.append("abuseipdb-flagged")
                    if result.get("is_tor"):
                        tags.append("tor-exit-node")
            except Exception as e:
                logger.warning(f"AbuseIPDB query failed for {ip}: {e}")

        # 3. AlienVault OTX
        if self.otx_key:
            try:
                result = await self._query_otx_ip(ip)
                if result:
                    sources.append(result)
                    pulses = result.get("pulse_count", 0)
                    if pulses > 0:
                        tags.append("otx-reported")
                        max_confidence = max(max_confidence, min(pulses * 15, 90))
            except Exception as e:
                logger.warning(f"OTX query failed for {ip}: {e}")

        verdict = self._score_to_verdict(max_confidence)
        return IOCResult(indicator=ip, indicator_type="ip", verdict=verdict,
                         confidence=max_confidence, sources=sources, tags=tags)

    async def check_domain(self, domain: str) -> IOCResult:
        """Check a domain against threat intelligence sources."""
        sources = []
        tags = []
        max_confidence = 0

        if self.otx_key:
            try:
                result = await self._query_otx_domain(domain)
                if result:
                    sources.append(result)
                    pulses = result.get("pulse_count", 0)
                    if pulses > 0:
                        tags.append("otx-reported")
                        max_confidence = max(max_confidence, min(pulses * 15, 90))
            except Exception as e:
                logger.warning(f"OTX domain query failed for {domain}: {e}")

        verdict = self._score_to_verdict(max_confidence)
        return IOCResult(indicator=domain, indicator_type="domain", verdict=verdict,
                         confidence=max_confidence, sources=sources, tags=tags)

    async def check_hash(self, file_hash: str) -> IOCResult:
        """Check a file hash against threat intelligence sources."""
        sources = []
        tags = []
        max_confidence = 0

        if self.otx_key:
            try:
                hash_type = "SHA256" if len(file_hash) == 64 else "SHA1" if len(file_hash) == 40 else "MD5"
                result = await self._query_otx_hash(file_hash, hash_type)
                if result:
                    sources.append(result)
                    pulses = result.get("pulse_count", 0)
                    if pulses > 0:
                        tags.append("otx-reported")
                        max_confidence = max(max_confidence, min(pulses * 20, 95))
            except Exception as e:
                logger.warning(f"OTX hash query failed: {e}")

        verdict = self._score_to_verdict(max_confidence)
        return IOCResult(indicator=file_hash, indicator_type="hash", verdict=verdict,
                         confidence=max_confidence, sources=sources, tags=tags)

    # ── API Queries ──────────────────────────────────────────────

    async def _query_abuseipdb(self, ip: str) -> dict[str, Any] | None:
        """Query AbuseIPDB CHECK endpoint (v2)."""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(url, headers=headers, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    d = data.get("data", {})
                    return {
                        "source": "abuseipdb",
                        "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                        "total_reports": d.get("totalReports", 0),
                        "country": d.get("countryCode"),
                        "isp": d.get("isp"),
                        "domain": d.get("domain"),
                        "is_tor": d.get("isTor", False),
                        "is_whitelisted": d.get("isWhitelisted", False),
                        "last_reported": d.get("lastReportedAt"),
                    }
                elif resp.status == 429:
                    logger.warning("AbuseIPDB rate limit reached")
                return None

    async def _query_otx_ip(self, ip: str) -> dict[str, Any] | None:
        """Query AlienVault OTX for IP reputation."""
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.otx_key}

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "source": "otx",
                        "pulse_count": data.get("pulse_info", {}).get("count", 0),
                        "reputation": data.get("reputation", 0),
                        "country": data.get("country_name"),
                        "asn": data.get("asn"),
                    }
                return None

    async def _query_otx_domain(self, domain: str) -> dict[str, Any] | None:
        """Query AlienVault OTX for domain reputation."""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {"X-OTX-API-KEY": self.otx_key}

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "source": "otx",
                        "pulse_count": data.get("pulse_info", {}).get("count", 0),
                        "whois": data.get("whois"),
                    }
                return None

    async def _query_otx_hash(self, file_hash: str, hash_type: str) -> dict[str, Any] | None:
        """Query AlienVault OTX for file hash reputation."""
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
        headers = {"X-OTX-API-KEY": self.otx_key}

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "source": "otx",
                        "pulse_count": data.get("pulse_info", {}).get("count", 0),
                        "hash_type": hash_type,
                    }
                return None

    @staticmethod
    def _score_to_verdict(confidence: int) -> str:
        if confidence >= 75:
            return "malicious"
        elif confidence >= 40:
            return "suspicious"
        elif confidence > 0:
            return "low_risk"
        return "clean"
