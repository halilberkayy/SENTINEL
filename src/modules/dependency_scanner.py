"""
Dependency Scanner Module - OWASP A06:2021 Vulnerable Components Detection
Detects outdated libraries, known CVEs, and vulnerable dependencies.
"""

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


@dataclass
class DependencyInfo:
    """Information about a detected dependency."""

    name: str
    version: str
    ecosystem: str  # npm, pypi, maven, composer
    source: str  # where it was detected
    known_vulns: list[dict] = None


class DependencyScanner(BaseScanner):
    """
    Advanced dependency scanner for detecting vulnerable components.

    Capabilities:
    - JavaScript library detection (CDN, inline, package.json)
    - Python requirements detection
    - PHP Composer detection
    - Known CVE matching
    - Outdated version detection
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "DependencyScanner"
        self.description = "Detects vulnerable and outdated dependencies (OWASP A06)"
        self.version = "1.0.0"

        # Known vulnerable library patterns
        self.js_library_patterns = {
            "jquery": {
                "pattern": r"jquery[.-]?([\d.]+)",
                "vulnerable_versions": ["1.x", "2.x", "<3.5.0"],
                "cve": "CVE-2020-11022, CVE-2020-11023",
            },
            "angular": {
                "pattern": r"angular[.-]?([\d.]+)",
                "vulnerable_versions": ["<1.8.0"],
                "cve": "Multiple XSS vulnerabilities",
            },
            "bootstrap": {
                "pattern": r"bootstrap[.-]?([\d.]+)",
                "vulnerable_versions": ["<4.3.1", "<3.4.1"],
                "cve": "CVE-2019-8331 (XSS)",
            },
            "lodash": {
                "pattern": r"lodash[.-]?([\d.]+)",
                "vulnerable_versions": ["<4.17.21"],
                "cve": "CVE-2021-23337 (Command Injection)",
            },
            "moment": {
                "pattern": r"moment[.-]?([\d.]+)",
                "vulnerable_versions": ["<2.29.4"],
                "cve": "CVE-2022-24785 (Path Traversal)",
            },
            "vue": {
                "pattern": r"vue[.-]?([\d.]+)",
                "vulnerable_versions": ["<2.7.14", "<3.2.47"],
                "cve": "Prototype pollution, XSS",
            },
            "react": {"pattern": r"react[.-]?([\d.]+)", "vulnerable_versions": ["<16.13.0"], "cve": "CVE-2020-7919"},
            "axios": {
                "pattern": r"axios[.-]?([\d.]+)",
                "vulnerable_versions": ["<0.21.1"],
                "cve": "CVE-2020-28168 (SSRF)",
            },
            "express": {
                "pattern": r"express[.-]?([\d.]+)",
                "vulnerable_versions": ["<4.17.3"],
                "cve": "CVE-2022-24999",
            },
        }

        # Common exposed config files
        self.config_paths = [
            "/package.json",
            "/package-lock.json",
            "/yarn.lock",
            "/requirements.txt",
            "/Pipfile",
            "/Pipfile.lock",
            "/composer.json",
            "/composer.lock",
            "/Gemfile",
            "/Gemfile.lock",
            "/pom.xml",
            "/build.gradle",
            "/.npmrc",
            "/.env",
            "/bower.json",
        ]

        # Severity mapping
        self.severity_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform dependency vulnerability scan."""
        logger.info(f"Starting dependency scan on {url}")
        vulnerabilities = []
        detected_dependencies = []

        try:
            self._update_progress(progress_callback, 10, "Analyzing page for dependencies")

            # 1. Analyze main page for JavaScript libraries
            page_deps = await self._analyze_page_dependencies(url)
            detected_dependencies.extend(page_deps)

            self._update_progress(progress_callback, 40, "Checking for exposed config files")

            # 2. Check for exposed configuration files
            config_deps = await self._check_exposed_configs(url)
            detected_dependencies.extend(config_deps)

            self._update_progress(progress_callback, 70, "Matching against vulnerability database")

            # 3. Check for known vulnerabilities
            for dep in detected_dependencies:
                vuln = self._check_vulnerability(dep)
                if vuln:
                    vulnerabilities.append(vuln)

            # 4. Check for information disclosure via exposed files
            info_vulns = await self._check_info_disclosure(url)
            vulnerabilities.extend(info_vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(
                status,
                f"Found {len(detected_dependencies)} dependencies, {len(vulnerabilities)} vulnerabilities",
                vulnerabilities,
            )

        except Exception as e:
            logger.exception(f"Dependency scan failed: {e}")
            return self._format_result("Error", f"Scan failed: {e}", [])

    async def _analyze_page_dependencies(self, url: str) -> list[DependencyInfo]:
        """Analyze main page for JavaScript library references."""
        dependencies = []

        try:
            response = await self.http_client.get(url)
            if not response or response.status != 200:
                return dependencies

            content = await response.text()

            # Find script tags with CDN references
            script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
            scripts = re.findall(script_pattern, content, re.IGNORECASE)

            for script_src in scripts:
                for lib_name, lib_info in self.js_library_patterns.items():
                    match = re.search(lib_info["pattern"], script_src, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.groups() else "unknown"
                        dependencies.append(
                            DependencyInfo(name=lib_name, version=version, ecosystem="npm", source=f"CDN: {script_src}")
                        )

            # Check inline version declarations
            for lib_name, lib_info in self.js_library_patterns.items():
                # Look for version comments or declarations
                version_patterns = [
                    rf"{lib_name}.*?v?([\d.]+)",
                    rf"{lib_name}.*?version.*?([\d.]+)",
                ]
                for pattern in version_patterns:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        if not any(d.name == lib_name for d in dependencies):
                            dependencies.append(
                                DependencyInfo(
                                    name=lib_name, version=version, ecosystem="npm", source="Inline detection"
                                )
                            )

        except Exception as e:
            logger.debug(f"Failed to analyze page dependencies: {e}")

        return dependencies

    async def _check_exposed_configs(self, url: str) -> list[DependencyInfo]:
        """Check for exposed dependency configuration files."""
        dependencies = []

        tasks = [self._fetch_config(url, path) for path in self.config_paths]
        results = await self._concurrent_task_runner(tasks, concurrency_limit=5)

        for result in results:
            if result:
                dependencies.extend(result)

        return dependencies

    async def _fetch_config(self, base_url: str, path: str) -> list[DependencyInfo] | None:
        """Fetch and parse a configuration file."""
        try:
            target = urljoin(base_url, path)
            response = await self.http_client.get(target)

            if not response or response.status != 200:
                return None

            content = await response.text()

            # Parse based on file type
            if path.endswith(".json"):
                return self._parse_json_config(content, path)
            elif path.endswith(".txt") or path == "/requirements.txt":
                return self._parse_requirements(content, path)
            elif path.endswith(".lock"):
                return self._parse_lockfile(content, path)
            elif path == "/pom.xml":
                return self._parse_pom(content, path)

        except Exception as e:
            logger.debug(f"Failed to fetch config {path}: {e}")

        return None

    def _parse_json_config(self, content: str, source: str) -> list[DependencyInfo]:
        """Parse JSON configuration files (package.json, composer.json)."""
        dependencies = []

        try:
            data = json.loads(content)

            # NPM package.json
            for dep_type in ["dependencies", "devDependencies", "peerDependencies"]:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        # Clean version string
                        clean_version = re.sub(r"[^0-9.]", "", version)
                        dependencies.append(
                            DependencyInfo(
                                name=name,
                                version=clean_version or version,
                                ecosystem="npm" if "package" in source else "composer",
                                source=source,
                            )
                        )

        except json.JSONDecodeError:
            logger.debug(f"Failed to parse JSON config: {source}")

        return dependencies

    def _parse_requirements(self, content: str, source: str) -> list[DependencyInfo]:
        """Parse Python requirements.txt."""
        dependencies = []

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Parse version specifier
            match = re.match(r"^([a-zA-Z0-9_-]+)([<>=!~]+)?(.*)$", line)
            if match:
                name = match.group(1)
                version = match.group(3) if match.group(3) else "unspecified"
                dependencies.append(DependencyInfo(name=name, version=version.strip(), ecosystem="pypi", source=source))

        return dependencies

    def _parse_lockfile(self, content: str, source: str) -> list[DependencyInfo]:
        """Parse lockfiles for dependencies."""
        dependencies = []

        # Simple pattern matching for common lockfile formats
        patterns = [
            r'"name":\s*"([^"]+)".*?"version":\s*"([^"]+)"',  # JSON style
            r"([a-zA-Z0-9_-]+)\s*\(([\d.]+)\)",  # Gemfile.lock style
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content)
            for name, version in matches[:50]:  # Limit to first 50
                dependencies.append(DependencyInfo(name=name, version=version, ecosystem="mixed", source=source))

        return dependencies

    def _parse_pom(self, content: str, source: str) -> list[DependencyInfo]:
        """Parse Maven pom.xml."""
        dependencies = []

        # Simple regex for Maven dependencies
        dep_pattern = r"<dependency>.*?<groupId>([^<]+)</groupId>.*?<artifactId>([^<]+)</artifactId>.*?<version>([^<]+)</version>.*?</dependency>"
        matches = re.findall(dep_pattern, content, re.DOTALL)

        for group_id, artifact_id, version in matches:
            dependencies.append(
                DependencyInfo(name=f"{group_id}:{artifact_id}", version=version, ecosystem="maven", source=source)
            )

        return dependencies

    def _check_vulnerability(self, dep: DependencyInfo) -> Vulnerability | None:
        """Check if dependency has known vulnerabilities."""

        # Check against known patterns
        lib_info = self.js_library_patterns.get(dep.name.lower())

        if lib_info:
            for vuln_version in lib_info["vulnerable_versions"]:
                if self._version_matches(dep.version, vuln_version):
                    return self._create_vulnerability(
                        title=f"Vulnerable {dep.name} Version Detected",
                        description=f"Outdated {dep.name} version {dep.version} detected. Known vulnerabilities: {lib_info['cve']}",
                        severity="high",
                        type="vulnerable_component",
                        evidence={
                            "library": dep.name,
                            "version": dep.version,
                            "ecosystem": dep.ecosystem,
                            "source": dep.source,
                            "cve": lib_info["cve"],
                        },
                        cwe_id="CWE-1104",
                        remediation=f"Update {dep.name} to the latest stable version.",
                    )

        return None

    def _version_matches(self, version: str, pattern: str) -> bool:
        """Check if version matches vulnerability pattern."""
        if not version or version == "unknown":
            return False

        try:
            # Simple version comparison
            if pattern.startswith("<"):
                target = pattern[1:]
                return self._compare_versions(version, target) < 0
            elif pattern.startswith(">"):
                target = pattern[1:]
                return self._compare_versions(version, target) > 0
            elif ".x" in pattern:
                major = pattern.split(".")[0]
                return version.startswith(major + ".")
            else:
                return version == pattern
        except (ValueError, IndexError):
            return False

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings."""

        def normalize(v):
            return [int(x) for x in re.sub(r"[^0-9.]", "", v).split(".") if x]

        n1, n2 = normalize(v1), normalize(v2)

        for i in range(max(len(n1), len(n2))):
            a = n1[i] if i < len(n1) else 0
            b = n2[i] if i < len(n2) else 0
            if a < b:
                return -1
            elif a > b:
                return 1
        return 0

    async def _check_info_disclosure(self, url: str) -> list[Vulnerability]:
        """Check for sensitive information disclosure via exposed files."""
        vulnerabilities = []

        sensitive_files = [
            ("/package.json", "Package configuration exposed"),
            ("/.env", "Environment file exposed"),
            ("/.npmrc", "NPM configuration exposed"),
            ("/composer.json", "Composer configuration exposed"),
            ("/.git/config", "Git repository exposed"),
        ]

        for path, description in sensitive_files:
            try:
                target = urljoin(url, path)
                response = await self.http_client.get(target)

                if response and response.status == 200:
                    content = await response.text()
                    if len(content) > 10:  # Has content
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title=f"Sensitive File Exposed: {path}",
                                description=f"{description}. This file may contain sensitive dependency information, internal paths, or credentials.",
                                severity="medium",
                                type="info_disclosure",
                                evidence={"url": target, "file": path, "content_preview": content[:200]},
                                cwe_id="CWE-200",
                                remediation=f"Restrict access to {path} or remove it from the web root.",
                            )
                        )
            except Exception as e:
                logger.debug(f"Error checking {path}: {e}")

        return vulnerabilities
