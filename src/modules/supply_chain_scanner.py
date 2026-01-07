"""
Supply Chain Scanner - OWASP A03:2025 Software Supply Chain Failures
Comprehensive detection of supply chain vulnerabilities and compromises.
"""

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

from .base_scanner import BaseScanner


@dataclass
class DependencyInfo:
    """Information about a detected dependency."""

    name: str
    version: str
    source: str
    location: str
    hash: str | None = None
    integrity: str | None = None


class SupplyChainScanner(BaseScanner):
    """
    Comprehensive Supply Chain Security Scanner.

    Covers OWASP A03:2025:
    - CWE-477: Use of Obsolete Function
    - CWE-1104: Use of Unmaintained Third Party Components
    - CWE-1329: Reliance on Component That is Not Updateable
    - CWE-1395: Dependency on Vulnerable Third-Party Component

    Features:
    - JavaScript library detection with CVE matching
    - Package manifest exposure detection
    - SBOM file detection
    - Outdated dependency detection
    - Malicious package indicators
    - CDN integrity verification
    - Lock file exposure
    """

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "Supply Chain Scanner"
        self.description = "Detects software supply chain vulnerabilities"

        # Known vulnerable JavaScript libraries (CVE database sample)
        self.vulnerable_js_libraries = {
            "jquery": {
                "1.": {"cve": "CVE-2020-11022", "severity": "medium", "fixed_in": "3.5.0"},
                "2.": {"cve": "CVE-2020-11023", "severity": "medium", "fixed_in": "3.5.0"},
                "3.0": {"cve": "CVE-2019-11358", "severity": "medium", "fixed_in": "3.4.0"},
                "3.1": {"cve": "CVE-2019-11358", "severity": "medium", "fixed_in": "3.4.0"},
                "3.2": {"cve": "CVE-2019-11358", "severity": "medium", "fixed_in": "3.4.0"},
                "3.3": {"cve": "CVE-2019-11358", "severity": "medium", "fixed_in": "3.4.0"},
            },
            "lodash": {
                "4.17.": {"cve": "CVE-2021-23337", "severity": "high", "fixed_in": "4.17.21"},
                "4.16.": {"cve": "CVE-2020-8203", "severity": "high", "fixed_in": "4.17.19"},
                "4.15.": {"cve": "CVE-2019-10744", "severity": "critical", "fixed_in": "4.17.12"},
            },
            "angular": {
                "1.": {"cve": "CVE-2022-25869", "severity": "medium", "fixed_in": "1.8.3"},
            },
            "vue": {
                "2.": {"cve": "CVE-2024-6783", "severity": "medium", "fixed_in": "2.7.16"},
            },
            "react": {
                "16.": {"cve": "CVE-2020-7774", "severity": "low", "fixed_in": "16.13.0"},
            },
            "bootstrap": {
                "3.": {"cve": "CVE-2019-8331", "severity": "medium", "fixed_in": "3.4.1"},
                "4.0": {"cve": "CVE-2019-8331", "severity": "medium", "fixed_in": "4.3.1"},
                "4.1": {"cve": "CVE-2019-8331", "severity": "medium", "fixed_in": "4.3.1"},
                "4.2": {"cve": "CVE-2019-8331", "severity": "medium", "fixed_in": "4.3.1"},
            },
            "moment": {
                "*": {"cve": "CVE-2022-31129", "severity": "high", "note": "Library is deprecated, use alternatives"}
            },
            "axios": {
                "0.": {"cve": "CVE-2023-45857", "severity": "high", "fixed_in": "1.6.0"},
            },
            "express": {
                "4.17.": {"cve": "CVE-2024-29041", "severity": "medium", "fixed_in": "4.19.2"},
            },
            "handlebars": {
                "4.": {"cve": "CVE-2021-23369", "severity": "critical", "fixed_in": "4.7.7"},
            },
            "marked": {
                "0.": {"cve": "CVE-2022-21680", "severity": "high", "fixed_in": "4.0.10"},
                "1.": {"cve": "CVE-2022-21680", "severity": "high", "fixed_in": "4.0.10"},
                "2.": {"cve": "CVE-2022-21680", "severity": "high", "fixed_in": "4.0.10"},
                "3.": {"cve": "CVE-2022-21680", "severity": "high", "fixed_in": "4.0.10"},
            },
            "socket.io": {
                "2.": {"cve": "CVE-2020-28481", "severity": "medium", "fixed_in": "2.4.0"},
            },
            "dompurify": {
                "2.": {"cve": "CVE-2024-45801", "severity": "high", "fixed_in": "2.5.4"},
            },
        }

        # Package manifest files that should not be exposed
        self.sensitive_files = [
            # JavaScript/Node.js
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "npm-shrinkwrap.json",
            ".npmrc",
            ".yarnrc",
            ".nvmrc",
            # Python
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-prod.txt",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            # Ruby
            "Gemfile",
            "Gemfile.lock",
            ".ruby-version",
            # PHP
            "composer.json",
            "composer.lock",
            # Java/Kotlin
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "gradle.properties",
            # Go
            "go.mod",
            "go.sum",
            # Rust
            "Cargo.toml",
            "Cargo.lock",
            # .NET
            "packages.config",
            "*.csproj",
            "*.fsproj",
            "nuget.config",
            # SBOM Files
            "sbom.json",
            "sbom.xml",
            "bom.json",
            "bom.xml",
            "cyclonedx.json",
            "cyclonedx.xml",
            "spdx.json",
            "spdx.rdf",
            # CI/CD (can reveal dependencies)
            ".github/workflows/*.yml",
            ".gitlab-ci.yml",
            "Jenkinsfile",
            ".travis.yml",
            "azure-pipelines.yml",
            "bitbucket-pipelines.yml",
        ]

        # Paths to check for exposed files
        self.check_paths = [
            "",
            "frontend/",
            "client/",
            "app/",
            "src/",
            "public/",
            "static/",
            "assets/",
            "web/",
            ".well-known/",
        ]

        # Malicious package indicators
        self.malicious_indicators = [
            r"eval\s*\(\s*atob\s*\(",  # Base64 eval
            r"document\.write\s*\(\s*unescape\s*\(",  # Obfuscated write
            r'new\s+Function\s*\(\s*[\'"]',  # Dynamic function creation
            r'\.innerHTML\s*=\s*[\'"][^"\']*<script',  # Script injection
            r'window\[\s*[\'"]eval[\'"]\s*\]',  # Indirect eval
            r'fetch\s*\(\s*[\'"]https?://(?![\w.-]*(?:cdn|unpkg|jsdelivr|cloudflare))',  # Suspicious fetches
        ]

    async def scan(self, url: str, progress_callback=None) -> dict[str, Any]:
        """Main scan method for supply chain vulnerabilities."""
        self.vulnerabilities = []
        self.detected_dependencies: list[DependencyInfo] = []

        try:
            if progress_callback:
                progress_callback(self.name, "starting", 0)

            # 1. Detect JavaScript libraries with vulnerabilities
            await self._scan_javascript_libraries(url)
            if progress_callback:
                progress_callback(self.name, "js_libraries", 20)

            # 2. Check for exposed package manifests
            await self._scan_exposed_manifests(url)
            if progress_callback:
                progress_callback(self.name, "manifests", 40)

            # 3. Verify CDN integrity
            await self._verify_cdn_integrity(url)
            if progress_callback:
                progress_callback(self.name, "cdn_integrity", 60)

            # 4. Check for malicious code patterns
            await self._scan_malicious_patterns(url)
            if progress_callback:
                progress_callback(self.name, "malicious_patterns", 80)

            # 5. Analyze dependency sources
            await self._analyze_dependency_sources(url)
            if progress_callback:
                progress_callback(self.name, "completed", 100)

            return {
                "status": "Completed",
                "details": f"Found {len(self.vulnerabilities)} supply chain issues",
                "vulnerabilities": self.vulnerabilities,
                "dependencies_detected": len(self.detected_dependencies),
                "risk_level": self._calculate_risk_level(),
            }

        except Exception as e:
            return {
                "status": "Error",
                "details": str(e),
                "vulnerabilities": self.vulnerabilities,
                "risk_level": "unknown",
            }

    async def _scan_javascript_libraries(self, url: str):
        """Scan for vulnerable JavaScript libraries."""

        try:
            response = await self.http_client.get(url)
            if not response:
                return

            content = response.text if hasattr(response, "text") else str(response.content)

            # Extract script sources
            script_pattern = r'<script[^>]*src=[\'"]([^\'"]+)[\'"]'
            scripts = re.findall(script_pattern, content, re.IGNORECASE)

            # Also check inline scripts for library references
            inline_pattern = r"<script[^>]*>(.*?)</script>"
            re.findall(inline_pattern, content, re.IGNORECASE | re.DOTALL)

            # Analyze each script
            for script_url in scripts:
                if not script_url.startswith(("http://", "https://")):
                    script_url = urljoin(url, script_url)

                await self._analyze_script_file(script_url)

            # Check for version patterns in page content
            await self._detect_library_versions(content, url)

        except Exception as e:
            logger.debug(f"Error analyzing HTML page for dependencies: {e}")

    async def _analyze_script_file(self, script_url: str):
        """Analyze a JavaScript file for vulnerable libraries."""

        try:
            response = await self.http_client.get(script_url)
            if not response:
                return

            content = response.text if hasattr(response, "text") else str(response.content)

            # Library detection patterns
            version_patterns = {
                "jquery": [
                    r"jQuery\s+v?([\d\.]+)",
                    r"jquery.*?v?([\d\.]+)",
                    r'\$\.fn\.jquery\s*=\s*[\'"]?([\d\.]+)',
                ],
                "lodash": [
                    r"lodash.*?v?([\d\.]+)",
                    r'_\.VERSION\s*=\s*[\'"]?([\d\.]+)',
                ],
                "angular": [
                    r"angular.*?v?([\d\.]+)",
                    r"AngularJS\s+v?([\d\.]+)",
                ],
                "vue": [
                    r"Vue\.js\s+v?([\d\.]+)",
                    r"vue.*?v?([\d\.]+)",
                ],
                "react": [
                    r"React\s+v?([\d\.]+)",
                    r"react\..*?v?([\d\.]+)",
                ],
                "bootstrap": [
                    r"Bootstrap\s+v?([\d\.]+)",
                    r"bootstrap.*?v?([\d\.]+)",
                ],
                "moment": [
                    r"moment\.js\s*v?([\d\.]+)",
                    r"momentjs.*?v?([\d\.]+)",
                ],
                "axios": [
                    r"axios.*?v?([\d\.]+)",
                ],
                "handlebars": [
                    r"Handlebars.*?v?([\d\.]+)",
                ],
            }

            for library, patterns in version_patterns.items():
                for pattern in patterns:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        self._check_vulnerable_version(library, version, script_url)

                        # Store dependency info
                        self.detected_dependencies.append(
                            DependencyInfo(name=library, version=version, source="external_script", location=script_url)
                        )
                        break

        except Exception as e:
            logger.debug(f"Error analyzing script file {script_url}: {e}")

    async def _detect_library_versions(self, content: str, url: str):
        """Detect library versions from page content and comments."""

        # Check for version comments
        comment_patterns = [
            r"<!--.*?(jquery|lodash|angular|vue|react|bootstrap).*?v?([\d\.]+).*?-->",
            r"/\*.*?(jquery|lodash|angular|vue|react|bootstrap).*?v?([\d\.]+).*?\*/",
        ]

        for pattern in comment_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                library, version = match
                self._check_vulnerable_version(library.lower(), version, url)

    def _check_vulnerable_version(self, library: str, version: str, location: str):
        """Check if a library version is known to be vulnerable."""

        if library not in self.vulnerable_js_libraries:
            return

        vulnerabilities = self.vulnerable_js_libraries[library]

        for version_prefix, vuln_info in vulnerabilities.items():
            if version_prefix == "*" or version.startswith(version_prefix):
                self.vulnerabilities.append(
                    {
                        "type": "vulnerable_dependency",
                        "severity": vuln_info.get("severity", "medium"),
                        "title": f"Vulnerable {library.title()} Library Detected",
                        "description": f"{library} version {version} has known vulnerabilities",
                        "library": library,
                        "version": version,
                        "cve": vuln_info.get("cve", "Unknown"),
                        "fixed_in": vuln_info.get("fixed_in", "Latest"),
                        "location": location,
                        "cwe": "CWE-1395",
                        "owasp": "A03:2025 Software Supply Chain Failures",
                        "remediation": f"Upgrade {library} to version {vuln_info.get('fixed_in', 'latest')} or newer",
                    }
                )
                break

    async def _scan_exposed_manifests(self, url: str):
        """Scan for exposed package manifest files."""

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.check_paths:
            for file_pattern in self.sensitive_files:
                # Skip glob patterns for now
                if "*" in file_pattern:
                    continue

                test_url = urljoin(base_url + "/" + path, file_pattern)

                try:
                    response = await self.http_client.get(test_url)

                    if response and response.status_code == 200:
                        content = response.text if hasattr(response, "text") else ""
                        content_type = response.headers.get("Content-Type", "")

                        # Verify it's actually the file (not a 404 page)
                        if self._is_valid_manifest(file_pattern, content, content_type):
                            severity = self._get_manifest_severity(file_pattern)

                            self.vulnerabilities.append(
                                {
                                    "type": "exposed_manifest",
                                    "severity": severity,
                                    "title": f"Exposed Package Manifest: {file_pattern}",
                                    "description": "Package manifest file is publicly accessible",
                                    "url": test_url,
                                    "file": file_pattern,
                                    "cwe": "CWE-538",
                                    "owasp": "A03:2025 Software Supply Chain Failures",
                                    "remediation": "Block access to package manifest files in web server configuration",
                                }
                            )

                            # Parse and analyze dependencies
                            await self._parse_manifest_dependencies(file_pattern, content, test_url)

                except Exception as e:
                    logger.debug(f"Error checking manifest file {file_pattern}: {e}")

    def _is_valid_manifest(self, filename: str, content: str, content_type: str) -> bool:
        """Verify if content is a valid manifest file."""

        if not content or len(content) < 10:
            return False

        # JSON files
        if filename.endswith(".json"):
            try:
                data = json.loads(content)
                # Check for common package.json fields
                if filename == "package.json":
                    return "name" in data or "dependencies" in data or "devDependencies" in data
                return True
            except Exception:
                return False

        # Lock files
        if "lock" in filename.lower():
            return len(content) > 100

        # Requirements files
        if "requirements" in filename.lower():
            return (
                "==" in content
                or ">=" in content
                or any(pkg in content.lower() for pkg in ["django", "flask", "requests", "numpy"])
            )

        # YAML files
        if filename.endswith((".yml", ".yaml")):
            return ":" in content and "html" not in content_type.lower()

        return True

    def _get_manifest_severity(self, filename: str) -> str:
        """Get severity based on manifest type."""

        # Lock files contain exact versions - higher risk
        if "lock" in filename.lower():
            return "high"

        # SBOM files are very sensitive
        if "sbom" in filename.lower() or "bom" in filename.lower():
            return "high"

        # Config files with potential secrets
        if filename in [".npmrc", ".yarnrc", "gradle.properties", "nuget.config"]:
            return "high"

        # Standard dependency files
        if filename in ["package.json", "requirements.txt", "Gemfile", "composer.json"]:
            return "medium"

        return "low"

    async def _parse_manifest_dependencies(self, filename: str, content: str, url: str):
        """Parse dependencies from manifest files."""

        try:
            if filename == "package.json":
                data = json.loads(content)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

                for name, version in deps.items():
                    self.detected_dependencies.append(
                        DependencyInfo(name=name, version=version, source="package.json", location=url)
                    )

            elif "requirements" in filename.lower():
                for line in content.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Parse package==version format
                        if "==" in line:
                            parts = line.split("==")
                            self.detected_dependencies.append(
                                DependencyInfo(
                                    name=parts[0].strip(),
                                    version=parts[1].strip() if len(parts) > 1 else "unknown",
                                    source="requirements.txt",
                                    location=url,
                                )
                            )

        except Exception as e:
            logger.debug(f"Error detecting library versions: {e}")

    async def _verify_cdn_integrity(self, url: str):
        """Verify CDN resources have Subresource Integrity (SRI)."""

        try:
            response = await self.http_client.get(url)
            if not response:
                return

            content = response.text if hasattr(response, "text") else ""

            # Find all script and link tags with external sources
            cdn_patterns = [
                r'<script[^>]*src=[\'"]([^\'"]+)[\'"][^>]*>',
                r'<link[^>]*href=[\'"]([^\'"]+\.(?:css|js))[\'"][^>]*>',
            ]

            cdn_domains = ["cdn", "unpkg", "jsdelivr", "cloudflare", "googleapis", "gstatic", "ajax"]

            for pattern in cdn_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)

                for match in matches:
                    resource_url = match.group(1)
                    full_tag = match.group(0)

                    # Check if it's a CDN resource
                    if any(cdn in resource_url.lower() for cdn in cdn_domains):
                        # Check for integrity attribute
                        if "integrity=" not in full_tag.lower():
                            self.vulnerabilities.append(
                                {
                                    "type": "missing_sri",
                                    "severity": "medium",
                                    "title": "CDN Resource Without Subresource Integrity",
                                    "description": "External resource loaded without SRI hash verification",
                                    "url": url,
                                    "resource": resource_url,
                                    "cwe": "CWE-353",
                                    "owasp": "A03:2025 Software Supply Chain Failures",
                                    "remediation": "Add integrity and crossorigin attributes to external resources",
                                }
                            )

                        # Check for crossorigin attribute
                        if "crossorigin" not in full_tag.lower():
                            # Less severe but still notable
                            logger.debug(f"CDN resource missing crossorigin attribute: {src}")

        except Exception as e:
            logger.debug(f"Error verifying CDN integrity: {e}")

    async def _scan_malicious_patterns(self, url: str):
        """Scan for malicious code patterns in JavaScript."""

        try:
            response = await self.http_client.get(url)
            if not response:
                return

            content = response.text if hasattr(response, "text") else ""

            # Extract inline scripts
            script_pattern = r"<script[^>]*>(.*?)</script>"
            scripts = re.findall(script_pattern, content, re.IGNORECASE | re.DOTALL)

            for script in scripts:
                for indicator in self.malicious_indicators:
                    if re.search(indicator, script, re.IGNORECASE):
                        self.vulnerabilities.append(
                            {
                                "type": "suspicious_code",
                                "severity": "high",
                                "title": "Suspicious Code Pattern Detected",
                                "description": "Potentially malicious code pattern found in inline script",
                                "url": url,
                                "pattern": indicator[:50],
                                "cwe": "CWE-506",
                                "owasp": "A03:2025 Software Supply Chain Failures",
                                "remediation": "Review and audit the suspicious code immediately",
                            }
                        )
                        break

        except Exception as e:
            logger.debug(f"Error scanning for malicious patterns: {e}")

    async def _analyze_dependency_sources(self, url: str):
        """Analyze where dependencies are loaded from."""

        try:
            response = await self.http_client.get(url)
            if not response:
                return

            content = response.text if hasattr(response, "text") else ""

            # Find all external resources
            src_pattern = r'(?:src|href)=[\'"]([^\'"]+)[\'"]'
            sources = re.findall(src_pattern, content, re.IGNORECASE)

            untrusted_domains = set()

            for source in sources:
                if source.startswith(("http://", "https://")):
                    parsed = urlparse(source)
                    domain = parsed.netloc

                    # Check for HTTP (non-HTTPS) CDN resources
                    if source.startswith("http://"):
                        self.vulnerabilities.append(
                            {
                                "type": "insecure_resource",
                                "severity": "medium",
                                "title": "Resource Loaded Over HTTP",
                                "description": "External resource loaded over insecure HTTP connection",
                                "url": url,
                                "resource": source,
                                "cwe": "CWE-319",
                                "owasp": "A03:2025 Software Supply Chain Failures",
                                "remediation": "Load all external resources over HTTPS",
                            }
                        )

                    # Track unique domains
                    untrusted_domains.add(domain)

            # Report on number of external domains
            if len(untrusted_domains) > 10:
                self.vulnerabilities.append(
                    {
                        "type": "excessive_dependencies",
                        "severity": "low",
                        "title": "Many External Dependency Sources",
                        "description": f"Page loads resources from {len(untrusted_domains)} different external domains",
                        "url": url,
                        "domains": list(untrusted_domains)[:10],
                        "cwe": "CWE-1104",
                        "owasp": "A03:2025 Software Supply Chain Failures",
                        "remediation": "Minimize external dependencies and consolidate CDN usage",
                    }
                )

        except Exception as e:
            logger.debug(f"Error analyzing dependency sources: {e}")

    def _calculate_risk_level(self) -> str:
        """Calculate overall risk level."""
        if not self.vulnerabilities:
            return "info"

        severities = [v.get("severity", "info") for v in self.vulnerabilities]

        if "critical" in severities:
            return "critical"
        elif "high" in severities:
            return "high"
        elif "medium" in severities:
            return "medium"
        elif "low" in severities:
            return "low"
        return "info"
