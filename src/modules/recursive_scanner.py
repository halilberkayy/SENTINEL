# Recursive Scanner Module - Halil Berkay Şahin
import asyncio
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from .base_scanner import BaseScanner


@dataclass
class FoundResource:
    """Represents a discovered resource during recursive scanning."""

    url: str
    resource_type: str  # 'link', 'form', 'script', 'image', 'api'
    method: str = "GET"
    parameters: dict = None
    parent_url: str = ""
    depth: int = 0
    status_code: int = None
    content_type: str = ""
    title: str = ""

    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}


class RecursiveScanner(BaseScanner):
    """Advanced recursive web scanner that discovers links, forms, and endpoints."""

    def __init__(
        self,
        config=None,
        http_client=None,
        base_url: str = None,
        max_depth: int = 3,
        max_pages: int = 100,
        delay: float = 0.5,
        timeout: int = 10,
        follow_external: bool = False,
        proxy_manager=None,
    ):
        """
        Initialize recursive scanner.

        Args:
            config: Scanner configuration object (for ScannerEngine compatibility)
            http_client: HTTP client instance (for ScannerEngine compatibility)
            base_url: Starting URL for scanning
            max_depth: Maximum recursion depth
            max_pages: Maximum number of pages to scan
            delay: Delay between requests
            timeout: Request timeout
            follow_external: Whether to follow external links
            proxy_manager: ProxyManager instance for proxy support
        """
        # ScannerEngine compatibility
        self.config = config
        self.http_client = http_client
        self.name = "RecursiveScanner"
        self.description = "Deep recursive web crawler for endpoint discovery"
        self.version = "1.0.0"

        # Traditional parameters (can be set later via scan method)
        self.base_url = base_url.rstrip("/") if base_url else None
        self.parsed_base = urlparse(base_url) if base_url else None
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.delay = delay
        self.timeout = timeout
        self.follow_external = follow_external
        self.proxy_manager = proxy_manager

        # Tracking sets
        self.visited_urls: set[str] = set()
        self.discovered_resources: list[FoundResource] = []
        self.found_forms: list[dict] = []
        self.found_apis: list[str] = []
        self.found_files: list[str] = []

        # Statistics
        self.stats = {
            "pages_scanned": 0,
            "links_found": 0,
            "forms_found": 0,
            "apis_found": 0,
            "files_found": 0,
            "errors": 0,
            "start_time": 0,
            "end_time": 0,
        }

        # Common file extensions to look for
        self.interesting_extensions = {
            ".php",
            ".asp",
            ".aspx",
            ".jsp",
            ".py",
            ".rb",
            ".pl",
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".zip",
            ".rar",
            ".sql",
            ".db",
            ".bak",
            ".backup",
            ".old",
            ".tmp",
            ".config",
            ".cfg",
            ".ini",
            ".conf",
            ".env",
            ".json",
            ".xml",
            ".csv",
            ".txt",
            ".log",
        }

        # API endpoint patterns
        self.api_patterns = [r"/api/", r"/v\d+/", r"/rest/", r"/graphql", r"\.json$", r"\.xml$", r"/ajax/", r"/rpc/"]

        # Common sensitive directories
        self.sensitive_dirs = {
            "/admin/",
            "/administrator/",
            "/panel/",
            "/dashboard/",
            "/config/",
            "/backup/",
            "/uploads/",
            "/files/",
            "/private/",
            "/internal/",
            "/dev/",
            "/test/",
        }

    async def scan(self, url: str, progress_callback=None) -> dict:
        """
        Start recursive scanning process.

        Args:
            url: URL to scan
            progress_callback: Optional callback for progress updates

        Returns:
            Dictionary containing scan results
        """
        self.base_url = url.rstrip("/")
        self.parsed_base = urlparse(url)
        self.stats["start_time"] = time.time()

        try:
            # Setup session with proxy if available
            session = await self._create_session()

            # Start scanning from base URL
            self._update_progress(progress_callback, 0, "starting")
            await self._scan_url(session, self.base_url, depth=0, progress_callback=progress_callback)
            self._update_progress(progress_callback, 100, "completed")

            await session.close()

        except Exception as e:
            print(f"Scanning error: {e}")
            self.stats["errors"] += 1

        self.stats["end_time"] = time.time()
        return self._generate_report()

    async def _create_session(self) -> aiohttp.ClientSession:
        """Create aiohttp session with proxy support."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

        timeout = aiohttp.ClientTimeout(total=self.timeout)

        if self.proxy_manager:
            return await self.proxy_manager.create_session_with_proxy(timeout=self.timeout, headers=headers)
        else:
            return aiohttp.ClientSession(timeout=timeout, headers=headers, connector=aiohttp.TCPConnector(ssl=False))

    async def _scan_url(
        self, session: aiohttp.ClientSession, url: str, depth: int = 0, parent_url: str = "", progress_callback=None
    ):
        """
        Recursively scan a single URL.

        Args:
            session: aiohttp session
            url: URL to scan
            depth: Current recursion depth
            parent_url: Parent URL that led to this URL
            progress_callback: Progress callback function
        """
        # Check limits
        if depth > self.max_depth or len(self.visited_urls) >= self.max_pages or url in self.visited_urls:
            return

        # Check if we should follow this URL
        if not self._should_follow_url(url):
            return

        self.visited_urls.add(url)

        try:
            # Add delay between requests
            if self.delay > 0:
                await asyncio.sleep(self.delay)

            # Make request
            async with session.get(url) as response:
                self.stats["pages_scanned"] += 1

                # Update progress
                if progress_callback:
                    percentage = int((self.stats["pages_scanned"] / self.max_pages) * 100)
                    self._update_progress(progress_callback, min(percentage, 99), f"Exploring: {url[:30]}...")

                # Create resource entry
                resource = FoundResource(
                    url=url,
                    resource_type="page",
                    status_code=response.status,
                    content_type=response.headers.get("content-type", ""),
                    parent_url=parent_url,
                    depth=depth,
                )

                # Only process HTML content
                content_type = response.headers.get("content-type", "").lower()
                if "text/html" in content_type and response.status == 200:
                    html_content = await response.text()
                    resource.title = self._extract_title(html_content)

                    # Parse HTML and extract resources
                    await self._parse_html(session, url, html_content, depth)

                self.discovered_resources.append(resource)

        except Exception as e:
            print(f"Error scanning {url}: {e}")
            self.stats["errors"] += 1

    def _should_follow_url(self, url: str) -> bool:
        """Determine if we should follow this URL."""
        parsed = urlparse(url)

        # Always follow same domain
        if parsed.netloc == self.parsed_base.netloc:
            return True

        # Follow external links only if enabled
        if self.follow_external and parsed.netloc:
            return True

        # Follow relative URLs
        if not parsed.netloc:
            return True

        return False

    async def _parse_html(self, session: aiohttp.ClientSession, base_url: str, html_content: str, depth: int):
        """Parse HTML content and extract links, forms, and other resources."""
        try:
            soup = BeautifulSoup(html_content, "html.parser")

            # Extract links
            await self._extract_links(session, soup, base_url, depth)

            # Extract forms
            self._extract_forms(soup, base_url)

            # Extract scripts and potential APIs
            self._extract_scripts_and_apis(soup, base_url)

            # Extract interesting files
            self._extract_files(soup, base_url)

            # Extract comments (might contain useful info)
            self._extract_comments(soup, base_url)

        except Exception as e:
            print(f"Error parsing HTML for {base_url}: {e}")

    async def _extract_links(self, session: aiohttp.ClientSession, soup: BeautifulSoup, base_url: str, depth: int):
        """Extract and follow links from HTML."""
        # Find all links
        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(base_url, href)

            # Clean URL (remove fragments)
            parsed = urlparse(full_url)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean_url += f"?{parsed.query}"

            # Check if it's an interesting file
            if any(clean_url.lower().endswith(ext) for ext in self.interesting_extensions):
                self.found_files.append(clean_url)
                self.stats["files_found"] += 1

            # Add to discovered resources
            resource = FoundResource(
                url=clean_url,
                resource_type="link",
                parent_url=base_url,
                depth=depth + 1,
                title=link.get_text(strip=True)[:100],
            )
            self.discovered_resources.append(resource)
            self.stats["links_found"] += 1

            # Recursively scan if within limits
            if depth + 1 <= self.max_depth:
                await self._scan_url(session, clean_url, depth + 1, base_url)

    def _extract_forms(self, soup: BeautifulSoup, base_url: str):
        """Extract forms from HTML."""
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()

            # Build full action URL
            if action:
                action_url = urljoin(base_url, action)
            else:
                action_url = base_url

            # Extract form fields
            fields = []
            for input_tag in form.find_all(["input", "select", "textarea"]):
                field_info = {
                    "name": input_tag.get("name", ""),
                    "type": input_tag.get("type", "text"),
                    "value": input_tag.get("value", ""),
                    "required": input_tag.has_attr("required"),
                }
                fields.append(field_info)

            form_info = {"url": action_url, "method": method, "fields": fields, "parent_url": base_url}

            self.found_forms.append(form_info)
            self.stats["forms_found"] += 1

            # Add as resource
            resource = FoundResource(
                url=action_url,
                resource_type="form",
                method=method,
                parameters={field["name"]: field["value"] for field in fields if field["name"]},
                parent_url=base_url,
            )
            self.discovered_resources.append(resource)

    def _extract_scripts_and_apis(self, soup: BeautifulSoup, base_url: str):
        """Extract script sources and potential API endpoints."""
        # Script sources
        for script in soup.find_all("script", src=True):
            src = script["src"]
            full_url = urljoin(base_url, src)

            # Check if it looks like an API endpoint
            if any(re.search(pattern, full_url) for pattern in self.api_patterns):
                self.found_apis.append(full_url)
                self.stats["apis_found"] += 1

            resource = FoundResource(url=full_url, resource_type="script", parent_url=base_url)
            self.discovered_resources.append(resource)

        # Inline scripts might contain API URLs
        for script in soup.find_all("script", src=False):
            script_content = script.get_text()
            if script_content:
                # Look for URLs in JavaScript
                url_pattern = r'["\']([^"\']*(?:api|ajax|rest|graphql)[^"\']*)["\']'
                matches = re.findall(url_pattern, script_content, re.IGNORECASE)
                for match in matches:
                    if match.startswith("http") or match.startswith("/"):
                        api_url = urljoin(base_url, match)
                        if api_url not in self.found_apis:
                            self.found_apis.append(api_url)
                            self.stats["apis_found"] += 1

    def _extract_files(self, soup: BeautifulSoup, base_url: str):
        """Extract references to interesting files."""
        # Images, stylesheets, etc.
        for tag_name, attr in [("img", "src"), ("link", "href"), ("embed", "src"), ("object", "data")]:
            for tag in soup.find_all(tag_name):
                if tag.get(attr):
                    src = tag[attr]
                    full_url = urljoin(base_url, src)

                    # Check for interesting extensions
                    if any(full_url.lower().endswith(ext) for ext in self.interesting_extensions):
                        if full_url not in self.found_files:
                            self.found_files.append(full_url)
                            self.stats["files_found"] += 1

    def _extract_comments(self, soup: BeautifulSoup, base_url: str):
        """Extract HTML comments that might contain useful information."""
        comments = soup.find_all(string=lambda text: isinstance(text, str) and "<!--" in text)
        for comment in comments:
            # Look for URLs in comments
            url_pattern = r'https?://[^\s<>"\']+|/[^\s<>"\']*'
            matches = re.findall(url_pattern, str(comment))
            for match in matches:
                if match.startswith("http") or match.startswith("/"):
                    comment_url = urljoin(base_url, match)
                    resource = FoundResource(url=comment_url, resource_type="comment_url", parent_url=base_url)
                    self.discovered_resources.append(resource)

    def _extract_title(self, html_content: str) -> str:
        """Extract page title from HTML."""
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            title_tag = soup.find("title")
            return title_tag.get_text(strip=True) if title_tag else ""
        except Exception:
            return ""

    def _generate_report(self) -> dict:
        """Generate comprehensive scan report."""
        scan_duration = self.stats["end_time"] - self.stats["start_time"]

        # Group resources by type
        resources_by_type = defaultdict(list)
        for resource in self.discovered_resources:
            resources_by_type[resource.resource_type].append(resource)

        # Find potentially sensitive URLs
        sensitive_urls = []
        for resource in self.discovered_resources:
            for sensitive_dir in self.sensitive_dirs:
                if sensitive_dir in resource.url.lower():
                    sensitive_urls.append(resource.url)
                    break

        report = {
            "scan_info": {
                "base_url": self.base_url,
                "start_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.stats["start_time"])),
                "duration": f"{scan_duration:.2f} seconds",
                "max_depth": self.max_depth,
                "follow_external": self.follow_external,
            },
            "statistics": self.stats,
            "discovered_resources": {
                "total": len(self.discovered_resources),
                "by_type": {rtype: len(resources) for rtype, resources in resources_by_type.items()},
                "unique_urls": len(self.visited_urls),
            },
            "findings": {
                "forms": self.found_forms,
                "apis": self.found_apis,
                "files": self.found_files,
                "sensitive_urls": sensitive_urls,
            },
            "all_resources": [
                {
                    "url": r.url,
                    "type": r.resource_type,
                    "method": r.method,
                    "status": r.status_code,
                    "title": r.title,
                    "parent": r.parent_url,
                    "depth": r.depth,
                }
                for r in self.discovered_resources
            ],
        }

        return report

    def export_urls_for_further_testing(self) -> dict[str, list[str]]:
        """Export discovered URLs categorized for further security testing."""
        return {
            "pages": [r.url for r in self.discovered_resources if r.resource_type == "page"],
            "forms": [form["url"] for form in self.found_forms],
            "apis": self.found_apis,
            "files": self.found_files,
            "all_urls": list(self.visited_urls),
        }


async def quick_recursive_scan(base_url: str, max_depth: int = 2, max_pages: int = 50, proxy_manager=None) -> dict:
    """
    Quick recursive scan function for easy usage.

    Args:
        base_url: Starting URL
        max_depth: Maximum depth to scan
        max_pages: Maximum pages to scan
        proxy_manager: Optional ProxyManager instance

    Returns:
        Scan results dictionary
    """
    scanner = RecursiveScanner(
        base_url=base_url, max_depth=max_depth, max_pages=max_pages, delay=0.3, proxy_manager=proxy_manager
    )

    return await scanner.scan()
