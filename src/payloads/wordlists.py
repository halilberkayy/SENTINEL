"""
Comprehensive directory and file wordlists for brute-force scanning.
"""

"""
Wordlists manager for directory scanning and enumeration.
Provides access to various wordlists for different scanning purposes.
"""

from pathlib import Path
from typing import Any


class Wordlists:
    """Wordlists manager for various scanning purposes."""

    def __init__(self, wordlists_dir: str = "wordlists"):
        """Initialize wordlists manager."""
        self.wordlists_dir = Path(wordlists_dir)
        self._cached_wordlists: dict[str, list[str]] = {}

    def _load_wordlist(self, filename: str) -> list[str]:
        """Load wordlist from file."""
        if filename in self._cached_wordlists:
            return self._cached_wordlists[filename]

        filepath = self.wordlists_dir / filename

        if not filepath.exists():
            # Create default wordlist if file doesn't exist
            default_list = self._get_default_wordlist(filename)
            self._cached_wordlists[filename] = default_list
            return default_list

        try:
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

            self._cached_wordlists[filename] = words
            return words

        except Exception as e:
            print(f"Error loading wordlist {filename}: {e}")
            return self._get_default_wordlist(filename)

    def _get_default_wordlist(self, filename: str) -> list[str]:
        """Get default wordlist based on filename."""
        if "directories" in filename or "dirs" in filename:
            return self._get_default_directories()
        elif "files" in filename:
            return self._get_default_files()
        elif "subdomains" in filename:
            return self._get_default_subdomains()
        elif "passwords" in filename:
            return self._get_default_passwords()
        elif "user_agents" in filename:
            return self._get_default_user_agents()
        else:
            return []

    def _get_default_directories(self) -> list[str]:
        """Get default directory wordlist."""
        return [
            "admin",
            "administrator",
            "backup",
            "backups",
            "bin",
            "blog",
            "cache",
            "cgi-bin",
            "config",
            "css",
            "data",
            "db",
            "debug",
            "dev",
            "docs",
            "download",
            "downloads",
            "files",
            "ftp",
            "home",
            "html",
            "images",
            "img",
            "inc",
            "include",
            "includes",
            "js",
            "lib",
            "library",
            "log",
            "logs",
            "mail",
            "media",
            "modules",
            "news",
            "old",
            "pages",
            "plugins",
            "private",
            "public",
            "script",
            "scripts",
            "search",
            "secure",
            "sql",
            "src",
            "static",
            "stats",
            "system",
            "temp",
            "templates",
            "test",
            "tests",
            "tmp",
            "tools",
            "upload",
            "uploads",
            "user",
            "users",
            "var",
            "web",
            "www",
            "api",
            "assets",
            "application",
            "app",
            "apps",
            "archive",
            "archives",
            "common",
            "content",
            "dashboard",
            "database",
            "demo",
            "development",
            "dist",
            "documentation",
            "examples",
            "forum",
            "forums",
            "gallery",
            "help",
            "install",
            "installation",
            "login",
            "manage",
            "management",
            "old_site",
            "panel",
            "phpmyadmin",
            "portal",
            "setup",
            "site",
            "storage",
            "support",
            "update",
            "utility",
            "vendor",
            "version",
            "webmail",
            "wp-admin",
            "wp-content",
            "wp-includes",
        ]

    def _get_default_files(self) -> list[str]:
        """Get default file wordlist."""
        return [
            "index.html",
            "index.php",
            "index.asp",
            "index.aspx",
            "index.jsp",
            "default.html",
            "default.php",
            "home.html",
            "main.html",
            "readme.txt",
            "README.md",
            "robots.txt",
            "sitemap.xml",
            "config.php",
            "configuration.php",
            "settings.php",
            "database.php",
            "db.php",
            "connect.php",
            "connection.php",
            "admin.php",
            "login.php",
            "logout.php",
            "upload.php",
            "download.php",
            "search.php",
            "test.php",
            "info.php",
            "phpinfo.php",
            "setup.php",
            "install.php",
            "backup.sql",
            "dump.sql",
            "database.sql",
            "db.sql",
            "users.sql",
            "passwd.txt",
            "password.txt",
            "passwords.txt",
            "users.txt",
            "usernames.txt",
            "accounts.txt",
            "access.log",
            "error.log",
            "debug.log",
            "application.log",
            "server.log",
            "web.config",
            "htaccess.txt",
            ".htaccess",
            ".htpasswd",
            "crossdomain.xml",
            "clientaccesspolicy.xml",
            "security.txt",
            "humans.txt",
            "favicon.ico",
            "apple-touch-icon.png",
            "manifest.json",
            "sw.js",
            "serviceworker.js",
            "app.js",
            "main.js",
            "common.js",
            "jquery.js",
            "bootstrap.js",
            "style.css",
            "main.css",
            "common.css",
            "bootstrap.css",
            "admin.css",
            "login.css",
            "theme.css",
            "custom.css",
        ]

    def _get_default_subdomains(self) -> list[str]:
        """Get default subdomain wordlist."""
        return [
            "www",
            "mail",
            "ftp",
            "admin",
            "administrator",
            "test",
            "dev",
            "development",
            "staging",
            "stage",
            "prod",
            "production",
            "api",
            "app",
            "apps",
            "blog",
            "forum",
            "forums",
            "shop",
            "store",
            "news",
            "support",
            "help",
            "docs",
            "documentation",
            "wiki",
            "portal",
            "dashboard",
            "panel",
            "control",
            "manage",
            "management",
            "secure",
            "security",
            "login",
            "auth",
            "authentication",
            "vpn",
            "remote",
            "webmail",
            "email",
            "smtp",
            "pop",
            "imap",
            "exchange",
            "mx",
            "ns",
            "dns",
            "ns1",
            "ns2",
            "ns3",
            "dns1",
            "dns2",
            "web",
            "www1",
            "www2",
            "server",
            "host",
            "cloud",
            "cdn",
            "static",
            "assets",
            "media",
            "images",
            "img",
            "video",
            "videos",
            "download",
            "downloads",
            "files",
            "file",
            "upload",
            "uploads",
            "backup",
            "backups",
            "old",
            "new",
            "beta",
            "alpha",
            "demo",
            "sandbox",
            "lab",
            "labs",
            "research",
            "mobile",
            "m",
            "wap",
            "pda",
            "subdomain",
            "sub",
            "redirect",
            "proxy",
            "cache",
            "load",
            "balance",
            "lb",
            "elb",
            "nlb",
            "alb",
            "origin",
            "edge",
        ]

    def _get_default_passwords(self) -> list[str]:
        """Get default password wordlist."""
        return [
            "password",
            "123456",
            "123456789",
            "qwerty",
            "abc123",
            "password123",
            "admin",
            "administrator",
            "root",
            "toor",
            "pass",
            "passw0rd",
            "p@ssw0rd",
            "p@ssword",
            "secret",
            "login",
            "guest",
            "user",
            "test",
            "demo",
            "welcome",
            "changeme",
            "default",
            "letmein",
            "dragon",
            "monkey",
            "sunshine",
            "iloveyou",
            "princess",
            "football",
            "charlie",
            "aa123456",
            "donald",
            "password1",
            "qwerty123",
            "1234567890",
            "computer",
            "michelle",
            "jessica",
            "pepper",
            "1234",
            "12345",
            "123",
            "master",
            "jordan",
            "superman",
            "harley",
            "1234567",
            "hunter",
            "trustno1",
            "ranger",
            "buster",
            "thomas",
            "robert",
            "soccer",
            "batman",
            "test123",
            "pass123",
            "password!",
            "password@",
            "password#",
            "password$",
            "password%",
            "password^",
            "admin123",
            "admin!",
            "admin@",
            "root123",
            "root!",
            "god",
            "love",
            "sex",
            "money",
            "samsung",
            "jordan23",
        ]

    def _get_default_user_agents(self) -> list[str]:
        """Get default user agent wordlist."""
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0",
            "Mozilla/5.0 (Android 11; Mobile; LG-M255; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.120 Mobile Safari/537.36",
            "curl/7.68.0",
            "wget/1.20.3",
            "python-requests/2.25.1",
            "WebVulnScanner/2.0",
        ]

    def get_directories(self, limit: int | None = None) -> list[str]:
        """Get directory wordlist."""
        dirs = self._load_wordlist("common_directories.txt")
        return dirs[:limit] if limit else dirs

    def get_files(self, limit: int | None = None) -> list[str]:
        """Get file wordlist."""
        files = self._load_wordlist("common_files.txt")
        return files[:limit] if limit else files

    def get_subdomains(self, limit: int | None = None) -> list[str]:
        """Get subdomain wordlist."""
        subs = self._load_wordlist("subdomains.txt")
        return subs[:limit] if limit else subs

    def get_passwords(self, limit: int | None = None) -> list[str]:
        """Get password wordlist."""
        passwords = self._load_wordlist("passwords.txt")
        return passwords[:limit] if limit else passwords

    def get_user_agents(self, limit: int | None = None) -> list[str]:
        """Get user agent wordlist."""
        agents = self._load_wordlist("user_agents.txt")
        return agents[:limit] if limit else agents

    def get_custom_wordlist(self, filename: str, limit: int | None = None) -> list[str]:
        """Get custom wordlist by filename."""
        words = self._load_wordlist(filename)
        return words[:limit] if limit else words

    def search_wordlist(self, wordlist_name: str, keyword: str) -> list[str]:
        """Search for entries containing keyword in wordlist."""
        words = self.get_custom_wordlist(wordlist_name)
        keyword = keyword.lower()
        return [word for word in words if keyword in word.lower()]

    def combine_wordlists(self, *wordlist_names: str) -> list[str]:
        """Combine multiple wordlists."""
        combined = []
        for name in wordlist_names:
            combined.extend(self.get_custom_wordlist(name))
        return list(set(combined))  # Remove duplicates

    def get_wordlist_info(self) -> dict[str, dict[str, Any]]:
        """Get information about available wordlists."""
        info = {}

        for filename in [
            "common_directories.txt",
            "common_files.txt",
            "subdomains.txt",
            "passwords.txt",
            "user_agents.txt",
        ]:
            words = self._load_wordlist(filename)
            info[filename] = {
                "count": len(words),
                "sample": words[:5] if words else [],
                "exists": (self.wordlists_dir / filename).exists(),
            }

        return info
