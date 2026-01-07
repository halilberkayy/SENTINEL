# SENTINEL Wordlists Collection

**Version 5.0.0 | January 2026**

Comprehensive security scanning wordlist collection, fully integrated with scanner modules.

---

## Directory Structure

```
wordlists/
├── README.md

├── DISCOVERY (Reconnaissance)
│   ├── directories.txt              # Directory/file discovery (700+ lines)
│   ├── web-content-modern.txt       # AI/ML, cloud, modern frameworks
│   ├── api-endpoints.txt            # REST/GraphQL endpoints
│   ├── api-endpoints-modern.txt     # AI/ML, K8s, cloud APIs
│   ├── subdomains.txt               # Common subdomains
│   └── subdomains-modern.txt        # Cloud/AI subdomains

├── INJECTION
│   ├── xss-payloads.txt             # Basic XSS payloads
│   ├── xss-payloads-modern.txt      # WAF bypass, framework bypass
│   ├── sqli-payloads.txt            # Basic SQLi payloads
│   └── sqli-payloads-modern.txt     # NoSQL, GraphQL, ORM injection

├── SENSITIVE (Sensitive Files)
│   ├── backup-files.txt             # Backup file patterns
│   ├── backup-files-modern.txt      # Container, IaC backups
│   └── webshell_signatures.txt      # Webshell detection signatures

├── SECURITY
│   ├── security-headers.txt         # HTTP security headers
│   └── passwords.txt                # Common weak passwords

└── UTILITIES
    └── user-agents.txt              # Browser/Bot user-agents
```

---

## Module Integration

Wordlists are automatically loaded via `BaseScanner._load_wordlist()` method.

| Module | Wordlist | Status |
|--------|----------|---------|
| DirectoryScanner | directories | Integrated |
| SubdomainScanner | subdomains | Integrated |
| WebshellScanner | webshell_signatures | Integrated |
| XSSScanner | xss-payloads | Integrated |
| SQLiScanner | sqli-payloads | Integrated |
| APIScanner | api-endpoints | Integrated |
| BackupScanner | backup-files | Integrated |
| GobusterScanner | directories | Integrated |
| WordlistBuilder | *Dynamic generation* | Integrated |
| HashCracker | passwords | Integrated |

### WordlistBuilder Module

The WordlistBuilder module generates custom wordlists from target URLs:

```bash
# Generate wordlist via CLI
python scanner.py -u https://example.com -m wordlist_builder

# Generated wordlists location
ls output/wordlists/
```

Generated wordlists can be automatically used by GobusterScanner and HashCracker.

---

## File Details

| File | Lines | Size | Description |
|------|-------|------|-------------|
| directories.txt | 700+ | 5.4KB | Web directories and file names |
| web-content-modern.txt | 600+ | 9KB | AI/ML, serverless, modern frameworks |
| api-endpoints.txt | 325 | 2.8KB | REST, GraphQL endpoints |
| api-endpoints-modern.txt | 400+ | 8.4KB | AI/ML, Cloud, K8s APIs |
| subdomains.txt | 270 | 1.6KB | Common subdomain names |
| subdomains-modern.txt | 500+ | 5.2KB | Cloud, AI subdomains |
| xss-payloads.txt | 200 | 5.1KB | Basic XSS payloads |
| xss-payloads-modern.txt | 400+ | 10KB | WAF bypass, framework bypass |
| sqli-payloads.txt | 225 | 5.3KB | Basic SQLi payloads |
| sqli-payloads-modern.txt | 500+ | 10KB | NoSQL, GraphQL, ORM injection |
| backup-files.txt | 300+ | 4KB | Backup file patterns |
| backup-files-modern.txt | 400+ | 6.4KB | Container, IaC backups |
| webshell_signatures.txt | 100+ | 1.3KB | Webshell detection signatures |
| security-headers.txt | 200+ | 4.3KB | HTTP security headers |
| passwords.txt | 265 | 5KB | Weak passwords |
| user-agents.txt | 70 | 8.3KB | User-agent strings |

**Total: 17 files | ~90KB**

---

## Usage

### Automatic Loading in Modules

```python
# Inside module (automatic)
class MyScanner(BaseScanner):
    async def scan(self, url, progress_callback=None):
        # Prefers modern version
        dirs = self._load_wordlist('directories')

        # Basic version only
        dirs = self._load_wordlist('directories', prefer_modern=False)
```

### CLI Scanning

```bash
# Directory discovery
python scanner.py -u https://example.com -m directory

# Subdomain discovery
python scanner.py -u example.com -m subdomain

# XSS testing
python scanner.py -u https://example.com -m xss

# SQL injection testing
python scanner.py -u https://example.com -m sqli
```

---

## 2025/2026 Updates

### Modern Wordlists Include:

- **AI/ML APIs** - OpenAI, Anthropic, Gemini endpoints
- **Cloud Metadata** - AWS/GCP/Azure SSRF targets
- **Kubernetes** - K8s API endpoints
- **WAF Bypass** - Cloudflare, AWS WAF, Akamai techniques
- **Framework Bypass** - React, Vue, Angular XSS
- **NoSQL/GraphQL** - MongoDB, Neo4j, GraphQL injection

---

## Naming Convention

| Format | Description |
|--------|-------------|
| `{category}.txt` | Basic wordlist (used by modules) |
| `{category}-modern.txt` | Extended 2025/2026 wordlist |

---

## Notes

1. **Automatic Integration:** Modules automatically load wordlists
2. **Modern Preference:** `prefer_modern=True` prioritizes updated lists
3. **Fallback:** Minimal fallback list used if file not found
4. **Performance:** Larger lists = longer scan times

---

**SENTINEL Security Scanner**
https://github.com/halilberkayy/SENTINEL
