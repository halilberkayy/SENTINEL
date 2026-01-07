# SENTINEL - Enterprise Security Assessment Platform

**Version 5.0.0 | 48 Security Modules | OWASP Top 10 2025 Compliant**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-5.0.0-red.svg)]()

---

## Overview

SENTINEL is an enterprise-grade web vulnerability scanner designed for professional penetration testing. It integrates internal scanning modules with external security tools to provide comprehensive security assessments.

### Key Features

- **48 Active Scanning Modules** - Complete OWASP Top 10 2025 coverage
- **External Tool Integration** - Nmap, Nikto, Gobuster, John the Ripper, Hashcat
- **Custom Wordlist Mining** - Target-specific payload generation
- **Attack Chain Correlation** - Automatic vulnerability linking and impact analysis
- **AI-Powered Reporting** - Technical and executive summaries via Google Gemini

---

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/halilberkayy/SENTINEL.git
cd SENTINEL

# Install external tools (optional)
brew install nmap nikto gobuster john hashcat  # macOS
apt install nmap nikto dirb john hashcat      # Linux

# Install Python dependencies
poetry install

# Start web interface
python web_app.py

# Access at http://localhost:8000
```

### CLI Usage

```bash
# Comprehensive scan
poetry run scanner -u https://example.com --modules all

# External tools only
poetry run scanner -u https://example.com -m nmap_scanner,nikto_scanner,gobuster_scanner

# Fast reconnaissance
poetry run scanner -u https://example.com -m recon_scanner,port_scanner,directory_scanner
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | Production deployment instructions |
| [docs/EXTERNAL_TOOLS.md](docs/EXTERNAL_TOOLS.md) | External tool integration guide |
| [docs/API_REFERENCE.md](docs/API_REFERENCE.md) | REST API documentation |
| [docs/PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md) | Plugin development guide |

---

## OWASP 2025 Coverage

| Category | OWASP ID | Modules |
|----------|----------|---------|
| Broken Access Control | A01 | broken_access_control, auth_scanner, jwt_scanner, cors_scanner |
| Security Misconfiguration | A02 | security_misconfig, headers_scanner, cloud_scanner, robots_txt |
| Supply Chain Failures | A03 | supply_chain_scanner, dependency_scanner, js_secrets_scanner |
| Cryptographic Failures | A04 | jwt_scanner, headers_scanner, security_misconfig |
| Injection | A05 | sqli_scanner, xss_scanner, command_injection, xxe_scanner, ssti_scanner |
| Insecure Design | A06 | api_scanner, graphql_scanner, websocket_scanner |
| Authentication Failures | A07 | auth_scanner, jwt_scanner, csrf_scanner |
| Integrity Failures | A08 | deserialization_scanner, proto_pollution |
| Logging Failures | A09 | logging_scanner |
| Exception Handling | A10 | exception_scanner |

---

## Scanning Modules

### Critical Risk

| Module | Description |
|--------|-------------|
| XSS Scanner | Cross-Site Scripting detection with 200+ payloads |
| SQL Injection | Database fingerprinting and injection testing |
| Command Injection | OS command and SSTI detection |
| LFI/RFI Scanner | File inclusion vulnerabilities |
| Webshell Scanner | Backdoor detection |
| XXE Scanner | XML External Entity attacks |
| SSTI Scanner | Template injection (Jinja2, Twig, Freemarker) |
| Deserialization | Insecure deserialization (Java, PHP, Python, .NET) |

### High Risk

| Module | Description |
|--------|-------------|
| SSRF Scanner | Server-Side Request Forgery |
| Auth Security | Authentication audits |
| API Security | REST/GraphQL security |
| JWT Scanner | JWT configuration audits |
| BAC Scanner | Broken Access Control |
| Proto Pollution | JavaScript Prototype Pollution |
| Cloud Security | Cloud configuration audits |
| GraphQL Scanner | GraphQL-specific attacks |
| Race Condition | TOCTOU and parallel attacks |

### Medium Risk

| Module | Description |
|--------|-------------|
| CSRF Scanner | Cross-Site Request Forgery |
| CORS Scanner | CORS misconfiguration |
| Open Redirect | Unvalidated redirects |
| Directory Brute | Path enumeration |

### Reconnaissance

| Module | Description |
|--------|-------------|
| Security Headers | HTTP header analysis |
| Subdomain Enum | Subdomain discovery |
| security.txt | RFC 9116 compliance |
| robots.txt Audit | Crawl path analysis |
| Recon Scanner | Fingerprinting |
| JS Secrets | Hardcoded credentials |
| Port Scanner | Network discovery |
| Supply Chain | Dependency audit |
| Exception Scan | Error handling audit |

### External Tools

| Module | Tool | Description |
|--------|------|-------------|
| Nmap Scanner | nmap | Network discovery and service mapping |
| Gobuster Scan | gobuster | Directory brute-forcing |
| Nikto Scanner | nikto | Web server vulnerability audit |
| Hash Cracker | john/hashcat | Hash detection and cracking |

Note: External tools require manual installation.

---

## Architecture

### Project Structure

```
SENTINEL/
├── src/
│   ├── api/              # FastAPI REST API
│   ├── core/             # Engine, Config, Auth, Database
│   ├── modules/          # Scanning modules (48 total)
│   ├── plugins/          # Plugin system
│   ├── payloads/         # Vulnerability payloads
│   ├── reporting/        # Report formatters
│   └── utils/            # Utilities
├── tests/                # Unit and integration tests
├── wordlists/            # Built-in dictionaries
├── config/               # Configuration files
├── scanner.py            # CLI interface
└── web_app.py            # Web dashboard
```

### Technology Stack

- **Backend:** FastAPI (Python 3.11+, Async)
- **Database:** PostgreSQL with SQLAlchemy
- **Cache:** Redis + Celery
- **AI Analysis:** Google Gemini (optional)
- **CI/CD:** GitHub Actions

---

## System Requirements

- **Python:** 3.10+
- **RAM:** 4GB minimum, 8GB recommended
- **Docker:** Optional, recommended for production
- **External Tools:** Nmap, Nikto, Gobuster (optional)

---

## Testing

```bash
# Run all tests
pytest tests/unit/

# Run with coverage
pytest --cov=src --cov-report=term-missing
```

---

## Output Formats

SENTINEL generates reports in multiple formats:

1. **JSON** - API integration
2. **HTML** - Interactive dashboard
3. **Executive Summary** - AI-powered business report
4. **Markdown** - GitHub-friendly
5. **SARIF** - Security tool integration
6. **Nuclei Templates** - Export as Nuclei YAML

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Legal Notice

This tool is intended for authorized security testing and educational purposes only.

**Authorized Use:**
- Penetration testing with written permission
- Security research on systems you own
- Bug bounty programs within defined scope
- Educational and academic purposes

**Prohibited:**
- Unauthorized access to systems or networks
- Malicious or illegal activities

Users are solely responsible for compliance with applicable laws. The author assumes no liability for misuse.

---

## Credits

- OWASP for security research guidelines
- The bug bounty community for payload research

---

**Developed by Halil Berkay Şahin**
