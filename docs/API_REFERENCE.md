# SENTINEL API Reference

**Version 5.0.0 | OWASP Top 10 2025 Compliant | 48 Modules**

This document provides API reference for the SENTINEL vulnerability scanner.

---

## Table of Contents

1. [Authentication](#authentication)
2. [Base URL](#base-url)
3. [Endpoints](#endpoints)
   - [Modules](#modules)
   - [Scanning](#scanning)
   - [Results](#results)
   - [AI Reports](#ai-reports)
   - [Payloads](#payloads)
   - [Settings](#settings)
4. [WebSocket API](#websocket-api)
5. [External Tools API](#external-tools-api)
6. [Error Handling](#error-handling)
7. [Rate Limiting](#rate-limiting)

---

## Authentication

Currently, the API does not require authentication for local development. For production deployments, implement proper API key or OAuth2 authentication.

## Base URL

```
http://localhost:8000/api
```

---

## Endpoints

### Modules

#### List All Modules

```http
GET /api/modules
```

Returns a list of all available scanning modules.

**Response:**

```json
[
  {
    "id": "xss_scanner",
    "name": "XSSScanner",
    "description": "Detects Cross-Site Scripting vulnerabilities",
    "owasp": "A05:2025"
  },
  {
    "id": "sqli_scanner",
    "name": "SQLIScanner",
    "description": "Detects SQL Injection vulnerabilities",
    "owasp": "A05:2025"
  },
  {
    "id": "supply_chain_scanner",
    "name": "SupplyChainScanner",
    "description": "Detects software supply chain vulnerabilities (OWASP A03:2025)",
    "owasp": "A03:2025"
  },
  {
    "id": "exception_scanner",
    "name": "ExceptionScanner",
    "description": "Detects improper exception handling (OWASP A10:2025)",
    "owasp": "A10:2025"
  }
]
```

---

### Scanning

#### Start Scan

```http
POST /api/scan/start
Content-Type: application/json
```

**Request Body:**

```json
{
  "url": "https://example.com",
  "modules": ["xss_scanner", "sqli_scanner", "api_scanner"]
}
```

**Response:**

```json
{
  "scan_id": "1",
  "target": "https://example.com",
  "status": "running",
  "modules": ["xss_scanner", "sqli_scanner", "api_scanner"]
}
```

#### Get Scan Status

```http
GET /api/scan/{scan_id}/status
```

**Response:**

```json
{
  "scan_id": "1",
  "status": "running",
  "progress": 65,
  "current_module": "sqli_scanner",
  "elapsed_time": "00:02:34"
}
```

#### Stop Scan

```http
POST /api/scan/{scan_id}/stop
```

**Response:**

```json
{
  "scan_id": "1",
  "status": "stopped",
  "message": "Scan stopped successfully"
}
```

---

### Results

#### Get Scan Results

```http
GET /api/results/{scan_id}
```

**Response:**

```json
{
  "scan_id": "1",
  "target": "https://example.com",
  "status": "completed",
  "duration": "00:05:23",
  "summary": {
    "total_vulnerabilities": 12,
    "critical": 2,
    "high": 3,
    "medium": 5,
    "low": 2,
    "info": 0
  },
  "vulnerabilities": [
    {
      "id": "vuln_001",
      "title": "Reflected XSS",
      "severity": "high",
      "type": "xss",
      "url": "https://example.com/search",
      "parameter": "q",
      "evidence": "<script>alert(1)</script>",
      "cwe_id": "CWE-79",
      "remediation": "Implement proper output encoding"
    }
  ]
}
```

#### Export Results

```http
GET /api/results/{scan_id}/export?format={format}
```

**Parameters:**
- `format`: `json`, `html`, `pdf`, `sarif`

**Response:** File download or JSON object.

---

### Scan History

#### Get Scan History

```http
GET /api/scans/history?limit=50
```

Returns recent scan history.

**Query Parameters:**
- `limit`: Maximum number of scans to return (default: 50)

**Response:**

```json
{
  "scans": [
    {
      "scan_id": "1",
      "url": "https://example.com",
      "modules": ["xss_scanner", "sqli_scanner"],
      "vulnerability_count": 5,
      "completed_at": "2026-01-11T02:30:00Z"
    }
  ],
  "count": 1
}
```

#### Get Scan Details

```http
GET /api/scans/{scan_id}
```

Returns detailed information about a specific scan.

**Response:**

```json
{
  "scan_id": "1",
  "url": "https://example.com",
  "modules": ["xss_scanner", "sqli_scanner"],
  "results": [...],
  "vulnerability_count": 5,
  "completed_at": "2026-01-11T02:30:00Z"
}
```

#### Delete Scan

```http
DELETE /api/scans/{scan_id}
```

Deletes a scan from history.

**Response:**

```json
{
  "message": "Scan deleted successfully"
}
```

---

### AI Reports

#### Generate AI Report

```http
POST /api/ai/report
Content-Type: application/json
```

**Request Body:**

```json
{
  "scan_id": "1",
  "report_type": "executive",
  "language": "en"
}
```

**Report Types:**
- `executive`: High-level summary for management
- `technical`: Detailed technical analysis
- `risk`: Risk assessment and prioritization
- `all`: Complete report with all sections

**Languages:**
- `en`: English
- `tr`: Turkish

**Response:**

```json
{
  "success": true,
  "report": {
    "type": "executive",
    "generated_at": "2026-01-05T10:30:00Z",
    "content": "..."
  }
}
```

#### Check AI Status

```http
GET /api/ai/status
```

**Response:**

```json
{
  "ai_configured": true,
  "model": "gemini-2.0-flash",
  "status": "ready"
}
```

---

### Payloads

#### List Payloads

```http
GET /api/payloads
```

**Query Parameters:**
- `category`: Filter by category (XSS, SQLi, RCE, etc.)

**Response:**

```json
[
  {
    "id": "xss_polyglot_context",
    "name": "Context Breaking Polyglot",
    "category": "XSS",
    "risk": "Critical",
    "description": "Polyglot XSS vector",
    "payload": "javascript://%250Aalert(1)",
    "evasion_techniques": ["Context Confusion"]
  }
]
```

#### Get Payload by ID

```http
GET /api/payloads/{payload_id}
```

---

### Settings

#### Get Settings

```http
GET /api/settings
```

**Response:**

```json
{
  "concurrent_requests": 10,
  "timeout": 30,
  "user_agent": "SENTINEL-Scanner/1.0",
  "follow_redirects": true,
  "verify_ssl": false
}
```

#### Update Settings

```http
PUT /api/settings
Content-Type: application/json
```

**Request Body:**

```json
{
  "concurrent_requests": 15,
  "timeout": 45
}
```

---

## WebSocket API

### Connection

```javascript
const socket = new WebSocket('ws://localhost:8000/ws');
```

### Message Types

#### Scan Progress

```json
{
  "type": "progress",
  "scan_id": "1",
  "module": "xss_scanner",
  "progress": 50,
  "message": "Testing parameter 'q'"
}
```

#### Vulnerability Found

```json
{
  "type": "vulnerability",
  "scan_id": "1",
  "vulnerability": {
    "title": "SQL Injection",
    "severity": "critical",
    "url": "https://example.com/api"
  }
}
```

#### Scan Complete

```json
{
  "type": "complete",
  "scan_id": "1",
  "summary": {
    "total": 15,
    "critical": 2,
    "high": 5
  }
}
```

---

## External Tools API

SENTINEL integrates with external security tools (Nmap, Nikto, Gobuster, etc.) for enhanced capabilities.

### Check Available Tools

```http
GET /api/external-tools
```

**Response:**

```json
{
  "tools": {
    "nmap": true,
    "nikto": false,
    "gobuster": true,
    "dirb": false,
    "john": false,
    "hashcat": false
  },
  "available_count": 2,
  "total_count": 6
}
```

### Run Nmap Scan

```http
POST /api/tools/nmap
Content-Type: application/json
```

**Request Body:**

```json
{
  "target": "example.com",
  "profile": "quick"
}
```

**Profiles:** `quick`, `standard`, `comprehensive`, `stealth`, `vuln`

### Run Gobuster Scan

```http
POST /api/tools/gobuster
Content-Type: application/json
```

**Request Body:**

```json
{
  "target": "https://example.com",
  "extensions": "php,asp,aspx,html"
}
```

### Run Nikto Scan

```http
POST /api/tools/nikto
Content-Type: application/json
```

**Request Body:**

```json
{
  "target": "https://example.com"
}
```

### Generate Wordlist

```http
POST /api/tools/wordlist
Content-Type: application/json
```

**Request Body:**

```json
{
  "target": "https://example.com",
  "min_length": 4,
  "max_length": 20
}
```

### List Generated Wordlists

```http
GET /api/tools/wordlists
```

**Response:**

```json
{
  "wordlists": [
    {
      "name": "example.com_wordlist.txt",
      "path": "output/wordlists/example.com_wordlist.txt",
      "size": 12453,
      "lines": 1250
    }
  ]
}
```

### Tool Requirements

| Tool | Installation (macOS) | Installation (Linux) |
|------|---------------------|---------------------|
| nmap | `brew install nmap` | `apt install nmap` |
| nikto | `brew install nikto` | `apt install nikto` |
| gobuster | `brew install gobuster` | `go install github.com/OJ/gobuster/v3@latest` |
| john | `brew install john` | `apt install john` |
| hashcat | `brew install hashcat` | `apt install hashcat` |

---

## Error Handling

### Error Response Format

```json
{
  "error": true,
  "code": "SCAN_FAILED",
  "message": "Scan failed due to connection timeout",
  "details": {
    "url": "https://example.com",
    "reason": "Connection refused"
  }
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `INVALID_URL` | Invalid or malformed URL |
| `SCAN_FAILED` | Scan execution failed |
| `MODULE_NOT_FOUND` | Requested module not found |
| `RATE_LIMITED` | Too many requests |
| `AI_ERROR` | AI report generation failed |
| `EXPORT_FAILED` | Report export failed |

---

## Rate Limiting

Default rate limits:
- 100 requests per minute per IP
- 10 concurrent scans

Rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1609459200
```

---

## Examples

### Python

```python
import requests

# Start a scan
response = requests.post('http://localhost:8000/api/scan/start', json={
    'url': 'https://example.com',
    'modules': ['xss_scanner', 'sqli_scanner']
})
scan_id = response.json()['scan_id']

# Get results
results = requests.get(f'http://localhost:8000/api/results/{scan_id}')
print(results.json())
```

### cURL

```bash
# Start scan
curl -X POST http://localhost:8000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","modules":["xss_scanner"]}'

# Get modules
curl http://localhost:8000/api/modules

# Get payloads
curl http://localhost:8000/api/payloads?category=XSS
```

### JavaScript

```javascript
// Start scan
const response = await fetch('/api/scan/start', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    url: 'https://example.com',
    modules: ['xss_scanner', 'sqli_scanner']
  })
});

const { scan_id } = await response.json();

// Listen for updates via WebSocket
const socket = new WebSocket('ws://localhost:8000/ws');
socket.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Update:', data);
};
```
