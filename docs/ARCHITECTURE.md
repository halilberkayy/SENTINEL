# SENTINEL Architecture

## Stack

- **Language**: Python 3.10+
- **API**: FastAPI with async lifespan, hardened CORS, GZip, rate limiting, auth middleware
- **Database**: PostgreSQL (prod) / SQLite (dev) via SQLAlchemy 2.0 async ORM
- **Cache**: Redis with hiredis driver, password-protected
- **Queue**: Celery with Redis broker
- **Auth**: Custom JWT (PyJWT) + bcrypt password hashing + RBAC
- **Observability**: Prometheus metrics (`/metrics`), OpenTelemetry instrumentation, structlog
- **AI**: Google Gemini for report generation (`src/reporting/ai_narrator.py`)

## Directory Structure

```
SENTINEL/
├── src/
│   ├── __init__.py
│   ├── cli/                          # CLI package
│   │   ├── __init__.py
│   │   ├── commands.py               # Click CLI commands
│   │   └── display.py                # Rich display utilities
│   ├── web/                          # Web UI package
│   │   ├── __init__.py
│   │   ├── app.py                    # FastAPI web dashboard, routes, WebSocket
│   │   └── scan_manager.py           # Scan state management, WebSocket broadcasting
│   ├── api/
│   │   ├── app.py                    # FastAPI API, middleware, health checks
│   │   ├── middleware/
│   │   │   ├── auth.py               # JWT authentication middleware
│   │   │   └── rate_limit.py         # Rate limiting + brute-force protection
│   │   ├── schemas/                  # Pydantic request/response schemas
│   │   └── v1/                       # API v1 router
│   ├── core/
│   │   ├── config.py                 # Dataclass-based configuration
│   │   ├── scanner_engine.py         # Orchestrator with lazy module registry
│   │   ├── http_client.py            # Async HTTP client (aiohttp/httpx)
│   │   ├── chain_analyzer.py         # Post-scan attack chain correlation
│   │   ├── cvss.py                   # CVSS v3.1 scoring
│   │   ├── scan_templates.py         # Predefined scan presets
│   │   ├── scan_repository.py        # Scan history persistence
│   │   ├── payload_manager.py        # Payload loading and management
│   │   ├── tamper_engine.py          # Payload tampering/encoding
│   │   ├── distributed_scanner.py    # Celery-based distributed scanning
│   │   ├── celery_app.py             # Celery configuration
│   │   ├── tasks.py                  # Celery task definitions
│   │   ├── exceptions.py             # Custom exception hierarchy
│   │   ├── cache/
│   │   │   └── redis_cache.py        # Redis cache manager
│   │   ├── database/
│   │   │   ├── models.py             # SQLAlchemy models (5 tables)
│   │   │   └── session.py            # Async session factory
│   │   └── security/
│   │       ├── auth.py               # Auth, JWT, RBAC, SecurityHeaders
│   │       └── secrets.py            # Secrets/env management
│   ├── modules/                      # 57 scanning modules (lazy-loaded)
│   │   ├── base_scanner.py           # Abstract base class
│   │   ├── xss_scanner.py            # XSS detection
│   │   ├── sqli_scanner.py           # SQL injection
│   │   ├── stealth_ops_scanner.py    # OPSEC assessment
│   │   ├── post_exploit_scanner.py   # Post-exploitation path simulation
│   │   ├── c2_detection_scanner.py   # C2 indicator detection
│   │   ├── credential_scanner.py     # Credential testing
│   │   ├── ldap_ad_scanner.py        # LDAP/AD assessment
│   │   ├── social_engineering_scanner.py  # Social engineering assessment
│   │   ├── evasion_scanner.py        # IDS/IPS evasion testing
│   │   ├── exfiltration_scanner.py   # Data exfiltration path assessment
│   │   ├── persistence_scanner.py    # Persistence vector assessment
│   │   └── ...                       # 45 more modules
│   ├── payloads/                     # Payload definitions
│   ├── plugins/                      # Plugin system
│   ├── reporting/                    # Formatters (JSON, HTML, TXT, MD, SARIF, AI, MITRE)
│   ├── utils/                        # Utilities (logging, metrics, evasion, fuzzing)
│   └── data/                         # Attack payload library
├── tests/
│   ├── conftest.py
│   ├── test_scanner.py
│   ├── unit/
│   │   ├── test_security_audit.py
│   │   ├── test_scanner_engine.py
│   │   ├── test_rate_limit_middleware.py
│   │   ├── test_cors_config.py
│   │   ├── test_auth.py
│   │   └── ...
│   └── integration/
│       └── system_check.py
├── web/                              # Web dashboard (HTML/JS/CSS)
├── wordlists/                        # Attack dictionaries
├── config/                           # Runtime configuration
├── docker/
│   ├── docker-compose.yml            # Hardened stack orchestration
│   └── prometheus.yml
├── migrations/                       # Alembic database migrations
├── scanner.py                        # CLI entry point (-> src.cli)
├── web_app.py                        # Web UI entry point (-> src.web)
├── gui_scanner.py                    # GUI scanner
├── Dockerfile                        # Multi-stage hardened container
├── .dockerignore
├── action.yml                        # GitHub Actions DAST integration
├── .pre-commit-config.yaml           # Pre-commit hooks (security scanning)
├── Makefile
└── pyproject.toml                    # Poetry config (60% coverage threshold)
```

## Module Loading

Modules are loaded on-demand via `MODULE_REGISTRY` dict + `importlib.import_module`. Only selected modules are instantiated for each scan. `engine.get_module(id)` provides lazy single-module access. `engine.modules` property still works for backward compatibility by eager-loading all modules.

## Scan Execution Flow

1. User starts scan via CLI (`scanner.py` -> `src.cli`), Web UI (`web_app.py` -> `src.web`), or API (`/api/v1/...`)
2. `Config` loads from `config/scanner_config.json`
3. `ScannerEngine` initializes with lazy module registry (no modules loaded yet)
4. Only selected modules are imported and instantiated on-demand
5. `HTTPClient` provides async HTTP with rate limiting, retries, stealth mode
6. Modules run concurrently via adaptive `asyncio.Semaphore`
7. `ChainAnalyzer` correlates findings into attack chains
8. Results exported via formatters (JSON, HTML, MD, SARIF, MITRE ATT&CK) + optional AI narration

## API Endpoints

- `GET /health` -- Health check
- `GET /health/detailed` -- Component-level health (DB, Redis)
- `GET /ready` -- Kubernetes readiness probe
- `GET /metrics` -- Prometheus metrics
- `GET /api/docs` -- Swagger UI
- `GET /api/v1/...` -- v1 API routes

## Middleware Stack

1. Security headers (custom HTTP middleware)
2. AuthMiddleware (JWT validation)
3. RateLimitMiddleware (dual-tier: general 60/min + auth 10/min with brute-force protection)
4. GZipMiddleware (min 1000 bytes)
5. CORSMiddleware (conditional: wildcard vs explicit origins)

## Deployment

- **Docker**: Multi-stage Dockerfile with pinned base image, non-root `scanner` user
- **Docker Compose**: Network segmentation, resource limits, security options
- **GitHub Actions**: `action.yml` with input validation, SHA-pinned actions
- **Pre-commit**: detect-secrets, gitleaks, bandit, hadolint
- **Port**: 8000 (uvicorn)

## Security

| Area | Implementation |
|------|---------------|
| CORS | Conditional wildcard/explicit, no wildcard+credentials |
| Auth | 10 req/min on auth endpoints, progressive lockout (5/10/20 failures) |
| JWT | HS256, short expiry, algorithm enforcement |
| Docker | Pinned images, non-root, read-only FS, no-new-privileges |
| Redis | Password required, dangerous commands disabled |
| PostgreSQL | SCRAM-SHA-256 auth, connection logging |
| Pre-commit | Secret detection, security linting, Dockerfile linting |
| Coverage | 60% minimum threshold |

## Red Team Modules

| Module | Purpose |
|--------|---------|
| Stealth/OPSEC | Proxy detection, UA rotation, timing jitter, TLS fingerprinting |
| Post-Exploitation | Attack path simulation, pivot points, priv-esc paths |
| C2 Detection | Cobalt Strike, Sliver, Mythic detection; DGA analysis; JA3 matching |
| Credential Testing | Default creds, lockout policy, password spray |
| LDAP/AD | LDAP injection, anonymous bind, Kerberoasting, AS-REP roasting |
| Social Engineering | SPF/DKIM/DMARC, typosquatting, metadata leakage |
| IDS/IPS Evasion | WAF fingerprinting, encoding bypass, request smuggling |
| Data Exfiltration | DNS tunneling, covert channels, data exposure |
| Persistence | Web shell vectors, scheduled tasks, backdoor detection |
| MITRE ATT&CK | ATT&CK Navigator layers, kill chain visualization, technique heatmaps |

---

## Red Team Platform Architecture (v6.0.0)

### Overview

SENTINEL v6.0.0 extends the vulnerability scanner into a comprehensive Red Team Platform with campaign management, payload framework, OOB callback infrastructure, threat intelligence, and team collaboration.

### New Directory Structure (additions only)

```
src/
├── api/
│   ├── schemas/
│   │   ├── campaigns.py              # Campaign Pydantic schemas
│   │   ├── payloads.py               # Payload builder schemas
│   │   ├── oob.py                    # OOB interaction schemas
│   │   └── threats.py                # Threat profile schemas
│   └── v1/
│       ├── campaigns.py              # Campaign CRUD + management routes
│       ├── payloads.py               # Payload builder + mutation routes
│       ├── oob.py                    # OOB listener + interaction routes
│       └── threats.py                # Threat profile + attack path routes
├── core/
│   ├── campaign_manager.py           # Campaign lifecycle management
│   ├── payload_builder.py            # Payload encoder/obfuscator chains
│   ├── mutation_engine.py            # Payload mutation + WAF bypass
│   ├── oob_listener.py              # Out-of-band callback listener
│   ├── threat_profiles.py           # APT/threat actor profile library
│   └── database/
│       └── models.py                 # Extended with 7 new tables
└── web/
    ├── templates/
    │   ├── campaigns.html            # Campaign dashboard
    │   ├── campaign_detail.html      # Campaign detail + findings
    │   ├── attack_map.html           # MITRE ATT&CK heatmap
    │   └── attack_chain.html         # Attack chain graph
    └── static/
        ├── js/
        │   ├── campaign.js           # Campaign UI logic
        │   ├── attack_map.js         # ATT&CK navigator heatmap
        │   └── attack_chain.js       # Attack chain graph (D3.js-like)
        └── css/
            └── redteam.css           # Red team UI styles
```

### New Database Models (7 tables)

All new models follow existing patterns: uuid4 PKs, timezone-aware timestamps, Mapped[] type annotations, SQLAlchemy 2.0 async.

#### Campaign

```
Table: campaigns
- id: String(36), PK, uuid4
- name: String(200), NOT NULL, indexed
- description: Text, nullable
- scope: JSON, NOT NULL                  # {"allowed_domains": [...], "allowed_ips": [...], "excluded_paths": [...]}
- objectives: JSON, default=[]           # List of campaign objectives
- phase: Enum(CampaignPhase), default=RECON, indexed
- status: Enum(CampaignStatus), default=ACTIVE, indexed
- mitre_coverage: JSON, default={}       # {"technique_id": {"count": N, "findings": [...]}}
- start_date: DateTime(tz), nullable
- end_date: DateTime(tz), nullable
- created_by: FK -> users.id, NOT NULL
- created_at: DateTime(tz), server_default=now()
- updated_at: DateTime(tz), server_default=now(), onupdate=now()

Relationships:
- targets: 1->N CampaignTarget (cascade delete)
- members: 1->N CampaignMember (cascade delete)
- findings: 1->N Finding (cascade delete)
- oob_interactions: 1->N OOBInteraction (cascade delete)

Enums:
- CampaignPhase: recon, initial_access, execution, persistence, lateral_movement, collection, exfiltration, c2, completed
- CampaignStatus: active, paused, completed, archived
```

#### CampaignTarget

```
Table: campaign_targets
- id: String(36), PK, uuid4
- campaign_id: FK -> campaigns.id (CASCADE), NOT NULL, indexed
- target_url: String(2048), NOT NULL, indexed
- target_type: String(50), default="web"    # web, api, network, host
- status: Enum(TargetStatus), default=PENDING, indexed
- notes: Text, nullable
- scan_job_id: FK -> scan_jobs.id (SET NULL), nullable  # Link to scan when executed
- created_at: DateTime(tz), server_default=now()
- updated_at: DateTime(tz), server_default=now(), onupdate=now()

Enums:
- TargetStatus: pending, scanning, completed, skipped
```

#### CampaignMember

```
Table: campaign_members
- id: String(36), PK, uuid4
- campaign_id: FK -> campaigns.id (CASCADE), NOT NULL, indexed
- user_id: FK -> users.id (CASCADE), NOT NULL, indexed
- role: Enum(MemberRole), default=OPERATOR
- joined_at: DateTime(tz), server_default=now()

Enums:
- MemberRole: lead, operator, observer

Constraint: UNIQUE(campaign_id, user_id)
```

#### Finding

```
Table: findings
- id: String(36), PK, uuid4
- campaign_id: FK -> campaigns.id (CASCADE), NOT NULL, indexed
- campaign_target_id: FK -> campaign_targets.id (SET NULL), nullable, indexed
- vulnerability_id: FK -> vulnerabilities.id (SET NULL), nullable, indexed   # Link to existing vuln if from scan
- title: String(500), NOT NULL, indexed
- description: Text, NOT NULL
- type: String(100), NOT NULL, indexed
- severity: Enum(Severity), NOT NULL, indexed
- status: Enum(FindingStatus), default=OPEN, indexed
- cvss_score: Float, nullable
- cwe_id: String(20), nullable
- evidence: JSON, default={}
- remediation: Text, nullable
- mitre_techniques: JSON, default=[]       # [{"id": "T1190", "name": "...", "tactic": "TA0001"}]
- notes: JSON, default=[]                  # [{"user_id": "...", "text": "...", "created_at": "..."}]
- payload_used: Text, nullable             # Payload that triggered this finding
- oob_interaction_id: FK -> oob_interactions.id (SET NULL), nullable  # Link to OOB hit
- detected_at: DateTime(tz), server_default=now()
- updated_at: DateTime(tz), server_default=now(), onupdate=now()

Enums:
- FindingStatus: open, confirmed, false_positive, remediated, accepted_risk
```

#### OOBInteraction

```
Table: oob_interactions
- id: String(36), PK, uuid4
- campaign_id: FK -> campaigns.id (CASCADE), NOT NULL, indexed
- listener_id: String(100), NOT NULL, indexed    # Unique listener identifier
- interaction_type: String(20), NOT NULL          # http, dns, smtp
- source_ip: String(45), nullable
- source_port: Integer, nullable
- raw_request: Text, nullable                    # Full HTTP request or DNS query
- headers: JSON, default={}
- body: Text, nullable
- dns_query: String(500), nullable               # For DNS callbacks
- correlation_id: String(100), nullable, indexed  # Links back to specific scan/payload
- scan_job_id: FK -> scan_jobs.id (SET NULL), nullable, indexed
- received_at: DateTime(tz), server_default=now()
```

#### PayloadRecord

```
Table: payload_records
- id: String(36), PK, uuid4
- campaign_id: FK -> campaigns.id (CASCADE), nullable, indexed
- name: String(200), NOT NULL
- category: String(50), NOT NULL, indexed         # xss, sqli, ssrf, xxe, etc.
- original_payload: Text, NOT NULL
- encoded_payload: Text, nullable                 # After encoder chain
- encoder_chain: JSON, default=[]                 # ["base64", "url_encode", "random_case"]
- mutations_applied: JSON, default=[]             # ["space_to_comment", "null_byte"]
- target_url: String(2048), nullable
- effectiveness: Enum(PayloadEffectiveness), nullable
- response_code: Integer, nullable
- response_snippet: Text, nullable                # First 500 chars of response
- waf_bypassed: Boolean, default=False
- created_at: DateTime(tz), server_default=now()
- used_at: DateTime(tz), nullable

Enums:
- PayloadEffectiveness: successful, partial, blocked, untested
```

#### ThreatProfile

```
Table: threat_profiles
- id: String(36), PK, uuid4
- name: String(200), NOT NULL, unique, indexed     # e.g., "APT28", "Lazarus Group"
- aliases: JSON, default=[]                        # Alternative names
- description: Text, NOT NULL
- country_origin: String(100), nullable
- motivation: String(100), nullable                # espionage, financial, hacktivism, destruction
- target_sectors: JSON, default=[]                 # ["government", "defense", "finance"]
- active_since: String(10), nullable               # Year string e.g. "2004"
- ttps: JSON, NOT NULL                             # {"tactics": {"TA0001": ["T1190", "T1133"]}, ...}
- tools: JSON, default=[]                          # ["Mimikatz", "Cobalt Strike", "Custom RAT"]
- iocs: JSON, default={}                           # {"domains": [], "ips": [], "hashes": []}
- references: JSON, default=[]                     # URLs to threat intelligence reports
- is_builtin: Boolean, default=False               # True for pre-loaded profiles
- created_at: DateTime(tz), server_default=now()
- updated_at: DateTime(tz), server_default=now(), onupdate=now()
```

### New API Contracts

#### Campaign Management: `/api/v1/campaigns`

| Method | Endpoint | Auth | Body/Params | Response | Description |
|--------|----------|------|-------------|----------|-------------|
| POST | `/campaigns` | Required (scanner+) | `{name, description, scope, objectives, start_date?, end_date?}` | `CampaignResponse` | Create campaign |
| GET | `/campaigns` | Required | `?status=&page=&page_size=` | `[CampaignResponse]` | List campaigns |
| GET | `/campaigns/{id}` | Required | -- | `CampaignDetailResponse` | Get campaign with targets + stats |
| PUT | `/campaigns/{id}` | Required (lead+) | `{name?, description?, scope?, objectives?, status?}` | `CampaignResponse` | Update campaign |
| DELETE | `/campaigns/{id}` | Required (admin) | -- | `204` | Delete campaign |
| PUT | `/campaigns/{id}/phase` | Required (lead+) | `{phase: CampaignPhase}` | `CampaignResponse` | Advance campaign phase |
| POST | `/campaigns/{id}/targets` | Required (operator+) | `{target_url, target_type?, notes?}` | `CampaignTargetResponse` | Add target |
| GET | `/campaigns/{id}/targets` | Required | `?status=` | `[CampaignTargetResponse]` | List targets |
| DELETE | `/campaigns/{id}/targets/{tid}` | Required (operator+) | -- | `204` | Remove target |
| POST | `/campaigns/{id}/targets/{tid}/scan` | Required (operator+) | `{modules: [...]}` | `ScanResponse` | Launch scan against target |
| POST | `/campaigns/{id}/members` | Required (lead) | `{user_id, role}` | `CampaignMemberResponse` | Add team member |
| GET | `/campaigns/{id}/members` | Required | -- | `[CampaignMemberResponse]` | List members |
| DELETE | `/campaigns/{id}/members/{mid}` | Required (lead) | -- | `204` | Remove member |
| GET | `/campaigns/{id}/findings` | Required | `?severity=&status=&type=&page=&page_size=` | `[FindingResponse]` | Aggregated findings |
| POST | `/campaigns/{id}/findings` | Required (operator+) | `{title, description, type, severity, evidence?, mitre_techniques?}` | `FindingResponse` | Manual finding |
| PUT | `/campaigns/{id}/findings/{fid}` | Required (operator+) | `{status?, notes?}` | `FindingResponse` | Update finding status/notes |
| POST | `/campaigns/{id}/findings/{fid}/notes` | Required | `{text}` | `FindingResponse` | Add note to finding |
| GET | `/campaigns/{id}/mitre` | Required | -- | `MITRECoverageResponse` | Campaign MITRE coverage matrix |
| GET | `/campaigns/{id}/report` | Required | `?format=json|html|pdf` | File/JSON | Export campaign report |

**Scope validation**: When launching scans (`/campaigns/{id}/targets/{tid}/scan`), the target URL MUST be validated against the campaign's `scope.allowed_domains` and `scope.allowed_ips`. Reject with `403 Forbidden` if target is out of scope.

**RBAC enforcement**:
- `observer`: read-only access to campaigns they are members of
- `operator`: can add targets, launch scans, add findings, update finding status
- `lead`: can update campaign, manage members, advance phase
- `admin`: full access including delete

#### Payload Builder: `/api/v1/payloads`

| Method | Endpoint | Auth | Body/Params | Response | Description |
|--------|----------|------|-------------|----------|-------------|
| POST | `/payloads/build` | Required (scanner+) | `{payload, encoders: ["base64", "url_encode", ...]}` | `{original, encoded, chain}` | Build encoded payload |
| POST | `/payloads/mutate` | Required (scanner+) | `{payload, mutations: ["random_case", "space_to_comment", ...], count?: 10}` | `{mutations: [{payload, applied}]}` | Generate payload mutations |
| GET | `/payloads/encoders` | Required | -- | `[{name, description}]` | List available encoders |
| GET | `/payloads/mutations` | Required | -- | `[{name, description}]` | List available mutation techniques |
| GET | `/payloads/templates` | Required | `?category=xss|sqli|ssrf|xxe` | `[PayloadTemplate]` | List payload templates |
| POST | `/payloads/track` | Required (scanner+) | `{campaign_id?, payload, target_url, effectiveness, response_code?, waf_bypassed?}` | `PayloadRecordResponse` | Track payload effectiveness |
| GET | `/payloads/effectiveness` | Required | `?campaign_id=&category=` | `[PayloadRecordResponse]` | Query payload effectiveness |

**Encoder chain**: Encoders are applied sequentially. Available encoders:
- `base64` -- Standard base64 encoding
- `hex` -- Hex encoding (\x41 format)
- `url_encode` -- Standard URL encoding
- `double_url_encode` -- Double URL encoding
- `html_entities` -- HTML entity encoding (&#x41; format)
- `unicode` -- Unicode encoding (\u0041 format)
- `utf7` -- UTF-7 encoding
- `random_case` -- Randomize character case

**Mutation techniques** (extends existing `TamperEngine`):
- `random_case`, `url_encode`, `double_url_encode`, `space_to_comment`, `space_to_plus`
- `null_byte_injection`, `between_operator`, `comment_garbage` (existing)
- `concat_split` -- Split strings with concatenation (NEW)
- `char_encoding` -- Use CHAR() functions (NEW)
- `whitespace_variation` -- Tabs, newlines, carriage returns (NEW)
- `case_swap` -- Swap keyword casing patterns (NEW)

#### OOB Callback Listener: `/api/v1/oob`

| Method | Endpoint | Auth | Body/Params | Response | Description |
|--------|----------|------|-------------|----------|-------------|
| POST | `/oob/listeners` | Required (scanner+) | `{campaign_id, types: ["http", "dns"]}` | `{listener_id, callback_url, dns_subdomain}` | Create OOB listener |
| GET | `/oob/listeners` | Required | `?campaign_id=` | `[ListenerResponse]` | List active listeners |
| DELETE | `/oob/listeners/{id}` | Required (scanner+) | -- | `204` | Deactivate listener |
| GET | `/oob/interactions` | Required | `?campaign_id=&listener_id=&type=&since=` | `[OOBInteractionResponse]` | List OOB interactions |
| GET | `/oob/interactions/correlate/{scan_id}` | Required | -- | `[OOBInteractionResponse]` | Correlate OOB hits with scan |
| POST | `/oob/callback/{listener_id}` | Public | Any | `200 OK` | HTTP callback endpoint (receives OOB hits) |

**OOB Architecture**:
1. When a listener is created, SENTINEL generates a unique callback URL: `https://{host}/api/v1/oob/callback/{listener_id}`
2. The listener_id encodes the campaign_id for correlation
3. Scanning modules inject the callback URL into payloads (blind SSRF, blind XXE, OAST)
4. When a callback is received, SENTINEL stores it as an OOBInteraction and correlates it with active scans
5. The correlation_id in the callback URL path allows mapping back to the specific payload/scan that triggered it
6. DNS callbacks use a subdomain pattern: `{correlation_id}.{listener_id}.oob.sentinel.local`

**Security constraints**:
- OOB listeners are only created within campaign scope
- Callback endpoints validate that the listener_id exists and belongs to an active campaign
- Rate limiting on callback endpoint to prevent abuse
- Listeners auto-expire after campaign end_date or 24 hours (configurable)

#### Threat Intelligence: `/api/v1/threats`

| Method | Endpoint | Auth | Body/Params | Response | Description |
|--------|----------|------|-------------|----------|-------------|
| GET | `/threats/profiles` | Required | `?sector=&motivation=&search=` | `[ThreatProfileResponse]` | List threat actor profiles |
| GET | `/threats/profiles/{id}` | Required | -- | `ThreatProfileDetailResponse` | Get profile with full TTPs |
| POST | `/threats/profiles` | Required (admin) | `{name, description, ttps, ...}` | `ThreatProfileResponse` | Create custom profile |
| PUT | `/threats/profiles/{id}` | Required (admin) | `{...fields}` | `ThreatProfileResponse` | Update profile |
| POST | `/threats/match` | Required | `{campaign_id}` or `{findings: [...]}` | `{matches: [{profile, coverage_pct, matched_techniques}]}` | Match findings to threat actor TTPs |
| GET | `/threats/attack-paths/{campaign_id}` | Required | -- | `{paths: [{chain, risk_score, steps}]}` | Enhanced attack path analysis |
| GET | `/threats/mitre-matrix` | Required | `?campaign_id=` | `{tactics: [{id, name, techniques: [{id, name, count, findings}]}]}` | Full MITRE matrix data for heatmap |

**Built-in threat profiles** (seeded data -- 10+ profiles):
- APT28 (Fancy Bear) -- Russia, espionage
- APT29 (Cozy Bear) -- Russia, espionage
- APT41 (Winnti) -- China, espionage + financial
- Lazarus Group -- DPRK, financial + destruction
- FIN7 -- Financial crime
- Turla -- Russia, espionage
- OceanLotus (APT32) -- Vietnam, espionage
- Sandworm -- Russia, destruction + espionage
- Carbanak -- Financial crime
- MuddyWater -- Iran, espionage

### Enhanced Chain Analyzer

The existing `ChainAnalyzer` is extended with:

1. **Risk scoring**: Each attack chain receives a composite risk score (0-100) based on:
   - Individual vulnerability CVSS scores
   - Chain length (longer chains = higher risk due to blast radius)
   - Presence of auth bypass + RCE combinations
   - Data sensitivity of affected endpoints

2. **Attack path visualization data**: Returns graph-ready data structures:
   ```python
   {
       "nodes": [{"id": "vuln_1", "type": "xss", "severity": "high", ...}],
       "edges": [{"source": "vuln_1", "target": "vuln_2", "relationship": "enables"}],
       "paths": [{"steps": [...], "risk_score": 85, "mitre_chain": [...]}]
   }
   ```

3. **Campaign-level correlation**: Aggregate chains across all targets in a campaign

### Campaign Scan Execution Flow

1. User creates campaign with scope definition (allowed domains/IPs)
2. User adds targets to campaign (each validated against scope)
3. User launches scan against a target (`POST /campaigns/{id}/targets/{tid}/scan`)
4. API validates target is in scope, creates ScanJob linked to CampaignTarget
5. OOB listener is optionally created for blind vulnerability verification
6. ScannerEngine runs selected modules with OOB callback URLs injected
7. Results are stored as Vulnerabilities (existing) AND Findings (new, campaign-linked)
8. OOB interactions are correlated with findings
9. ChainAnalyzer runs with campaign-level context
10. MITRE coverage is updated on the Campaign model
11. Findings are available for team review, notes, status updates

### CLI Red Team Commands

New Click command group under `sentinel redteam`:

```
sentinel campaign create --name "Pentest Q1" --scope '{"allowed_domains": ["example.com"]}'
sentinel campaign list
sentinel campaign status <campaign-id>
sentinel campaign scan <campaign-id> --target https://example.com --modules xss,sqli,ssrf
sentinel campaign report <campaign-id> --format html
sentinel redteam --profile apt28 --target example.com    # Quick scan with threat actor TTP focus
sentinel redteam --stealth --target example.com          # Slow scan, human-like timing
sentinel payload build "alert(1)" --encoders base64,url_encode
sentinel payload mutate "SELECT * FROM users" --mutations random_case,space_to_comment --count 5
```

### WebSocket Events (additions)

Extend existing WebSocket protocol in `src/web/scan_manager.py`:

```
# New event types
{"type": "campaign_phase_changed", "campaign_id": "...", "phase": "execution"}
{"type": "finding_added", "campaign_id": "...", "finding": {...}}
{"type": "oob_hit", "campaign_id": "...", "interaction": {...}}
{"type": "attack_chain_discovered", "campaign_id": "...", "chain": {...}}
```
