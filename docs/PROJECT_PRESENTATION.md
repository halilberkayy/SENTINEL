# 🛡️ SENTINEL - Enterprise Security Assessment Platform

> **Profesyonel Güvenlik Değerlendirme Platformu**
> 
> 48 aktif tarama modülü + 7 harici araç entegrasyonu ile kapsamlı güvenlik analizi
> 
> 🆕 **OWASP Top 10 2025 Tam Uyumlu | Nmap, Nikto, Gobuster Entegre!**

---

## 📊 Proje Özeti

**SENTINEL**, modern web uygulamalarının güvenlik açıklarını otomatik olarak tespit eden, harici güvenlik araçlarını (Nmap, Nikto, Gobuster, John the Ripper) tek bir platformda birleştiren kurumsal düzeyde bir penetrasyon testi aracıdır.

### 💡 Temel Değer Önerisi

```
Geleneksel: Nmap → Nikto → Gobuster → Manuel Birleştirme → Rapor (Saatler)
SENTINEL:   Tek Komut → 48 Modül + 7 Araç → AI Rapor (Dakikalar)
```

| Özellik | Değer |
|---------|-------|
| **Aktif Tarama Modülü** | 48 |
| **Harici Araç Entegrasyonu** | 7 (Nmap, Nikto, Gobuster, John, Hashcat, SSE, Protocol) |
| **OWASP Top 10 Kapsamı** | %100 (2025) |
| **Desteklenen Formatlar** | JSON, HTML, Markdown, SARIF, TXT |
| **AI Raporlama** | Google Gemini AI |
| **Çalışma Modları** | CLI, Web API, GUI |
| **Lisans** | Proprietary (Özel) |

---

## 🎯 Ana Özellikler

### 🔍 Kapsamlı Güvenlik Taraması

```
┌─────────────────────────────────────────────────────────────────┐
│                    SENTINEL SCANNER ENGINE                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌────────────┐│
│  │ Injection   │ │ Auth/Access │ │ Client-Side │ │ Recon      ││
│  │ ─────────── │ │ ─────────── │ │ ─────────── │ │ ────────── ││
│  │ • SQL Inj.  │ │ • JWT       │ │ • XSS       │ │ • Subdomain││
│  │ • NoSQL     │ │ • OAuth     │ │ • CSRF      │ │ • Port     ││
│  │ • Command   │ │ • Session   │ │ • CORS      │ │ • Dir Enum ││
│  │ • LDAP      │ │ • IDOR      │ │ • ClickJack │ │ • Robots   ││
│  │ • XXE       │ │ • Privilege │ │ • Open Redir│ │ • JS Secrets│
│  │ • SSTI      │ │ • Rate Limit│ │ • WebSocket │ │ • Cloud    ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └────────────┘│
│                                                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌────────────┐│
│  │ Advanced    │ │ API Testing │ │ Defense     │ │ Reporting  ││
│  │ ─────────── │ │ ─────────── │ │ ─────────── │ │ ────────── ││
│  │ • Race Cond.│ │ • REST API  │ │ • WAF Detec.│ │ • CVSS     ││
│  │ • Deseiral. │ │ • GraphQL   │ │ • Bypass    │ │ • PoC Gen  ││
│  │ • Proto Poll│ │ • gRPC      │ │ • Evasion   │ │ • AI Summar││
│  │ • Webshell  │ │ • Mobile API│ │ • Logging   │ │ • Chain    ││
│  │ • LFI/RFI   │ │ • WebSocket │ │ • Headers   │ │ • SARIF    ││
│  │ • SSI       │ │ • Recursiv  │ │ • Dependency│ │ • Templates││
│  └─────────────┘ └─────────────┘ └─────────────┘ └────────────┘│
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🏗️ Mimari

### Sistem Mimarisi

```
                    ┌──────────────────────┐
                    │      CLIENT          │
                    │  (CLI/Web UI/API)    │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │     FastAPI Layer    │
                    │  ┌────────────────┐  │
                    │  │ Authentication │  │
                    │  │ Rate Limiting  │  │
                    │  │ API Versioning │  │
                    │  └────────────────┘  │
                    └──────────┬───────────┘
                               │
           ┌───────────────────┼───────────────────┐
           │                   │                   │
┌──────────▼─────┐  ┌─────────▼────────┐  ┌──────▼────────┐
│ Scanner Engine │  │ Report Generator │  │ Plugin System │
│ ─────────────  │  │ ────────────────  │  │ ────────────  │
│ • Module Disco.│  │ • Multi-format   │  │ • Hot Reload  │
│ • Async Exec.  │  │ • Templates      │  │ • Capability  │
│ • Chain Analys.│  │ • CVSS Scoring   │  │ • Lifecycle   │
└──────────┬─────┘  └──────────────────┘  └───────────────┘
           │
    ┌──────▼──────────────────────────────────────────┐
    │              41 Scanner Modules                  │
    │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐│
    │  │XSS  │ │SQLi │ │SSRF │ │XXE  │ │JWT  │ │ ... ││
    │  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘│
    └─────────────────────────────────────────────┘
           │
    ┌──────▼──────────────────────────────────────┐
    │         7 External Tool Modules                   │
    │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐│
    │  │Nmap │ │Nikto│ │Gobus│ │JtR  │ │Hash │ │ ... ││
    │  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘│
    └─────────────────────────────────────────────┘
           │
    ┌──────▼──────────────────────────────────────────┐
    │           Infrastructure Layer                   │
    │  ┌──────────┐ ┌─────────┐ ┌───────────────────┐ │
    │  │PostgreSQL│ │  Redis  │ │ Prometheus/Grafana│ │
    │  └──────────┘ └─────────┘ └───────────────────┘ │
    └─────────────────────────────────────────────────┘
```

---

## 📁 Proje Yapısı

```
SENTINEL/
├── 📄 scanner.py              # Ana CLI arayüzü
├── 📄 web_app.py              # FastAPI web sunucusu
├── 📄 gui_scanner.py          # Tkinter GUI uygulaması
├── 📄 async_scanner.py        # Async CLI wrapper
│
├── 📁 src/                    # Kaynak kodları
│   ├── 📁 core/               # Çekirdek bileşenler
│   │   ├── scanner_engine.py  # Ana tarama motoru
│   │   ├── http_client.py     # HTTP istemcisi
│   │   ├── config.py          # Konfigürasyon yönetimi
│   │   ├── chain_analyzer.py  # Saldırı zinciri analizi
│   │   ├── cvss.py            # CVSS puanlama
│   │   ├── auth_manager.py    # Kimlik doğrulama
│   │   ├── distributed_scanner.py # Dağıtık tarama
│   │   ├── 📁 database/       # SQLAlchemy modelleri
│   │   ├── 📁 cache/          # Redis önbellekleme
│   │   └── 📁 security/       # Güvenlik katmanları
│   │
│   ├── 📁 modules/            # 36 Tarama Modülü
│   │   ├── xss_scanner.py
│   │   ├── sqli_scanner.py
│   │   ├── jwt_scanner.py
│   │   ├── graphql_scanner.py
│   │   ├── grpc_scanner.py
│   │   ├── mobile_api_scanner.py
│   │   ├── websocket_scanner.py
│   │   ├── waf_detector.py
│   │   └── ... (28 modül daha)
│   │
│   ├── 📁 api/                # REST API
│   │   ├── app.py             # FastAPI uygulama
│   │   ├── 📁 v1/             # API v1 rotaları
│   │   ├── 📁 middleware/     # Rate limit, auth
│   │   └── 📁 schemas/        # Pydantic şemaları
│   │
│   ├── 📁 reporting/          # Raporlama
│   │   ├── formatters.py      # JSON, HTML, MD, TXT
│   │   ├── sarif_formatter.py # SARIF format
│   │   ├── poc_generator.py   # PoC üretici
│   │   ├── ai_narrator.py     # AI özet
│   │   └── templates.py       # Rapor şablonları
│   │
│   ├── 📁 plugins/            # Plugin sistemi
│   │   ├── manager.py         # Plugin yöneticisi
│   │   └── example_plugin.py  # Örnek plugin
│   │
│   ├── 📁 utils/              # Yardımcılar
│   │   ├── fuzzing.py         # Fuzzing motoru
│   │   ├── waf_bypass.py      # WAF bypass
│   │   ├── scoring.py         # Risk puanlama
│   │   └── payloads.py        # Payload koleksiyonları
│   │
│   └── 📁 payloads/           # Payload dosyaları
│
├── 📁 tests/                  # Test altyapısı
│   ├── 📁 unit/               # Birim testleri
│   └── 📁 integration/        # Entegrasyon testleri
│
├── 📁 web/                    # Web arayüzü
│   ├── index.html             # Ana sayfa
│   └── 📁 static/             # CSS, JS
│
├── 📁 docker/                 # Docker yapılandırması
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── prometheus.yml
│
├── 📁 docs/                   # Dokümantasyon
│   ├── API_REFERENCE.md
│   ├── PLUGIN_DEVELOPMENT.md
│   └── README.md
│
├── 📁 wordlists/              # Sözlük dosyaları
│   ├── sqli_payloads.txt
│   ├── xss_payloads.txt
│   ├── directories.txt
│   └── ... (14 dosya daha)
│
└── 📁 config/                 # Konfigürasyon
    └── scanner_config.json
```

---

## 🔧 Tarama Modülleri (48 Adet)

### OWASP Top 10 2025 Tam Kapsam

| OWASP 2025 | Kategori | Modüller |
|------------|----------|----------|
| **A01** | Broken Access Control | `broken_access_control`, `auth_scanner`, `jwt_scanner`, `cors_scanner` |
| **A02** | Security Misconfiguration | `security_misconfig`, `headers_scanner`, `cloud_scanner`, `robots_txt` |
| **A03** | Software Supply Chain Failures 🆕 | `supply_chain_scanner`, `dependency_scanner`, `js_secrets_scanner` |
| **A04** | Cryptographic Failures | `jwt_scanner`, `headers_scanner`, `security_misconfig` |
| **A05** | Injection | `sqli_scanner`, `xss_scanner`, `command_injection`, `xxe_scanner`, `ssti_scanner`, `ssi_scanner`, `lfi_rfi_scanner` |
| **A06** | Insecure Design | `api_scanner`, `graphql_scanner`, `websocket_scanner` |
| **A07** | Authentication Failures | `auth_scanner`, `jwt_scanner`, `csrf_scanner` |
| **A08** | Software/Data Integrity Failures | `deserialization_scanner`, `proto_pollution` |
| **A09** | Logging & Alerting Failures | `logging_scanner` |
| **A10** | Mishandling of Exceptional Conditions 🆕 | `exception_scanner` |

### Ek Modüller

| Kategori | Modüller |
|----------|----------|
| **Keşif** | `recon_scanner`, `subdomain_scanner`, `port_scanner`, `directory_scanner`, `recursive_scanner` |
| **API Güvenliği** | `api_scanner`, `graphql_scanner`, `grpc_scanner`, `mobile_api_scanner`, `websocket_scanner` |
| **Savunma Analizi** | `waf_detector`, `rate_limit_scanner` |
| **Gelişmiş** | `race_condition`, `webshell_scanner`, `webshell_uploader`, `ssrf_scanner`, `open_redirect` |

### 🛠️ Harici Araç Entegrasyonları (NEW!)

| Modül | Araç | Açıklama |
|-------|------|----------|
| **nmap_scanner** | Nmap | Ağ keşfi, servis tespiti, OS fingerprinting |
| **gobuster_scanner** | Gobuster/Dirb | Yüksek hızlı dizin brute-force |
| **nikto_scanner** | Nikto | Web sunucusu zafiyet taraması |
| **hash_cracker** | John/Hashcat | Parola hash analizi ve kırma |
| **wordlist_builder** | Native | Hedef odaklı wordlist oluşturma |
| **sse_scanner** | Native | Server-Sent Events güvenlik |
| **protocol_scanner** | Native | SSL/TLS ve çoklu protokol |

> ⚠️ **Kurulum:** `brew install nmap nikto gobuster john hashcat`

---

## 🚀 Kullanım

### CLI Kullanımı

```bash
# Temel tarama
python scanner.py -t https://example.com

# Belirli modüllerle tarama
python scanner.py -t https://example.com -m xss sqli jwt

# Kapsamlı tarama
python scanner.py -t https://example.com -m all --output report.html

# Stealth mod (WAF bypass)
python scanner.py -t https://example.com --stealth --delay 2
```

### Web API Kullanımı

```bash
# Sunucuyu başlat
python web_app.py

# API üzerinden tarama başlat
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com", "modules": ["xss", "sqli"]}'
```

### Web Arayüzü

```bash
# Sunucuyu başlat
python web_app.py

# Tarayıcıda aç
open http://localhost:8000
```

---

## 📈 Özellikler Detayı

### 🔐 Güvenlik

- **JWT Authentication** - Token tabanlı kimlik doğrulama
- **RBAC** - Rol bazlı erişim kontrolü (Admin, Analyst, Viewer, API User)
- **Rate Limiting** - Token bucket algoritması
- **Security Headers** - HSTS, CSP, XSS Protection
- **Secrets Management** - Çoklu backend desteği

### ⚡ Performans

- **Async/Await** - Tüm I/O işlemlerinde asenkron yapı
- **Connection Pooling** - Veritabanı bağlantı havuzu
- **Redis Caching** - Sonuç önbellekleme
- **Concurrent Scanning** - Paralel modül çalıştırma
- **Stealth Mode** - WAF bypass teknikleri

### 📊 Raporlama

- **Multi-Format** - JSON, HTML, Markdown, TXT, SARIF
- **CVSS Scoring** - Otomatik risk puanlama
- **PoC Generation** - Kanıt kodu üretimi
- **AI Summarization** - Yapay zeka özeti
- **Attack Chain Analysis** - Saldırı zinciri tespiti
- **Template System** - Özelleştirilebilir şablonlar

### 🔌 Eklentilik

- **Plugin System** - Dinamik modül yükleme
- **Hot Reload** - Yeniden başlatmadan güncelleme
- **Capability Discovery** - Özellik keşfi
- **Lifecycle Hooks** - Yaşam döngüsü yönetimi

### 📈 Monitoring

- **Prometheus Metrics** - Performans metrikleri
- **Grafana Dashboards** - Görsel izleme
- **Structured Logging** - JSON formatında loglar
- **Performance Tracking** - İstek süresi takibi

---

## 🐳 Docker ile Kurulum

```bash
# Tüm servisleri başlat
cd docker
docker-compose up -d

# Erişim noktaları:
# API: http://localhost:8000
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000
```

---

## 📜 Lisans

Bu proje **Özel Lisans (Proprietary)** altında sunulmaktadır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## 👤 Geliştirici

**Halil Berkay Şahin**

📧 halilberkaysahin@gmail.com

---

## 🙏 Teşekkürler

- OWASP Foundation - Güvenlik standartları
- Python topluluğu - Harika kütüphaneler
- Güvenlik araştırmacıları - Metodoloji rehberliği

---

## 📋 Lisans

Bu proje **Özel Lisans (Proprietary License)** altındadır.

- ✅ Eğitim ve akademik amaçlı inceleme serbest
- ⚠️ Kullanım için yazılı izin gerekli
- 📧 İzin için: halilberkaysahin@gmail.com

---

<div align="center">

**© 2024-2026 Halil Berkay Şahin - Tüm Hakları Saklıdır**

</div>
