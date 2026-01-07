# 🛡️ 48 Modüllü Web Vulnerability Scanner + Harici Araç Entegrasyonu | OWASP 2025 Uyumlu!

*Nmap, Nikto, Gobuster'ı Python ile nasıl birleştirdim?*

---

## 🎯 TL;DR

Merhaba arkadaşlar! 👋

Son birkaç aydır üzerinde çalıştığım bir projeyi sizlerle paylaşmak istiyorum: **SENTINEL** - 48 aktif tarama modülü, **7 harici araç entegrasyonu** (Nmap, Nikto, Gobuster, John the Ripper...), **%100 OWASP Top 10 2025** kapsamı ve AI-powered raporlama ile donatılmış kapsamlı bir Web Vulnerability Scanner.

**GitHub:** [github.com/halilberkayy/SENTINEL](https://github.com/halilberkayy/SENTINEL)

---

## 🤔 Neden Bu Projeyi Geliştirdim?

Penetrasyon testi yapan herkes bu sorunu bilir: **Her test için 10 farklı araç, 10 farklı rapor, saatlerce manuel korelasyon.**

Tipik bir web güvenlik testi şöyle görünür:
1. 🔍 **Nmap** ile port taraması → terminal çıktısı
2. 🌐 **Nikto** ile web sunucu analizi → text dosyası
3. 📂 **Gobuster** ile dizin bruteforce → başka bir dosya
4. 💉 **SQLMap** ile injection testi → JSON rapor
5. 📝 **Manuel olarak** tüm bulguları birleştir → saatler...

**SENTINEL bu sorunu çözer:**

```
Tek Komut → 48 Modül + 7 Harici Araç → Birleşik AI Rapor
```

> "Ama zaten Burp Suite var?" diyebilirsiniz. Evet, ama Burp **$449/yıl**. SENTINEL ise **eğitim amaçlı ücretsiz incelenebilir**.

---

## 🏗️ Proje Hakkında

### Teknik Özellikler

```python
{
    "scanner_modules": 48,
    "external_tools": ["nmap", "nikto", "gobuster", "john", "hashcat"],
    "owasp_coverage": "100% (2025)",
    "languages": ["Python 3.10+"],
    "frameworks": ["FastAPI", "SQLAlchemy", "aiohttp"],
    "ai_integration": "Google Gemini AI",
    "output_formats": ["JSON", "HTML", "Markdown", "SARIF", "TXT"],
    "interfaces": ["CLI", "Web API", "GUI"],
    "license": "Proprietary"
}
```

### Tarama Modülleri

Proje **48 farklı güvenlik tarama modülü** içeriyor:

**🔴 Injection Testleri:**
- SQL Injection (Error-based, Blind, Time-based)
- XSS (Reflected, Stored, DOM-based)
- Command Injection
- XXE (XML External Entity)
- SSTI (Server-Side Template Injection)
- SSI (Server-Side Includes)
- LFI/RFI (Local/Remote File Inclusion)

**🟠 Authentication & Authorization:**
- JWT Token analizi ve saldırıları
- OAuth/OIDC güvenlik testleri
- Session yönetimi testleri
- Broken Access Control
- CSRF (Cross-Site Request Forgery)
- IDOR (Insecure Direct Object Reference)

**🟡 API Güvenliği:**
- REST API güvenlik testleri
- GraphQL introspection ve injection
- gRPC güvenlik analizi
- WebSocket güvenlik testleri
- Mobile API güvenlik kontrolleri

**🟢 Keşif & Reconnaissance:**
- Subdomain keşfi
- Port tarama
- Dizin bruteforce
- Robots.txt analizi
- Security.txt kontrolleri
- JS dosyalarında secret arama

**🔵 Gelişmiş Testler:**
- Race Condition testleri
- Deserialization saldırıları
- Prototype Pollution
- WAF tespit ve bypass
- Rate Limiting testleri
- Dependency vulnerability scanning
- 🆕 **Supply Chain Scanning** (OWASP A03:2025)
- 🆕 **Exception Handling Analysis** (OWASP A10:2025)

**🛠️ Harici Araç Entegrasyonları (YENİ!):**
- Nmap - Ağ keşfi ve servis tespiti
- Gobuster/Dirb - Yüksek hızlı dizin brute-force
- Nikto - Web sunucusu zafiyet taraması
- John/Hashcat - Parola hash analizi
- Wordlist Builder - Hedef odaklı wordlist oluşturma
- SSE Scanner - Server-Sent Events güvenlik
- Protocol Scanner - SSL/TLS ve çoklu protokol

---

## ⚙️ Teknik Altyapı

### Mimari Kararlar

Projeyi geliştirirken bazı önemli mimari kararlar aldım:

**1. Async-First Tasarım**
```python
async def scan_target(self, url: str, modules: List[str]) -> List[ScanResult]:
    """Tüm modüller paralel olarak çalışır"""
    tasks = [self._run_module(mid, url) for mid in modules]
    return await asyncio.gather(*tasks)
```

Neden? Çünkü güvenlik taraması I/O-bound bir işlem. HTTP istekleri beklerken CPU boşta kalmamalı.

**2. Plugin Sistemi**
```python
class PluginManager:
    def discover_plugins(self):
        """Dinamik plugin keşfi"""
        for plugin_file in plugins_dir.glob("*.py"):
            # Hot reload destekli yükleme
            spec = importlib.util.spec_from_file_location(...)
```

Kullanıcılar kendi tarama modüllerini yazıp sisteme entegre edebilir.

**3. Chain Analyzer**

Farklı modüllerin bulgularını birleştirerek **saldırı zincirleri** tespit ediyorum:

```
SSRF → Internal Service → Command Injection = Critical Chain!
```

Bu özellik, tek başına düşük riskli görünen bulguların birleştiğinde ne kadar tehlikeli olabileceğini gösteriyor.

**4. External Command Runner (YENİ!)**

Harici araçları Python'dan güvenli ve asenkron olarak çalıştırmak için özel bir utility geliştirdim:

```python
class ExternalCommandRunner:
    async def run_command(self, tool: str, args: list, timeout: int = 600):
        """Harici aracı güvenli ve asenkron çalıştır"""
        if not self.check_tool_available(tool):
            return None
        
        process = await asyncio.create_subprocess_exec(
            tool, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )
        return stdout.decode()
```

Bu sayede Nmap, Nikto, Gobuster gibi araçlar **non-blocking** olarak çalışıyor ve sonuçları otomatik olarak dahili modüllerle birleştiriliyor.

---

## 📊 OWASP Top 10 2025 Kapsamı

| OWASP 2025 | Durum | Modüller |
|------------|-------|----------|
| A01: Broken Access Control | ✅ | 4 modül |
| A02: Security Misconfiguration | ✅ | 4 modül |
| A03: Software Supply Chain Failures 🆕 | ✅ | 3 modül |
| A04: Cryptographic Failures | ✅ | 3 modül |
| A05: Injection | ✅ | 7 modül |
| A06: Insecure Design | ✅ | 3 modül |
| A07: Authentication Failures | ✅ | 3 modül |
| A08: Software/Data Integrity Failures | ✅ | 2 modül |
| A09: Logging & Alerting Failures | ✅ | 1 modül |
| A10: Mishandling of Exceptional Conditions 🆕 | ✅ | 1 modül |

---

## 🚀 Nasıl Kullanılır?

### Hızlı Başlangıç

```bash
# Clone
git clone https://github.com/halilberkayy/SENTINEL.git
cd SENTINEL

# Kurulum
pip install -r requirements.txt

# Tarama başlat
python scanner.py -t https://target.com
```

### Web API

```bash
# Sunucu başlat
python web_app.py

# API ile tarama
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://target.com", "modules": ["xss", "sqli"]}'
```

### Docker

```bash
cd docker
docker-compose up -d

# Erişim
# API: http://localhost:8000
# Grafana: http://localhost:3000
```

---

## 🔧 Öğrendiğim Dersler

Bu projeyi geliştirirken çok şey öğrendim. İşte bazıları:

### 1. Async Programming Zordur Ama Değer

İlk başta senkron kod yazmak daha kolay geldi. Ama 48 modülü sırayla çalıştırmak saatler alıyordu. Async'e geçince tarama süresi **10 kat** azaldı.

### 2. Harici Araç Entegrasyonu Düşündüğünden Zor

Nmap ve Nikto gibi araçları Python'a entegre etmek basit görünüyor. Ama timeout yönetimi, output parsing, error handling... Her biri ayrı bir mühendislik problemi. `asyncio.create_subprocess_exec` ile asenkron process yönetimi kritik oldu.

### 3. False Positive Yönetimi Kritik

Bir güvenlik aracının en büyük düşmanı false positive. Kullanıcılar sahte uyarılarla boğulursa aracı kullanmayı bırakır. Bu yüzden her modülde **doğrulama mekanizmaları** kurdum.

### 4. Modüler Tasarım Her Şeydir

İlk versiyonda tüm kodlar tek dosyadaydı. 🙈 Sonra modüler yapıya geçtim ve bakım **100 kat** kolaylaştı. Şimdi yeni bir araç eklemek sadece bir Python dosyası yazmak kadar basit.

### 5. Wordlist Kalitesi Kritik

Dizin bruteforce için kullandığınız wordlist ne kadar iyi olursa, bulgular o kadar kaliteli olur. Bu yüzden **dinamik wordlist oluşturucu** ekledim - hedef siteden kelime çekip özel wordlist üretiyor.

---

## 📈 Tamamlanan ve Gelecek Planları

**✅ Tamamlanan:**
- [x] **48 Tarama Modülü** - OWASP Top 10 2025 tam kapsam
- [x] **Harici Araç Entegrasyonu** - Nmap, Nikto, Gobuster, JtR, Hashcat
- [x] **Wordlist Builder** - Hedef odaklı wordlist oluşturma
- [x] **AI Raporlama** - Gemini AI ile akıllı özet

**🔜 Gelecek:**
- [ ] **Distributed Scanning** - Kubernetes üzerinde dağıtık tarama
- [ ] **Metasploit Entegrasyonu** - Otomatik exploit önerisi
- [ ] **Plugin Marketplace** - Topluluk pluginleri için marketplace
- [ ] **Cloud Integration** - AWS/GCP/Azure API entegrasyonları
---

## 📋 Lisans ve Kullanım

Bu proje **Özel Lisans (Proprietary License)** altında sunulmaktadır:

- ✅ **Eğitim Amaçlı:** Kodu inceleyebilir ve öğrenebilirsiniz
- ✅ **Akademik:** Araştırma amacıyla kullanabilirsiniz
- ⚠️ **Kullanım İzni:** Çalıştırmak için yazılı izin gereklidir
- ❌ **Ticari Kullanım:** İzinsiz ticari kullanım yasaktır

**İzin İçin:** halilberkaysahin@gmail.com

---

## 📬 İletişim

Sorularınız veya işbirliği teklifleriniz için:

- � **Bug Report** - GitHub Issues üzerinden hata bildirebilirsiniz
- � **Feature Request** - Özellik önerileri için iletişime geçin
- 📧 **Email** - halilberkaysahin@gmail.com

**GitHub:** [github.com/halilberkayy/SENTINEL](https://github.com/halilberkayy/SENTINEL)

---

## 🎓 Kullanılan Teknolojiler

| Kategori | Teknoloji |
|----------|-----------|
| **Backend** | Python 3.10+, FastAPI, aiohttp |
| **Database** | PostgreSQL, SQLAlchemy 2.0 |
| **Cache** | Redis |
| **Monitoring** | Prometheus, Grafana |
| **CI/CD** | GitHub Actions |
| **Container** | Docker, Docker Compose |
| **Testing** | Pytest, Coverage |

---

## 💬 Son Sözler

Bu proje benim için hem bir öğrenme deneyimi hem de güvenlik metodolojilerini göstermek için bir vitrin oldu. 

Eğer siz de:
- Güvenlik alanında kariyer yapmak istiyorsanız
- Penetrasyon testi metodolojilerini öğrenmek istiyorsanız
- Profesyonel güvenlik araçları nasıl tasarlanır görmek istiyorsanız

Bu proje sizin için harika bir referans noktası olabilir!

Sorularınız olursa bana ulaşın. İşbirliği tekliflerine açığım! 🙏

---

**#Python #Security #PenetrationTesting #CyberSecurity #WebSecurity #OWASP #FastAPI #AsyncPython #Vulnerability**

---

*Halil Berkay Şahin*
*Software Engineer & Security Enthusiast*

📧 halilberkaysahin@gmail.com
🔗 [GitHub](https://github.com/halilberkayy)
🔗 [LinkedIn](https://linkedin.com/in/halilberkaysahin)
