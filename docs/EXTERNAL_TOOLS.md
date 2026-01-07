# SENTINEL External Tool Integration

SENTINEL integrates external security tools through dedicated modules. This document describes the available integrations.

## Integrated Tools

| Modül | Araç | Açıklama |
|-------|------|----------|
| `nmap_scanner` | Nmap | Ağ keşfi ve servis tespiti |
| `gobuster_scanner` | Gobuster/Dirb | Yüksek hızlı dizin enumeration |
| `nikto_scanner` | Nikto | Web sunucusu zafiyet taraması |
| `hash_cracker` | John/Hashcat | Parola hash analizi ve kırma |
| `wordlist_builder` | CeWL-like | Hedef odaklı wordlist oluşturma |
| `sse_scanner` | Native | Server-Sent Events güvenlik analizi |
| `protocol_scanner` | Native | Çoklu protokol ve SSL/TLS analizi |

---

## Nmap Scanner

Nmap entegrasyonu ile kapsamlı ağ keşfi yapabilirsiniz.

### Yetenekler
- Port taraması (TCP/UDP)
- Servis versiyon tespiti
- OS fingerprinting
- NSE script taraması (vuln, auth, default)
- Banner grabbing

### Gereksinimler
```bash
# macOS
brew install nmap

# Linux
apt install nmap
```

### Kullanım
```python
# Tek modül çalıştırma
python scanner.py -u https://example.com -m nmap_scanner
```

---

## Gobuster Scanner

Go tabanlı yüksek performanslı dizin keşfi.

### Yetenekler
- Wordlist-based brute-forcing
- Dosya uzantısı fuzzing
- Recursive discovery
- Dirb fallback desteği

### Gereksinimler
```bash
# Go ile kurulum
go install github.com/OJ/gobuster/v3@latest

# veya macOS
brew install gobuster
```

### Kullanım
```python
python scanner.py -u https://example.com -m gobuster_scanner
```

---

## Nikto Scanner

Kapsamlı web sunucusu zafiyet tarayıcısı.

### Yetenekler
- Sunucu misconfiguration tespiti
- Güncel olmayan yazılım tespiti
- Tehlikeli dosya keşfi
- CGI zafiyet kontrolü
- Default credential kontrolü

### Gereksinimler
```bash
# macOS
brew install nikto

# Linux
apt install nikto
```

---

## 🔐 Hash Cracker

Parola hash'lerini tespit eden ve analiz eden modül.

### Yetenekler
- Hash tipi tespiti (MD5, SHA1, SHA256, bcrypt, etc.)
- Sayfa içeriğinden hash çıkarma
- John the Ripper entegrasyonu
- Hashcat desteği

### Desteklenen Hash Tipleri
- MD5
- SHA1 / SHA256 / SHA512
- bcrypt
- MySQL hashes
- NTLM

### Gereksinimler
```bash
# John the Ripper
brew install john  # macOS
apt install john   # Linux

# Hashcat
brew install hashcat  # macOS
apt install hashcat   # Linux
```

---

## Wordlist Builder

Hedef odaklı özel wordlist oluşturma (CeWL benzeri).

### Yetenekler
- Sayfa içeriğinden kelime çıkarma
- Email adresi keşfi
- Kullanıcı adı çıkarma
- Parola varyasyon oluşturma
- Leet speak dönüşümü

### Çıktı
```
output/wordlists/<hostname>_wordlist.txt
```

---

## 📡 SSE Scanner

Server-Sent Events (SSE) endpoint güvenlik tarayıcısı.

### Yetenekler
- SSE endpoint keşfi
- Kimlik doğrulama kontrolü
- Hassas veri sızıntısı tespiti
- Real-time stream analizi

### Taranan Endpointler
- `/events`, `/sse`, `/stream`
- `/api/events`, `/api/stream`
- `/realtime`, `/live`, `/push`

---

## Protocol Scanner

Çoklu protokol ve SSL/TLS güvenlik analizi.

### Yetenekler
- SSL/TLS versiyon kontrolü
- Cipher suite analizi
- Banner grabbing
- Zayıf protokol tespiti (SSLv3, TLS 1.0, TLS 1.1)

### Taranan Portlar
- HTTP: 80, 8080, 8000
- HTTPS: 443, 8443
- FTP: 21
- SSH: 22
- MySQL: 3306
- Redis: 6379
- MongoDB: 27017

---

## Tüm Modülleri Çalıştırma

```bash
# Tüm modüller
python scanner.py -u https://example.com

# Sadece harici araç modülleri
python scanner.py -u https://example.com -m nmap_scanner,gobuster_scanner,nikto_scanner

# Hızlı tarama (sadece dahili modüller)
python scanner.py -u https://example.com --quick
```

---

## Web API Kullanımı

Harici araçları Web API üzerinden de çalıştırabilirsiniz:

### Araç Durumunu Kontrol Et
```bash
curl http://localhost:8000/api/external-tools
```

### Nmap Taraması Başlat
```bash
curl -X POST http://localhost:8000/api/tools/nmap \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "profile": "quick"}'
```

### Gobuster Taraması Başlat
```bash
curl -X POST http://localhost:8000/api/tools/gobuster \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

### Nikto Taraması Başlat
```bash
curl -X POST http://localhost:8000/api/tools/nikto \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

### Wordlist Oluştur
```bash
curl -X POST http://localhost:8000/api/tools/wordlist \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

### Oluşturulan Wordlist'leri Listele
```bash
curl http://localhost:8000/api/tools/wordlists
```

> 📖 **Detaylı API Referansı:** [docs/API_REFERENCE.md](API_REFERENCE.md#external-tools-api)

---

## ⚠️ Önemli Notlar

1. **Araç Gereksinimleri**: Harici araçlar (nmap, nikto, gobuster vb.) sistemde yüklü olmalıdır. Yüklü değilse modül "Skipped" durumunda geçer.

2. **Timeout Ayarları**: Harici araçlar için varsayılan timeout 10 dakikadır. Bu süre config ile ayarlanabilir.

3. **Yasal Uyarı**: Bu araçları sadece izin aldığınız sistemlerde kullanın. Yetkisiz tarama yasal suçtur.

4. **Performans**: Harici araçlar paralel çalıştırılır ancak sistem kaynaklarını yoğun kullanabilir.
