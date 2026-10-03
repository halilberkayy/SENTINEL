# SENTINEL

[Türkçe](#türkçe) · [English](#english)

[![CI](https://github.com/halilberkayy/SENTINEL/actions/workflows/ci.yml/badge.svg)](https://github.com/halilberkayy/SENTINEL/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Türkçe

Yetkili web güvenlik değerlendirme platformu. Red Team, test etmeye izinli olduğun bir
hedefi tarar ve kanıt toplar. Blue Team, high/critical bulguları aynı konsolda
sertleştirme skoruna ve takip edilen olaylara çevirir.

> ⚠️ **Sadece izinli olduğun hedefi tara.** Yazılı izin, bir bounty kapsamı ya da sana
> ait bir sistem. Gerisi senin sorunun, özellik değil.

**Kurulum** (Python 3.10+, Poetry)

```bash
git clone https://github.com/halilberkayy/SENTINEL.git
cd SENTINEL
poetry install
```

**Tarama**

```bash
poetry run scanner -u https://example.com --no-interactive   # bounty profili
poetry run python web_app.py                                 # web konsolu: http://127.0.0.1:8000
```

Bounty profili: recon, headers, CORS, misconfig, security.txt, robots.txt, JS secrets,
open redirect, JWT, GraphQL. Injection yok. Raporlar `output/reports/` altına düşer
(txt, json, html, md, sarif).

**Tasarımı gereği kapsam dışı:** webshell yükleme, veri sızdırma, parola kırma,
kalıcılık, C2 ve istemciyi gizleyen trafik. SENTINEL bulur ve raporlar, silah hâline
getirmez. Injection/SSRF modülleri kayıtlı ama varsayılan kapalı; yalnızca engagement
izin veriyorsa `-m` ile çağır.

**Testler**

```bash
poetry run ruff check src tests
poetry run black --check src tests
poetry run pytest tests/unit/ -o addopts=
```

---

## English

An authorized web security assessment platform. Red Team scans a host you are allowed to
test and records evidence. Blue Team turns high/critical findings into hardening scores
and tracked incidents, in the same console.

> ⚠️ **Scan only what you are allowed to.** Written permission, a bounty scope, or a
> system you own. Anything else is your problem, not a feature.

**Install** (Python 3.10+, Poetry)

```bash
git clone https://github.com/halilberkayy/SENTINEL.git
cd SENTINEL
poetry install
```

**Scan**

```bash
poetry run scanner -u https://example.com --no-interactive   # bounty profile
poetry run python web_app.py                                 # web console: http://127.0.0.1:8000
```

Bounty profile: recon, headers, CORS, misconfig, security.txt, robots.txt, JS secrets,
open redirect, JWT, GraphQL. No injection. Reports land in `output/reports/`
(txt, json, html, md, sarif).

**Out of scope by design:** webshell deployment, data extraction, password cracking,
persistence, C2, and client-hiding traffic. SENTINEL finds and reports; it does not
weaponize. Injection/SSRF modules stay registered but off by default; pass them with
`-m` only when the engagement allows.

**Tests**

```bash
poetry run ruff check src tests
poetry run black --check src tests
poetry run pytest tests/unit/ -o addopts=
```

---

License: [MIT](LICENSE).
