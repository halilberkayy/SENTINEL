# SENTINEL Deployment Guide

**Version 6.0.0 | OWASP Top 10 2025 | 57 Security Modules**

Comprehensive deployment instructions for all environments.

---

## Contents

1. [Ön Gereksinimler](#ön-gereksinimler)
2. [Development Ortamı](#1-development-ortamı)
3. [Docker ile Deployment](#2-docker-ile-deployment)
4. [Production Deployment (Docker Compose)](#3-production-deployment-docker-compose)
5. [Kubernetes Deployment](#4-kubernetes-deployment)
6. [VPS Deployment (Ubuntu/Debian)](#5-vps-deployment-ubuntudebian)
7. [SSL Sertifikası Kurulumu](#6-ssl-sertifikası-kurulumu)
8. [Monitoring & Logging](#7-monitoring--logging)
9. [Backup & Recovery](#8-backup--recovery)
10. [Troubleshooting](#9-troubleshooting)

---

## Ön Gereksinimler

### Minimum Sistem Gereksinimleri

**Development:**
- CPU: 2 cores
- RAM: 4 GB
- Disk: 10 GB
- OS: macOS, Linux, Windows (WSL2)

**Production:**
- CPU: 4 cores
- RAM: 8 GB
- Disk: 50 GB SSD
- OS: Ubuntu 20.04+ / Debian 11+

### Yazılım Gereksinimleri

- **Python**: 3.10 veya üzeri
- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **Git**: 2.30+
- **PostgreSQL**: 15+ (production)
- **Redis**: 7+ (production)

---

## 1. Development Ortamı

### Adım 1: Repository'yi Klonla

```bash
git clone https://github.com/halilberkayy/SENTINEL.git
cd SENTINEL
```

### Adım 2: Poetry Kur

```bash
# macOS / Linux
curl -sSL https://install.python-poetry.org | python3 -

# Windows (PowerShell)
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | py -

# PATH'e ekle
export PATH="$HOME/.local/bin:$PATH"
```

### Adım 3: Bağımlılıkları Yükle

```bash
# Production dependencies
poetry install --no-dev

# Development dependencies dahil
poetry install
```

### Adım 4: Development Servisleri Başlat

```bash
# PostgreSQL ve Redis'i Docker ile başlat
docker-compose -f docker/docker-compose.yml up -d postgres redis

# Servislerin hazır olduğunu kontrol et
docker-compose -f docker/docker-compose.yml ps
```

### Adım 5: Environment Ayarla

```bash
# .env dosyası oluştur
cp .env.example .env

# .env dosyasını düzenle
nano .env
```

**Minimum .env configuration:**

```env
# Development settings
ENVIRONMENT=development
DEBUG=true

# Database (Docker PostgreSQL)
DATABASE_URL=postgresql://scanner:scanner@localhost:5432/scanner

# Redis (Docker Redis)
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=dev-secret-key-change-in-production
JWT_SECRET_KEY=dev-jwt-key-change-in-production
```

### Adım 6: Veritabanını Başlat

```bash
# Database tablolarını oluştur
poetry run python -c "
import asyncio
from src.core.database import init_database
asyncio.run(init_database('postgresql://scanner:scanner@localhost:5432/scanner'))
"
```

### Adım 7: İlk Admin Kullanıcısı Oluştur

```bash
# Python shell'de
poetry run python

>>> import asyncio
>>> from src.core.database import init_database, get_db_manager

>>> from src.core.database.models import UserModel
>>> from src.core.security import AuthenticationManager
>>> 
>>> async def create_admin():
>>>     await init_database('postgresql://scanner:scanner@localhost:5432/scanner')
>>>     db = get_db_manager()
>>>     auth = AuthenticationManager('secret')
>>>     
>>>     async with db.session() as session:
>>>         admin = UserModel(
>>>             username='admin',
>>>             email='admin@scanner.local',
>>>             hashed_password=auth.get_password_hash('admin123'),
>>>             role='admin',
>>>             is_active=True
>>>         )
>>>         session.add(admin)
>>>         await session.commit()
>>>         print('Admin user created!')
>>> 
>>> asyncio.run(create_admin())
>>> exit()
```

### Adım 8: API Sunucusunu Başlat

```bash
# Development mode (hot reload)
poetry run uvicorn src.api.app:app --reload --host 0.0.0.0 --port 8000

# Veya
poetry run scanner-api
```

### Adım 9: Test Et

```bash
# Tarayıcıda aç
open http://localhost:8000/api/docs

# cURL ile test
curl http://localhost:8000/health

# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

---

## 2. Docker ile Deployment

### Adım 1: Docker Image Build

```bash
# Production image oluştur
docker build -f docker/Dockerfile -t scanner:latest .

# Multi-platform build (ARM + x86)
docker buildx build --platform linux/amd64,linux/arm64 \
  -f docker/Dockerfile \
  -t scanner:latest .
```

### Adım 2: Image'ı Test Et

```bash
# Container çalıştır
docker run -d \
  --name scanner-api \
  -p 8000:8000 \
  -e DATABASE_URL=postgresql://user:pass@host:5432/db \
  -e REDIS_URL=redis://host:6379/0 \
  -e SECRET_KEY=your-secret-key \
  scanner:latest

# Logları kontrol et
docker logs -f scanner-api

# Test
curl http://localhost:8000/health
```

### Adım 3: Docker Registry'e Push

```bash
# Docker Hub
docker tag scanner:latest yourusername/scanner:latest
docker push yourusername/scanner:latest

# GitHub Container Registry
docker tag scanner:latest ghcr.io/yourusername/scanner:latest
docker push ghcr.io/yourusername/scanner:latest

# Private Registry
docker tag scanner:latest registry.example.com/scanner:latest
docker push registry.example.com/scanner:latest
```

---

## 3. Production Deployment (Docker Compose)

### Adım 1: Production Environment Hazırla

```bash
# Production server'a bağlan
ssh user@your-production-server.com

# Proje dizini oluştur
mkdir -p /opt/scanner
cd /opt/scanner

# Repository'yi klonla
git clone https://github.com/halilberkayy/SENTINEL.git .
```

### Adım 2: Production .env Dosyası

```bash
# .env dosyası oluştur
cat > .env << 'EOF'
# Production Environment
ENVIRONMENT=production
DEBUG=false

# Database (PostgreSQL)
POSTGRES_USER=scanner_prod
POSTGRES_PASSWORD=CHANGE_ME_STRONG_PASSWORD_HERE
POSTGRES_DB=scanner_production
DATABASE_URL=postgresql://scanner_prod:CHANGE_ME_STRONG_PASSWORD_HERE@postgres:5432/scanner_production

# Redis
REDIS_URL=redis://redis:6379/0

# Security - GENERATE STRONG KEYS!
SECRET_KEY=CHANGE_ME_USE_openssl_rand_base64_32
JWT_SECRET_KEY=CHANGE_ME_USE_openssl_rand_base64_32
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=30

# Rate Limiting
RATE_LIMIT_PER_MINUTE=100

# Scanner Config
SCANNER_CONCURRENT_REQUESTS=20
SCANNER_MAX_PAYLOADS=200
SCANNER_TIMEOUT=60

# Monitoring
PROMETHEUS_ENABLED=true

# Grafana
GF_SECURITY_ADMIN_PASSWORD=CHANGE_ME_GRAFANA_PASSWORD

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Celery
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2
EOF

# Güvenlik için permissions ayarla
chmod 600 .env
```

**Guclu secret key olustur:**

```bash
# SECRET_KEY oluştur
openssl rand -base64 32

# JWT_SECRET_KEY oluştur
openssl rand -base64 32

# .env dosyasında değiştir
nano .env
```

### Adım 3: Docker Compose Başlat

```bash
# Servisleri başlat
docker-compose -f docker/docker-compose.yml up -d

# Logları izle
docker-compose -f docker/docker-compose.yml logs -f

# Servis durumlarını kontrol et
docker-compose -f docker/docker-compose.yml ps
```

### Adım 4: Database Initialize

```bash
# API container'ına bağlan
docker-compose -f docker/docker-compose.yml exec api bash

# İçeride:
python -c "
import asyncio
from src.core.database import init_database
import os
asyncio.run(init_database(os.getenv('DATABASE_URL')))
"

# Admin user oluştur (yukarıdaki scripti kullan)
exit
```

### Adım 5: Health Check

```bash
# API sağlığını kontrol et
curl http://localhost:8000/health

# Prometheus metrics
curl http://localhost:8000/metrics

# Database bağlantısı
curl http://localhost:8000/ready
```

### Adım 6: Nginx Reverse Proxy Kur (Önerilen)

```bash
# Nginx yükle
sudo apt update
sudo apt install -y nginx

# Nginx config
sudo nano /etc/nginx/sites-available/scanner
```

**Nginx configuration:**

```nginx
upstream scanner_api {
    server localhost:8000;
}

server {
    listen 80;
    server_name scanner.example.com;

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";

    # API proxy
    location / {
        proxy_pass http://scanner_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Grafana
    location /grafana/ {
        proxy_pass http://localhost:3000/;
        proxy_set_header Host $host;
    }

    # Prometheus (protect with auth!)
    location /prometheus/ {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://localhost:9090/;
    }
}
```

```bash
# Nginx config'i aktif et
sudo ln -s /etc/nginx/sites-available/scanner /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## 4. Kubernetes Deployment

### Adım 1: Kubernetes Manifests Oluştur

```bash
mkdir -p kubernetes
```

**`kubernetes/namespace.yaml`:**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: scanner
```

**`kubernetes/configmap.yaml`:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: scanner-config
  namespace: scanner
data:
  ENVIRONMENT: "production"
  LOG_LEVEL: "INFO"
  SCANNER_CONCURRENT_REQUESTS: "20"
```

**`kubernetes/secrets.yaml`:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: scanner-secrets
  namespace: scanner
type: Opaque
stringData:
  DATABASE_URL: "postgresql://user:pass@postgres:5432/scanner"
  REDIS_URL: "redis://redis:6379/0"
  SECRET_KEY: "YOUR-SECRET-KEY-HERE"
  JWT_SECRET_KEY: "YOUR-JWT-SECRET-HERE"
```

**`kubernetes/deployment.yaml`:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scanner-api
  namespace: scanner
spec:
  replicas: 3
  selector:
    matchLabels:
      app: scanner-api
  template:
    metadata:
      labels:
        app: scanner-api
    spec:
      containers:
      - name: api
        image: ghcr.io/yourusername/scanner:latest
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: scanner-config
        - secretRef:
            name: scanner-secrets
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
```

**`kubernetes/service.yaml`:**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: scanner-api
  namespace: scanner
spec:
  selector:
    app: scanner-api
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

**`kubernetes/ingress.yaml`:**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: scanner-ingress
  namespace: scanner
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - scanner.example.com
    secretName: scanner-tls
  rules:
  - host: scanner.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: scanner-api
            port:
              number: 80
```

### Adım 2: Deploy to Kubernetes

```bash
# Namespace oluştur
kubectl apply -f kubernetes/namespace.yaml

# Secrets ve ConfigMap
kubectl apply -f kubernetes/secrets.yaml
kubectl apply -f kubernetes/configmap.yaml

# Deployment
kubectl apply -f kubernetes/deployment.yaml

# Service & Ingress
kubectl apply -f kubernetes/service.yaml
kubectl apply -f kubernetes/ingress.yaml

# Durumu kontrol et
kubectl get pods -n scanner
kubectl get svc -n scanner
kubectl get ingress -n scanner

# Logs
kubectl logs -f deployment/scanner-api -n scanner
```

### Adım 3: Database (PostgreSQL) Deploy

**`kubernetes/postgres-pvc.yaml`:**

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: scanner
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
```

**`kubernetes/postgres-deployment.yaml`:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: scanner
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        env:
        - name: POSTGRES_DB
          value: scanner
        - name: POSTGRES_USER
          valueFrom:
            secretKeyRef:
              name: scanner-secrets
              key: POSTGRES_USER
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: scanner-secrets
              key: POSTGRES_PASSWORD
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: postgres-pvc
```

```bash
kubectl apply -f kubernetes/postgres-pvc.yaml
kubectl apply -f kubernetes/postgres-deployment.yaml
```

---

## 5. VPS Deployment (Ubuntu/Debian)

### Adım 1: Server Hazırlığı

```bash
# Server'a SSH ile bağlan
ssh root@your-server-ip

# System güncelle
apt update && apt upgrade -y

# Gerekli paketleri yükle
apt install -y git curl wget build-essential python3 python3-pip \
  postgresql postgresql-contrib redis-server nginx certbot \
  python3-certbot-nginx supervisor

# Firewall ayarla
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

### Adım 2: PostgreSQL Kurulumu

```bash
# PostgreSQL başlat
systemctl start postgresql
systemctl enable postgresql

# Database ve user oluştur
sudo -u postgres psql << EOF
CREATE DATABASE scanner_production;
CREATE USER scanner_user WITH ENCRYPTED PASSWORD 'STRONG_PASSWORD_HERE';
GRANT ALL PRIVILEGES ON DATABASE scanner_production TO scanner_user;
\q
EOF
```

### Adım 3: Redis Kurulumu

```bash
# Redis başlat
systemctl start redis-server
systemctl enable redis-server

# Redis şifresi ayarla
redis-cli
> CONFIG SET requirepass "STRONG_REDIS_PASSWORD"
> CONFIG REWRITE
> exit
```

### Adım 4: Application User Oluştur

```bash
# scanner user oluştur
useradd -m -s /bin/bash scanner
su - scanner

# Repository klonla
cd /home/scanner
git clone https://github.com/halilberkayy/SENTINEL.git scanner
cd scanner
```

### Adım 5: Python Environment

```bash
# Poetry kur
curl -sSL https://install.python-poetry.org | python3 -

# PATH'e ekle
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Bağımlılıkları yükle
poetry install --no-dev
```

### Adım 6: Environment Configuration

```bash
# .env dosyası oluştur
cat > .env << 'EOF'
ENVIRONMENT=production
DATABASE_URL=postgresql://scanner_user:STRONG_PASSWORD_HERE@localhost:5432/scanner_production
REDIS_URL=redis://:STRONG_REDIS_PASSWORD@localhost:6379/0
SECRET_KEY=GENERATE_WITH_openssl_rand_base64_32
JWT_SECRET_KEY=GENERATE_WITH_openssl_rand_base64_32
EOF

chmod 600 .env
```

### Adım 7: Supervisor Configuration

```bash
# Root olarak
exit
sudo nano /etc/supervisor/conf.d/scanner.conf
```

```ini
[program:scanner-api]
command=/home/scanner/.local/bin/poetry run uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --workers 4
directory=/home/scanner/scanner
user=scanner
autostart=true
autorestart=true
stderr_logfile=/var/log/scanner/api.err.log
stdout_logfile=/var/log/scanner/api.out.log
environment=PATH="/home/scanner/.local/bin:%(ENV_PATH)s"

[program:scanner-celery]
command=/home/scanner/.local/bin/poetry run celery -A src.core.celery_app worker --loglevel=info
directory=/home/scanner/scanner
user=scanner
autostart=true
autorestart=true
stderr_logfile=/var/log/scanner/celery.err.log
stdout_logfile=/var/log/scanner/celery.out.log
```

```bash
# Log dizini oluştur
mkdir -p /var/log/scanner
chown scanner:scanner /var/log/scanner

# Supervisor'ı yeniden başlat
supervisorctl reread
supervisorctl update
supervisorctl start all
supervisorctl status
```

### Adım 8: Nginx Configuration

```bash
sudo nano /etc/nginx/sites-available/scanner
```

(Yukarıdaki Nginx config'i kullan)

```bash
sudo ln -s /etc/nginx/sites-available/scanner /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## 6. SSL Sertifikası Kurulumu

### Let's Encrypt ile Ücretsiz SSL

```bash
# Certbot ile SSL sertifikası al
sudo certbot --nginx -d scanner.example.com

# Auto-renewal test
sudo certbot renew --dry-run

# Cron job (otomatik yenileme)
sudo crontab -e
# Ekle:
0 12 * * * /usr/bin/certbot renew --quiet
```

### Cloudflare ile SSL (Önerilen)

1. Domain'i Cloudflare'e ekle
2. DNS kayıtlarını güncelle:
   ```
   A    scanner.example.com    YOUR_SERVER_IP
   ```
3. SSL/TLS → Full (Strict) seç
4. Origin Certificate oluştur
5. Nginx'e ekle

---

## 7. Monitoring & Logging

### Prometheus & Grafana Setup

```bash
# Docker Compose ile (zaten var)
docker-compose -f docker/docker-compose.yml up -d prometheus grafana

# Grafana'ya erişim
open http://localhost:3000
# Default: admin / admin (değiştir!)

# Prometheus datasource ekle
# Configuration → Data Sources → Add Prometheus
# URL: http://prometheus:9090
```

### Log Aggregation (Optional - ELK Stack)

**Not:** ELK Stack kurulumu opsiyoneldir. Küçük ve orta ölçekli deployment'lar için yapılandırılmış loglama (structlog) ve Grafana yeterlidir. Kurulum gerekmiyorsa bu bölümü atlayabilirsiniz.

**ELK Stack gerekli ise aşağıdaki adımları izleyin:**

```bash
# Docker Compose ile ELK Stack kurulumu
cat > docker-compose.elk.yml << 'EOF'
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
    volumes:
      - elk_data:/usr/share/elasticsearch/data

  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    ports:
      - "5044:5044"
      - "9600:9600"
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch

volumes:
  elk_data:
EOF

# ELK Stack başlat
docker-compose -f docker-compose.elk.yml up -d

# Kibana'ya erişim: http://localhost:5601
```

**Logstash yapılandırması (logstash.conf):**

```conf
input {
  file {
    path => "/var/log/scanner/*.log"
    type => "scanner"
    codec => json
  }
}

filter {
  if [type] == "scanner" {
    json {
      source => "message"
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "scanner-logs-%{+YYYY.MM.dd}"
  }
}
```

---

## 8. Backup & Recovery

### Database Backup

```bash
# Otomatik backup scripti
cat > /usr/local/bin/backup-scanner-db.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/scanner"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# PostgreSQL backup
pg_dump -U scanner_user scanner_production | gzip > $BACKUP_DIR/db_$DATE.sql.gz

# Old backups temizle (30 gün)
find $BACKUP_DIR -name "db_*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/db_$DATE.sql.gz"
EOF

chmod +x /usr/local/bin/backup-scanner-db.sh

# Cron job (günlük 2:00 AM)
sudo crontab -e
0 2 * * * /usr/local/bin/backup-scanner-db.sh
```

### Restore from Backup

```bash
# Backup'tan restore
gunzip -c /var/backups/scanner/db_20231227_020000.sql.gz | \
  psql -U scanner_user scanner_production
```

---

## 9. Troubleshooting

### API Başlamıyor

```bash
# Logs kontrol et
docker-compose -f docker/docker-compose.yml logs api

# Database bağlantısı test et
docker-compose -f docker/docker-compose.yml exec api python -c \
  "from src.core.database import init_database; import asyncio; asyncio.run(init_database('...'))"

# Environment variables kontrol et
docker-compose -f docker/docker-compose.yml exec api env | grep DATABASE_URL
```

### Database Connection Hatası

```bash
# PostgreSQL çalışıyor mu?
systemctl status postgresql

# Port dinliyor mu?
netstat -tulpn | grep 5432

# User/password doğru mu?
psql -U scanner_user -d scanner_production
```

### High CPU/Memory Usage

```bash
# Resource kullanımı
docker stats

# Concurrent requests azalt
# .env dosyasında:
SCANNER_CONCURRENT_REQUESTS=5

# Worker sayısını azalt
# supervisor config'de workers=2
```

### SSL Certificate Hatası

```bash
# Certbot yenile
sudo certbot renew --force-renew

# Nginx reload
sudo systemctl reload nginx
```

---

## Quick Reference Commands

```bash
# Development
poetry run scanner-api

# Production restart
docker-compose -f docker/docker-compose.yml restart api

# View logs
docker-compose -f docker/docker-compose.yml logs -f api

# Database migrate
docker-compose -f docker/docker-compose.yml exec api alembic upgrade head

# Backup database
pg_dump scanner_production | gzip > backup.sql.gz

# Health check
curl http://localhost:8000/health

# Metrics
curl http://localhost:8000/metrics
```

---

## Support

Deployment sorunlari icin:
- Email: halilberkaysahin@gmail.com
- Documentation: `docs/README.md`
- GitHub Issues: https://github.com/halilberkayy/SENTINEL/issues
