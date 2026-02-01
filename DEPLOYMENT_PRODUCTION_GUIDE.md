# Production Deployment Guide

**Secure GED v2 - Production Hardening Checklist**

---

## Prerequisites

- Ubuntu 20.04+ or equivalent Linux server
- PostgreSQL 12+
- Python 3.10+
- SSL/TLS certificate (Let's Encrypt or commercial)
- Optional: AWS KMS, HashiCorp Vault, ClamAV

---

## 1. Environment Configuration

### 1.1 Generate Production SECRET_KEY

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

Copy the output and set in `.env`:

```bash
DJANGO_SECRET_KEY=<generated-key>
```

### 1.2 Production .env Template

```dotenv
# ============ DJANGO SETTINGS ============
DJANGO_SECRET_KEY=<generate-new-key-above>
DEBUG=False
ALLOWED_HOSTS=secure-ged.example.com,www.secure-ged.example.com

# ============ DATABASE ============
DB_ENGINE=postgresql
DB_NAME=secure_ged_prod
DB_USER=ged_app
DB_PASSWORD=<generate-strong-password>
DB_HOST=postgres.example.com
DB_PORT=5432

# ============ ENCRYPTION ============
ENCRYPTION_KEY=<generate-256-bit-key-base64>
KMS_PROVIDER=aws  # or vault, local (dev only)
KMS_AWS_REGION=us-east-1
KMS_AWS_KEY_ID=arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID

# ============ SECURITY HEADERS ============
SECURE_HSTS_SECONDS=31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS=True
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True

# ============ ANTIVIRUS ============
CLAMAV_ENABLED=True
CLAMAV_HOST=clamav.example.com
CLAMAV_PORT=3310

# ============ MFA ============
MFA_ENABLED=True
TOTP_ISSUER=SecureGED
```

### 1.3 Generate Encryption Key

```bash
python -c "import os; import base64; key = os.urandom(32); print(base64.b64encode(key).decode())"
```

---

## 2. Database Setup

### 2.1 Create PostgreSQL User and Database

```bash
sudo -u postgres psql <<EOF
CREATE USER ged_app WITH PASSWORD '<strong-password>';
CREATE DATABASE secure_ged_prod OWNER ged_app;
GRANT CONNECT ON DATABASE secure_ged_prod TO ged_app;
GRANT USAGE ON SCHEMA public TO ged_app;
GRANT ALL PRIVILEGES ON SCHEMA public TO ged_app;
EOF
```

### 2.2 Run Migrations

```bash
export DJANGO_SETTINGS_MODULE=config.settings
python manage.py migrate --noinput
```

### 2.3 Enable Row-Level Security (Optional but Recommended)

```sql
-- Connect as superuser
psql -U postgres -d secure_ged_prod <<EOF
ALTER SCHEMA public OWNER TO postgres;
GRANT USAGE ON SCHEMA public TO ged_app;
GRANT ALL ON ALL TABLES IN SCHEMA public TO ged_app;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ged_app;

-- Create audit role (read-only)
CREATE USER ged_audit WITH PASSWORD '<audit-password>';
GRANT CONNECT ON DATABASE secure_ged_prod TO ged_audit;
GRANT USAGE ON SCHEMA public TO ged_audit;
GRANT SELECT ON documents_accesslog TO ged_audit;
GRANT SELECT ON documents_accesslog_id_seq TO ged_audit;

-- Append-only constraint on AccessLog
ALTER TABLE documents_accesslog DISABLE TRIGGER ALL;
CREATE TRIGGER append_only_trigger BEFORE UPDATE ON documents_accesslog
  FOR EACH ROW EXECUTE FUNCTION raise_immutable_violation();
ALTER TABLE documents_accesslog ENABLE TRIGGER ALL;
EOF
```

---

## 3. Application Setup

### 3.1 Create App User

```bash
sudo useradd -m -s /bin/bash ged_app
sudo usermod -aG www-data ged_app
```

### 3.2 Deploy Code

```bash
sudo -u ged_app git clone https://github.com/your-org/secure-ged.git /opt/secure_ged
cd /opt/secure_ged
sudo -u ged_app python -m venv venv
sudo -u ged_app venv/bin/pip install -r requirements.txt
```

### 3.3 Create Required Directories

```bash
sudo -u ged_app mkdir -p /opt/secure_ged/secure_storage/{documents,temp,quarantine}
sudo -u ged_app mkdir -p /opt/secure_ged/logs
sudo chmod 700 /opt/secure_ged/secure_storage
```

### 3.4 Collect Static Files

```bash
sudo -u ged_app python manage.py collectstatic --noinput
```

### 3.5 Create Superuser

```bash
sudo -u ged_app python manage.py createsuperuser
```

---

## 4. Web Server Configuration

### 4.1 Install Gunicorn

```bash
sudo -u ged_app /opt/secure_ged/venv/bin/pip install gunicorn
```

### 4.2 Create Systemd Service

**File:** `/etc/systemd/system/secure-ged.service`

```ini
[Unit]
Description=Secure GED Application
After=network.target postgresql.service

[Service]
Type=notify
User=ged_app
Group=www-data
WorkingDirectory=/opt/secure_ged
Environment="PATH=/opt/secure_ged/venv/bin"
Environment="DJANGO_SETTINGS_MODULE=config.settings"
EnvironmentFile=/opt/secure_ged/.env
ExecStart=/opt/secure_ged/venv/bin/gunicorn \
  --workers 4 \
  --worker-class sync \
  --bind unix:/run/secure_ged.sock \
  --access-logfile /opt/secure_ged/logs/access.log \
  --error-logfile /opt/secure_ged/logs/error.log \
  --log-level info \
  config.wsgi:application

SyslogIdentifier=secure-ged
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable secure-ged
sudo systemctl start secure-ged
```

### 4.3 Nginx Configuration

**File:** `/etc/nginx/sites-available/secure-ged`

```nginx
upstream secure_ged {
    server unix:/run/secure_ged.sock fail_timeout=0;
}

server {
    listen 80;
    server_name secure-ged.example.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name secure-ged.example.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/secure-ged.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/secure-ged.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;

    # Logging
    access_log /var/log/nginx/secure-ged.access.log;
    error_log /var/log/nginx/secure-ged.error.log;

    # Client upload size limit
    client_max_body_size 100M;

    # Proxy settings
    location / {
        proxy_pass http://secure_ged;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Static files caching
    location /static/ {
        alias /opt/secure_ged/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Deny access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
```

Enable:

```bash
sudo ln -s /etc/nginx/sites-available/secure-ged /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 5. SSL/TLS Setup

### 5.1 Let's Encrypt Certificate

```bash
sudo apt-get install certbot python3-certbot-nginx -y
sudo certbot certonly --nginx -d secure-ged.example.com
sudo certbot renew --dry-run
```

### 5.2 Auto-Renewal

```bash
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

---

## 6. KMS Integration

### 6.1 AWS KMS Setup

```bash
# Install AWS SDK
pip install boto3

# Configure credentials
aws configure
# Enter AWS Access Key ID, Secret Access Key, Region
```

Update `.env`:

```
KMS_PROVIDER=aws
KMS_AWS_REGION=us-east-1
KMS_AWS_KEY_ID=arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID
```

### 6.2 HashiCorp Vault Setup

```bash
# Install Vault SDK
pip install hvac

# Configure Vault
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=<your-token>
```

Update `.env`:

```
KMS_PROVIDER=vault
VAULT_ADDR=https://vault.example.com:8200
VAULT_TOKEN=<token>
VAULT_NAMESPACE=secure-ged
```

---

## 7. MFA Setup

### 7.1 TOTP Configuration

```bash
pip install pyotp qrcode
```

Users can generate TOTP secret via:

```python
import pyotp
secret = pyotp.random_base32()
# Generate QR code for scanning in authenticator app
```

### 7.2 Email Backup Codes

Implement backup code generation in `documents/security_decorators.py:mfa_required()`

---

## 8. Antivirus Integration

### 8.1 ClamAV Daemon Installation

```bash
sudo apt-get install clamav clamav-daemon -y
sudo freshclam  # Update virus definitions
sudo systemctl restart clamav-daemon
```

### 8.2 Update Integration

In `documents/security.py:_scan_with_antivirus()`:

```python
import pyclamd

def _scan_with_antivirus(self, file_path):
    """Scan file with ClamAV daemon"""
    clam = pyclamd.ClamD(host='localhost', port=3310)
    result = clam.scan_file(file_path)
    if result:
        return False  # Virus detected
    return True  # Clean
```

---

## 9. Monitoring & Logging

### 9.1 Log Aggregation

```bash
pip install python-syslog
```

Configure centralized logging to ELK stack or CloudWatch

### 9.2 Audit Log Monitoring

```bash
# Query recent access logs
python manage.py shell <<EOF
from documents.models import AccessLog
failed = AccessLog.objects.filter(success=False).order_by('-timestamp')[:10]
for log in failed:
    print(f"{log.timestamp} | {log.action} | {log.user} | {log.ip_address}")
EOF
```

### 9.3 Monitoring Dashboard

Install monitoring tools:

```bash
pip install prometheus-django django-extensions
```

Expose metrics at `/metrics/` for Prometheus

---

## 10. Security Hardening

### 10.1 OS Level Hardening

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Enable UFW firewall
sudo ufw enable
sudo ufw allow 22/tcp  # SSH
sudo ufw allow 80/tcp  # HTTP
sudo ufw allow 443/tcp # HTTPS

# Disable unused services
sudo systemctl disable cups
sudo systemctl disable avahi-daemon
```

### 10.2 SSH Hardening

**File:** `/etc/ssh/sshd_config`

```bash
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
```

Restart SSH:

```bash
sudo systemctl restart ssh
```

### 10.3 File Permissions

```bash
sudo chown -R ged_app:www-data /opt/secure_ged
sudo chmod 750 /opt/secure_ged
sudo chmod 700 /opt/secure_ged/secure_storage
sudo chmod 600 /opt/secure_ged/.env
```

---

## 11. Backup & Disaster Recovery

### 11.1 Database Backup

```bash
# Daily backup script
cat > /opt/secure_ged/backup.sh <<'EOF'
#!/bin/bash
BACKUP_DIR="/opt/secure_ged/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

pg_dump -U ged_app secure_ged_prod | gzip > $BACKUP_DIR/db_$TIMESTAMP.sql.gz

# Keep only last 30 days
find $BACKUP_DIR -name "db_*.sql.gz" -mtime +30 -delete
EOF

chmod +x /opt/secure_ged/backup.sh

# Cron job (daily at 2 AM)
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/secure_ged/backup.sh") | crontab -
```

### 11.2 Document Archive Backup

```bash
# Sync encrypted documents to S3
pip install boto3
aws s3 sync /opt/secure_ged/secure_storage/documents s3://backup-bucket/secure-ged-docs/ --sse AES256
```

---

## 12. Pre-Production Checklist

- [ ] Generate new `SECRET_KEY`
- [ ] Set `DEBUG = False`
- [ ] Set `ALLOWED_HOSTS` correctly
- [ ] Enable `SECURE_SSL_REDIRECT`
- [ ] Enable `SECURE_HSTS_SECONDS`
- [ ] Set `SESSION_COOKIE_SECURE = True`
- [ ] Set `CSRF_COOKIE_SECURE = True`
- [ ] Configure PostgreSQL with strong password
- [ ] Set up SSL/TLS certificate
- [ ] Create app user with limited permissions
- [ ] Create required directories with correct permissions
- [ ] Run `python manage.py check --deploy` (should have 0 errors)
- [ ] Run test suite: `python manage.py test documents.tests`
- [ ] Set up KMS provider (AWS/Vault)
- [ ] Configure MFA infrastructure
- [ ] Install and configure ClamAV
- [ ] Set up logging and monitoring
- [ ] Configure backups (database + documents)
- [ ] Set up SSL certificate auto-renewal
- [ ] Test disaster recovery procedure
- [ ] Conduct security audit
- [ ] Document infrastructure

---

## 13. Post-Deployment Verification

```bash
# Check Django setup
python manage.py check --deploy

# Run security tests
python manage.py test documents.tests -v 2

# Verify migrations applied
python manage.py showmigrations

# Test access to admin
curl -I https://secure-ged.example.com/admin/

# Check Nginx
sudo nginx -t

# Verify Gunicorn service
sudo systemctl status secure-ged

# Test file upload (manual via web interface)
# Test document access
# Test audit logging
# Verify encryption at rest (ls -la /opt/secure_ged/secure_storage/documents/)
```

---

## 14. Emergency Contacts & Escalation

- **Security Incident:** security@example.com
- **Infrastructure:** ops@example.com
- **Database Admin:** dba@example.com
- **On-Call:** Use PagerDuty/similar

---

**Last Updated:** January 24, 2026  
**Version:** 1.0 (Production-Ready)
