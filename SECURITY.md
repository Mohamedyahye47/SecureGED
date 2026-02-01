# Secure GED Security Implementation Report

## Overview

This document describes the security hardening of the Secure GED (Gestion Électronique de Documents) project to align with the v2 workflow specification. The implementation follows **Zero Trust** principles and **Defense in Depth** architecture.

**Project Status**: ✅ **Phase 1-4 Complete** | 🔄 **Phase 5-6 In Progress**

---

## 1. Identity, Access & Session Establishment

### ✅ Implemented Features

#### Session ID Regeneration After Authentication
- **File**: `documents/views.py` (login_view)
- **Implementation**: 
  - `request.session.flush()` clears old session before login
  - `login()` creates authenticated session
  - `request.session.create()` generates new session ID post-auth
  - Prevents session fixation attacks
  
```python
# After authentication succeeds
request.session.flush()  # Clear old session
login(request, user)
request.session.create()  # New session ID
request.session['login_time'] = timezone.now().timestamp()
```

#### Hardened Cookie Flags
- **File**: `config/settings.py`
- **Flags Set**:
  - `SESSION_COOKIE_HTTPONLY = True` → Prevents XSS cookie theft
  - `CSRF_COOKIE_HTTPONLY = True` → CSRF token protected
  - `SESSION_COOKIE_SAMESITE = 'Strict'` → No cross-site cookies
  - `CSRF_COOKIE_SAMESITE = 'Strict'` → CSRF protected
  - Production: `SESSION_COOKIE_SECURE = True`, `CSRF_COOKIE_SECURE = True` (HTTPS only)
  - Production: `SECURE_HSTS_SECONDS = 31536000` (HSTS enabled)

#### Progressive Rate Limiting (No Account Lockout DoS)
- **File**: `documents/rate_limiting_middleware.py`
- **Algorithm**: Exponential backoff with configurable delays
  - After 3 failed attempts: 1 second delay
  - After 4 attempts: 2 seconds
  - After 5 attempts: 4 seconds
  - Capped at 60 seconds max
- **Prevents DoS** by not locking accounts permanently
- **Respects Windows**: 5-minute attempt window before reset
- **Configurable**: `RATE_LIMIT_LOGIN_ATTEMPTS`, `RATE_LIMIT_DELAY_*` in settings

#### MFA Enforcement Stubs
- **File**: `documents/security_decorators.py` (`@mfa_required` decorator)
- **Current Status**: Checks if MFA enabled; enforcement ready for TOTP/hardware key integration
- **TODO**: Integrate with:
  - `django-otp` for TOTP support
  - Hardware key libraries (u2f, webauthn)
  - LDAP/SAML for federated MFA

#### Audit Logging for Auth Events
- **File**: `documents/views.py` (login_view, logout_view)
- **Logged Events**:
  - Successful login (with timestamp, IP, user agent)
  - Failed login attempts (with attempt count)
  - Logout events
  - User not found errors
- **Prevents**: Silent account compromise; alerts on suspicious activity

### 🔄 Not Yet Implemented

- TOTP-based MFA (ready with decorator, needs HOTP library)
- WebAuthn/FIDO2 hardware keys
- IP reputation checks
- Device fingerprinting

---

## 2. Secure File Ingestion & Quarantine

### ✅ Implemented Features

#### File Ingestion Pipeline with Quarantine Zone
- **File**: `documents/file_ingestion_enhanced.py` (`EnhancedFileIngestionPipeline`)
- **Steps**:
  1. **File size validation** (fail fast)
  2. **Quarantine zone placement** → Isolated directory before processing
  3. **Magic number validation** → Binary signatures (not extensions)
  4. **Decompression bomb guards** → Zip/7z compression ratio checks
  5. **Antivirus scanning** → External AV engine integration with fallback
  6. **SHA-256 hashing** → Integrity tracking, duplicate detection
  7. **Duplicate check** → Reject if file hash exists
  8. **Encryption** → AES-256 per classification level
  9. **Final storage** → Move to permanent encrypted location

#### Magic Number Validation
- **File**: `documents/file_ingestion_enhanced.py`
- **Supported Types**:
  - PDF: `%PDF` (0x25504446)
  - ZIP: `PK\x03\x04` (0x504B0304)
  - MS Word 97-2003: `0xD0CF11E0`
  - JPEG: `0xFFD8FF`
  - PNG: `0x89504E47`
  - GIF: `0x474946`
- **Security**: Validates binary signature, not file extension

#### Decompression Bomb Protection
- **File**: `documents/file_ingestion_enhanced.py` (`DecompressionBombGuard`)
- **Checks**:
  - Uncompressed size limit: 100 MB
  - Compression ratio limit: 1000x (suspicious above this)
  - File count limit: 10,000 files max
- **Prevents**: Zip-bomb DoS attacks
- **Action**: Reject with detailed reason

#### Filename Sanitization
- **File**: `documents/file_ingestion_enhanced.py`
- **Sanitization**:
  - Remove path components (`../`, `./`)
  - Remove null bytes, control characters
  - Allow only: alphanumeric, dash, underscore, dot
  - Prevent multiple extensions (`.pdf.exe`)
  - Limit length to 200 chars
- **Prevents**: Path traversal, shell injection

#### Antivirus Integration Points
- **File**: `documents/file_ingestion_enhanced.py` (`AVScannerIntegration`)
- **Engines Supported**:
  - **ClamAV** (local): Requires `pyclamd` library and ClamAV daemon
  - **VirusTotal** (cloud): Requires API key (TODO)
  - **Mock** (development): Pattern matching (for testing)
- **Safe Failure**:
  - If AV unavailable: Log warning, permit upload (configurable)
  - If threat detected: Reject immediately
  - If suspicious: Quarantine for manual review
- **Configuration**: Set `AV_ENGINE` in settings (default: 'mock')

#### SHA-256 Integrity Hashing
- **File**: `documents/file_ingestion_enhanced.py`
- **Usage**:
  - Calculated on quarantined file
  - Stored in Document model
  - Used for duplicate detection
  - Enables file integrity verification at retrieval

### 🔄 Not Yet Implemented

- ClamAV integration (stubs ready, needs daemon)
- VirusTotal API integration
- Content sanitization (PDF script removal)
- YARA rule scanning for advanced threats

---

## 3. Secure Storage & Cryptography (Data at Rest)

### ✅ Implemented Features

#### AES-256 Encryption Before Persistence
- **File**: `documents/security.py` (FileIngestionPipeline.encrypt_file)
- **Mode**: AES-256 EAX (Encrypt-and-Authenticate)
- **Storage**: 
  - Nonce (16 bytes) + Tag (16 bytes) + Ciphertext
  - Files stored as `.enc` in classification-level subdirectories
- **Keys**: Derived per classification level using PBKDF2

#### Metadata Encryption
- **File**: `documents/security.py` (EncryptionManager)
- **Methods**:
  - `encrypt_metadata(text)` → Fernet encryption for DB fields
  - `decrypt_metadata(encrypted_text)` → Decryption on retrieval
  - `encrypt_sensitive_fields()` → Bulk encryption of document dicts
- **Use Cases**:
  - Document titles, descriptions
  - User notes, comments
  - Sensitive classification metadata

#### KMS/Vault Integration Boundary
- **File**: `documents/kms.py`
- **Providers**:
  - **LocalKMS**: Development only (keys from env vars)
  - **AWSKMSProvider**: AWS Key Management Service (TODO)
  - **HashiCorp Vault**: Vault server integration (TODO)
- **Pattern**: Envelope Encryption
  - Master key managed by KMS (never stored with data)
  - Data encryption key (DEK) wrapped by master key
  - Supports key rotation policies
  - **Critical**: Keys NEVER stored alongside ciphertext

#### Key Isolation From Encrypted Data
- **File**: `documents/kms.py` (EnvelopeEncryption)
- **Architecture**:
  - File encrypted with DEK
  - DEK wrapped with master key (from KMS)
  - Wrapped DEK stored with ciphertext, but master key external
  - Decryption requires access to KMS (can be revoked)

#### Key Rotation Hooks
- **File**: `documents/kms.py` (KeyRotationPolicy)
- **Interface**:
  - `should_rotate_key(key_id, last_rotation)` → Check if rotation needed
  - `schedule_rotation(key_id, date)` → Schedule future rotation
  - `execute_scheduled_rotations()` → Run rotations
- **Default**: 90-day rotation interval

#### Encrypted Backups (Interface)
- **File**: `documents/kms.py` (EncryptedBackup)
- **Status**: TODO - Interface ready for backup strategy implementation
- **Requirements**: Backups encrypted with different key than production data

### 🔄 Not Yet Implemented

- AWS KMS provider
- HashiCorp Vault integration
- Backup encryption strategy
- Key versioning and rollover
- Hardware security module (HSM) support

---

## 4. Authorization & Policy Enforcement

### ✅ Implemented Features

#### Deny-by-Default Access Model
- **File**: `documents/security_decorators.py` (`@deny_by_default` decorator)
- **Principle**: All access denied unless explicitly permitted
- **Implementation**:
  - View fails closed on permission errors
  - All denials logged to audit trail
  - Error messages generic (no information leakage)

#### Object-Level Permissions (OLP)
- **File**: `documents/models.py` (Document.can_access)
- **Logic**:
  1. User must be authenticated
  2. Check clearance level ≥ document classification
  3. Check if user is document uploader
  4. Check explicit user permissions
  5. Check department membership
  6. Default: DENY

#### Clearance × Classification Matrix
- **File**: `documents/models.py`
- **Clearance Levels**: 1-5 (Public → Top Secret)
- **Classification Levels**: 1-5 (Public → Top Secret)
- **Rule**: `user.clearance_level ≥ document.classification_level` required
- **Additional Checks**: Department, explicit permissions

#### Access Control Decorators
- **File**: `documents/security_decorators.py`
- **Decorators**:
  - `@deny_by_default` → Generic deny-by-default enforcement
  - `@require_clearance(min_level)` → Minimum clearance check
  - `@mfa_required` → MFA verification (when implemented)
  - `@login_required` → Django built-in

#### Upload Privilege Control
- **File**: `documents/views.py` (document_upload_view)
- **Rules**:
  - Level 3 (Confidential): Staff or higher
  - Level 4 (Secret): Superuser (admin) only
  - Levels 1-2: Any authenticated user

### 🔄 Not Yet Implemented

- Time-based access (e.g., 9-5 business hours only)
- Location-based access (e.g., VPN required)
- Action-type constraints (view vs. download)
- Attribute-based access control (ABAC)

---

## 5. Secure Retrieval & Protected View

### ✅ Implemented Features

#### Authenticated Proxy Endpoint (No Direct URLs)
- **File**: `documents/views.py` (document_download_view)
- **Pattern**: 
  - URL: `/document/<id>/download/` (not `/media/documents/...`)
  - Authentication required (`@login_required`)
  - Authorization check before decryption
- **Prevents**: Direct filesystem access, permission bypass

#### Final Authorization Check at View Time
- **File**: `documents/views.py` (document_download_view)
- **Check**: `can_view_document()` before decryption
- **Logging**: All denied access attempts

#### Decryption in RAM Only
- **File**: `documents/views.py` (document_download_view)
- **Process**:
  - Read encrypted file
  - Decrypt in memory (EncryptionManager)
  - Stream response to browser
  - RAM-only (no decrypted copy on disk)
- **Cleanup**: Python garbage collection frees decrypted data

#### Secure HTTP Streaming
- **File**: `documents/views.py` (document_download_view)
- **Headers**:
  - `Content-Disposition: inline` → For PDF viewing in browser
  - `X-Content-Type-Options: nosniff` → Prevent MIME sniffing
  - `X-Frame-Options: DENY` → No framing
- **Streaming**: HttpResponse streams encrypted data efficiently

### 🔄 Not Yet Implemented

- Watermarking policy for sensitive docs
- Rate limiting on downloads (prevent scraping)
- File access timeout (e.g., link expires in 1 hour)
- Download usage tracking (copy/print prevention)
- Client-side integrity verification

---

## 6. Audit, Traceability & Non-Repudiation

### ✅ Implemented Features

#### Comprehensive Event Logging
- **File**: `documents/views.py` + `documents/audit_models.py`
- **Events Logged**:
  - Login/logout
  - Document view/download/upload
  - Access denied (attempted unauthorized access)
  - MFA verification attempts
- **Per Event**: Timestamp, user, action, IP, user agent, success/failure

#### Append-Only Log Storage (WORM)
- **File**: `documents/audit_models.py` (WORMAuditLog)
- **Features**:
  - `auto_now_add=True` on timestamp (immutable)
  - `editable=False` on all fields
  - `on_delete=PROTECT` for user references (no orphaned logs)
  - `save()` override: Prevents modifications, raises `ValidationError`
  - `delete()` override: Prevents deletion, raises `ValidationError`
  - **DB Constraint**: Could add INSERT-only trigger (future)

#### Hash-Chaining for Integrity
- **File**: `documents/audit_models.py` (WORMAuditLog)
- **Algorithm**:
  - Each entry includes `previous_entry_hash` (links to prior entry)
  - Entry's `entry_hash` computed as SHA-256 of all fields
  - Tampering breaks chain (detected by `verify_log_integrity()`)
- **Verification**:
  - `entry.verify_integrity(previous_entry)` → Check single entry
  - `WORMAuditLog.verify_log_integrity()` → Verify entire chain

#### Restricted Audit Log Access
- **File**: `documents/audit_models.py` (RestrictedAuditAccess)
- **Model**: Links users to audit log access permissions
- **Permissions**:
  - `view_audit_log` → Can view logs
  - `export_audit_log` → Can export logs
  - `manage` → Can grant others access
- **Default**: Staff/superuser only
- **Expiration**: Optional time-based grants

#### Meta-Audit Trail
- **File**: `documents/audit_models.py` (AuditLogAccessTrail)
- **Tracks**: Who accessed the audit log, when, what they viewed
- **Purpose**: Accountability for audit log access itself
- **Events**: View, export, search, integrity verification

### 🔄 Not Yet Implemented

- Digital signatures on audit entries (PKI)
- Trusted time source synchronization (NTP, etc.)
- Audit log export to external SIEM
- Automated alerting on integrity failures
- Legal chain-of-custody for e-discovery

---

## Security Testing

### Automated Tests
- **Location**: `documents/tests.py`
- **Coverage**:
  - Authentication workflows
  - File ingestion pipeline
  - Permission checks
  - Session management
- **Run Tests**: `python manage.py test documents -v 2`

### Manual Security Checklist

- [ ] **Auth**: Test login with invalid credentials, account lockout behavior
- [ ] **Rate Limiting**: Attempt 10+ logins in 30 seconds; verify delays increase
- [ ] **MFA**: Verify MFA check blocks access if enabled
- [ ] **File Upload**: 
  - [ ] Try uploading .exe, .sh (should reject)
  - [ ] Try zip bomb (10MB→1TB compression ratio)
  - [ ] Try PDF with malicious scripts
- [ ] **Permissions**: Log in as low-clearance user; attempt viewing Secret docs
- [ ] **Download**: Decrypt large file; verify not written to disk
- [ ] **Audit**: Check audit logs for all access events; verify immutability

---

## Deployment Checklist

### Before Going to Production

1. **Environment Variables** (`.env`):
   ```
   DEBUG=False
   SECRET_KEY=<generate-new-key>
   ALLOWED_HOSTS=yourdomain.com
   DB_ENGINE=postgresql
   DB_NAME=secure_ged_prod
   DB_USER=<strong-password>
   DB_PASSWORD=<strong-password>
   ENCRYPTION_KEY=<Fernet-key>
   AV_ENGINE=clamav  # or virustotal
   ```

2. **Django Settings**:
   - [ ] `DEBUG = False`
   - [ ] `SECURE_SSL_REDIRECT = True`
   - [ ] `SESSION_COOKIE_SECURE = True`
   - [ ] `CSRF_COOKIE_SECURE = True`
   - [ ] `SECURE_HSTS_SECONDS = 31536000`

3. **Database**:
   - [ ] Run migrations: `python manage.py migrate`
   - [ ] Run security check: `python manage.py check --deploy`

4. **External Services**:
   - [ ] ClamAV daemon running (if using ClamAV)
   - [ ] KMS (AWS, Vault) configured and accessible
   - [ ] NTP synchronized for trusted time

5. **File Permissions**:
   - [ ] Quarantine dir: `700` (rwx------)
   - [ ] Secure storage: `700` (rwx------)
   - [ ] Key files: `600` (rw-------)

6. **HTTPS/TLS**:
   - [ ] Valid SSL certificate (not self-signed)
   - [ ] HSTS preload enabled
   - [ ] TLS 1.2+ only

---

## Known Limitations & TODOs

### Infrastructure Not Yet Available

| Feature | Status | Blocker |
|---------|--------|---------|
| AWS KMS / HashiCorp Vault | TODO | Requires account/deployment |
| ClamAV Integration | TODO | Requires daemon setup |
| VirusTotal API | TODO | Requires API key |
| Hardware Security Module (HSM) | TODO | Infrastructure requirement |
| SIEM Integration | TODO | External service |
| LDAP/SAML MFA | TODO | IdP setup required |

### Current Mitigations

- **Local KMS**: Development uses environment variables; safe for testing
- **Mock AV Scanner**: Pattern matching; upgrade to ClamAV in production
- **File Sanitization**: Currently pattern-based; integrate advanced tools if needed
- **TOTP MFA**: Decorator ready; integrate django-otp when needed

---

## Configuration Reference

### Critical Settings

```python
# config/settings.py

# Security
DEBUG = False  # MUST be False in production
SECRET_KEY = env('DJANGO_SECRET_KEY')  # Generate with get_random_secret_key()

# Sessions
SESSION_COOKIE_SECURE = True  # HTTPS only
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 3600  # 1 hour

# Encryption
ENCRYPTION_KEY = env('ENCRYPTION_KEY')  # Fernet key from .env
AV_ENGINE = 'clamav'  # or 'virustotal', 'mock'

# Rate Limiting
MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_TIMEOUT = 900  # 15 min
RATE_LIMIT_DELAY_MAX = 60  # Max delay (seconds)

# File Upload
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
QUARANTINE_ROOT = BASE_DIR / 'quarantine'
MEDIA_ROOT = BASE_DIR / 'secure_storage'
```

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Django Security Documentation](https://docs.djangoproject.com/en/stable/topics/security/)
- [RFC 3394 - AES Key Wrap](https://tools.ietf.org/html/rfc3394)

---

## Support & Questions

For security issues, contact the security team. Do **not** report in public issue trackers.

**Last Updated**: 2026-01-24
**Security Review**: Required before production deployment
