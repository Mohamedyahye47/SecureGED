from pathlib import Path
from decouple import config as env_config

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env_config('DJANGO_SECRET_KEY')

# ✅ MODE DEBUG
DEBUG = env_config('DEBUG', default=False, cast=bool)
ALLOWED_HOSTS = ['localhost', '127.0.0.1']


# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Apps tierces
    'django.contrib.sites',
    # Vos apps
    'core',
    'documents',
    'audit',

]
SITE_ID = 2
SITE_URL = 'http://127.0.0.1:8000'


MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'documents.rate_limiting_middleware.ProgressiveRateLimitMiddleware',
    'documents.rate_limiting_middleware.SessionSecurityMiddleware',
    'documents.profile_completion_middleware.ProfileCompletionMiddleware',
    'documents.middleware.RestrictAdminMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'documents.context_processors.global_context',

            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

# Database - PostgreSQL
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env_config('DB_NAME'),
        'USER': env_config('DB_USER'),
        'PASSWORD': env_config('DB_PASSWORD'),
        'HOST': env_config('DB_HOST'),
        'PORT': env_config('DB_PORT'),
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 12}
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# --- SÉCURITÉ & COOKIES (CRITIQUE POUR OAUTH) ---

SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_SAVE_EVERY_REQUEST = True

# ⚠️ MODIFIÉ : Doit être False pour éviter de perdre la session pendant la redirection
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# ⚠️ MODIFIÉ : Configuration stricte Production vs Développement
if not DEBUG:
    # PRODUCTION SETTINGS
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'

    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_SSL_REDIRECT = True

    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

    # En Prod, Strict ou Lax est bien si tout est en HTTPS
    SESSION_COOKIE_SAMESITE = 'Lax'
    CSRF_COOKIE_SAMESITE = 'Lax'

    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_HTTPONLY = True

else:
    # DEVELOPMENT SETTINGS (Localhost)
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'  # Ou 'SAMEORIGIN' si besoin d'iframes

    # IMPÉRATIF POUR OAUTH EN LOCAL (HTTP)
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False

    # ⚠️ 'Lax' est obligatoire pour que le cookie survive au retour de Google
    SESSION_COOKIE_SAMESITE = 'Lax'
    CSRF_COOKIE_SAMESITE = 'Lax'

    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_HTTPONLY = True

# Login attempts protection
MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_TIMEOUT = 900
RATE_LIMIT_LOGIN_ATTEMPTS = 3
RATE_LIMIT_DELAY_BASE = 1
RATE_LIMIT_DELAY_MAX = 60
RATE_LIMIT_WINDOW = 300

# File Upload Settings
QUARANTINE_ROOT = BASE_DIR / 'quarantine'
MAX_UPLOAD_SIZE = 50 * 1024 * 1024

ALLOWED_FILE_TYPES = {
    'application/pdf': ['.pdf'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
    'application/msword': ['.doc'],
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
}

ENCRYPTION_KEY = env_config('ENCRYPTION_KEY')

# Audit Settings
AUDIT_LOG_DIR = BASE_DIR / 'audit_logs'

# Internationalization
LANGUAGE_CODE = 'fr-fr'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
# MEDIA_URL pour l'accès web (si nécessaire)
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

AUTO_APPROVE_OAUTH_DOMAINS = [
    'votreuniversite.edu',
    'departement-approuve.gov',
]


# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Login URL
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'dashboard'
LOGOUT_REDIRECT_URL = 'login'

# Google OAuth Configuration
GOOGLE_OAUTH_CLIENT_ID = env_config('GOOGLE_OAUTH_CLIENT_ID')
GOOGLE_OAUTH_CLIENT_SECRET = env_config('GOOGLE_OAUTH_CLIENT_SECRET')
GOOGLE_OAUTH_REDIRECT_URI = env_config('GOOGLE_OAUTH_REDIRECT_URI')



# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = '23647@isms.esp.mr'
EMAIL_HOST_PASSWORD = 'opff ueuv kvgu awcz'
DEFAULT_FROM_EMAIL = '23647@isms.esp.mr'