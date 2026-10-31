import dj_database_url
import os
import sys
from datetime import timedelta
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

BASE_DIR = Path(__file__).resolve().parent.parent

_MANAGEMENT_COMMANDS_ALLOWING_INSECURE_DEFAULTS = {
    "check",
    "collectstatic",
    "compilemessages",
    "makemessages",
    "makemigrations",
    "migrate",
    "showmigrations",
    "shell",
    "test",
}
_ALLOW_INSECURE_CONFIG_DEFAULTS = (
    len(sys.argv) > 1
    and Path(sys.argv[0]).name == "manage.py"
    and sys.argv[1] in _MANAGEMENT_COMMANDS_ALLOWING_INSECURE_DEFAULTS
)

# Load .env only when the file exists (local development).
if load_dotenv is not None:
    load_dotenv(BASE_DIR / ".env")

# ---------------------------------------------------------------------------
# Core security
# ---------------------------------------------------------------------------

# Default to False so production is safe without any extra configuration.
# Set DJANGO_DEBUG=True in .env for local development.
DEBUG = os.environ.get("DJANGO_DEBUG", "False").strip().lower() not in ("0", "false", "no")

# Always require an explicit secret key in production.
# Fallback is only kept so `manage.py` commands work in a fresh clone
# before the developer has created their .env file.
_secret_key_fallback = "f2zx8*lb*em*-*b+!&1lpp&$_9q9kmkar+l3x90do@s(+sr&x7"
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", _secret_key_fallback)
if not DEBUG and SECRET_KEY == _secret_key_fallback and not _ALLOW_INSECURE_CONFIG_DEFAULTS:
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set when DJANGO_DEBUG is False.")

# Comma-separated list, e.g. "myapp.ondigitalocean.app,www.myschool.edu"
# Falls back to '*' when not set so collectstatic and other build-time
# management commands work without environment variables being available.
_allowed_hosts_env = os.environ.get("DJANGO_ALLOWED_HOSTS", "").strip()
if _allowed_hosts_env:
    ALLOWED_HOSTS = [h.strip() for h in _allowed_hosts_env.split(",") if h.strip()]
elif DEBUG or _ALLOW_INSECURE_CONFIG_DEFAULTS:
    ALLOWED_HOSTS = ["*"]
else:
    raise ImproperlyConfigured("DJANGO_ALLOWED_HOSTS must be set when DJANGO_DEBUG is False.")

# Required so CSRF accepts POSTs arriving via the HTTPS load-balancer, whose
# Origin (e.g. https://app.iceberglc.com) can differ from the internal Host.
# Set CSRF_TRUSTED_ORIGINS=https://app.iceberglc.com,https://iceberglc.com
CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",")
    if origin.strip()
]
if DEBUG:
    CSRF_TRUSTED_ORIGINS.extend(
        [
            "http://localhost",
            "http://127.0.0.1",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "https://*.app.github.dev",
        ]
    )
USE_X_FORWARDED_HOST = True

# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "axes",  # brute-force lockout
    "rest_framework",  # Django REST Framework
    "rest_framework_simplejwt",  # JWT auth
    "rest_framework_simplejwt.token_blacklist",  # JWT logout blacklist
    "corsheaders",  # CORS for mobile apps
    "main_app.apps.MainAppConfig",
]

MIDDLEWARE = [
    # CorsMiddleware must be as high as possible, before anything that generates responses.
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    # WhiteNoise must be directly after SecurityMiddleware and before all others.
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # Activates the user's chosen web language (uz/ru/en); needs request.user.
    "main_app.middleware.UserLanguageMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "main_app.middleware.LoginCheckMiddleWare",
    # Remembers the Iceberg brand in a cookie (no-op while SCHOOL_BRAND_ENABLED is off).
    "main_app.middleware.BrandCookieMiddleware",
    # Axes must come AFTER AuthenticationMiddleware so request.user is set.
    "axes.middleware.AxesMiddleware",
]

ROOT_URLCONF = "college_management_system.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        # Absolute path — works regardless of the working directory gunicorn starts from.
        "DIRS": [BASE_DIR / "main_app" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "main_app.context_processors.notification_count",
                "main_app.context_processors.student_theme",
                "main_app.context_processors.brand",
                "main_app.context_processors.school_nav",
            ],
        },
    },
]

WSGI_APPLICATION = "college_management_system.wsgi.application"

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# Default to SQLite for local development.
# In production set DATABASE_URL to a PostgreSQL URL, e.g.:
#   postgres://user:pass@host:5432/dbname
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# Override with DATABASE_URL env var when present (Digital Ocean managed DB).
# conn_max_age=0: disable persistent connections. Django 3.1 has no CONN_HEALTH_CHECKS,
# so reusing a connection that PostgreSQL already closed raises OperationalError → 500.
_db_from_env = dj_database_url.config(conn_max_age=0, ssl_require=not DEBUG)
DATABASES["default"].update(_db_from_env)
DATABASES["default"]["ATOMIC_REQUESTS"] = True

# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
# Used to memoise expensive dashboard aggregates (see main_app/api/views.py).
# In production set REDIS_URL (or CACHE_URL) to a redis:// URL so the cache is
# shared across gunicorn workers; otherwise we fall back to a per-process
# in-memory cache that needs no extra service or dependency.
_redis_url = os.environ.get("REDIS_URL") or os.environ.get("CACHE_URL", "")
if _redis_url:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": _redis_url,
            "KEY_PREFIX": "erp",
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "erp-locmem",
        }
    }

# How long (seconds) dashboard aggregate stats are cached per user.
DASHBOARD_CACHE_TTL = int(os.environ.get("DASHBOARD_CACHE_TTL", "60"))

# ---------------------------------------------------------------------------
# Password validation
# ---------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# The default PBKDF2 hasher is deliberately slow; in the test runner that cost
# dominates the suite. Never applies outside `manage.py test`.
if "test" in sys.argv:
    PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

# ---------------------------------------------------------------------------
# Internationalisation
# ---------------------------------------------------------------------------

# Web languages (plan task P3.0, decision D17). English stays the default; each
# user picks theirs with the header switch (main_app.middleware.UserLanguageMiddleware).
LANGUAGE_CODE = "en"
LANGUAGES = [
    ("uz", "Oʻzbekcha"),
    ("ru", "Русский"),
    ("en", "English"),
]
LANGUAGE_COOKIE_NAME = "iceberg_language"
LANGUAGE_COOKIE_AGE = 365 * 24 * 60 * 60
# Translations live in backend/locale/<lang>/LC_MESSAGES/django.po; the .mo files are
# compiled in the build (`python manage.py compilemessages`), never committed.
LOCALE_PATHS = [BASE_DIR / "locale"]
TIME_ZONE = "Asia/Tashkent"
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Static & media files
# ---------------------------------------------------------------------------

STATIC_URL = "/static/"
# collectstatic copies everything here; WhiteNoise serves from here.
STATIC_ROOT = BASE_DIR / "staticfiles"

# Files in public/ are served by WhiteNoise at the site root (no /static/ prefix).
# This makes /favicon.ico, /manifest.json, /robots.txt, etc. publicly accessible
# at the paths browsers and crawlers expect to find them.
WHITENOISE_ROOT = BASE_DIR.parent / "infra" / "public"

MEDIA_URL = "/media/"
# Uploads must survive redeploys. On a VPS, set DJANGO_MEDIA_ROOT to a
# directory OUTSIDE the repo clone (e.g. /home/iceberg/media) so git
# operations and re-clones can never touch user uploads. The in-repo
# default is for local development only.
MEDIA_ROOT = Path(os.environ.get("DJANGO_MEDIA_ROOT") or (BASE_DIR / "media"))

# ---------------------------------------------------------------------------
# Media file storage — DigitalOcean Spaces (S3-compatible)
#
# Set these env vars in the DigitalOcean App Platform dashboard:
#   SPACES_KEY        — Spaces access key ID
#   SPACES_SECRET     — Spaces secret access key
#   SPACES_BUCKET     — bucket name, e.g. "iceberg-media"
#   SPACES_REGION     — region slug, e.g. "nyc3" or "fra1"
#   SPACES_ENDPOINT   — (optional) custom endpoint, defaults to
#                       https://{SPACES_REGION}.digitaloceanspaces.com
#
# When these vars are present, all profile pictures are stored on Spaces
# and survive every redeploy. Without them the app falls back to the local
# media/ directory (useful for local development).
# ---------------------------------------------------------------------------
_spaces_key = os.environ.get("SPACES_KEY", "")
_spaces_secret = os.environ.get("SPACES_SECRET", "")
_spaces_bucket = os.environ.get("SPACES_BUCKET", "")
_spaces_region = os.environ.get("SPACES_REGION", "nyc3")
_spaces_endpoint = os.environ.get(
    "SPACES_ENDPOINT",
    f"https://{_spaces_region}.digitaloceanspaces.com",
)

_use_spaces = bool(_spaces_key and _spaces_secret and _spaces_bucket)

if _use_spaces:
    AWS_ACCESS_KEY_ID = _spaces_key
    AWS_SECRET_ACCESS_KEY = _spaces_secret
    AWS_STORAGE_BUCKET_NAME = _spaces_bucket
    AWS_S3_ENDPOINT_URL = _spaces_endpoint
    AWS_S3_REGION_NAME = _spaces_region
    AWS_DEFAULT_ACL = "public-read"
    AWS_S3_FILE_OVERWRITE = False
    AWS_QUERYSTRING_AUTH = False
    # Serve files directly from the CDN subdomain
    AWS_S3_CUSTOM_DOMAIN = os.environ.get(
        "SPACES_CDN_DOMAIN",
        f"{_spaces_bucket}.{_spaces_region}.digitaloceanspaces.com",
    )
    MEDIA_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/"

# ---------------------------------------------------------------------------
# Storage backends — Django 4.2+ STORAGES API.
# IMPORTANT: Django 6 removed the legacy STATICFILES_STORAGE and
# DEFAULT_FILE_STORAGE settings. They are silently ignored, falling back to
# plain local/unhashed storage, unless configured here in STORAGES.
# ---------------------------------------------------------------------------
if DEBUG or "test" in sys.argv:
    # Plain storage: no hashing, works without running collectstatic.
    _staticfiles_backend = "django.contrib.staticfiles.storage.StaticFilesStorage"
else:
    # Fingerprinted files for production (cache-busting). manifest_strict=False
    # on the custom class makes missing entries fall back to the original path
    # instead of raising ValueError.
    _staticfiles_backend = "main_app.staticfiles_storage.NonStrictManifestStaticFilesStorage"

STORAGES = {
    # Media uploads: DigitalOcean Spaces (S3) when configured, else local disk.
    "default": {
        "BACKEND": "storages.backends.s3boto3.S3Boto3Storage"
        if _use_spaces
        else "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": _staticfiles_backend,
    },
}

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

AUTH_USER_MODEL = "main_app.CustomUser"

# Keep existing integer PKs — avoids a pointless migration that touches every table.
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# AxesStandaloneBackend must come FIRST so it can short-circuit
# authenticate() with AxesSignal-raised lockouts before the real
# email/password check runs.
AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesBackend",
    "main_app.EmailBackend.EmailBackend",
]

# ── Login brute-force protection (django-axes) ────────────────────────────────
# 5 failed attempts trigger a 15-minute lockout. Each list entry is tracked
# independently, so this locks a *username* after 5 failures from any IPs, and
# separately locks an *IP* after 5 failures across any usernames. (Use
# [["username", "ip_address"]] instead to lock only the exact pair.)
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(minutes=15)
AXES_LOCK_OUT_AT_FAILURE = True
AXES_RESET_ON_SUCCESS = True
AXES_LOCKOUT_PARAMETERS = ["username", "ip_address"]
AXES_USERNAME_FORM_FIELD = "identifier"  # doLogin posts ?identifier=
AXES_LOCKOUT_TEMPLATE = None  # use the JSON 403 default

# ---------------------------------------------------------------------------
# Sessions (Remember Me support)
# ---------------------------------------------------------------------------

SESSION_COOKIE_AGE = 3600  # 1 hour — auto-logout after inactivity (all roles)
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
# True so the 1-hour window slides forward on every request: active users stay
# signed in, but a session left idle for an hour expires server-side and the
# next request bounces to the login page. Empty (anonymous) sessions are not
# written, so the login-page GET still avoids a DB write.
SESSION_SAVE_EVERY_REQUEST = True

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
EMAIL_USE_TLS = os.environ.get("EMAIL_USE_TLS", "True").strip().lower() not in ("0", "false", "no")
EMAIL_USE_SSL = os.environ.get("EMAIL_USE_SSL", "False").strip().lower() in ("1", "true", "yes")
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.environ.get(
    "DEFAULT_FROM_EMAIL", EMAIL_HOST_USER or "noreply@iceberg-erp.local"
)

# Optional Google reCAPTCHA. Disabled unless explicitly enabled so missing or
# hostname-mismatched keys cannot lock users out in production.
CAPTCHA_ENABLED = os.environ.get("CAPTCHA_ENABLED", "False").strip().lower() in (
    "1",
    "true",
    "yes",
)
CAPTCHA_SITE_KEY = os.environ.get("CAPTCHA_SITE_KEY", "")
CAPTCHA_SECRET_KEY = os.environ.get("CAPTCHA_SECRET_KEY", "")

# Token expected by the public lead receiver. The external website should send:
# Authorization: Bearer <REGISTRATION_LEADS_API_TOKEN>
REGISTRATION_LEADS_API_TOKEN = os.environ.get("REGISTRATION_LEADS_API_TOKEN", "").strip()

# Push notifications (FCM HTTP v1, P2.8): the Firebase service-account key as one JSON
# string. Empty = push off. Never commit it; set it as a secret env var.
FCM_SERVICE_ACCOUNT_JSON = os.environ.get("FCM_SERVICE_ACCOUNT_JSON", "").strip()
# Tests send on the calling thread instead of a background one.
FCM_SEND_INLINE = False

# Iceberg School brand (see docs/plans/ICEBERG_SCHOOL_BRAND_PLAN.md). While off,
# every request resolves to the Learning Center brand, so nothing changes.
SCHOOL_BRAND_ENABLED = os.environ.get("SCHOOL_BRAND_ENABLED", "False").strip().lower() in (
    "1",
    "true",
    "yes",
)

# Oldest app version still supported (plan task P4.12). The app reads it from
# GET /api/v1/app/version/ before login and asks for an update when it is older.
# The _ANDROID / _IOS values override MIN_APP_VERSION for one store (store review
# can hold one platform back). Blank or malformed means "0.0.0": never blocks.
MIN_APP_VERSION = os.environ.get("MIN_APP_VERSION", "").strip()
MIN_APP_VERSION_ANDROID = os.environ.get("MIN_APP_VERSION_ANDROID", "").strip()
MIN_APP_VERSION_IOS = os.environ.get("MIN_APP_VERSION_IOS", "").strip()
# Store pages the app's "update" screen opens; blank until the listings exist (P5).
APP_STORE_URL_ANDROID = os.environ.get("APP_STORE_URL_ANDROID", "").strip()
APP_STORE_URL_IOS = os.environ.get("APP_STORE_URL_IOS", "").strip()
# Page the QR code on printed parent login letters opens (PL.1); one link for both
# phones, e.g. a page with both store buttons. Blank: this site's /download/ page.
APP_DOWNLOAD_URL = os.environ.get("APP_DOWNLOAD_URL", "").strip()

if EMAIL_HOST_USER and EMAIL_HOST_PASSWORD:
    # Full SMTP — used in production when credentials are configured.
    EMAIL_BACKEND = "main_app.mail_backends.CompatibleSMTPEmailBackend"
elif DEBUG:
    # Development without SMTP: save emails to files so reset links are readable.
    EMAIL_BACKEND = "django.core.mail.backends.filebased.EmailBackend"
    EMAIL_FILE_PATH = BASE_DIR / "sent_emails"
    EMAIL_FILE_PATH.mkdir(exist_ok=True)  # auto-create directory if missing
else:
    # Production without SMTP credentials: print to stdout (visible in DO logs).
    # Set EMAIL_HOST_USER + EMAIL_HOST_PASSWORD in the App Platform console
    # to switch to real delivery.
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# ── Auth ──────────────────────────────────────────────────────────────────────
LOGIN_URL = "/login/"

# ---------------------------------------------------------------------------
# Logging — surface 500 errors in Digital Ocean App Platform logs
# ---------------------------------------------------------------------------

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {process:d} {thread:d} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "WARNING",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        "django.request": {
            "handlers": ["console"],
            "level": "ERROR",
            "propagate": False,
        },
        "main_app": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

# ---------------------------------------------------------------------------
# Production security hardening
# ---------------------------------------------------------------------------

if not DEBUG:
    # Trust the X-Forwarded-Proto header set by Digital Ocean's proxy/load-balancer.
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

    # Redirect all HTTP → HTTPS (the proxy handles the actual TLS).
    SECURE_SSL_REDIRECT = True

    # Send HSTS header: browsers will enforce HTTPS for 1 year.
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

    # Keep cookies off non-HTTPS connections.
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

    # Prevent browsers from sniffing the content type.
    SECURE_CONTENT_TYPE_NOSNIFF = True

# ---------------------------------------------------------------------------
# Django REST Framework (mobile API - STEP 3)
# ---------------------------------------------------------------------------

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        # JWT, plus the first-login password change (PL.1).
        "main_app.api.authentication.PasswordChangeJWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
}

# ---------------------------------------------------------------------------
# SimpleJWT configuration
# ---------------------------------------------------------------------------

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
}

# ---------------------------------------------------------------------------
# CORS — allow Flutter apps on mobile and web clients
# ---------------------------------------------------------------------------

if DEBUG:
    # Development: allow all origins so the Flutter dev server can connect.
    CORS_ALLOW_ALL_ORIGINS = True
else:
    # Production: restrict to explicitly listed origins.
    # Set CORS_ALLOWED_ORIGINS=https://app.example.com,https://www.example.com
    _cors_origins_env = os.environ.get("CORS_ALLOWED_ORIGINS", "").strip()
    CORS_ALLOWED_ORIGINS = [o.strip() for o in _cors_origins_env.split(",") if o.strip()]

# Allow the Authorization header for JWT tokens.
CORS_ALLOW_HEADERS = [
    "accept",
    "accept-encoding",
    "authorization",
    "content-type",
    "dnt",
    "origin",
    "user-agent",
    "x-api-key",
    "x-csrftoken",
    "x-registration-token",
    "x-requested-with",
]

CORS_ALLOW_CREDENTIALS = True
