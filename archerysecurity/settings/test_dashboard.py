"""Isolated regression tests; never connect to the configured application DB."""
from .base import *  # noqa: F403,F401

INSTALLED_APPS = [app for app in INSTALLED_APPS if app not in (
    "stronghold", "debug_toolbar", "sitetree",
    "rest_framework_simplejwt.token_blacklist",
)]
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
# These regressions exercise the current models, not historical scanner migrations
# that import optional scanner/encryption dependencies.
MIGRATION_MODULES = {app: None for app in INSTALLED_APPS
                     if not app.startswith("django.") and app not in (
                         "notifications", "rest_framework.authtoken")}
ROOT_URLCONF = "dashboard.test_urls"
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
}
TEMPLATES[0]["OPTIONS"]["context_processors"] = [
    item for item in TEMPLATES[0]["OPTIONS"]["context_processors"]
    if item != "django_settings_export.settings_export"
]
LOGGING = {}
