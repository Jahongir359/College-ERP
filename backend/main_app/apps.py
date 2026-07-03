from django.apps import AppConfig
from django.conf import settings
import os


class MainAppConfig(AppConfig):
    name = "main_app"

    def ready(self):
        from django.db.models.signals import post_migrate

        from . import checks  # noqa: F401 — registers deployment checks

        # Seed admin accounts after migrations complete.  We intentionally
        # avoid any DB calls here — doing so triggers Django's "Accessing the
        # database during app initialization is discouraged" RuntimeWarning and
        # can fail on a fresh database before migrations have run.
        post_migrate.connect(create_default_test_admin, dispatch_uid="main_app.seed_test_admin")
        post_migrate.connect(
            create_recovery_admin_access, dispatch_uid="main_app.seed_recovery_admin"
        )


def create_default_test_admin(sender, **kwargs):
    # Create a predictable admin account only for local debug/testing use.
    if not settings.DEBUG:
        return

    from django.contrib.auth import get_user_model

    user_model = get_user_model()
    email = os.environ.get("TEST_ADMIN_EMAIL", "admin@test.com")
    password = os.environ.get("TEST_ADMIN_PASSWORD", "admin123")

    user, created = user_model.objects.get_or_create(
        email=email,
        defaults={
            "first_name": "Test",
            "last_name": "Admin",
            "user_type": "1",
            "gender": "M",
            "address": "Test Admin Account",
            "profile_pic": "",
            "is_staff": True,
            "is_superuser": True,
            "is_active": True,
        },
    )

    # Keep local debug login deterministic even if the record already exists.
    user.first_name = user.first_name or "Test"
    user.last_name = user.last_name or "Admin"
    user.user_type = "1"
    user.gender = user.gender or "M"
    user.address = user.address or "Test Admin Account"
    user.is_staff = True
    user.is_superuser = True
    user.is_active = True
    user.set_password(password)
    user.save()


def create_recovery_admin_access(sender, **kwargs):
    """Bootstrap a recovery super admin on a brand-new system ONLY.

    The recovery account is seeded from RECOVERY_ADMIN_* env config the first
    time the system comes up with no admins. After that it is an ordinary super
    admin account: a super admin can change its email/password or delete it from
    the UI, and those changes are permanent. We must therefore NEVER recreate or
    overwrite it once any admin exists — otherwise editing or deleting it would
    silently come back as a duplicate.
    """
    recovery_enabled = os.environ.get("RECOVERY_ADMIN_ENABLED", "1").strip().lower() not in {
        "0",
        "false",
        "no",
    }
    if not recovery_enabled:
        return

    from django.contrib.auth import get_user_model

    user_model = get_user_model()
    recovery_email = (
        os.environ.get("RECOVERY_ADMIN_EMAIL", "iceberg.edu.center@gmail.com").strip().lower()
    )
    recovery_password = os.environ.get("RECOVERY_ADMIN_PASSWORD", "").strip()
    # Never fall back to a known weak password in production. A dev convenience
    # default is fine under DEBUG; in production an unset password yields an
    # unusable-password account (must be set via the reset flow) instead of a
    # publicly-known "iceberg" super admin — closing a full-takeover landmine.
    if not recovery_password and settings.DEBUG:
        recovery_password = "iceberg"

    if not recovery_email:
        return

    # Bootstrap only on a fresh system. The moment any admin (user_type "1")
    # exists, the recovery account is fully UI-managed and must not be
    # auto-(re)created — this is what makes credential changes and deletion
    # ("self destruct") stick instead of reappearing as a duplicate.
    if user_model.objects.filter(user_type="1").exists():
        return

    user = user_model.objects.create(
        email=recovery_email,
        first_name="Recovery",
        last_name="Admin",
        user_type="1",
        gender="M",
        address="Production recovery account",
        is_staff=True,
        is_superuser=True,
        is_active=True,
    )
    if recovery_password:
        user.set_password(recovery_password)
    else:
        user.set_unusable_password()
    user.save()
