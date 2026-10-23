"""Deployment safety checks.

Registered in MainAppConfig.ready(); they run on `manage.py check`,
`check --deploy`, `migrate`, and every server start.
"""

from django.conf import settings
from django.core.checks import Warning, register


@register(deploy=True)
def check_media_storage_persistence(app_configs, **kwargs):
    """Warn when production uploads would not survive a redeploy.

    Uploads are safe when either:
      - an S3/Spaces bucket is the default storage backend, or
      - MEDIA_ROOT points outside the repo clone (so git operations,
        re-clones, and platform rebuilds can't delete it).
    """
    errors = []

    if settings.DEBUG:
        return errors

    default_backend = settings.STORAGES.get("default", {}).get("BACKEND", "")
    uses_object_storage = "s3" in default_backend.lower()
    if uses_object_storage:
        return errors

    media_root = str(settings.MEDIA_ROOT)
    base_dir = str(settings.BASE_DIR)
    if media_root.startswith(base_dir):
        errors.append(
            Warning(
                "User uploads are stored inside the repository directory "
                f"({media_root}) with no object storage configured. "
                "A re-clone, `git clean`, or platform redeploy will DELETE "
                "every uploaded file (profile pictures, chat attachments, "
                "story images, result files).",
                hint=(
                    "Either set DJANGO_MEDIA_ROOT to a directory outside the "
                    "repo (e.g. /home/iceberg/media) or configure DigitalOcean "
                    "Spaces via SPACES_KEY / SPACES_SECRET / SPACES_BUCKET. "
                    "See .env.example."
                ),
                id="main_app.W001",
            )
        )
    return errors


@register(deploy=True)
def check_registration_leads_token(app_configs, **kwargs):
    """Warn when the public lead endpoint has no token in production.

    Without REGISTRATION_LEADS_API_TOKEN the endpoint refuses every lead
    (503) outside DEBUG, so website enquiries would be lost.
    """
    if settings.DEBUG or getattr(settings, "REGISTRATION_LEADS_API_TOKEN", "").strip():
        return []
    return [
        Warning(
            "REGISTRATION_LEADS_API_TOKEN is not set, so /public/registration-leads/ "
            "rejects every website lead with HTTP 503.",
            hint=(
                "Set REGISTRATION_LEADS_API_TOKEN to a long random value and give the same "
                "value to the iceberglc.com website. See .env.example."
            ),
            id="main_app.W002",
        )
    ]
