"""Minimum app version (plan task P4.12): ``GET /api/v1/app/version/``.

The app calls this before login, on start. When its own version is lower than
the ``min_app_version`` for its platform it shows an "update" screen with that
platform's store link. Values come from the ``MIN_APP_VERSION`` settings
(``_ANDROID`` / ``_IOS`` override the shared one). A blank or malformed value
means ``"0.0.0"``, so a typo in the environment never locks everyone out.

The path is under ``/api/``, which ``LoginCheckMiddleWare`` always lets
through, so it needs no allow-list entry.
"""

import logging
import re

from django.conf import settings
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

logger = logging.getLogger(__name__)

NO_MINIMUM = "0.0.0"
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def _checked(name):
    """Setting ``name`` if it looks like ``1.2.3``; blank if unset or malformed."""
    value = getattr(settings, name)
    if value and not _VERSION.match(value):
        logger.warning("%s=%r is not like 1.2.3; ignoring it.", name, value)
        return ""
    return value


def min_app_version(platform=None):
    """The minimum for ``platform`` ("android"/"ios"), else the shared one, else 0.0.0."""
    if platform:
        value = _checked(f"MIN_APP_VERSION_{platform.upper()}")
        if value:
            return value
    return _checked("MIN_APP_VERSION") or NO_MINIMUM


class AppVersionView(APIView):
    # Public and token-free: an old or expired token must not stop the check.
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        return Response(
            {
                # For the web app at /app/ and anything without a platform.
                "min_app_version": min_app_version(),
                "android": {
                    "min_app_version": min_app_version("android"),
                    "store_url": settings.APP_STORE_URL_ANDROID,
                },
                "ios": {
                    "min_app_version": min_app_version("ios"),
                    "store_url": settings.APP_STORE_URL_IOS,
                },
            }
        )
