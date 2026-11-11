"""Forgotten password for parents: a code by SMS, then a new password (PL.2, D13).

Both endpoints are public and answer the same way whoever asks, so they don't tell
a stranger which login IDs or phone numbers exist. The rules are in ``parents_sms``.
"""

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from .. import parents_sms


class PasswordResetThrottle(AnonRateThrottle):
    """Per address, on top of the per-phone limits in ``parents_sms``."""

    scope = "password_reset"
    rate = "20/hour"


class _PublicView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]


class PasswordResetRequestView(_PublicView):
    def post(self, request):
        login_id = str(request.data.get("login_id") or "").strip()
        phone = str(request.data.get("phone") or "").strip()
        if not login_id or not phone:
            return Response(
                {"detail": _("Login ID and phone number are required.")},
                status=status.HTTP_400_BAD_REQUEST,
            )
        parents_sms.request_reset(login_id, phone)
        return Response(
            {
                "detail": _(
                    "If the login ID and phone number match, a code was sent by SMS. "
                    "It works for %(minutes)s minutes."
                )
                % {"minutes": parents_sms.CODE_MINUTES}
            }
        )


class PasswordResetConfirmView(_PublicView):
    def post(self, request):
        login_id = str(request.data.get("login_id") or "").strip()
        code = str(request.data.get("code") or "").strip()
        password = str(request.data.get("new_password") or "")
        if not login_id or not code or not password:
            return Response(
                {"detail": _("Login ID, code and new password are required.")},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            validate_password(password)
        except ValidationError as error:
            return Response({"new_password": error.messages}, status=status.HTTP_400_BAD_REQUEST)
        # Plain 400 responses, not exceptions: the wrong-try counter must be saved.
        if not parents_sms.confirm_reset(login_id, code, password):
            return Response(
                {
                    "detail": _("The code is wrong or no longer works. Ask for a new one."),
                    "code": "invalid_code",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response({"detail": _("Password changed. Sign in with the new password.")})
