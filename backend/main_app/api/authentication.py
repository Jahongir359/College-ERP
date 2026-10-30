"""JWT authentication that enforces the first-login password change (plan task PL.1).

When the office set a user's password (a new parent, a reset, a printed login
letter), ``CustomUser.must_change_password`` is true. Until the user picks their
own password, the API answers every request with 403 ``password_change_required``
except the few the app needs to show the change screen. The app reads the same
flag from ``me/`` and the login response.
"""

from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework_simplejwt.authentication import JWTAuthentication

# URL names (api/urls.py) a user may call before changing the password.
ALLOWED_BEFORE_CHANGE = {
    "api_me",
    "api_change_password",
    "api_logout",
    "api_fcm_token",
    "api_app_version",
}


class PasswordChangeRequired(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "Change your password before continuing."
    default_code = "password_change_required"


class PasswordChangeJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            return None
        user, _token = result
        if getattr(user, "must_change_password", False):
            match = getattr(request._request, "resolver_match", None)
            if match is None or match.url_name not in ALLOWED_BEFORE_CHANGE:
                raise PasswordChangeRequired()
        return result
