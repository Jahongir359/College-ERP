import logging

from django.conf import settings
from django.contrib.auth import logout
from django.utils.deprecation import MiddlewareMixin
from django.urls import reverse
from django.shortcuts import redirect
from django.db.utils import OperationalError, ProgrammingError

# Parents have no web pages: they use the app, at /app/ in the browser.
PARENT_HOME_URL = "/app/"
PARENT_WEB_PREFIXES = ("/app", "/download/", "/media/")


class LoginCheckMiddleWare(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        # API paths use JWT authentication — let DRF handle auth/permission.
        if request.path.startswith("/api/"):
            return None

        modulename = view_func.__module__

        auth_allowed_paths = {
            reverse("entry_page"),
            reverse("login_page"),
            reverse("user_login"),
            reverse("user_logout"),
        }

        try:
            user = request.user
            user_type = str(getattr(user, "user_type", ""))
        except (OperationalError, ProgrammingError):
            # DB tables not yet initialised (first deploy, pre-migrate).
            # Let auth and admin pages through so the site can bootstrap.
            if (
                request.path in auth_allowed_paths
                or modulename.startswith("django.contrib.auth")
                or request.path.startswith("/admin/")
            ):
                return None
            return redirect(reverse("login_page"))

        if user.is_authenticated:
            if user_type == "1":  # HOD / Admin
                if modulename in ("main_app.student_views", "main_app.staff_views"):
                    return redirect(reverse("admin_home"))

            elif user_type == "2":  # Staff
                if modulename in ("main_app.student_views", "main_app.hod_views"):
                    return redirect(reverse("staff_home"))

            elif user_type == "3":  # Student
                if modulename in ("main_app.hod_views", "main_app.staff_views"):
                    return redirect(reverse("student_home"))

            elif user_type == "4":  # Parent: uses the app only (D15)
                if not (
                    request.path in auth_allowed_paths
                    or request.path.startswith(PARENT_WEB_PREFIXES)
                ):
                    return redirect(PARENT_HOME_URL)

            else:
                # Unknown/corrupt user_type: log out and redirect to login.
                if request.path not in auth_allowed_paths:
                    logout(request)
                    return redirect(reverse("login_page"))

        else:
            if (
                request.path in auth_allowed_paths
                or modulename.startswith("django.contrib.auth")
                or request.path.startswith("/accounts/")
                or request.path.startswith("/admin/")
                or request.path in ("/public/registration-leads", "/public/registration-leads/")
                or request.path == "/health/"
                # Custom code-based password recovery flow.
                or modulename == "main_app.password_recovery"
                or request.path.startswith("/forgot-password")
                or request.path.startswith("/verify-reset-code")
                or request.path.startswith("/reset-password")
                or request.path.startswith("/password-reset-success")
                # Flutter web SPA — handles its own JWT auth internally.
                or request.path.startswith("/app")
                # Public APK download and install guide — no login required.
                or request.path.startswith("/download/")
                # media_views.protected_media enforces its own per-prefix
                # access checks (session or mobile JWT) for private files.
                or request.path.startswith("/media/")
            ):
                pass
            else:
                return redirect(reverse("login_page"))


class BrandCookieMiddleware:
    """Remember which Iceberg brand (Learning Center / School) a browser uses.

    Sets the ``iceberg_brand`` cookie when a visitor arrives with ``?brand=``
    or on a /school/ page, and when a signed-in user's branch decides the
    brand — so the sign-in and password-recovery pages keep the right look
    after logout. Presentation only; does nothing while SCHOOL_BRAND_ENABLED
    is off. See docs/plans/ICEBERG_SCHOOL_BRAND_PLAN.md (Phase 3).
    """

    SKIP_PREFIXES = ("/api/", "/static/", "/media/", "/app", "/admin/", "/download/")
    MAX_AGE = 365 * 24 * 60 * 60

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if not getattr(settings, "SCHOOL_BRAND_ENABLED", False):
            return response
        if request.path.startswith(self.SKIP_PREFIXES):
            return response
        try:
            self._remember_brand(request, response)
        except Exception:  # presentation must never break a response
            logging.getLogger(__name__).exception("Could not set the brand cookie")
        return response

    def _remember_brand(self, request, response):
        from . import branding

        user = getattr(request, "user", None)
        signed_in = bool(user is not None and user.is_authenticated)
        explicit = request.path.startswith(branding.SCHOOL_PATH_PREFIX) or branding.is_valid_brand(
            request.GET.get("brand", "")
        )
        if not (signed_in or explicit):
            return
        # The view may have signed the user in or out during this request, so
        # don't trust a brand cached before that happened.
        request.__dict__.pop("_iceberg_brand", None)
        key = branding.resolve_brand_key(request)
        if request.COOKIES.get(branding.BRAND_COOKIE) == key:
            return
        response.set_cookie(
            branding.BRAND_COOKIE,
            key,
            max_age=self.MAX_AGE,
            secure=getattr(settings, "SESSION_COOKIE_SECURE", False),
            httponly=True,
            samesite="Lax",
        )
