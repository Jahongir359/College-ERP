import json
import logging
import os

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import PasswordResetView
from django.core.exceptions import PermissionDenied
from django.db import DatabaseError
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render, reverse
from django.urls import reverse_lazy

from .EmailBackend import EmailBackend
from .apps import create_recovery_admin_access
from .models import Admin, Attendance, Session, Staff, Student, Subject

logger = logging.getLogger(__name__)


def _ensure_role_profile(user):
    """Best-effort role profile healing to avoid login-time crashes."""
    user_type = str(user.user_type)
    model_map = {
        '1': Admin,
        '2': Staff,
        '3': Student,
    }
    profile_model = model_map.get(user_type)
    if profile_model is None:
        return

    try:
        if not profile_model.objects.filter(admin=user).exists():
            profile_model.objects.create(admin=user)
    except Exception:
        # Keep login flow alive; dashboard views will enforce access rules.
        logger.exception("Role profile healing failed for user pk=%s", user.pk)


def _redirect_authenticated_user(user):
    """Return the correct home redirect for an already-logged-in user."""
    user_type = str(user.user_type)
    if user_type == '1':
        return redirect(reverse("admin_home"))
    if user_type == '2':
        return redirect(reverse("staff_home"))
    if user_type == '3':
        return redirect(reverse("student_home"))
    return None  # Unknown type — fall through to show login page


def entry_page(request):
    """Root URL — branded entry splash + welcome question page.

    Authenticated users bypass this and go straight to their dashboard.
    The template itself uses localStorage to skip the 2-second animation
    on repeat visits (first visit flag 'iceberg_entry_seen').
    """
    if request.user.is_authenticated:
        destination = _redirect_authenticated_user(request.user)
        if destination:
            return destination
    return render(request, 'main_app/entry.html')


def login_page(request):
    if request.user.is_authenticated:
        destination = _redirect_authenticated_user(request.user)
        if destination:
            return destination
    return render(request, 'main_app/login.html')


def doLogin(request, **kwargs):
    if request.method != 'POST':
        return HttpResponse("<h4>Denied</h4>")

    # Identifier is either an email address (admin) or a login_id (staff/student).
    identifier = (request.POST.get('identifier') or '').strip()
    if not identifier:
        # Fallback: some browsers or old bookmarks may still post 'email'.
        identifier = (request.POST.get('email') or '').strip()
    password = request.POST.get('password') or ''

    if not identifier or not password:
        messages.error(request, "Please enter both your ID/email and password.")
        return redirect(reverse("login_page"))

    try:
        user = authenticate(request, username=identifier, password=password)
    except PermissionDenied:
        # django-axes raises this once AXES_FAILURE_LIMIT is hit.
        logger.warning("Login locked out by axes for identifier=%s", identifier)
        messages.error(
            request,
            "Too many failed login attempts. "
            "Please wait 15 minutes before trying again."
        )
        return redirect(reverse("login_page"))
    except Exception:
        logger.exception("authenticate() raised for identifier=%s — DB may be missing migrations", identifier)
        messages.error(request, "Login is temporarily unavailable. Please try again in a moment.")
        return redirect(reverse("login_page"))

    # Recovery fallback: only fires for the designated recovery account.
    recovery_email = os.environ.get(
        'RECOVERY_ADMIN_EMAIL', 'iceberg.edu.center@gmail.com'
    ).strip().lower()

    if user is None and identifier.lower() == recovery_email:
        try:
            create_recovery_admin_access(sender=None, force_password=True)
            user = authenticate(request, username=identifier, password=password)
        except Exception as exc:
            logger.error("Recovery admin re-seed failed: %s", exc)
            user = None

    if user is None:
        messages.error(request, "Invalid ID/email or password.")
        return redirect(reverse("login_page"))

    try:
        login(request, user)
    except DatabaseError:
        logger.exception("Login failed due to session/database error for identifier=%s", identifier)
        messages.error(
            request,
            "Login is temporarily unavailable. Please try again in a moment."
        )
        return redirect(reverse("login_page"))
    except Exception:
        logger.exception("Unexpected login failure for identifier=%s", identifier)
        messages.error(
            request,
            "Login failed due to a server issue. Please try again shortly."
        )
        return redirect(reverse("login_page"))

    # Ensure the role profile row exists (heals accounts created before signals).
    user_type = str(user.user_type)
    _ensure_role_profile(user)

    # Remember Me
    if request.POST.get('remember'):
        request.session.set_expiry(30 * 24 * 60 * 60)
    else:
        request.session.set_expiry(0)

    # Deterministic redirect — no catch-all else that silently misroutes users.
    if user_type == '1':
        return redirect(reverse("admin_home"))
    if user_type == '2':
        return redirect(reverse("staff_home"))
    if user_type == '3':
        return redirect(reverse("student_home"))

    # Unknown user_type: log it, inform the user, and log them out safely.
    logger.error(
        "Login rejected: user pk=%s has unrecognised user_type=%r",
        user.pk, user.user_type,
    )
    logout(request)
    messages.error(
        request,
        "Your account role is not configured correctly. "
        "Please contact the administrator."
    )
    return redirect("/")


def logout_user(request):
    if request.method != 'POST':
        # Ignore accidental GET hits on the logout URL — redirect to home.
        if request.user.is_authenticated:
            return _redirect_authenticated_user(request.user) or redirect(reverse("login_page"))
        return redirect(reverse("login_page"))

    if request.user is not None:
        logout(request)
    return redirect(reverse("login_page"))


# ---------------------------------------------------------------------------
# Password reset — wraps Django's built-in view to prevent SMTP errors from
# becoming HTTP 500s.  Any exception during email dispatch is logged and the
# user is still sent to the "check your inbox" page (avoids email enumeration).
# ---------------------------------------------------------------------------

class SafePasswordResetView(PasswordResetView):
    template_name = 'registration/password_reset_form.html'
    email_template_name = 'registration/password_reset_email.html'
    subject_template_name = 'registration/password_reset_subject.txt'
    success_url = reverse_lazy('password_reset_done')

    def form_valid(self, form):
        try:
            return super().form_valid(form)
        except Exception as exc:
            logger.error(
                "Password reset email dispatch failed: %s", exc, exc_info=True
            )
            # Still redirect to "done" — do not leak whether the address exists
            # and do not expose a 500 to the user.
            return HttpResponseRedirect(self.success_url)


# ---------------------------------------------------------------------------
# Shared AJAX / utility views
# ---------------------------------------------------------------------------

@login_required
def get_attendance(request):
    group_id = request.POST.get('group')
    try:
        from .models import Group
        group = get_object_or_404(Group, id=group_id)
        attendance_qs = Attendance.objects.filter(group=group).order_by('-date')
        attendance_list = [
            {"id": a.id, "attendance_date": str(a.date)}
            for a in attendance_qs
        ]
        return JsonResponse(json.dumps(attendance_list), safe=False)
    except Exception:
        return JsonResponse({'error': 'Unable to fetch attendance.'}, status=400)


def health(request):
    """Lightweight health-check endpoint for DO load-balancer probes."""
    from django.db import connection
    try:
        connection.ensure_connection()
        db_ok = True
    except Exception:
        db_ok = False
    status = 200 if db_ok else 503
    return JsonResponse({'status': 'ok' if db_ok else 'db_unavailable', 'db': db_ok}, status=status)


_FIREBASE_CONFIG_KEYS = (
    'FIREBASE_API_KEY',
    'FIREBASE_AUTH_DOMAIN',
    'FIREBASE_DATABASE_URL',
    'FIREBASE_PROJECT_ID',
    'FIREBASE_STORAGE_BUCKET',
    'FIREBASE_MESSAGING_SENDER_ID',
    'FIREBASE_APP_ID',
    'FIREBASE_MEASUREMENT_ID',
)


def showFirebaseJS(request):
    """Serve the FCM service-worker script with env-driven config.

    Audit item #6: previously hardcoded the Firebase web config in the
    response body, which forced a code push for key rotation. Web FCM
    keys are intended to be public, but project/sender IDs and bucket
    names belong in deployment config, not git.
    """
    cfg = {k: os.environ.get(k, '') for k in _FIREBASE_CONFIG_KEYS}
    # If no Firebase env is configured, emit a no-op SW so the page does
    # not 404 and the browser does not register a broken worker.
    if not cfg['FIREBASE_API_KEY']:
        return HttpResponse(
            "/* Firebase not configured. Set FIREBASE_* env vars to enable FCM. */\n",
            content_type='application/javascript',
        )

    data = (
        "importScripts('https://www.gstatic.com/firebasejs/7.22.1/firebase-app.js');\n"
        "importScripts('https://www.gstatic.com/firebasejs/7.22.1/firebase-messaging.js');\n\n"
        "firebase.initializeApp(" + json.dumps({
            'apiKey':            cfg['FIREBASE_API_KEY'],
            'authDomain':        cfg['FIREBASE_AUTH_DOMAIN'],
            'databaseURL':       cfg['FIREBASE_DATABASE_URL'],
            'projectId':         cfg['FIREBASE_PROJECT_ID'],
            'storageBucket':     cfg['FIREBASE_STORAGE_BUCKET'],
            'messagingSenderId': cfg['FIREBASE_MESSAGING_SENDER_ID'],
            'appId':             cfg['FIREBASE_APP_ID'],
            'measurementId':     cfg['FIREBASE_MEASUREMENT_ID'],
        }) + ");\n\n"
        "const messaging = firebase.messaging();\n"
        "messaging.setBackgroundMessageHandler(function (payload) {\n"
        "    const notification = JSON.parse(payload);\n"
        "    const notificationOption = { body: notification.body, icon: notification.icon };\n"
        "    return self.registration.showNotification(\n"
        "        payload.notification.title, notificationOption\n"
        "    );\n"
        "});\n"
    )
    return HttpResponse(data, content_type='application/javascript')


# ── Branded error handlers (registered in college_management_system/urls.py) ──

def _render_error(request, code, title, message, status):
    return render(
        request,
        'main_app/error.html',
        {'error_code': code, 'error_title': title, 'error_message': message},
        status=status,
    )


def page_not_found(request, exception):
    return _render_error(
        request, 404,
        "We can't find that page",
        "The page you were looking for has moved or no longer exists. "
        "Head back to your dashboard to keep learning.",
        status=404,
    )


def server_error(request):
    return _render_error(
        request, 500,
        "Something went wrong on our end",
        "An unexpected error occurred. The team has been notified — "
        "please try again in a moment.",
        status=500,
    )


def permission_denied(request, exception):
    return _render_error(
        request, 403,
        "You don't have access to this page",
        "Your account doesn't have permission to view this section. "
        "Contact an administrator if you believe this is a mistake.",
        status=403,
    )


def bad_request(request, exception):
    return _render_error(
        request, 400,
        "That request didn't look right",
        "The server couldn't process your request. Please refresh the page "
        "and try again.",
        status=400,
    )
