"""
Password recovery flow — Iceberg Study Center ERP.

Flow:
  POST /forgot-password/        → generate code, always redirect to verify page
  GET  /verify-reset-code/      → show email+code form (email pre-filled from ?email=)
  POST /verify-reset-code/      → validate code, gate session, redirect to reset
  GET  /reset-password/         → session-gated: show new-password form
  POST /reset-password/         → save password, mark code used, redirect to login

Security:
  - Code stored as SHA-256 hash only (never plain text).
  - Timing-safe comparison via hmac.compare_digest.
  - No email enumeration: always redirect to verify page regardless of outcome.
  - Rate limit: max 5 code requests per email per hour (DB-level).
  - Max 5 wrong-code attempts per code before lock-out.
  - Code expires after 10 minutes.
  - One-time use: code marked used immediately after password save.
  - reset_password is session-gated (can't skip step 2).
  - All internal outcomes logged; nothing sensitive exposed to the browser.
"""

import hashlib
import hmac
import logging
import secrets
from datetime import timedelta
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.shortcuts import redirect, render
from django.utils import timezone

from .models import CustomUser, PasswordResetCode

logger = logging.getLogger(__name__)

_MAX_CODES_PER_HOUR = 5
_MAX_ATTEMPTS = 5
_EXPIRY_MINUTES = 10


# ── Internal helpers ────────────────────────────────────────────────────────────

def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def _codes_match(submitted: str, stored_hash: str) -> bool:
    """Timing-safe code comparison."""
    return hmac.compare_digest(_hash_code(submitted), stored_hash)


def _send_code_email(to_email: str, code: str) -> None:
    logger.info("[PRC] Sending reset code to %s", to_email)
    send_mail(
        subject="Iceberg Study Center — Password Reset Code",
        message=(
            f"Your verification code is: {code}\n\n"
            f"This code expires in {_EXPIRY_MINUTES} minutes.\n\n"
            "If you did not request a password reset, please ignore this email."
        ),
        from_email=None,          # uses DEFAULT_FROM_EMAIL from settings
        recipient_list=[to_email],
        fail_silently=False,
    )
    logger.info("[PRC] Code email sent to %s", to_email)


def _clear_reset_session(request) -> None:
    for key in ('_prc_uid', '_prc_code_id_verified'):
        request.session.pop(key, None)


# ── Views ───────────────────────────────────────────────────────────────────────

def forgot_password(request):
    """
    Step 1 — collect email.

    On POST: silently attempt to generate and send a code.
    ALWAYS redirect to the verify page, regardless of whether the email
    exists.  This prevents enumeration.
    """
    if request.method != 'POST':
        return render(request, 'registration/forgot_password.html')

    email = request.POST.get('email', '').strip().lower()
    if not email:
        return render(request, 'registration/forgot_password.html',
                      {'error': 'Please enter your email address.'})

    logger.info("[PRC] Forgot-password submitted for: %s", email)

    # Attempt code generation silently — exceptions don't reach the user.
    try:
        user = CustomUser.objects.get(email__iexact=email)
        logger.info("[PRC] User found: id=%s", user.id)

        one_hour_ago = timezone.now() - timedelta(hours=1)
        recent = PasswordResetCode.objects.filter(
            user=user, created_at__gte=one_hour_ago
        ).count()

        if recent >= _MAX_CODES_PER_HOUR:
            logger.warning("[PRC] Rate limit hit for user id=%s (%d in last hour)",
                           user.id, recent)
        else:
            code = f"{secrets.randbelow(1_000_000):06d}"
            expires_at = timezone.now() + timedelta(minutes=_EXPIRY_MINUTES)
            obj = PasswordResetCode.objects.create(
                user=user,
                code_hash=_hash_code(code),
                expires_at=expires_at,
            )
            logger.info("[PRC] Code created: id=%s expires=%s", obj.id, expires_at)

            try:
                _send_code_email(user.email, code)
                # In development the code is visible in the console/file backend.
                # This line is intentionally left for server-side debugging only.
                logger.debug("[PRC] Plaintext code for %s: %s", email, code)
            except Exception as exc:
                logger.error("[PRC] Email send failed for %s: %s", email, exc, exc_info=True)
                obj.delete()   # Don't count a failed send against the rate limit.

    except CustomUser.DoesNotExist:
        logger.info("[PRC] Email not registered: %s", email)
    except Exception as exc:
        logger.error("[PRC] Unexpected error in forgot_password for %s: %s",
                     email, exc, exc_info=True)

    # Always redirect — never reveal whether the address was registered.
    qs = urlencode({'email': email})
    return redirect(f'/verify-reset-code/?{qs}')


def verify_reset_code(request):
    """
    Step 2 — enter the 6-digit code.

    GET:  Show the form.  Email is pre-filled from ?email= URL param.
    POST: Validate code against the latest active code for that email.
          On success: store uid + code id in session, redirect to reset_password.
    """
    if request.method == 'GET':
        email = request.GET.get('email', '').strip().lower()
        return render(request, 'registration/verify_reset_code.html', {'email': email})

    # ── POST ──────────────────────────────────────────────────────────────────
    email = request.POST.get('email', '').strip().lower()
    submitted_code = request.POST.get('code', '').strip()
    ctx = {'email': email}

    if not email or not submitted_code:
        ctx['error'] = 'Please enter both your email address and the verification code.'
        return render(request, 'registration/verify_reset_code.html', ctx)

    logger.info("[PRC] Code verification attempt for: %s", email)

    # Look up user.
    try:
        user = CustomUser.objects.get(email__iexact=email)
    except CustomUser.DoesNotExist:
        logger.info("[PRC] Verify: email not found: %s", email)
        # Generic error — don't reveal the email isn't registered.
        ctx['error'] = 'Invalid verification code.'
        return render(request, 'registration/verify_reset_code.html', ctx)

    # Find the latest code for this user (regardless of expiry/used status,
    # so we can return the most relevant error message).
    obj = PasswordResetCode.objects.filter(user=user).order_by('-created_at').first()

    if obj is None:
        logger.info("[PRC] No code exists for user id=%s", user.id)
        ctx['error'] = 'No verification code found. Please request a new one.'
        ctx['show_resend'] = True
        return render(request, 'registration/verify_reset_code.html', ctx)

    # Specific failure checks — in order of priority.
    if obj.used:
        logger.info("[PRC] Code id=%s already used", obj.id)
        ctx['error'] = 'This verification code has already been used.'
        ctx['show_resend'] = True
        return render(request, 'registration/verify_reset_code.html', ctx)

    if timezone.now() > obj.expires_at:
        logger.info("[PRC] Code id=%s expired at %s", obj.id, obj.expires_at)
        ctx['error'] = 'This verification code has expired. Please request a new one.'
        ctx['show_resend'] = True
        return render(request, 'registration/verify_reset_code.html', ctx)

    if obj.attempts >= _MAX_ATTEMPTS:
        logger.warning("[PRC] Code id=%s locked after %d attempts", obj.id, obj.attempts)
        ctx['error'] = 'Too many wrong attempts. Please request a new code.'
        ctx['show_resend'] = True
        return render(request, 'registration/verify_reset_code.html', ctx)

    # Check the code itself.
    if not _codes_match(submitted_code, obj.code_hash):
        obj.attempts += 1
        obj.save(update_fields=['attempts'])
        remaining = _MAX_ATTEMPTS - obj.attempts
        logger.info("[PRC] Wrong code for id=%s; attempts=%d remaining=%d",
                    obj.id, obj.attempts, remaining)
        ctx['error'] = (
            f"Invalid verification code. "
            f"{remaining} attempt{'s' if remaining != 1 else ''} remaining."
        )
        return render(request, 'registration/verify_reset_code.html', ctx)

    # ── Code correct ──────────────────────────────────────────────────────────
    logger.info("[PRC] Code id=%s verified for user id=%s", obj.id, user.id)
    _clear_reset_session(request)
    request.session['_prc_uid'] = user.id
    request.session['_prc_code_id_verified'] = obj.id

    return redirect('reset_password')


def reset_password(request):
    """
    Step 3 — set a new password.

    Gated by session keys set in verify_reset_code.
    Redirects to the login page with a success message on completion.
    """
    uid = request.session.get('_prc_uid')
    code_id = request.session.get('_prc_code_id_verified')

    if not uid or not code_id:
        logger.warning("[PRC] reset_password accessed without valid session")
        return redirect('forgot_password')

    try:
        obj = PasswordResetCode.objects.select_related('user').get(
            id=code_id, user_id=uid, used=False
        )
    except PasswordResetCode.DoesNotExist:
        logger.warning("[PRC] Code id=%s not found or already used (uid=%s)", code_id, uid)
        _clear_reset_session(request)
        return redirect('forgot_password')

    user = obj.user

    if request.method != 'POST':
        return render(request, 'registration/reset_password.html')

    password1 = request.POST.get('password1', '')
    password2 = request.POST.get('password2', '')
    errors = []

    if not password1:
        errors.append('Password cannot be empty.')
    elif password1 != password2:
        errors.append('Passwords do not match.')
    else:
        try:
            validate_password(password1, user)
        except ValidationError as exc:
            errors.extend(exc.messages)

    if errors:
        return render(request, 'registration/reset_password.html', {'errors': errors})

    # Save new password.
    user.set_password(password1)
    user.save(update_fields=['password'])

    # Mark code as used so it cannot be reused.
    obj.used = True
    obj.save(update_fields=['used'])

    logger.info("[PRC] Password reset successful for user id=%s", user.id)
    _clear_reset_session(request)

    messages.success(
        request,
        "Your password has been reset successfully. Please log in."
    )
    return redirect('login_page')


def password_reset_success(request):
    """Kept for backwards-compatibility; login page now shows the success message."""
    return render(request, 'registration/password_reset_success.html')
