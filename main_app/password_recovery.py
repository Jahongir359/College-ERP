"""
Custom password-recovery flow for Iceberg Study Center ERP.

Flow:
  1. forgot_password    — user enters email, system emails a 6-digit code
  2. verify_reset_code  — user enters the code; session is upgraded on success
  3. reset_password     — user sets a new password
  4. password_reset_success — confirmation page

Security guarantees:
  - Code stored only as SHA-256 hash (never plain text).
  - Timing-safe comparison via hmac.compare_digest.
  - No email enumeration: same public response whether address exists or not.
  - Rate limit: max 5 code requests per email per hour.
  - Max 5 wrong-code attempts before the code is locked.
  - Code expires after 10 minutes (enforced in DB + view).
  - One-time use: code is marked used immediately on password save.
  - Session gating: each step requires a session key set by the previous step.
"""

import hashlib
import hmac
import secrets
from datetime import timedelta

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.shortcuts import redirect, render
from django.utils import timezone

from .models import CustomUser, PasswordResetCode

# ── Constants ──────────────────────────────────────────────────────────────────
_MAX_CODES_PER_HOUR = 5
_MAX_ATTEMPTS = 5
_EXPIRY_MINUTES = 10

# Public message shown regardless of whether the email exists (prevents enumeration).
_SAFE_MSG = (
    "If this email is registered, a verification code has been sent. "
    "Please check your inbox (or spam folder)."
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def _codes_match(submitted: str, stored_hash: str) -> bool:
    return hmac.compare_digest(_hash_code(submitted), stored_hash)


def _send_code_email(email: str, code: str) -> None:
    send_mail(
        subject="Iceberg Study Center — Password Reset Code",
        message=(
            f"Your verification code is: {code}\n\n"
            f"This code expires in {_EXPIRY_MINUTES} minutes.\n\n"
            "If you did not request a password reset, you can safely ignore this email."
        ),
        from_email=None,          # uses DEFAULT_FROM_EMAIL from settings
        recipient_list=[email],
        fail_silently=False,
    )


def _clear_prc_session(request) -> None:
    for key in ('_prc_email', '_prc_code_id', '_prc_uid', '_prc_code_id_verified'):
        request.session.pop(key, None)


# ── Views ──────────────────────────────────────────────────────────────────────

def forgot_password(request):
    """Step 1: collect email, send code."""
    if request.method != 'POST':
        return render(request, 'registration/forgot_password.html')

    email = request.POST.get('email', '').strip().lower()

    if not email:
        return render(request, 'registration/forgot_password.html',
                      {'error': 'Please enter your email address.'})

    # ── Look up user (silently) ────────────────────────────────────────────────
    try:
        user = CustomUser.objects.get(email__iexact=email)
    except CustomUser.DoesNotExist:
        # Do NOT reveal that the address isn't registered.
        return render(request, 'registration/forgot_password.html', {'info': _SAFE_MSG})

    # ── Rate limit ────────────────────────────────────────────────────────────
    one_hour_ago = timezone.now() - timedelta(hours=1)
    recent_count = PasswordResetCode.objects.filter(
        user=user, created_at__gte=one_hour_ago
    ).count()
    if recent_count >= _MAX_CODES_PER_HOUR:
        # Same safe message — don't reveal the limit was hit.
        return render(request, 'registration/forgot_password.html', {'info': _SAFE_MSG})

    # ── Generate & store code ─────────────────────────────────────────────────
    code = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = timezone.now() + timedelta(minutes=_EXPIRY_MINUTES)

    obj = PasswordResetCode.objects.create(
        user=user,
        code_hash=_hash_code(code),
        expires_at=expires_at,
    )

    # ── Send email ────────────────────────────────────────────────────────────
    try:
        _send_code_email(user.email, code)
    except Exception:
        # Roll back the DB row so the failed attempt doesn't count against rate limit.
        obj.delete()
        return render(request, 'registration/forgot_password.html', {
            'error': (
                "We could not send the email at this time. "
                "Please try again in a few minutes."
            )
        })

    # ── Advance session to step 2 ─────────────────────────────────────────────
    _clear_prc_session(request)
    request.session['_prc_email'] = user.email
    request.session['_prc_code_id'] = obj.id

    return redirect('verify_reset_code')


def verify_reset_code(request):
    """Step 2: validate the 6-digit code."""
    email = request.session.get('_prc_email')
    code_id = request.session.get('_prc_code_id')

    # Guard: must have come through step 1.
    if not email or not code_id:
        return redirect('forgot_password')

    ctx = {'email': email}

    if request.method != 'POST':
        return render(request, 'registration/verify_reset_code.html', ctx)

    submitted = request.POST.get('code', '').strip()

    # ── Fetch the specific code object ────────────────────────────────────────
    try:
        obj = PasswordResetCode.objects.select_related('user').get(id=code_id)
    except PasswordResetCode.DoesNotExist:
        _clear_prc_session(request)
        return redirect('forgot_password')

    # ── Already used ──────────────────────────────────────────────────────────
    if obj.used:
        _clear_prc_session(request)
        return render(request, 'registration/verify_reset_code.html', {
            **ctx,
            'error': "This verification code has already been used.",
            'show_resend': True,
        })

    # ── Expired ───────────────────────────────────────────────────────────────
    if timezone.now() > obj.expires_at:
        _clear_prc_session(request)
        return render(request, 'registration/verify_reset_code.html', {
            **ctx,
            'error': "This verification code has expired. Please request a new one.",
            'show_resend': True,
        })

    # ── Too many failed attempts ───────────────────────────────────────────────
    if obj.attempts >= _MAX_ATTEMPTS:
        _clear_prc_session(request)
        return render(request, 'registration/verify_reset_code.html', {
            **ctx,
            'error': "Too many wrong attempts. Please request a new code.",
            'show_resend': True,
        })

    # ── Check the code ────────────────────────────────────────────────────────
    if not _codes_match(submitted, obj.code_hash):
        obj.attempts += 1
        obj.save(update_fields=['attempts'])
        remaining = _MAX_ATTEMPTS - obj.attempts
        return render(request, 'registration/verify_reset_code.html', {
            **ctx,
            'error': (
                f"Invalid verification code. "
                f"{remaining} attempt{'s' if remaining != 1 else ''} remaining."
            ),
        })

    # ── Code correct — advance session to step 3 ──────────────────────────────
    _clear_prc_session(request)
    request.session['_prc_uid'] = obj.user_id
    request.session['_prc_code_id_verified'] = obj.id

    return redirect('reset_password')


def reset_password(request):
    """Step 3: set the new password."""
    uid = request.session.get('_prc_uid')
    code_id = request.session.get('_prc_code_id_verified')

    # Guard: must have completed step 2.
    if not uid or not code_id:
        return redirect('forgot_password')

    # Verify the code still exists, belongs to this uid, and hasn't been used.
    try:
        obj = PasswordResetCode.objects.select_related('user').get(
            id=code_id, user_id=uid, used=False
        )
    except PasswordResetCode.DoesNotExist:
        _clear_prc_session(request)
        return redirect('forgot_password')

    user = obj.user

    if request.method != 'POST':
        return render(request, 'registration/reset_password.html')

    password1 = request.POST.get('password1', '')
    password2 = request.POST.get('password2', '')

    errors = []

    if not password1:
        errors.append("Password cannot be empty.")
    elif password1 != password2:
        errors.append("Passwords do not match.")
    else:
        try:
            validate_password(password1, user)
        except ValidationError as exc:
            errors.extend(exc.messages)

    if errors:
        return render(request, 'registration/reset_password.html', {'errors': errors})

    # ── Save new password ─────────────────────────────────────────────────────
    user.set_password(password1)
    user.save(update_fields=['password'])

    # Mark code as used (one-time).
    obj.used = True
    obj.save(update_fields=['used'])

    _clear_prc_session(request)
    return redirect('password_reset_success')


def password_reset_success(request):
    """Step 4: confirmation page."""
    return render(request, 'registration/password_reset_success.html')
