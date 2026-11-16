"""SMS for parents (plan task PL.2, decisions D13 and D14).

* ``request_reset`` / ``confirm_reset``: a parent who forgot their password asks for
  a one-time code, sent by SMS (Eskiz, the gateway ``payments.py`` already uses) to
  the phone the school stored, and sets a new password with it.
* ``send_login_sms``: the office sends a parent their login ID and the link to the
  app. Never a password (D14).

Callers learn nothing about who exists: ``request_reset`` returns nothing, and
``confirm_reset`` gives one error for every failure. Codes are stored hashed.
"""

import secrets
from datetime import timedelta

from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.utils import timezone, translation
from django.utils.translation import gettext as _

from . import parents, payments
from .models import Parent, SmsResetCode, PasswordResetLog

CODE_MINUTES = 10  # how long a code works
MAX_ATTEMPTS = 5  # wrong tries before a code is dead
RESEND_SECONDS = 60  # wait between two codes to one phone
MAX_PER_DAY = 5  # codes to one phone in 24 hours


def _language(user):
    # Parents who never picked a language get Uzbek, the school's first language.
    return user.language or "uz"


def _new_code():
    return f"{secrets.randbelow(10**6):06d}"


def _may_send(digits, now):
    sent = SmsResetCode.objects.filter(phone=digits)
    if sent.filter(created_at__gt=now - timedelta(seconds=RESEND_SECONDS)).exists():
        return False
    return sent.filter(created_at__gt=now - timedelta(hours=24)).count() < MAX_PER_DAY


def request_reset(login_id, phone):
    """Send a reset code when the login ID and phone belong to one active parent.

    Returns True when an SMS went out. The API must not pass that on to the caller.
    """
    parent = parents.parent_by_login_and_phone(login_id, phone)
    if parent is None or not parent.admin.is_active:
        return False
    digits = parents.phone_digits(parent.phone)
    now = timezone.now()
    if not _may_send(digits, now):
        return False
    code = _new_code()
    SmsResetCode.objects.create(
        user=parent.admin,
        phone=digits,
        code_hash=make_password(code),
        expires_at=now + timedelta(minutes=CODE_MINUTES),
    )
    with translation.override(_language(parent.admin)):
        text = _(
            "Iceberg: your password reset code is %(code)s. "
            "It works for %(minutes)s minutes. Do not share it."
        ) % {"code": code, "minutes": CODE_MINUTES}
    return payments._send_sms(parent.phone, text)


def confirm_reset(login_id, code, new_password):
    """Set ``new_password`` when ``code`` is the parent's live code. Returns True or False.

    The newest code is the only one that counts. A wrong try is counted on it, so
    guessing stops after ``MAX_ATTEMPTS``. The password is the parent's own choice,
    so there is no forced change afterwards, and their old sign-ins stop working.
    """
    parent = (
        Parent.objects.select_related("admin")
        .filter(admin__login_id__iexact=(login_id or "").strip(), admin__is_active=True)
        .first()
    )
    if parent is None:
        return False
    with transaction.atomic():
        entry = (
            SmsResetCode.objects.select_for_update()
            .filter(user=parent.admin)
            .order_by("-created_at", "-pk")
            .first()
        )
        if (
            entry is None
            or entry.used_at is not None
            or entry.expires_at <= timezone.now()
            or entry.attempts >= MAX_ATTEMPTS
        ):
            return False
        if not check_password(str(code or "").strip(), entry.code_hash):
            entry.attempts += 1
            entry.save(update_fields=["attempts"])
            return False
        entry.used_at = timezone.now()
        entry.save(update_fields=["used_at"])
        user = parent.admin
        user.set_password(new_password)
        user.must_change_password = False
        user.save()
        PasswordResetLog.objects.create(user=user, method=PasswordResetLog.METHOD_SMS)
        _sign_out_everywhere(user)
    return True


def _sign_out_everywhere(user):
    from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

    for token in OutstandingToken.objects.filter(user=user):
        BlacklistedToken.objects.get_or_create(token=token)


def send_login_sms(parent, download_url):
    """Text the parent their login ID and where to get the app (D14). Never a password."""
    with translation.override(_language(parent.admin)):
        text = _("Iceberg School: your login ID is %(login)s. Get the app: %(url)s") % {
            "login": parent.admin.login_id,
            "url": download_url,
        }
    return payments._send_sms(parent.phone, text)
