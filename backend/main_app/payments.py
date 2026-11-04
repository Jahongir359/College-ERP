"""Tuition billing services (Uzbekistan, UZS soʻm).

Shared by the payments views and the ``send_payment_reminders`` management
command so the business logic lives in one place:

- generate_invoices_for_month: idempotent monthly invoice generation
- send_invoice_reminder: in-app notification + email (+ optional Eskiz SMS)
"""

import logging
import os
import re

from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext

from .models import Enrollment, Invoice, Notification

logger = logging.getLogger(__name__)


def format_uzs_number(amount, localized=False):
    """Format a whole-soʻm amount the Uzbek way.

    Round thousands/millions use the local "ming"/"million" words (cleaner than
    a wall of zeros); anything else falls back to comma-grouped digits:

        200000   -> "200 ming"
        750000   -> "750 ming"
        10000000 -> "10 million"
        1500000  -> "1.5 million"
        200500   -> "200,500"
        500      -> "500"

    With ``localized=True`` the "ming"/"million" words follow the page
    language (e.g. "200 тыс." in Russian); leave it off for text that is
    stored, such as notifications.
    """
    try:
        n = int(round(float(amount)))
    except (TypeError, ValueError):
        return str(amount)
    sign = "-" if n < 0 else ""
    n = abs(n)
    million = gettext("%(amount)s million") if localized else "%(amount)s million"
    thousand = gettext("%(amount)s ming") if localized else "%(amount)s ming"
    if n >= 1_000_000:
        if n % 1_000_000 == 0:
            body = million % {"amount": f"{n // 1_000_000:,}"}
        elif n % 100_000 == 0:
            body = million % {"amount": f"{n / 1_000_000:.1f}"}
        else:
            body = f"{n:,}"
    elif n >= 1_000 and n % 1_000 == 0:
        body = thousand % {"amount": f"{n // 1_000:,}"}
    else:
        body = f"{n:,}"
    return sign + body


def _uzs(amount):
    return f"{format_uzs_number(amount)} soʻm"


def format_uzs(amount):
    """``_uzs`` in the page language, for pages and messages (not stored text)."""
    return gettext("%(amount)s soʻm") % {"amount": format_uzs_number(amount, localized=True)}


def generate_invoices_for_month(period, due_date, user=None, branch=None):
    """Create one invoice per active enrollment for ``period`` (a first-of-month date).

    Idempotent: enrollments that already have an invoice for that
    student/group/month are skipped (enforced by a DB unique constraint as
    the last line of defence). Enrollments whose group has no resolvable fee
    are reported, not invoiced.

    Returns a dict with ``created``, ``skipped`` and ``no_fee`` lists.
    """
    from . import branching

    enrollments = Enrollment.objects.filter(
        is_active=True, group__is_archived=False
    ).select_related("student__admin", "group__course")
    if user is not None:
        enrollments = branching.filter_enrollments_for_user(user, enrollments)
    if branch is not None:
        enrollments = enrollments.filter(group__branch=branch)

    created, skipped, no_fee = [], [], []
    for enrollment in enrollments:
        fee = enrollment.group.effective_monthly_fee
        if fee is None or fee <= 0:
            no_fee.append(enrollment)
            continue
        invoice, was_created = Invoice.objects.get_or_create(
            student=enrollment.student,
            group=enrollment.group,
            period=period,
            defaults={
                "amount": fee,
                "due_date": due_date,
                "created_by": user,
            },
        )
        if not was_created:
            skipped.append(invoice)
            continue
        created.append(invoice)
        Notification.objects.create(
            recipient=enrollment.student.admin,
            category=Notification.PAYMENT,
            message=(
                f"Tuition invoice for {invoice.period_label}: {_uzs(invoice.total_due)} "
                f"({enrollment.group.name}). Due by {due_date:%d %b %Y}."
            ),
            link=reverse("student_payments"),
        )
    return {"created": created, "skipped": skipped, "no_fee": no_fee}


# ── Reminders ─────────────────────────────────────────────────────────────────


def _reminder_message(invoice):
    balance = _uzs(invoice.balance)
    group = f" ({invoice.group.name})" if invoice.group else ""
    if invoice.is_overdue:
        days = (timezone.localdate() - invoice.due_date).days
        return (
            f"Payment reminder: overdue by {days} day{'s' if days != 1 else ''}: {balance} "
            f"for {invoice.period_label}{group}. Please pay at the front desk or contact your branch."
        )
    return (
        f"Payment reminder: {balance} for {invoice.period_label}{group} "
        f"is due by {invoice.due_date:%d %b %Y}."
    )


def send_invoice_reminder(invoice, force=False):
    """Send an in-app + email (+ optional SMS) reminder for an unpaid invoice.

    Deduplicates to at most one reminder per invoice per day unless ``force``
    (the HOD "remind now" button) is set. Returns True when a reminder went out.
    """
    today = timezone.localdate()
    if invoice.status not in (Invoice.STATUS_DUE, Invoice.STATUS_PARTIAL):
        return False
    if not force and invoice.last_reminded_on == today:
        return False

    user = invoice.student.admin
    message = _reminder_message(invoice)
    Notification.objects.create(
        recipient=user,
        category=Notification.PAYMENT,
        message=message,
        link=reverse("student_payments"),
    )
    if user.email:
        try:
            send_mail(
                subject="Tuition payment reminder — Iceberg Study Center",
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=True,
            )
        except Exception:  # noqa: BLE001 — reminders must never break the caller
            logger.exception("Reminder email failed for invoice %s", invoice.pk)
    _send_sms(invoice.student.phone, message)

    invoice.last_reminded_on = today
    invoice.save(update_fields=["last_reminded_on", "updated_at"])
    return True


# ── Optional SMS via Eskiz.uz ────────────────────────────────────────────────
# Configure with ESKIZ_EMAIL + ESKIZ_PASSWORD env vars; silently disabled
# otherwise. Eskiz is the de-facto SMS gateway for Uzbekistan (+998 numbers).

_ESKIZ_BASE = "https://notify.eskiz.uz/api"
_eskiz_token = None


def _normalize_uz_phone(phone):
    """Return digits in 998XXXXXXXXX form, or None if not a valid UZ number."""
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) == 9:
        digits = "998" + digits
    if len(digits) == 12 and digits.startswith("998"):
        return digits
    return None


def _eskiz_login(session):
    global _eskiz_token
    email = os.environ.get("ESKIZ_EMAIL", "")
    password = os.environ.get("ESKIZ_PASSWORD", "")
    if not email or not password:
        return None
    resp = session.post(
        f"{_ESKIZ_BASE}/auth/login", data={"email": email, "password": password}, timeout=10
    )
    resp.raise_for_status()
    _eskiz_token = resp.json().get("data", {}).get("token")
    return _eskiz_token


def _send_sms(phone, text):
    """Best-effort SMS. Never raises; returns True only on confirmed send."""
    global _eskiz_token
    if not os.environ.get("ESKIZ_EMAIL"):
        return False
    number = _normalize_uz_phone(phone)
    if not number:
        return False
    try:
        import requests

        session = requests.Session()
        token = _eskiz_token or _eskiz_login(session)
        if not token:
            return False
        for attempt in range(2):
            resp = session.post(
                f"{_ESKIZ_BASE}/message/sms/send",
                headers={"Authorization": f"Bearer {token}"},
                data={
                    "mobile_phone": number,
                    "message": text,
                    "from": os.environ.get("ESKIZ_FROM", "4546"),
                },
                timeout=10,
            )
            if resp.status_code == 401 and attempt == 0:
                token = _eskiz_login(session)  # token expired — refresh once
                if not token:
                    return False
                continue
            return resp.ok
    except Exception:  # noqa: BLE001 — SMS is an optional channel
        logger.warning("Eskiz SMS send failed for %s", phone, exc_info=True)
    return False
