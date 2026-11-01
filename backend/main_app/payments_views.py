"""Payments views for all three roles (HOD / staff / student).

Money amounts are UZS soʻm. Admin views are branch-scoped through
``branching``; students only ever see their own invoices; teachers get a
read-only payment status board for the groups they teach.
"""

import csv
from datetime import date

from django.contrib import messages
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext
from django.views.decorators.http import require_POST

from . import branching, payments
from .decorators import admin_only, staff_only, student_only
from .forms import GenerateInvoicesForm, ManualInvoiceForm, RecordPaymentForm
from .models import (
    Branch,
    Enrollment,
    Group,
    Invoice,
    Notification,
    Payment,
    Staff,
    Student,
)


def _current_period():
    today = timezone.localdate()
    return date(today.year, today.month, 1)


def _parse_period(raw):
    """Parse a YYYY-MM query value; fall back to the current month."""
    try:
        year, month = str(raw).split("-")
        return date(int(year), int(month), 1)
    except (ValueError, AttributeError):
        return _current_period()


def _scoped_invoices(user, queryset=None):
    """Invoices the admin may see, limited by their accessible branches."""
    qs = queryset if queryset is not None else Invoice.objects.all()
    accessible_students = branching.filter_students_for_user(user, Student.objects.all())
    return qs.filter(student__in=accessible_students)


def _get_scoped_invoice_or_404(request, invoice_id):
    invoice = get_object_or_404(
        Invoice.objects.select_related("student__admin", "group"), id=invoice_id
    )
    if not branching.filter_students_for_user(
        request.user, Student.objects.filter(id=invoice.student_id)
    ).exists():
        from django.http import Http404

        raise Http404("Invoice not found.")
    return invoice


# ── Admin (HOD) ───────────────────────────────────────────────────────────────


@admin_only
def admin_payments(request):
    period = _parse_period(request.GET.get("month") or "")
    status = request.GET.get("status", "")
    branch_id = request.GET.get("branch", "")
    group_id = request.GET.get("group", "")

    invoices = (
        _scoped_invoices(request.user)
        .select_related("student__admin", "student__branch", "group")
        .prefetch_related("payments")
        .filter(period=period)
    )
    if status == "overdue":
        invoices = invoices.filter(
            status__in=[Invoice.STATUS_DUE, Invoice.STATUS_PARTIAL],
            due_date__lt=timezone.localdate(),
        )
    elif status:
        invoices = invoices.filter(status=status)
    if branch_id:
        invoices = invoices.filter(Q(student__branch_id=branch_id) | Q(group__branch_id=branch_id))
    if group_id:
        invoices = invoices.filter(group_id=group_id)
    invoices = invoices.order_by("student__admin__last_name", "student__admin__first_name")

    if request.GET.get("export") == "csv":
        return _payments_csv(invoices, period)

    open_statuses = [Invoice.STATUS_DUE, Invoice.STATUS_PARTIAL]
    active = [inv for inv in invoices if inv.status != Invoice.STATUS_CANCELLED]
    total_billed = sum(inv.total_due for inv in active)
    total_collected = sum(inv.paid_amount for inv in active)
    total_outstanding = sum(inv.balance for inv in active if inv.status in open_statuses)
    overdue_count = sum(1 for inv in active if inv.is_overdue)

    context = {
        "page_title": gettext("Payments"),
        "invoices": invoices,
        "period": period,
        "month_value": period.strftime("%Y-%m"),
        "status": status,
        "selected_branch": branch_id,
        "selected_group": group_id,
        "branches": branching.filter_branches_for_user(
            request.user, Branch.objects.all().order_by("name")
        ),
        "groups": branching.filter_groups_for_user(
            request.user, Group.objects.filter(is_archived=False).order_by("name")
        ),
        "total_billed": total_billed,
        "total_collected": total_collected,
        "total_outstanding": total_outstanding,
        "overdue_count": overdue_count,
        "status_choices": Invoice.STATUS_CHOICES,
        "is_super_admin": branching.is_super_admin(request.user),
    }
    return render(request, "hod_template/manage_payments.html", context)


def _payments_csv(invoices, period):
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="payments-{period:%Y-%m}.csv"'
    writer = csv.writer(response)
    writer.writerow(
        [
            "Student",
            "Login ID",
            "Group",
            "Month",
            "Amount",
            "Discount",
            "Paid",
            "Balance",
            "Status",
            "Due date",
        ]
    )
    for inv in invoices:
        writer.writerow(
            [
                str(inv.student),
                inv.student.admin.login_id or "",
                inv.group.name if inv.group else "—",
                inv.period.strftime("%Y-%m"),
                inv.amount,
                inv.discount,
                inv.paid_amount,
                inv.balance,
                inv.get_status_display(),
                inv.due_date.isoformat(),
            ]
        )
    return response


@admin_only
def admin_collections(request):
    """Tuition collection analytics for a month.

    Super admins compare expected vs collected money per branch and see which
    branch is lagging most. Branch admins are scoped to their branches and see
    the same comparison per group, plus who is overdue / paying partially.
    """
    period = _parse_period(request.GET.get("month") or "")
    is_super = branching.is_super_admin(request.user)

    invoices = list(
        _scoped_invoices(request.user)
        .select_related("student__admin", "student__branch", "group", "group__branch")
        .prefetch_related("payments")
        .filter(period=period)
        .exclude(status=Invoice.STATUS_CANCELLED)
    )

    def _bucket_for(inv):
        """Group rows by branch for super admins, by group for branch admins."""
        if is_super:
            branch = inv.group.branch if (inv.group and inv.group.branch_id) else inv.student.branch
            return ("none", "No branch") if branch is None else (branch.id, branch.name)
        if inv.group is not None:
            return (inv.group.id, inv.group.name)
        return ("none", "Other / one-off")

    expected = collected = 0
    buckets = {}
    for inv in invoices:
        due = inv.total_due
        paid = inv.paid_amount
        expected += due
        collected += paid
        key, label = _bucket_for(inv)
        row = buckets.setdefault(
            key,
            {
                "label": label,
                "expected": 0,
                "collected": 0,
                "outstanding": 0,
                "students": 0,
                "overdue": 0,
                "partial": 0,
            },
        )
        row["expected"] += due
        row["collected"] += paid
        row["outstanding"] += inv.balance if inv.balance > 0 else 0
        row["students"] += 1
        if inv.is_overdue:
            row["overdue"] += 1
        if inv.status == Invoice.STATUS_PARTIAL:
            row["partial"] += 1

    outstanding = expected - collected
    # Worst collector first — that's the branch/group "lacking the most".
    rows = sorted(buckets.values(), key=lambda r: r["outstanding"], reverse=True)
    for row in rows:
        row["rate"] = round(row["collected"] / row["expected"] * 100, 1) if row["expected"] else 0
    worst = rows[0] if rows and rows[0]["outstanding"] > 0 else None

    # Branch admins get a "needs attention" list: overdue first, then partial,
    # each ordered by the biggest outstanding balance.
    attention = []
    if not is_super:
        flagged = [
            inv for inv in invoices if inv.is_overdue or inv.status == Invoice.STATUS_PARTIAL
        ]
        flagged.sort(key=lambda i: (0 if i.is_overdue else 1, -float(i.balance)))
        attention = flagged[:50]

    chart_data = {
        "labels": [r["label"] for r in rows],
        "expected": [int(r["expected"]) for r in rows],
        "collected": [int(r["collected"]) for r in rows],
    }

    context = {
        "page_title": "Collections",
        "period": period,
        "month_value": period.strftime("%Y-%m"),
        "is_super_admin": is_super,
        "expected": expected,
        "collected": collected,
        "outstanding": outstanding,
        "collection_rate": round(collected / expected * 100, 1) if expected else 0,
        "group_by_label": "Branch" if is_super else "Group",
        "rows": rows,
        "worst": worst,
        "attention": attention,
        "chart_data": chart_data,
    }
    return render(request, "hod_template/collections.html", context)


@admin_only
def admin_generate_invoices(request):
    form = GenerateInvoicesForm(request.POST or None, user=request.user)
    if request.method != "POST":
        today = timezone.localdate()
        form.initial.setdefault("month", today.strftime("%Y-%m"))
        form.initial.setdefault("due_date", date(today.year, today.month, min(today.day + 5, 28)))
    if request.method == "POST" and form.is_valid():
        period = form.cleaned_data["month"]
        result = payments.generate_invoices_for_month(
            period=period,
            due_date=form.cleaned_data["due_date"],
            user=request.user,
            branch=form.cleaned_data.get("branch"),
        )
        created, skipped, no_fee = (
            len(result["created"]),
            len(result["skipped"]),
            len(result["no_fee"]),
        )
        if created:
            messages.success(
                request,
                f"Created {created} invoice{'s' if created != 1 else ''} for {period:%B %Y}.",
            )
        if skipped:
            messages.info(request, f"{skipped} already existed and were skipped.")
        if no_fee:
            messages.warning(
                request,
                f"{no_fee} enrollment{'s have' if no_fee != 1 else ' has'} no monthly fee set "
                "(set a fee on the group or its course, then generate again).",
            )
        if not (created or skipped or no_fee):
            messages.info(request, "No active enrollments matched your selection.")
        return redirect(f"{reverse('admin_payments')}?month={period:%Y-%m}")
    return render(
        request,
        "hod_template/generate_invoices.html",
        {"form": form, "page_title": "Generate Monthly Invoices"},
    )


@admin_only
def admin_add_invoice(request):
    form = ManualInvoiceForm(request.POST or None, user=request.user)
    if request.method == "POST" and form.is_valid():
        invoice = form.save(commit=False)
        invoice.period = form.cleaned_data["month"]
        invoice.group = None
        invoice.created_by = request.user
        invoice.save()
        Notification.objects.create(
            recipient=invoice.student.admin,
            category=Notification.PAYMENT,
            message=(
                f"New invoice for {invoice.period_label}: "
                f"{payments._uzs(invoice.total_due)}. Due by {invoice.due_date:%d %b %Y}."
            ),
            link=reverse("student_payments"),
        )
        messages.success(request, f"Invoice created for {invoice.student}.")
        return redirect(f"{reverse('admin_payments')}?month={invoice.period:%Y-%m}")
    return render(
        request,
        "hod_template/add_invoice.html",
        {"form": form, "page_title": "Add One-off Invoice"},
    )


@admin_only
def admin_record_payment(request, invoice_id):
    invoice = _get_scoped_invoice_or_404(request, invoice_id)
    if invoice.status == Invoice.STATUS_CANCELLED:
        messages.error(request, "This invoice is cancelled — payments cannot be recorded on it.")
        return redirect(f"{reverse('admin_payments')}?month={invoice.period:%Y-%m}")
    form = RecordPaymentForm(request.POST or None, invoice=invoice)
    if request.method != "POST":
        form.initial.setdefault("paid_on", timezone.localdate())
    if request.method == "POST" and form.is_valid():
        payment = form.save(commit=False)
        payment.invoice = invoice
        payment.received_by = request.user
        payment.save()
        invoice.refresh_status()
        Notification.objects.create(
            recipient=invoice.student.admin,
            category=Notification.PAYMENT,
            message=(
                f"Payment received: {payments._uzs(payment.amount)} for "
                f"{invoice.period_label} ({payment.get_method_display()}). Thank you!"
            ),
            link=reverse("student_payments"),
        )
        messages.success(
            request,
            f"Recorded {payments._uzs(payment.amount)} from {invoice.student}. "
            f"Invoice is now {invoice.get_status_display().lower()}.",
        )
        return redirect(f"{reverse('admin_payments')}?month={invoice.period:%Y-%m}")
    return render(
        request,
        "hod_template/record_payment.html",
        {"form": form, "invoice": invoice, "page_title": "Record Payment"},
    )


@admin_only
@require_POST
def admin_cancel_invoice(request, invoice_id):
    invoice = _get_scoped_invoice_or_404(request, invoice_id)
    if invoice.paid_amount > 0:
        messages.error(
            request,
            gettext(
                "This invoice already has payments. Void the payments first (super admin only)."
            ),
        )
    elif invoice.status == Invoice.STATUS_CANCELLED:
        messages.info(request, gettext("Invoice is already cancelled."))
    else:
        invoice.status = Invoice.STATUS_CANCELLED
        invoice.save(update_fields=["status", "updated_at"])
        messages.success(
            request,
            gettext("Invoice for %(student)s (%(period)s) cancelled.")
            % {"student": invoice.student, "period": invoice.period_label},
        )
    return redirect(f"{reverse('admin_payments')}?month={invoice.period:%Y-%m}")


@admin_only
@require_POST
def admin_void_payment(request, payment_id):
    payment = get_object_or_404(Payment.objects.select_related("invoice__student"), id=payment_id)
    invoice = payment.invoice
    if not branching.filter_students_for_user(
        request.user, Student.objects.filter(id=invoice.student_id)
    ).exists():
        from django.http import Http404

        raise Http404("Payment not found.")
    if not branching.is_super_admin(request.user):
        messages.error(request, gettext("Only the super admin can void payments."))
        return redirect(f"{reverse('admin_payments')}?month={invoice.period:%Y-%m}")
    receipt = payment.receipt_no
    payment.delete()
    invoice.refresh_status()
    messages.success(
        request,
        gettext("Payment %(receipt)s voided. Invoice balance restored.") % {"receipt": receipt},
    )
    return redirect(f"{reverse('admin_payments')}?month={invoice.period:%Y-%m}")


@admin_only
@require_POST
def admin_send_payment_reminder(request, invoice_id):
    invoice = _get_scoped_invoice_or_404(request, invoice_id)
    if payments.send_invoice_reminder(invoice, force=True):
        messages.success(
            request, gettext("Reminder sent to %(student)s.") % {"student": invoice.student}
        )
    else:
        messages.info(request, gettext("This invoice is settled — no reminder needed."))
    return redirect(f"{reverse('admin_payments')}?month={invoice.period:%Y-%m}")


# ── Staff (teachers) ─────────────────────────────────────────────────────────


@staff_only
def staff_payments(request):
    staff = get_object_or_404(Staff, admin=request.user)
    period = _parse_period(request.GET.get("month") or "")
    groups = Group.objects.filter(teacher=staff, is_archived=False).order_by("name")

    boards = []
    for group in groups:
        enrollments = (
            Enrollment.objects.filter(group=group, is_active=True)
            .select_related("student__admin")
            .order_by("student__admin__last_name")
        )
        invoices = {
            inv.student_id: inv
            for inv in Invoice.objects.filter(group=group, period=period).prefetch_related(
                "payments"
            )
        }
        rows = []
        for enrollment in enrollments:
            invoice = invoices.get(enrollment.student_id)
            if invoice is None or invoice.status == Invoice.STATUS_CANCELLED:
                state = "none"
            elif invoice.status == Invoice.STATUS_PAID:
                state = "paid"
            elif invoice.is_overdue:
                state = "overdue"
            else:
                state = "due"
            rows.append({"student": enrollment.student, "invoice": invoice, "state": state})
        boards.append({"group": group, "rows": rows})

    return render(
        request,
        "staff_template/staff_payments.html",
        {
            "page_title": "Payments Status",
            "boards": boards,
            "period": period,
            "month_value": period.strftime("%Y-%m"),
        },
    )


# ── Student ──────────────────────────────────────────────────────────────────


@student_only
def student_payments(request):
    student = get_object_or_404(Student, admin=request.user)
    invoices = (
        Invoice.objects.filter(student=student)
        .exclude(status=Invoice.STATUS_CANCELLED)
        .select_related("group")
        .prefetch_related("payments")
        .order_by("-period")
    )
    open_invoices = [
        inv for inv in invoices if inv.status in (Invoice.STATUS_DUE, Invoice.STATUS_PARTIAL)
    ]
    total_outstanding = sum(inv.balance for inv in open_invoices)
    overdue = [inv for inv in open_invoices if inv.is_overdue]
    payment_history = (
        Payment.objects.filter(invoice__student=student)
        .select_related("invoice")
        .order_by("-paid_on", "-created_at")
    )
    return render(
        request,
        "student_template/student_payments.html",
        {
            "page_title": "My Payments",
            "invoices": invoices,
            "total_outstanding": total_outstanding,
            "open_count": len(open_invoices),
            "overdue_count": len(overdue),
            "payment_history": payment_history,
        },
    )


def payment_receipt(request, payment_id):
    """Printable receipt. Students see their own; admins see their branches'."""
    if not request.user.is_authenticated:
        return redirect("/")
    payment = get_object_or_404(
        Payment.objects.select_related("invoice__student__admin", "invoice__group", "received_by"),
        id=payment_id,
    )
    user_type = str(request.user.user_type)
    student = payment.invoice.student
    allowed = False
    if user_type == "3":
        allowed = student.admin_id == request.user.id
    elif user_type == "1":
        allowed = branching.filter_students_for_user(
            request.user, Student.objects.filter(id=student.id)
        ).exists()
    if not allowed:
        from django.http import Http404

        raise Http404("Receipt not found.")
    return render(
        request,
        "main_app/payment_receipt.html",
        {
            "payment": payment,
            "invoice": payment.invoice,
            "page_title": f"Receipt {payment.receipt_no}",
        },
    )
