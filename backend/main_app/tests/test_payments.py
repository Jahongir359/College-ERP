from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from main_app.models import (
    Admin,
    Branch,
    Course,
    Enrollment,
    Group,
    Staff,
    Student,
)


_BASE_OVERRIDES = dict(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    # Disable SSL redirect so the test client (HTTP) reaches views without
    # being bounced to HTTPS (which then strips POST bodies on 301 redirect).
    SECURE_SSL_REDIRECT=False,
)


class PaymentsTests(TestCase):
    """Tuition billing: generation idempotency, statuses, access control, reminders."""

    def _make_user(self, email, user_type, login_id=None):
        UserModel = get_user_model()
        return UserModel.objects.create_user(
            email=email,
            password="Pass123!",
            first_name="Test",
            last_name="User",
            user_type=user_type,
            gender="M",
            address="",
            profile_pic="",
            login_id=login_id,
        )

    def setUp(self):
        from main_app.models import Branch

        self.branch_a = Branch.objects.create(name="Pay Branch A")
        self.branch_b = Branch.objects.create(name="Pay Branch B")
        self.course = Course.objects.create(name="Paid Course", monthly_fee=600000)
        self.free_course = Course.objects.create(name="Unpriced Course")

        self.super_admin_user = self._make_user("paysuper@iceberg.internal", "1")
        self.branch_admin_user = self._make_user("payba@iceberg.internal", "1")
        self.branch_admin = self.branch_admin_user.admin
        self.branch_admin.is_super_admin = False
        self.branch_admin.save()
        self.branch_admin.branches.add(self.branch_a)

        self.teacher_user = self._make_user("payt@iceberg.internal", "2", "TC91001")
        self.teacher = Staff.objects.get(admin=self.teacher_user)
        self.teacher.branch = self.branch_a
        self.teacher.save()

        # Group A: fee from course default. Group B: explicit override.
        self.group_a = Group.objects.create(
            name="Pay Group A", course=self.course, teacher=self.teacher, branch=self.branch_a
        )
        self.group_b = Group.objects.create(
            name="Pay Group B", course=self.course, branch=self.branch_b, monthly_fee=750000
        )
        self.group_unpriced = Group.objects.create(
            name="Unpriced Group", course=self.free_course, branch=self.branch_a
        )

        self.student_a_user = self._make_user("paysa@iceberg.internal", "3", "IC91001")
        self.student_b_user = self._make_user("paysb@iceberg.internal", "3", "IC91002")
        self.student_c_user = self._make_user("paysc@iceberg.internal", "3", "IC91003")
        self.student_a = Student.objects.get(admin=self.student_a_user)
        self.student_b = Student.objects.get(admin=self.student_b_user)
        self.student_c = Student.objects.get(admin=self.student_c_user)
        self.student_a.branch = self.branch_a
        self.student_a.phone = "+998 90 123 45 67"
        self.student_a.save()
        self.student_b.branch = self.branch_b
        self.student_b.save()
        self.student_c.branch = self.branch_a
        self.student_c.save()
        Enrollment.objects.create(student=self.student_a, group=self.group_a, is_active=True)
        Enrollment.objects.create(student=self.student_b, group=self.group_b, is_active=True)
        Enrollment.objects.create(student=self.student_c, group=self.group_unpriced, is_active=True)

        self.period = date(2026, 6, 1)
        self.due = date(2026, 6, 10)

    def _generate(self, user=None, branch=None):
        from main_app.payments import generate_invoices_for_month

        return generate_invoices_for_month(
            self.period, self.due, user=user or self.super_admin_user, branch=branch
        )

    # ── Generation ──

    def test_generate_creates_one_invoice_per_active_enrollment(self):
        from main_app.models import Invoice

        result = self._generate()
        self.assertEqual(len(result["created"]), 2)  # a + b; unpriced reported separately
        self.assertEqual(len(result["no_fee"]), 1)
        amounts = {inv.student_id: inv.amount for inv in Invoice.objects.all()}
        self.assertEqual(amounts[self.student_a.id], 600000)  # course default
        self.assertEqual(amounts[self.student_b.id], 750000)  # group override

    def test_generate_is_idempotent(self):
        from main_app.models import Invoice

        self._generate()
        result = self._generate()
        self.assertEqual(len(result["created"]), 0)
        self.assertEqual(len(result["skipped"]), 2)
        self.assertEqual(Invoice.objects.count(), 2)

    def test_generate_scoped_to_branch_admin(self):
        result = self._generate(user=self.branch_admin_user)
        students = {inv.student_id for inv in result["created"]}
        self.assertEqual(students, {self.student_a.id})

    def test_generate_notifies_students(self):
        from main_app.models import Notification

        self._generate()
        self.assertTrue(
            Notification.objects.filter(recipient=self.student_a_user, category="payment").exists()
        )

    # ── Status transitions ──

    def test_payment_status_transitions(self):
        from main_app.models import Invoice, Payment

        self._generate()
        invoice = Invoice.objects.get(student=self.student_a)
        self.assertEqual(invoice.status, Invoice.STATUS_DUE)

        Payment.objects.create(invoice=invoice, amount=200000, method="cash")
        invoice.refresh_status()
        self.assertEqual(invoice.status, Invoice.STATUS_PARTIAL)
        self.assertEqual(invoice.balance, 400000)

        Payment.objects.create(invoice=invoice, amount=400000, method="card")
        invoice.refresh_status()
        self.assertEqual(invoice.status, Invoice.STATUS_PAID)
        self.assertEqual(invoice.balance, 0)

    @override_settings(**_BASE_OVERRIDES)
    def test_record_payment_view_rejects_overpayment(self):
        from main_app.models import Invoice

        self._generate()
        invoice = Invoice.objects.get(student=self.student_a)
        self.client.force_login(self.super_admin_user)
        response = self.client.post(
            reverse("admin_record_payment", args=[invoice.id]),
            {"amount": "999999999", "method": "cash", "paid_on": "2026-06-05", "note": ""},
        )
        self.assertEqual(response.status_code, 200)  # re-rendered with form error
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, Invoice.STATUS_DUE)
        self.assertEqual(invoice.paid_amount, 0)

    @override_settings(**_BASE_OVERRIDES)
    def test_record_payment_view_marks_paid_and_notifies(self):
        from main_app.models import Invoice, Notification

        self._generate()
        invoice = Invoice.objects.get(student=self.student_a)
        self.client.force_login(self.super_admin_user)
        response = self.client.post(
            reverse("admin_record_payment", args=[invoice.id]),
            {"amount": "600000", "method": "cash", "paid_on": "2026-06-05", "note": ""},
        )
        self.assertEqual(response.status_code, 302)
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, Invoice.STATUS_PAID)
        self.assertTrue(
            Notification.objects.filter(
                recipient=self.student_a_user,
                category="payment",
                message__icontains="Payment received",
            ).exists()
        )

    @override_settings(**_BASE_OVERRIDES)
    def test_cancel_invoice_with_payments_is_blocked(self):
        from main_app.models import Invoice, Payment

        self._generate()
        invoice = Invoice.objects.get(student=self.student_a)
        Payment.objects.create(invoice=invoice, amount=100000, method="cash")
        invoice.refresh_status()
        self.client.force_login(self.super_admin_user)
        self.client.post(reverse("admin_cancel_invoice", args=[invoice.id]))
        invoice.refresh_from_db()
        self.assertNotEqual(invoice.status, Invoice.STATUS_CANCELLED)

    @override_settings(**_BASE_OVERRIDES)
    def test_void_payment_requires_super_admin(self):
        from main_app.models import Invoice, Payment

        self._generate()
        invoice = Invoice.objects.get(student=self.student_a)
        payment = Payment.objects.create(invoice=invoice, amount=600000, method="cash")
        invoice.refresh_status()

        self.client.force_login(self.branch_admin_user)
        self.client.post(reverse("admin_void_payment", args=[payment.id]))
        self.assertTrue(Payment.objects.filter(id=payment.id).exists())

        self.client.force_login(self.super_admin_user)
        self.client.post(reverse("admin_void_payment", args=[payment.id]))
        self.assertFalse(Payment.objects.filter(id=payment.id).exists())
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, Invoice.STATUS_DUE)

    # ── Access control ──

    @override_settings(**_BASE_OVERRIDES)
    def test_branch_admin_cannot_record_payment_for_other_branch(self):
        from main_app.models import Invoice

        self._generate()
        other_invoice = Invoice.objects.get(student=self.student_b)  # branch B
        self.client.force_login(self.branch_admin_user)
        response = self.client.get(reverse("admin_record_payment", args=[other_invoice.id]))
        self.assertEqual(response.status_code, 404)

    @override_settings(**_BASE_OVERRIDES)
    def test_student_sees_only_own_invoices(self):
        self._generate()
        self.client.force_login(self.student_a_user)
        response = self.client.get(reverse("student_payments"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Pay Group A")
        self.assertNotContains(response, "Pay Group B")

    @override_settings(**_BASE_OVERRIDES)
    def test_receipt_blocked_for_other_student(self):
        from main_app.models import Invoice, Payment

        self._generate()
        invoice = Invoice.objects.get(student=self.student_a)
        payment = Payment.objects.create(invoice=invoice, amount=600000, method="cash")

        self.client.force_login(self.student_b_user)
        response = self.client.get(reverse("payment_receipt", args=[payment.id]))
        self.assertEqual(response.status_code, 404)

        self.client.force_login(self.student_a_user)
        response = self.client.get(reverse("payment_receipt", args=[payment.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, payment.receipt_no)

    @override_settings(**_BASE_OVERRIDES)
    def test_staff_payments_board_shows_status(self):
        self._generate()
        self.client.force_login(self.teacher_user)
        response = self.client.get(
            reverse("staff_payments"), {"month": self.period.strftime("%Y-%m")}
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Pay Group A")

    # ── Reminders ──

    @override_settings(**_BASE_OVERRIDES)
    def test_reminder_dedup_per_day(self):
        from main_app.models import Invoice, Notification
        from main_app.payments import send_invoice_reminder

        self._generate()
        invoice = Invoice.objects.get(student=self.student_a)
        self.assertTrue(send_invoice_reminder(invoice))
        self.assertFalse(send_invoice_reminder(invoice))  # same day → deduped
        self.assertTrue(send_invoice_reminder(invoice, force=True))  # HOD button
        self.assertEqual(
            Notification.objects.filter(
                recipient=self.student_a_user,
                category="payment",
                message__icontains="reminder",
            ).count(),
            2,
        )

    @override_settings(**_BASE_OVERRIDES)
    def test_reminder_skips_paid_invoices(self):
        from main_app.models import Invoice, Payment
        from main_app.payments import send_invoice_reminder

        self._generate()
        invoice = Invoice.objects.get(student=self.student_a)
        Payment.objects.create(invoice=invoice, amount=600000, method="cash")
        invoice.refresh_status()
        self.assertFalse(send_invoice_reminder(invoice, force=True))

    @override_settings(**_BASE_OVERRIDES)
    def test_reminder_command_targets_overdue_and_due_soon(self):
        from django.core.management import call_command
        from django.utils import timezone as dj_tz
        from main_app.models import Invoice

        self._generate()
        today = dj_tz.localdate()
        overdue = Invoice.objects.get(student=self.student_a)
        overdue.due_date = today - timedelta(days=5)
        overdue.save(update_fields=["due_date"])
        far_future = Invoice.objects.get(student=self.student_b)
        far_future.due_date = today + timedelta(days=30)
        far_future.save(update_fields=["due_date"])

        call_command("send_payment_reminders")
        overdue.refresh_from_db()
        far_future.refresh_from_db()
        self.assertEqual(overdue.last_reminded_on, today)
        self.assertIsNone(far_future.last_reminded_on)

        # Second run on the same day: overdue repeat interval not reached.
        from main_app.models import Notification

        before = Notification.objects.filter(category="payment").count()
        call_command("send_payment_reminders")
        self.assertEqual(Notification.objects.filter(category="payment").count(), before)

    # ── Misc ──

    def test_uzs_filter_formatting(self):
        from main_app.templatetags.uzs import uzs

        # Round thousands/millions use the local "ming"/"million" words.
        self.assertEqual(uzs(1200000), "1.2 million soʻm")
        self.assertEqual(uzs(200000), "200 ming soʻm")
        self.assertEqual(uzs(None), "—")

    def test_uz_phone_normalization(self):
        from main_app.payments import _normalize_uz_phone

        self.assertEqual(_normalize_uz_phone("+998 90 123 45 67"), "998901234567")
        self.assertEqual(_normalize_uz_phone("901234567"), "998901234567")
        self.assertIsNone(_normalize_uz_phone("12345"))


class UzsFormattingTests(TestCase):
    """Whole-soʻm display formatting: ming/million words + comma fallback."""

    def test_format_uzs_number(self):
        from main_app.payments import format_uzs_number

        cases = {
            0: "0",
            500: "500",
            5000: "5 ming",
            200000: "200 ming",
            750000: "750 ming",
            200500: "200,500",
            1000000: "1 million",
            1500000: "1.5 million",
            10000000: "10 million",
            1250000: "1,250,000",
        }
        for amount, expected in cases.items():
            self.assertEqual(format_uzs_number(amount), expected, amount)

    def test_uzs_filter_adds_suffix(self):
        from main_app.templatetags.uzs import uzs, uzs_plain

        self.assertEqual(uzs(200000), "200 ming soʻm")
        self.assertEqual(uzs(200500), "200,500 soʻm")
        self.assertEqual(uzs_plain(10000000), "10 million")


class MoneyInputParsingTests(TestCase):
    """Admins can type ANY amount, optionally comma/space grouped."""

    def test_grouped_input_strips_separators(self):
        from main_app.forms import GroupedNumberInput

        w = GroupedNumberInput()
        self.assertEqual(w.value_from_datadict({"amount": "200,000"}, {}, "amount"), "200000")
        self.assertEqual(w.value_from_datadict({"amount": "1 500 000"}, {}, "amount"), "1500000")
        self.assertEqual(w.value_from_datadict({"amount": "200500"}, {}, "amount"), "200500")

    def test_record_payment_accepts_any_amount(self):
        from main_app.forms import RecordPaymentForm

        # A non-multiple-of-1000, comma-grouped amount must validate (the old
        # step="1000"/min="1" widget rejected anything not ending in 1).
        form = RecordPaymentForm(
            {"amount": "200,501", "method": "cash", "paid_on": "2026-06-15", "note": ""},
            invoice=None,
        )
        self.assertTrue(form.is_valid(), form.errors)
        from decimal import Decimal

        self.assertEqual(form.cleaned_data["amount"], Decimal("200501"))

    def test_amount_widget_has_no_step_constraint(self):
        from main_app.forms import RecordPaymentForm

        html = str(RecordPaymentForm(invoice=None)["amount"])
        self.assertIn('type="text"', html)  # not a stepped number input
        self.assertIn("data-money", html)  # JS comma-grouping hook
        self.assertNotIn('step="1000"', html)


@override_settings(**_BASE_OVERRIDES)
class CollectionsViewTests(TestCase):
    """Expected-vs-collected analytics: branch breakdown for super admins,
    group breakdown + attention list for branch admins."""

    def _user(self, email, user_type, login_id=None):
        return get_user_model().objects.create_user(
            email=email,
            password="Pass123!",
            first_name=email.split("@")[0],
            last_name="X",
            user_type=user_type,
            login_id=login_id,
        )

    def setUp(self):
        from main_app.models import Invoice, Payment

        self.today = date.today()
        self.period = date(self.today.year, self.today.month, 1)
        self.branch_a = Branch.objects.create(name="Branch A")
        self.branch_b = Branch.objects.create(name="Branch B")
        self.course = Course.objects.create(name="IELTS")

        # Super admin (signal default) + branch admin scoped to Branch A.
        self.super_user = self._user("super-coll@example.com", "1")
        self.ba_user = self._user("ba-coll@example.com", "1")
        ba = Admin.objects.get(admin=self.ba_user)
        ba.is_super_admin = False
        ba.branches.set([self.branch_a])
        ba.save()

        ta = self._user("ta-coll@example.com", "2", login_id="TCC001")
        teacher = Staff.objects.get(admin=ta)
        self.group_a = Group.objects.create(
            name="Group A", course=self.course, teacher=teacher, branch=self.branch_a
        )
        self.group_b = Group.objects.create(
            name="Group B", course=self.course, teacher=teacher, branch=self.branch_b
        )

        def make_invoice(login_id, branch, group, amount, paid, overdue=False):
            su = self._user(f"s{login_id}@example.com", "3", login_id=login_id)
            student = Student.objects.get(admin=su)
            student.branch = branch
            student.course = self.course
            student.save()
            Enrollment.objects.create(student=student, group=group, is_active=True)
            due = self.today - timedelta(days=1) if overdue else self.today + timedelta(days=10)
            inv = Invoice.objects.create(
                student=student,
                group=group,
                period=self.period,
                amount=amount,
                discount=0,
                due_date=due,
            )
            if paid:
                Payment.objects.create(invoice=inv, amount=paid, method="cash")
            inv.refresh_status()
            return inv

        # Branch A: one fully paid, one partial + overdue.
        make_invoice("ICA001", self.branch_a, self.group_a, 600000, 600000)
        make_invoice("ICA002", self.branch_a, self.group_a, 600000, 200000, overdue=True)
        # Branch B: unpaid.
        make_invoice("ICB001", self.branch_b, self.group_b, 600000, 0)

    def test_super_admin_sees_all_branches_and_worst(self):
        self.client.force_login(self.super_user)
        ctx = self.client.get(reverse("admin_collections")).context
        self.assertEqual(ctx["expected"], 1800000)
        self.assertEqual(ctx["collected"], 800000)
        self.assertEqual(ctx["outstanding"], 1000000)
        labels = {r["label"] for r in ctx["rows"]}
        self.assertEqual(labels, {"Branch A", "Branch B"})
        # Branch B has the bigger gap (600k vs 400k) → ranked worst.
        self.assertEqual(ctx["worst"]["label"], "Branch B")
        self.assertEqual(ctx["rows"][0]["label"], "Branch B")

    def test_branch_admin_scoped_to_own_branch_groups(self):
        self.client.force_login(self.ba_user)
        ctx = self.client.get(reverse("admin_collections")).context
        # Only Branch A money is visible.
        self.assertEqual(ctx["expected"], 1200000)
        self.assertEqual(ctx["collected"], 800000)
        labels = {r["label"] for r in ctx["rows"]}
        self.assertEqual(labels, {"Group A"})  # grouped by group, Branch B excluded
        # Attention list holds the overdue/partial student, not the fully-paid one.
        self.assertEqual(len(ctx["attention"]), 1)
        self.assertTrue(ctx["attention"][0].is_overdue)
