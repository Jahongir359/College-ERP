"""Study Center admin pages on the Admin UI kit (P3.9c, mockups 16c and 16d).

Home: this month's paid total, collection rate, the overdue count and the
6-month chart, all limited to the admin's branches. Students: payment state
per row and the numbers above the list. Teachers, groups and payments: kit
markup and their own numbers.
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from main_app.models import (
    Admin,
    Branch,
    Course,
    Enrollment,
    Group,
    Invoice,
    Payment,
    Staff,
    Student,
)
from main_app.payments import dashboard_payment_summary, student_payment_states

PASSWORD = "Pass12345!"


def _user(email, user_type, **extra):
    return get_user_model().objects.create_user(
        email=email,
        password=PASSWORD,
        first_name=email.split("@")[0].title(),
        last_name="Test",
        user_type=user_type,
        **extra,
    )


@override_settings(SECURE_SSL_REDIRECT=False)
class CenterAdminPagesTests(TestCase):
    def setUp(self):
        self.today = timezone.localdate()
        self.month = self.today.replace(day=1)
        self.branch_a = Branch.objects.create(name="Center A")
        self.branch_b = Branch.objects.create(name="Center B")
        self.course = Course.objects.create(name="IELTS")

        self.admin_user = _user("nodir@example.com", "1")
        admin = Admin.objects.get(admin=self.admin_user)
        admin.is_super_admin = False
        admin.save()
        admin.branches.set([self.branch_a])

        teacher = _user("kamola@example.com", "2", login_id="TC100001")
        self.staff = Staff.objects.get(admin=teacher)
        self.staff.branch = self.branch_a
        self.staff.save()
        idle = _user("idle@example.com", "2", login_id="TC100002")
        idle_staff = Staff.objects.get(admin=idle)
        idle_staff.branch = self.branch_a
        idle_staff.save()

        self.group = Group.objects.create(
            name="IELTS 6.5", course=self.course, teacher=self.staff, branch=self.branch_a
        )
        self.group_b = Group.objects.create(
            name="Far group", course=self.course, branch=self.branch_b
        )
        self.lonely = Group.objects.create(
            name="No teacher yet", course=self.course, branch=self.branch_a
        )

        self.paid = self._student("paid@example.com", self.branch_a)
        self.late = self._student("late@example.com", self.branch_a)
        self.open = self._student("open@example.com", self.branch_a)
        self.far = self._student("far@example.com", self.branch_b)
        for s in (self.paid, self.late, self.open):
            Enrollment.objects.create(student=s, group=self.group)

        yesterday = self.today - timedelta(days=1)
        later = self.today + timedelta(days=10)
        self._invoice(self.paid, 600000, later, paid=600000)
        self._invoice(self.late, 600000, yesterday, paid=200000)
        self._invoice(self.open, 600000, later)
        # Other branch: never counted for this admin.
        self._invoice(self.far, 900000, yesterday, paid=900000)
        self.client.force_login(self.admin_user)

    def _student(self, email, branch):
        student = Student.objects.get(admin=_user(email, "3"))
        student.branch = branch
        student.course = self.course
        student.save()
        return student

    def _invoice(self, student, amount, due, paid=0):
        status = Invoice.STATUS_DUE
        if paid >= amount:
            status = Invoice.STATUS_PAID
        elif paid:
            status = Invoice.STATUS_PARTIAL
        invoice = Invoice.objects.create(
            student=student,
            group=self.group if student.branch == self.branch_a else self.group_b,
            period=self.month,
            amount=amount,
            status=status,
            due_date=due,
        )
        if paid:
            Payment.objects.create(invoice=invoice, amount=paid, paid_on=self.today)
            Invoice.objects.filter(pk=invoice.pk).update(status=status)
        return invoice

    def _months(self):
        prev = (self.month - timedelta(days=1)).replace(day=1)
        nxt = (self.month + timedelta(days=32)).replace(day=1)
        return [(prev, self.month, "prev"), (self.month, nxt, "now")]

    # ── helpers ────────────────────────────────────────────────────────────

    def test_summary_counts_only_the_given_students(self):
        mine = Student.objects.filter(branch=self.branch_a)
        summary = dashboard_payment_summary(mine, self._months(), today=self.today)
        self.assertEqual(summary["paid_this_month"], 800000)
        self.assertEqual(summary["collection_rate"], 44)  # 800k of 1.8M
        self.assertEqual(summary["overdue_students"], 1)
        self.assertEqual([m["total"] for m in summary["monthly"]], [0, 800000])
        self.assertEqual([m["pct"] for m in summary["monthly"]], [0, 100])

    def test_summary_without_invoices_has_no_rate(self):
        summary = dashboard_payment_summary(
            Student.objects.none(), self._months(), today=self.today
        )
        self.assertEqual(summary["paid_this_month"], 0)
        self.assertIsNone(summary["collection_rate"])
        self.assertEqual(summary["overdue_students"], 0)

    def test_payment_state_per_student_worst_wins(self):
        later = self.today + timedelta(days=5)
        # An open invoice (here a one-off, no group) beats a paid one.
        Invoice.objects.create(student=self.paid, period=self.month, amount=100000, due_date=later)
        states = student_payment_states(Student.objects.all(), today=self.today)
        self.assertEqual(states[self.paid.id], "due")
        self.assertEqual(states[self.late.id], "debt")
        self.assertEqual(states[self.open.id], "due")
        self.assertEqual(states[self.far.id], "paid")
        lonely = self._student("new@example.com", self.branch_a)
        self.assertNotIn(lonely.id, student_payment_states(Student.objects.all()))

    # ── pages ──────────────────────────────────────────────────────────────

    def test_home_shows_paid_this_month_and_the_overdue_alert(self):
        html = self.client.get(reverse("admin_home")).content.decode()
        self.assertIn('class="page-eyebrow"', html)
        self.assertIn("Paid this month", html)
        self.assertIn('data-stat="paid"', html)
        self.assertIn("800", html)
        self.assertIn("1 student has an overdue payment", html)
        self.assertIn(reverse("admin_payments") + "?status=overdue", html)
        self.assertNotIn("Far group", html)

    def test_home_is_calm_without_overdue(self):
        Invoice.objects.filter(student=self.late).update(due_date=self.today + timedelta(days=3))
        html = self.client.get(reverse("admin_home")).content.decode()
        self.assertIn("No overdue payments.", html)
        self.assertIn('data-overdue="0"', html)

    def test_students_list_has_stats_and_payment_badges(self):
        response = self.client.get(reverse("manage_student"))
        stats = response.context["student_stats"]
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["in_groups"], 3)
        self.assertEqual(stats["debtors"], 1)
        html = response.content.decode()
        self.assertIn('class="ui-table"', html)
        self.assertIn("data-no-table-enhance", html)
        self.assertIn('ui-badge ui-badge--abs">Overdue', html)
        self.assertIn('ui-badge ui-badge--ok">Paid', html)
        self.assertNotIn("far@example.com", html)

    def test_teachers_list_counts_groups(self):
        response = self.client.get(reverse("manage_staff"))
        stats = response.context["staff_stats"]
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["groups"], 1)
        self.assertEqual(stats["without_group"], 1)
        html = response.content.decode()
        self.assertIn('class="ui-table"', html)
        self.assertIn("IELTS 6.5", html)

    def test_groups_list_counts_and_flags_no_teacher(self):
        Group.objects.create(
            name="Old",
            course=self.course,
            branch=self.branch_a,
            teacher=self.staff,
            is_archived=True,
        )
        response = self.client.get(reverse("manage_group"))
        stats = response.context["group_stats"]
        self.assertEqual(stats, {"active": 2, "students": 3, "no_teacher": 1, "archived": 1})
        html = response.content.decode()
        self.assertIn('ui-badge ui-badge--late">No teacher', html)
        self.assertNotIn("Far group", html)

    def test_payments_page_uses_the_kit(self):
        html = self.client.get(reverse("admin_payments")).content.decode()
        self.assertIn('class="page-actions"', html)
        self.assertIn('class="ui-stats"', html)
        self.assertIn('class="ui-table"', html)
        self.assertIn('ui-badge ui-badge--abs">Overdue', html)
        self.assertNotIn("ice-hero", html)
        # One branch: no branch picker.
        self.assertNotIn('id="branch-filter"', html)

    def test_pages_render_in_uzbek_and_russian(self):
        for language, text in (("uz", "Bu oy toʻlangan"), ("ru", "Оплачено в этом месяце")):
            self.admin_user.language = language
            self.admin_user.save(update_fields=["language"])
            self.assertContains(self.client.get(reverse("admin_home")), text)
        self.assertContains(self.client.get(reverse("manage_staff")), "Без группы")
