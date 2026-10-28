"""Demo school data command (plan task P0.6)."""

from datetime import date
from io import StringIO

from django.core.management import CommandError, call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from main_app.models import (
    Branch,
    ClassSubject,
    CustomUser,
    Enrollment,
    Group,
    Invoice,
    Parent,
    ParentChild,
    Payment,
    Session,
    Student,
    Term,
)
from main_app.school_demo import DEMO_BRANCH, DEMO_PASSWORD, seed_school_demo

TODAY = date(2026, 10, 28)


def _totals():
    return {
        "users": CustomUser.objects.count(),
        "groups": Group.objects.count(),
        "class_subjects": ClassSubject.objects.count(),
        "enrollments": Enrollment.objects.count(),
        "links": ParentChild.objects.count(),
        "terms": Term.objects.count(),
        "invoices": Invoice.objects.count(),
        "payments": Payment.objects.count(),
    }


class SeedSchoolDemoTests(TestCase):
    def test_builds_a_complete_demo_school(self):
        counts = seed_school_demo(today=TODAY)
        branch = Branch.objects.get(name=DEMO_BRANCH)
        self.assertEqual(branch.brand, Branch.BRAND_SCHOOL)

        classes = Group.objects.filter(branch=branch, kind=Group.KIND_CLASS)
        self.assertEqual(sorted(classes.values_list("name", flat=True)), ["1-A", "11-A", "7-B"])
        for group in classes:
            group.full_clean()
            self.assertIsNotNone(group.teacher)
            self.assertTrue(group.class_subjects.exists())
            self.assertFalse(group.class_subjects.filter(teacher__isnull=True).exists())
        self.assertEqual(counts["class_subjects"], 32)

        year = Session.objects.get()
        self.assertTrue(year.is_current)
        self.assertEqual(str(year), "2026–2027")
        self.assertEqual(year.terms.count(), 4)

        students = Student.objects.filter(branch=branch)
        self.assertEqual(students.count(), 12)
        for student in students:
            self.assertEqual(Enrollment.objects.filter(student=student, is_active=True).count(), 1)

        self.assertEqual(Parent.objects.count(), 12)
        two_kids = Parent.objects.get(admin__login_id="DEMO-PR01")
        self.assertEqual(two_kids.children.count(), 2)
        aziz = Student.objects.get(admin__login_id="DEMO-IC01")
        self.assertEqual(aziz.parent_links.count(), 2)
        self.assertEqual(aziz.parent_links.filter(is_primary=True).count(), 1)

        invoices = Invoice.objects.filter(group__branch=branch, period=date(2026, 10, 1))
        self.assertEqual(invoices.count(), 12)
        self.assertEqual(invoices.filter(status=Invoice.STATUS_PAID).count(), 3)
        self.assertEqual(invoices.filter(status=Invoice.STATUS_PARTIAL).count(), 1)
        self.assertEqual(invoices.filter(status=Invoice.STATUS_DUE).count(), 8)

    def test_running_again_adds_nothing_and_keeps_passwords(self):
        seed_school_demo(today=TODAY)
        before = _totals()
        counts = seed_school_demo(password="Changed987!", today=TODAY)
        self.assertEqual(_totals(), before)
        for key in ("teachers", "classes", "students", "parents", "links", "invoices"):
            self.assertEqual(counts[key], 0, key)
        user = CustomUser.objects.get(login_id="DEMO-PR01")
        self.assertTrue(user.check_password(DEMO_PASSWORD))

    def test_an_existing_year_and_its_quarters_are_kept(self):
        real = Session.objects.create(
            name="Real year",
            start_year=date(2026, 9, 2),
            end_year=date(2027, 5, 31),
            is_current=True,
        )
        Term.objects.create(
            session=real, number=1, start_date=date(2026, 9, 2), end_date=date(2026, 11, 1)
        )
        seed_school_demo(today=TODAY)
        self.assertEqual(Session.objects.get(), real)
        self.assertEqual(real.terms.count(), 1)
        self.assertTrue(Group.objects.filter(session=real, name="7-B").exists())

    # Staging runs with the School brand on (P0.5).
    @override_settings(SECURE_SSL_REDIRECT=False, SCHOOL_BRAND_ENABLED=True)
    def test_demo_parent_can_log_in_and_sees_both_children(self):
        seed_school_demo(today=TODAY)
        res = APIClient().post(
            reverse("api_login"),
            {"identifier": "DEMO-PR01", "password": DEMO_PASSWORD},
            format="json",
        )
        self.assertEqual(res.status_code, 200, res.data)
        user = res.data["user"]
        self.assertEqual(user["role"], "parent")
        self.assertEqual(user["brand"], "school")
        self.assertEqual(
            sorted(c["class"]["name"] for c in user["children"]),
            ["1-A", "7-B"],
        )


class SeedSchoolDemoCommandTests(TestCase):
    @override_settings(DEBUG=False)
    def test_refuses_without_force_when_debug_is_off(self):
        with self.assertRaises(CommandError):
            call_command("seed_school_demo", stdout=StringIO())
        self.assertFalse(Branch.objects.filter(name=DEMO_BRANCH).exists())

    @override_settings(DEBUG=False)
    def test_force_runs_and_reports(self):
        out = StringIO()
        call_command("seed_school_demo", "--force", stdout=out)
        self.assertIn("3 classes", out.getvalue())
        self.assertIn("12 parents", out.getvalue())
        self.assertNotIn(DEMO_PASSWORD, out.getvalue())

    @override_settings(DEBUG=True)
    def test_runs_when_debug_is_on(self):
        call_command("seed_school_demo", stdout=StringIO())
        self.assertTrue(Branch.objects.filter(name=DEMO_BRANCH).exists())
