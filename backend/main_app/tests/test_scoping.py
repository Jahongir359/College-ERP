"""Branch scoping review for the School code (plan task P1.8).

* A guard that fails when School modules filter by branch inline instead of
  through ``branching.py`` (plan rule 0.1).
* Per-role tests for the School helpers of plan section 4.2 that had no direct
  test yet.
* A parent can't take another family's phone number in their profile (D4).
"""

import re
from datetime import date
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from main_app import branching
from main_app.models import (
    Admin,
    Branch,
    ClassSubject,
    Course,
    Enrollment,
    Group,
    Parent,
    ParentChild,
    Session,
    Staff,
    Student,
    Subject,
)
from main_app.school import seed_school_subjects

APP_DIR = Path(__file__).resolve().parent.parent

# School modules that answer users' requests and must leave access rules to
# branching.py. Add new School views, forms and helpers here. Seeding code
# (school_demo.py, management commands) looks up its own rows by branch and is
# not listed.
SCHOOL_MODULES = (
    "api/school_views.py",
    "api/register_views.py",
    "api/marks_views.py",
    "api/term_grades_views.py",
    "api/family.py",
    "api/parent_messages.py",
    "parents.py",
    "school.py",
    "school_admin_views.py",
    "school_board_views.py",
    "school_timetable_views.py",
    "school_register_report_views.py",
    "school_demo.py",
    "school_forms.py",
    "push.py",
)

_CALL = re.compile(r"\.(?:filter|exclude|get)\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)", re.S)
_BRANCH_LOOKUP = re.compile(r"\b(?:\w+__)?branch(?:_id|es)?(?:__\w+)?\s*=")
_BRANCHES_ATTR = re.compile(r"\.branches\b")
_ALLOW = "scoping-ok"


def inline_branch_filters(source):
    """Line numbers of queryset calls that filter by branch, plus ``.branches`` uses.

    A line ending in ``# scoping-ok: <reason>`` is allowed (for example a
    ``?branch=`` filter that narrows a list already scoped by branching.py).
    """
    lines = source.splitlines()
    found = set()
    for match in _CALL.finditer(source):
        if _BRANCH_LOOKUP.search(match.group(0)):
            found.add(source.count("\n", 0, match.start()) + 1)
    for number, line in enumerate(lines, start=1):
        if _BRANCHES_ATTR.search(line.split("#")[0]):
            found.add(number)
    return sorted(n for n in found if _ALLOW not in lines[n - 1])


class InlineBranchFilterGuardTests(SimpleTestCase):
    def test_guard_catches_inline_filters(self):
        sample = (
            "qs = Group.objects.filter(branch_id__in=ids)\n"
            "qs = qs.exclude(\n    student__branch=branch,\n)\n"
            "ids = profile.branches.all()\n"
            "ok = qs.filter(branch_id=1)  # scoping-ok: narrows a scoped list\n"
            "obj = BellPeriod(branch=branch)\n"
        )
        self.assertEqual(inline_branch_filters(sample), [1, 2, 5])

    def test_school_modules_leave_scoping_to_branching(self):
        for name in SCHOOL_MODULES:
            path = APP_DIR / name
            if not path.exists():  # module of a task not merged yet
                continue
            with self.subTest(module=name):
                self.assertEqual(
                    inline_branch_filters(path.read_text(encoding="utf-8")),
                    [],
                    f"{name} filters by branch inline; add a helper to branching.py",
                )


def _user(email, user_type, first="T"):
    return get_user_model().objects.create_user(
        email=email, password="Pass12345!", first_name=first, last_name="U", user_type=user_type
    )


def _reload(user):
    return get_user_model().objects.get(pk=user.pk)


class _SchoolFixture:
    def make_fixture(self):
        self.school = Branch.objects.create(name="School", brand=Branch.BRAND_SCHOOL)
        self.other_school = Branch.objects.create(name="School 2", brand=Branch.BRAND_SCHOOL)
        self.course, _ = seed_school_subjects()
        self.year = Session.objects.create(
            name="2026–2027", start_year=date(2026, 9, 1), end_year=date(2027, 6, 30)
        )
        self.homeroom = Staff.objects.get(admin=_user("home@example.com", "2"))
        self.subject_teacher = Staff.objects.get(admin=_user("maths@example.com", "2"))
        self.class_7b = self.make_class("7-B", "B", self.school, teacher=self.homeroom)
        self.class_4b = self.make_class("4-B", "B", self.school)
        self.class_other = self.make_class("5-A", "A", self.other_school)
        self.course_group = Group.objects.create(
            name="IELTS", course=Course.objects.create(name="IELTS"), branch=self.school
        )
        ClassSubject.objects.create(
            group=self.class_4b,
            subject=Subject.objects.get(course=self.course, name="Matematika"),
            teacher=self.subject_teacher,
        )

        self.kid = Student.objects.get(admin=_user("kid@example.com", "3"))
        Enrollment.objects.create(student=self.kid, group=self.class_7b)
        Enrollment.objects.create(student=self.kid, group=self.course_group)
        self.far_kid = Student.objects.get(admin=_user("far@example.com", "3"))
        Enrollment.objects.create(student=self.far_kid, group=self.class_other)

        self.parent_user = _user("mum@example.com", "4")
        self.parent = Parent.objects.get(admin=self.parent_user)
        self.link_kid = ParentChild.objects.create(parent=self.parent, student=self.kid)
        self.link_far = ParentChild.objects.create(parent=self.parent, student=self.far_kid)

        self.super_admin = _user("boss@example.com", "1")
        self.branch_admin = _user("office@example.com", "1")
        profile = Admin.objects.get(admin=self.branch_admin)
        profile.is_super_admin = False
        profile.save()
        profile.branches.set([self.school])

    def make_class(self, name, letter, branch, teacher=None):
        return Group.objects.create(
            name=name,
            course=self.course,
            branch=branch,
            teacher=teacher,
            kind=Group.KIND_CLASS,
            grade_level=int(name.split("-")[0]),
            letter=letter,
            session=self.year,
        )


class SchoolHelperScopeTests(_SchoolFixture, TestCase):
    def setUp(self):
        self.make_fixture()

    def test_filter_classes_for_user(self):
        def visible(user):
            return set(branching.filter_classes_for_user(_reload(user), Group.objects.all()))

        everything = {self.class_7b, self.class_4b, self.class_other}
        cases = [
            ("super admin", self.super_admin, everything),
            ("branch admin", self.branch_admin, {self.class_7b, self.class_4b}),
            ("homeroom teacher", self.homeroom.admin, {self.class_7b}),
            ("subject teacher", self.subject_teacher.admin, {self.class_4b}),
            ("teacher without classes", _user("new@example.com", "2"), set()),
            ("student", self.kid.admin, {self.class_7b}),
            ("parent", self.parent_user, {self.class_7b, self.class_other}),
            ("other parent", _user("dad@example.com", "4"), set()),
        ]
        for name, user, expected in cases:
            with self.subTest(name):
                # Course groups (IELTS) never count as classes.
                self.assertEqual(visible(user), expected)

    def test_inactive_enrollment_hides_the_class(self):
        Enrollment.objects.filter(student=self.kid, group=self.class_7b).update(is_active=False)
        classes = branching.filter_classes_for_user(_reload(self.kid.admin), Group.objects.all())
        self.assertFalse(classes.exists())

    def test_filter_parent_links_for_user(self):
        def visible(user):
            return set(
                branching.filter_parent_links_for_user(_reload(user), ParentChild.objects.all())
            )

        cases = [
            ("super admin", self.super_admin, {self.link_kid, self.link_far}),
            ("branch admin", self.branch_admin, {self.link_kid}),
            ("the parent", self.parent_user, {self.link_kid, self.link_far}),
            ("other parent", _user("dad@example.com", "4"), set()),
            ("teacher", self.homeroom.admin, set()),
            ("student", self.kid.admin, set()),
        ]
        for name, user, expected in cases:
            with self.subTest(name):
                self.assertEqual(visible(user), expected)


@override_settings(SECURE_SSL_REDIRECT=False)
class ParentProfilePhoneTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.mum = _user("mum@example.com", "4")
        Parent.objects.filter(admin=self.mum).update(phone="+998 90 111-22-33")
        self.dad = _user("dad@example.com", "4")
        Parent.objects.filter(admin=self.dad).update(phone="+998 91 000-00-01")

    def patch_phone(self, user, phone):
        self.api.force_authenticate(user=_reload(user))
        return self.api.patch(reverse("api_me"), {"phone": phone}, format="json")

    def test_parent_cannot_take_another_familys_phone(self):
        res = self.patch_phone(self.dad, "998901112233")
        self.assertEqual(res.status_code, 400)
        self.assertIn("phone", res.data)
        self.assertEqual(Parent.objects.get(admin=self.dad).phone, "+998 91 000-00-01")

    def test_parent_can_keep_or_change_own_phone(self):
        self.assertEqual(self.patch_phone(self.mum, "+998 90 111 22 33").status_code, 200)
        self.assertEqual(self.patch_phone(self.mum, "+998 93 555-66-77").status_code, 200)
        self.assertEqual(Parent.objects.get(admin=self.mum).phone, "+998 93 555-66-77")

    def test_student_phone_is_not_checked_against_parents(self):
        kid = _user("kid@example.com", "3")
        self.assertEqual(self.patch_phone(kid, "+998 90 111-22-33").status_code, 200)
