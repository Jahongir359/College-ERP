"""School subjects per class (plan task P1.3)."""

from datetime import date
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db.models import ProtectedError
from django.test import TestCase, override_settings
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
from main_app.school import SCHOOL_COURSE_NAME, STANDARD_SUBJECTS, seed_school_subjects

_OVERRIDES = dict(SECURE_SSL_REDIRECT=False)


def _user(email, user_type, first="T"):
    return get_user_model().objects.create_user(
        email=email, password="Pass12345!", first_name=first, last_name="U", user_type=user_type
    )


def _reload(user):
    return get_user_model().objects.get(pk=user.pk)


class _ClassFixture:
    def make_fixture(self):
        self.school = Branch.objects.create(name="School", brand=Branch.BRAND_SCHOOL)
        self.other_school = Branch.objects.create(name="School 2", brand=Branch.BRAND_SCHOOL)
        self.course, _ = seed_school_subjects()
        self.year = Session.objects.create(
            name="2026–2027", start_year=date(2026, 9, 1), end_year=date(2027, 6, 30)
        )
        self.class_7b = self.make_class("7-B", "B", self.school)
        self.class_other = self.make_class("5-A", "A", self.other_school)
        self.maths = Subject.objects.get(course=self.course, name="Matematika")
        self.english = Subject.objects.get(course=self.course, name="Ingliz tili")
        self.teacher = Staff.objects.get(admin=_user("teacher@example.com", "2", "Nodira"))
        self.teacher.branch = self.school
        self.teacher.save()

    def make_class(self, name, letter, branch):
        return Group.objects.create(
            name=name,
            course=self.course,
            branch=branch,
            kind=Group.KIND_CLASS,
            grade_level=int(name.split("-")[0]),
            letter=letter,
            session=self.year,
        )


class SeedSchoolSubjectsTests(TestCase):
    def test_creates_course_and_standard_subjects_once(self):
        course, created = seed_school_subjects()
        self.assertEqual(course.name, SCHOOL_COURSE_NAME)
        self.assertEqual(created, len(STANDARD_SUBJECTS))
        self.assertTrue(Subject.objects.filter(course=course, staff__isnull=True).exists())
        _, again = seed_school_subjects()
        self.assertEqual(again, 0)
        self.assertEqual(Course.objects.filter(name=SCHOOL_COURSE_NAME).count(), 1)

    def test_edited_subjects_are_kept(self):
        course, _ = seed_school_subjects()
        Subject.objects.filter(course=course, name="Musiqa").update(name="Music")
        seed_school_subjects()
        self.assertTrue(Subject.objects.filter(course=course, name="Music").exists())

    def test_command(self):
        out = StringIO()
        call_command("seed_school_subjects", stdout=out)
        self.assertIn(f"{len(STANDARD_SUBJECTS)} subject(s) added", out.getvalue())


class ClassSubjectModelTests(_ClassFixture, TestCase):
    def setUp(self):
        self.make_fixture()

    def test_valid_class_subject(self):
        cs = ClassSubject(group=self.class_7b, subject=self.maths, teacher=self.teacher)
        cs.full_clean()
        cs.save()
        self.assertEqual(list(self.class_7b.class_subjects.all()), [cs])

    def test_course_groups_cannot_have_class_subjects(self):
        course_group = Group.objects.create(name="IELTS", course=self.course, branch=self.school)
        with self.assertRaises(ValidationError) as ctx:
            ClassSubject(group=course_group, subject=self.maths).full_clean()
        self.assertIn("group", ctx.exception.message_dict)

    def test_subject_must_belong_to_the_class_course(self):
        other = Subject.objects.create(name="Speaking", course=Course.objects.create(name="LC"))
        with self.assertRaises(ValidationError) as ctx:
            ClassSubject(group=self.class_7b, subject=other).full_clean()
        self.assertIn("subject", ctx.exception.message_dict)

    def test_weekly_hours_range(self):
        for hours in (0, 13):
            with self.subTest(hours=hours), self.assertRaises(ValidationError):
                ClassSubject(
                    group=self.class_7b, subject=self.maths, weekly_hours=hours
                ).full_clean()

    def test_one_row_per_subject_per_class(self):
        ClassSubject.objects.create(group=self.class_7b, subject=self.maths)
        with self.assertRaises(ValidationError):
            ClassSubject(group=self.class_7b, subject=self.maths).full_clean()

    def test_subject_in_use_cannot_be_deleted_and_teacher_removal_keeps_row(self):
        cs = ClassSubject.objects.create(
            group=self.class_7b, subject=self.maths, teacher=self.teacher
        )
        with self.assertRaises(ProtectedError):
            self.maths.delete()
        self.teacher.admin.delete()
        cs.refresh_from_db()
        self.assertIsNone(cs.teacher)


class ClassSubjectBranchingTests(_ClassFixture, TestCase):
    def setUp(self):
        self.make_fixture()
        self.cs = ClassSubject.objects.create(
            group=self.class_7b, subject=self.maths, teacher=self.teacher
        )
        self.cs_other = ClassSubject.objects.create(group=self.class_other, subject=self.maths)

    def visible(self, user):
        return set(
            branching.filter_class_subjects_for_user(_reload(user), ClassSubject.objects.all())
        )

    def test_scope_per_role(self):
        student = Student.objects.get(admin=_user("kid@example.com", "3"))
        Enrollment.objects.create(student=student, group=self.class_7b)
        parent_user = _user("mum@example.com", "4")
        ParentChild.objects.create(parent=Parent.objects.get(admin=parent_user), student=student)

        self.assertEqual(self.visible(self.teacher.admin), {self.cs})
        self.assertEqual(self.visible(student.admin), {self.cs})
        self.assertEqual(self.visible(parent_user), {self.cs})
        self.assertEqual(self.visible(_user("stranger@example.com", "3")), set())


@override_settings(**_OVERRIDES)
class ClassSubjectApiTests(_ClassFixture, TestCase):
    def setUp(self):
        self.make_fixture()
        self.api = APIClient()
        self.super_admin = _user("boss@example.com", "1")
        self.branch_admin = _user("office@example.com", "1")
        profile = Admin.objects.get(admin=self.branch_admin)
        profile.is_super_admin = False
        profile.save()
        profile.branches.set([self.school])

    def as_user(self, user):
        self.api.force_authenticate(user=_reload(user))

    def list_url(self, group):
        return reverse("api_admin_class_subjects", args=[group.pk])

    def test_branch_admin_adds_lists_updates_and_removes(self):
        self.as_user(self.branch_admin)
        res = self.api.post(
            self.list_url(self.class_7b),
            {"subject_id": self.maths.pk, "teacher_id": self.teacher.pk, "weekly_hours": 5},
            format="json",
        )
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(res.data["teacher_name"], "Nodira U")
        self.assertEqual(res.data["weekly_hours"], 5)
        cs_id = res.data["id"]

        res = self.api.get(self.list_url(self.class_7b))
        self.assertEqual([r["subject_name"] for r in res.data], ["Matematika"])

        detail = reverse("api_admin_class_subject_detail", args=[cs_id])
        res = self.api.patch(detail, {"teacher_id": None, "weekly_hours": 4}, format="json")
        self.assertEqual(res.status_code, 200, res.data)
        self.assertIsNone(res.data["teacher_id"])
        self.assertEqual(res.data["weekly_hours"], 4)

        self.assertEqual(self.api.delete(detail).status_code, 204)
        self.assertFalse(ClassSubject.objects.filter(pk=cs_id).exists())

    def test_subject_in_use_cannot_be_deleted_through_the_api(self):
        ClassSubject.objects.create(group=self.class_7b, subject=self.maths)
        self.as_user(self.super_admin)
        res = self.api.delete(reverse("api_admin_subject_detail", args=[self.maths.pk]))
        self.assertEqual(res.status_code, 400)
        self.assertTrue(Subject.objects.filter(pk=self.maths.pk).exists())

    def test_validation_errors(self):
        self.as_user(self.super_admin)
        url = self.list_url(self.class_7b)
        self.api.post(url, {"subject_id": self.maths.pk}, format="json")
        dup = self.api.post(url, {"subject_id": self.maths.pk}, format="json")
        self.assertEqual(dup.status_code, 400)
        bad_hours = self.api.post(
            url, {"subject_id": self.english.pk, "weekly_hours": 40}, format="json"
        )
        self.assertEqual(bad_hours.status_code, 400)
        self.assertEqual(self.api.post(url, {"subject_id": 999999}, format="json").status_code, 404)
        course_group = Group.objects.create(name="IELTS", course=self.course, branch=self.school)
        res = self.api.post(self.list_url(course_group), {"subject_id": self.maths.pk})
        self.assertEqual(res.status_code, 404)

    def test_branch_admin_cannot_reach_other_branch(self):
        cs = ClassSubject.objects.create(group=self.class_other, subject=self.maths)
        self.as_user(self.branch_admin)
        self.assertEqual(self.api.get(self.list_url(self.class_other)).status_code, 404)
        res = self.api.post(
            self.list_url(self.class_other), {"subject_id": self.maths.pk}, format="json"
        )
        self.assertEqual(res.status_code, 404)
        detail = reverse("api_admin_class_subject_detail", args=[cs.pk])
        self.assertEqual(self.api.patch(detail, {"weekly_hours": 2}).status_code, 404)
        self.assertEqual(self.api.delete(detail).status_code, 404)

    def test_teacher_from_other_branch_is_rejected(self):
        outsider = Staff.objects.get(admin=_user("far@example.com", "2"))
        outsider.branch = self.other_school
        outsider.save()
        self.as_user(self.branch_admin)
        res = self.api.post(
            self.list_url(self.class_7b),
            {"subject_id": self.maths.pk, "teacher_id": outsider.pk},
            format="json",
        )
        self.assertEqual(res.status_code, 404)

    def test_non_admins_and_anonymous_are_rejected(self):
        url = self.list_url(self.class_7b)
        self.assertEqual(self.api.get(url).status_code, 401)
        for user in (
            self.teacher.admin,
            _user("kid@example.com", "3"),
            _user("p@example.com", "4"),
        ):
            with self.subTest(user=user.email):
                self.as_user(user)
                self.assertEqual(self.api.get(url).status_code, 403)

    def test_subject_without_teacher_via_admin_subjects_api(self):
        self.as_user(self.super_admin)
        res = self.api.post(
            reverse("api_admin_subjects"),
            {"name": "Astronomiya", "course_id": self.course.pk},
            format="json",
        )
        self.assertEqual(res.status_code, 201, res.data)
        res = self.api.get(reverse("api_admin_subject_detail", args=[res.data["id"]]))
        self.assertEqual(res.data["staff_name"], "")
