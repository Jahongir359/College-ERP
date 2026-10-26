"""School years, quarters and classes (plan tasks P1.1 and P1.2)."""

from datetime import date

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from main_app.models import (
    Admin,
    Branch,
    Course,
    Enrollment,
    Group,
    Session,
    Student,
    Term,
    class_enrollment_conflict,
)

_OVERRIDES = dict(SECURE_SSL_REDIRECT=False)


def _user(email, user_type):
    return get_user_model().objects.create_user(
        email=email, password="Pass12345!", first_name="T", last_name="U", user_type=user_type
    )


def _branch_admin(email, branch):
    """A non-super admin limited to ``branch`` (re-read so no stale profile is cached)."""
    user = _user(email, "1")
    profile = Admin.objects.get(admin=user)
    profile.is_super_admin = False
    profile.save()
    profile.branches.set([branch])
    return get_user_model().objects.get(pk=user.pk)


class _SchoolFixture:
    def make_fixture(self):
        self.school = Branch.objects.create(name="School", brand=Branch.BRAND_SCHOOL)
        self.center = Branch.objects.create(name="Center")
        self.course = Course.objects.create(name="Iceberg School")
        self.year = Session.objects.create(
            name="2026–2027", start_year=date(2026, 9, 1), end_year=date(2027, 6, 30)
        )
        self.next_year = Session.objects.create(
            name="2027–2028", start_year=date(2027, 9, 1), end_year=date(2028, 6, 30)
        )

    def make_class(self, name="7-B", letter="B", grade=7, session=None, branch=None):
        return Group.objects.create(
            name=name,
            course=self.course,
            branch=branch or self.school,
            kind=Group.KIND_CLASS,
            grade_level=grade,
            letter=letter,
            session=session or self.year,
        )

    def make_student(self, email="kid@example.com"):
        student = Student.objects.get(admin=_user(email, "3"))
        student.branch = self.school
        student.save()
        return student


class SessionModelTests(_SchoolFixture, TestCase):
    def setUp(self):
        self.make_fixture()

    def test_name_is_shown(self):
        self.assertEqual(str(self.year), "2026–2027")

    def test_end_must_be_after_start(self):
        bad = Session(start_year=date(2027, 1, 1), end_year=date(2026, 1, 1))
        with self.assertRaises(ValidationError):
            bad.full_clean()

    def test_only_one_session_is_marked_current(self):
        self.year.is_current = True
        self.year.save()
        self.next_year.is_current = True
        self.next_year.full_clean()  # marking a new one is allowed
        self.next_year.save()
        self.year.refresh_from_db()
        self.assertFalse(self.year.is_current)
        self.assertEqual(Session.current(), self.next_year)

    def test_database_rejects_two_current_sessions(self):
        Session.objects.filter(pk=self.year.pk).update(is_current=True)
        with self.assertRaises(IntegrityError), transaction.atomic():
            Session.objects.filter(pk=self.next_year.pk).update(is_current=True)

    def test_current_falls_back_to_dates(self):
        Session.objects.all().delete()
        Session.objects.create(start_year=date(2000, 9, 1), end_year=date(2001, 6, 30))
        covering = Session.objects.create(start_year=date(2000, 1, 1), end_year=date(2999, 1, 1))
        self.assertEqual(Session.current(), covering)


class TermModelTests(_SchoolFixture, TestCase):
    def setUp(self):
        self.make_fixture()

    def _term(self, number, start, end):
        return Term(session=self.year, number=number, start_date=start, end_date=end)

    def test_valid_quarter(self):
        term = self._term(1, date(2026, 9, 2), date(2026, 10, 31))
        term.full_clean()
        term.save()
        self.assertEqual(list(self.year.terms.all()), [term])

    def test_number_must_be_1_to_4(self):
        with self.assertRaises(ValidationError):
            self._term(5, date(2026, 9, 2), date(2026, 10, 31)).full_clean()

    def test_quarter_must_fall_inside_the_year(self):
        with self.assertRaises(ValidationError):
            self._term(1, date(2026, 8, 1), date(2026, 10, 31)).full_clean()

    def test_quarters_must_not_overlap(self):
        self._term(1, date(2026, 9, 2), date(2026, 10, 31)).save()
        with self.assertRaises(ValidationError):
            self._term(2, date(2026, 10, 15), date(2026, 12, 25)).full_clean()

    def test_one_number_per_year(self):
        self._term(1, date(2026, 9, 2), date(2026, 10, 31)).save()
        with self.assertRaises(IntegrityError), transaction.atomic():
            self._term(1, date(2026, 11, 5), date(2026, 12, 25)).save()


class ClassModelTests(_SchoolFixture, TestCase):
    def setUp(self):
        self.make_fixture()

    def test_course_groups_are_unchanged(self):
        group = Group.objects.create(name="IELTS 1", course=self.course, branch=self.center)
        self.assertEqual(group.kind, Group.KIND_COURSE)
        group.full_clean()

    def test_valid_class(self):
        self.make_class().full_clean()

    def test_class_needs_grade_letter_and_year(self):
        group = Group(name="7", course=self.course, branch=self.school, kind=Group.KIND_CLASS)
        with self.assertRaises(ValidationError) as ctx:
            group.full_clean()
        self.assertEqual(
            set(ctx.exception.message_dict) & {"grade_level", "letter", "session"},
            {"grade_level", "letter", "session"},
        )

    def test_grade_must_be_1_to_11(self):
        group = self.make_class()
        group.grade_level = 12
        with self.assertRaises(ValidationError):
            group.full_clean()

    def test_class_must_be_in_a_school_branch(self):
        group = self.make_class(branch=self.center)
        with self.assertRaises(ValidationError) as ctx:
            group.full_clean()
        self.assertIn("branch", ctx.exception.message_dict)

    def test_course_group_cannot_carry_class_fields(self):
        group = Group(name="IELTS", course=self.course, branch=self.center, grade_level=7)
        with self.assertRaises(ValidationError):
            group.full_clean()

    def test_database_rejects_class_without_grade(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            Group.objects.create(name="X", course=self.course, kind=Group.KIND_CLASS)

    def test_year_with_classes_cannot_be_deleted(self):
        self.make_class()
        from django.db.models import ProtectedError

        with self.assertRaises(ProtectedError):
            self.year.delete()


class OneClassPerYearTests(_SchoolFixture, TestCase):
    def setUp(self):
        self.make_fixture()
        self.class_7b = self.make_class()
        self.class_7a = self.make_class(name="7-A", letter="A")
        self.student = self.make_student()
        Enrollment.objects.create(student=self.student, group=self.class_7b)

    def test_second_class_in_same_year_conflicts(self):
        self.assertEqual(class_enrollment_conflict(self.student.id, self.class_7a), self.class_7b)
        with self.assertRaises(ValidationError):
            Enrollment(student=self.student, group=self.class_7a).full_clean()

    def test_class_in_another_year_is_fine(self):
        next_8b = self.make_class(name="8-B", grade=8, session=self.next_year)
        self.assertIsNone(class_enrollment_conflict(self.student.id, next_8b))

    def test_courses_never_conflict(self):
        ielts = Group.objects.create(name="IELTS", course=self.course, branch=self.school)
        Enrollment(student=self.student, group=ielts).full_clean()

    def test_inactive_old_class_does_not_block(self):
        Enrollment.objects.filter(group=self.class_7b).update(is_active=False)
        self.assertIsNone(class_enrollment_conflict(self.student.id, self.class_7a))


@override_settings(**_OVERRIDES)
class ClassEnrollmentPathsTests(_SchoolFixture, TestCase):
    """Every way of enrolling a student enforces one class per academic year."""

    def setUp(self):
        self.make_fixture()
        self.class_7b = self.make_class()
        self.class_7a = self.make_class(name="7-A", letter="A")
        self.student = self.make_student()
        Enrollment.objects.create(student=self.student, group=self.class_7b)
        self.admin_user = _user("super@example.com", "1")  # new admins are super admins
        self.api = APIClient()
        self.api.force_authenticate(user=self.admin_user)

    def _second_class_exists(self):
        return Enrollment.objects.filter(student=self.student, group=self.class_7a).exists()

    def test_admin_enroll_api(self):
        res = self.api.post(
            "/api/v1/admin/enroll/",
            {"student_id": self.student.id, "group_id": self.class_7a.id},
            format="json",
        )
        self.assertEqual(res.status_code, 400)
        self.assertFalse(self._second_class_exists())

    def test_admin_enrollments_api(self):
        res = self.api.post(
            "/api/v1/admin/enrollments/",
            {"student": self.student.id, "group": self.class_7a.id},
            format="json",
        )
        self.assertEqual(res.status_code, 400)
        self.assertFalse(self._second_class_exists())

    def test_web_enrollment_page(self):
        self.client.force_login(self.admin_user)
        self.client.post(
            reverse("add_enrollment"),
            {"student": self.student.id, "group": self.class_7a.id, "is_active": "True"},
        )
        self.assertFalse(self._second_class_exists())


@override_settings(**_OVERRIDES)
class SessionApiAccessTests(_SchoolFixture, TestCase):
    """admin/sessions/ and quarters: who may read and who may change."""

    def setUp(self):
        self.make_fixture()
        self.super_user = _user("super@example.com", "1")
        self.branch_user = _branch_admin("branch@example.com", self.school)
        self.teacher_user = _user("teacher@example.com", "2")
        self.student_user = _user("student@example.com", "3")

    def _api(self, user=None):
        api = APIClient()
        if user is not None:
            api.force_authenticate(user=user)
        return api

    def test_list_shows_name_and_current(self):
        self.year.is_current = True
        self.year.save()
        res = self._api(self.branch_user).get("/api/v1/admin/sessions/")
        self.assertEqual(res.status_code, 200)
        by_id = {s["id"]: s for s in res.json()}
        self.assertEqual(by_id[self.year.id]["name"], "2026–2027")
        self.assertTrue(by_id[self.year.id]["is_current"])
        self.assertFalse(by_id[self.next_year.id]["is_current"])

    def test_teacher_student_and_anonymous_are_refused(self):
        self.assertEqual(
            self._api(self.teacher_user).get("/api/v1/admin/sessions/").status_code, 403
        )
        self.assertEqual(
            self._api(self.student_user).get("/api/v1/admin/sessions/").status_code, 403
        )
        self.assertEqual(self._api().get("/api/v1/admin/sessions/").status_code, 401)

    def test_super_admin_creates_year_and_marks_it_current(self):
        res = self._api(self.super_user).post(
            "/api/v1/admin/sessions/",
            {
                "name": "2028–2029",
                "start_year": "2028-09-01",
                "end_year": "2029-06-30",
                "is_current": True,
            },
            format="json",
        )
        self.assertEqual(res.status_code, 201, res.content)
        self.assertTrue(res.json()["is_current"])
        self.assertEqual(Session.objects.get(is_current=True).name, "2028–2029")

    def test_bad_dates_are_rejected(self):
        res = self._api(self.super_user).post(
            "/api/v1/admin/sessions/",
            {"start_year": "2029-09-01", "end_year": "2028-06-30"},
            format="json",
        )
        self.assertEqual(res.status_code, 400)

    def test_branch_admin_cannot_change_years_or_quarters(self):
        api = self._api(self.branch_user)
        self.assertEqual(
            api.patch(f"/api/v1/admin/sessions/{self.year.id}/", {"name": "x"}).status_code, 403
        )
        res = api.post(
            f"/api/v1/admin/sessions/{self.year.id}/terms/",
            {"number": 1, "start_date": "2026-09-02", "end_date": "2026-10-31"},
            format="json",
        )
        self.assertEqual(res.status_code, 403)

    def test_quarter_crud(self):
        api = self._api(self.super_user)
        res = api.post(
            f"/api/v1/admin/sessions/{self.year.id}/terms/",
            {"number": 1, "name": "1-chorak", "start_date": "2026-09-02", "end_date": "2026-10-31"},
            format="json",
        )
        self.assertEqual(res.status_code, 201, res.content)
        term_id = res.json()["id"]

        listing = self._api(self.branch_user).get(f"/api/v1/admin/sessions/{self.year.id}/terms/")
        self.assertEqual([t["id"] for t in listing.json()], [term_id])
        detail = api.get(f"/api/v1/admin/sessions/{self.year.id}/")
        self.assertEqual(detail.json()["terms"][0]["name"], "1-chorak")

        bad = api.patch(
            f"/api/v1/admin/terms/{term_id}/", {"end_date": "2027-08-01"}, format="json"
        )
        self.assertEqual(bad.status_code, 400)
        ok = api.patch(f"/api/v1/admin/terms/{term_id}/", {"name": "I chorak"}, format="json")
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(api.delete(f"/api/v1/admin/terms/{term_id}/").status_code, 204)
        self.assertFalse(Term.objects.exists())

    def test_quarter_refused_for_teacher(self):
        res = self._api(self.teacher_user).get(f"/api/v1/admin/sessions/{self.year.id}/terms/")
        self.assertEqual(res.status_code, 403)

    def test_year_used_by_a_class_cannot_be_deleted(self):
        self.make_class()
        res = self._api(self.super_user).delete(f"/api/v1/admin/sessions/{self.year.id}/")
        self.assertEqual(res.status_code, 400)
        self.assertTrue(Session.objects.filter(pk=self.year.pk).exists())


@override_settings(**_OVERRIDES)
class ClassApiTests(_SchoolFixture, TestCase):
    """admin/groups/ creates and edits school classes; courses are unchanged."""

    def setUp(self):
        self.make_fixture()
        self.branch_user = _branch_admin("branch@example.com", self.school)
        self.api = APIClient()
        self.api.force_authenticate(user=self.branch_user)

    def test_create_class(self):
        res = self.api.post(
            "/api/v1/admin/groups-manage/",
            {
                "name": "7-B",
                "course": self.course.id,
                "branch": self.school.id,
                "kind": "class",
                "grade_level": 7,
                "letter": "b",
                "session": self.year.id,
            },
            format="json",
        )
        self.assertEqual(res.status_code, 201, res.content)
        group = Group.objects.get(pk=res.json()["id"])
        self.assertEqual((group.kind, group.grade_level, group.letter), ("class", 7, "B"))
        detail = self.api.get(f"/api/v1/admin/groups-manage/{group.id}/").json()
        self.assertEqual(detail["kind"], "class")
        self.assertEqual(detail["session"], self.year.id)

    def test_class_without_grade_is_rejected(self):
        res = self.api.post(
            "/api/v1/admin/groups-manage/",
            {"name": "7", "course": self.course.id, "branch": self.school.id, "kind": "class"},
            format="json",
        )
        self.assertEqual(res.status_code, 400)
        self.assertFalse(Group.objects.filter(name="7").exists())

    def test_course_group_create_is_unchanged(self):
        res = self.api.post(
            "/api/v1/admin/groups-manage/",
            {"name": "IELTS", "course": self.course.id, "branch": self.school.id},
            format="json",
        )
        self.assertEqual(res.status_code, 201)
        listed = {g["id"]: g for g in self.api.get("/api/v1/admin/groups-manage/").json()}
        self.assertEqual(listed[res.json()["id"]]["kind"], "course")
        self.assertIsNone(listed[res.json()["id"]]["grade_level"])

    def test_patch_bad_grade_is_rejected(self):
        group = self.make_class()
        res = self.api.patch(
            f"/api/v1/admin/groups-manage/{group.id}/", {"grade_level": 14}, format="json"
        )
        self.assertEqual(res.status_code, 400)
        group.refresh_from_db()
        self.assertEqual(group.grade_level, 7)

    def test_other_branch_admin_cannot_see_the_class(self):
        group = self.make_class()
        other = _branch_admin("other@example.com", self.center)
        api = APIClient()
        api.force_authenticate(user=other)
        self.assertEqual(api.get(f"/api/v1/admin/groups-manage/{group.id}/").status_code, 403)


@override_settings(**_OVERRIDES)
class SessionWebPageTests(_SchoolFixture, TestCase):
    def setUp(self):
        self.make_fixture()
        self.client.force_login(_user("super@example.com", "1"))

    def test_manage_page_shows_name_and_current(self):
        self.year.is_current = True
        self.year.save()
        res = self.client.get(reverse("manage_session"))
        self.assertContains(res, "2026–2027")
        self.assertContains(res, "Current")

    def test_add_page_can_mark_a_new_current_year(self):
        self.year.is_current = True
        self.year.save()
        self.client.post(
            reverse("add_session"),
            {
                "name": "2028–2029",
                "start_year": "2028-09-01",
                "end_year": "2029-06-30",
                "is_current": "on",
            },
        )
        self.assertEqual(Session.objects.get(is_current=True).name, "2028–2029")
