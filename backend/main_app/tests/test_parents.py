"""Parent role: accounts, links to children, login and access (plan tasks P1.4–P1.6)."""

from datetime import date

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from main_app import branching
from main_app.models import (
    Attendance,
    AttendanceReport,
    Branch,
    Course,
    Enrollment,
    Group,
    Invoice,
    Parent,
    ParentChild,
    Session,
    Student,
    StudentResult,
)

_OVERRIDES = dict(SECURE_SSL_REDIRECT=False)
PASSWORD = "Pass12345!"


def _user(email, user_type, login_id=None, first="T", last="U"):
    return get_user_model().objects.create_user(
        email=email,
        password=PASSWORD,
        first_name=first,
        last_name=last,
        user_type=user_type,
        login_id=login_id,
    )


def _reload(user):
    """Re-read so no stale cached profile is used."""
    return get_user_model().objects.get(pk=user.pk)


class _FamilyFixture:
    """Two school children of one parent, plus a stranger child and a stranger parent."""

    def make_fixture(self):
        self.school = Branch.objects.create(name="School", brand=Branch.BRAND_SCHOOL)
        self.course = Course.objects.create(name="Iceberg School")
        self.year = Session.objects.create(
            name="2026–2027",
            start_year=date(2026, 9, 1),
            end_year=date(2027, 6, 30),
            is_current=True,
        )
        self.class_7b = Group.objects.create(
            name="7-B",
            course=self.course,
            branch=self.school,
            kind=Group.KIND_CLASS,
            grade_level=7,
            letter="B",
            session=self.year,
        )
        self.aziz = self.make_student("aziz@example.com", "Aziz")
        self.malika = self.make_student("malika@example.com", "Malika")
        self.other = self.make_student("other@example.com", "Other")
        Enrollment.objects.create(student=self.aziz, group=self.class_7b)

        self.parent_user = _user("mum@example.com", "4", login_id="PAR0001", first="Dilnoza")
        self.parent = Parent.objects.get(admin=self.parent_user)
        ParentChild.objects.create(
            parent=self.parent, student=self.aziz, relation="mother", is_primary=True
        )
        ParentChild.objects.create(parent=self.parent, student=self.malika, relation="mother")

        self.lonely_user = _user("lonely@example.com", "4", login_id="PAR0002")
        self.one_child_user = _user("dad@example.com", "4", login_id="PAR0003")
        ParentChild.objects.create(
            parent=Parent.objects.get(admin=self.one_child_user),
            student=self.aziz,
            relation="father",
        )

    def make_student(self, email, first):
        student = Student.objects.get(admin=_user(email, "3", first=first))
        student.branch = self.school
        student.save()
        return student


class ParentModelTests(_FamilyFixture, TestCase):
    def setUp(self):
        self.make_fixture()

    def test_profile_is_created_for_user_type_4(self):
        self.assertTrue(Parent.objects.filter(admin=self.parent_user).exists())
        self.assertEqual(self.parent_user.get_user_type_display(), "Parent")

    def test_children_through_links(self):
        self.assertEqual(set(self.parent.children.all()), {self.aziz, self.malika})
        self.assertEqual(set(self.aziz.parents.all()), {self.parent, self.parent_of_dad()})

    def parent_of_dad(self):
        return Parent.objects.get(admin=self.one_child_user)

    def test_same_child_cannot_be_linked_twice(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            ParentChild.objects.create(parent=self.parent, student=self.aziz)

    def test_deleting_the_user_removes_profile_and_links(self):
        self.parent_user.delete()
        self.assertFalse(Parent.objects.filter(pk=self.parent.pk).exists())
        self.assertFalse(ParentChild.objects.filter(parent_id=self.parent.pk).exists())
        self.assertTrue(Student.objects.filter(pk=self.aziz.pk).exists())


class ParentBranchingTests(_FamilyFixture, TestCase):
    def setUp(self):
        self.make_fixture()
        self.parent_user = _reload(self.parent_user)

    def test_children_for_parent(self):
        self.assertEqual(
            set(branching.children_for_parent(self.parent_user)), {self.aziz, self.malika}
        )
        self.assertFalse(branching.children_for_parent(_reload(self.lonely_user)).exists())

    def test_children_for_non_parents_is_empty(self):
        self.assertFalse(branching.children_for_parent(self.aziz.admin).exists())

    def test_user_can_access_student(self):
        self.assertTrue(branching.user_can_access_student(self.parent_user, self.aziz))
        self.assertTrue(branching.user_can_access_student(self.parent_user, self.malika.pk))
        self.assertFalse(branching.user_can_access_student(self.parent_user, self.other))
        self.assertFalse(branching.user_can_access_student(self.parent_user, None))
        # Students see only themselves.
        self.assertTrue(branching.user_can_access_student(self.aziz.admin, self.aziz))
        self.assertFalse(branching.user_can_access_student(self.aziz.admin, self.malika))

    def test_filters_and_branches_follow_children(self):
        students = branching.filter_students_for_user(self.parent_user, Student.objects.all())
        self.assertEqual(set(students), {self.aziz, self.malika})
        self.assertEqual(list(branching.get_accessible_branches(self.parent_user)), [self.school])
        self.assertFalse(
            branching.filter_attendance_for_user(
                self.parent_user, Attendance.objects.all()
            ).exists()
        )


@override_settings(**_OVERRIDES)
class ParentWebLoginTests(_FamilyFixture, TestCase):
    def setUp(self):
        self.make_fixture()

    def test_login_with_login_id_goes_to_the_app(self):
        res = self.client.post(
            reverse("user_login"), {"identifier": "PAR0001", "password": PASSWORD}
        )
        self.assertRedirects(res, "/app/", fetch_redirect_response=False)
        # Still signed in: the parent was not logged out as an unknown role.
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.parent_user.pk)

    def test_parent_cannot_use_web_pages(self):
        self.client.force_login(self.parent_user)
        for name in ("admin_home", "staff_home", "student_home"):
            res = self.client.get(reverse(name))
            self.assertRedirects(res, "/app/", fetch_redirect_response=False)
        self.assertIn("_auth_user_id", self.client.session)

    def test_login_page_sends_signed_in_parent_to_the_app(self):
        self.client.force_login(self.parent_user)
        res = self.client.get(reverse("login_page"))
        self.assertRedirects(res, "/app/", fetch_redirect_response=False)

    def test_parent_can_log_out(self):
        self.client.force_login(self.parent_user)
        self.client.post(reverse("user_logout"))
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_missing_profile_is_healed_on_login(self):
        Parent.objects.filter(admin=self.lonely_user).delete()
        self.client.post(reverse("user_login"), {"identifier": "PAR0002", "password": PASSWORD})
        self.assertTrue(Parent.objects.filter(admin=self.lonely_user).exists())


@override_settings(**_OVERRIDES, SCHOOL_BRAND_ENABLED=True)
class ParentApiLoginAndMeTests(_FamilyFixture, TestCase):
    def setUp(self):
        self.make_fixture()
        self.api = APIClient()

    def test_login_returns_role_and_children(self):
        res = self.api.post(
            reverse("api_login"), {"identifier": "PAR0001", "password": PASSWORD}, format="json"
        )
        self.assertEqual(res.status_code, 200)
        user = res.data["user"]
        self.assertEqual(user["role"], "parent")
        self.assertEqual(user["user_type"], "4")
        self.assertEqual(user["brand"], "school")
        self.assertEqual(user["role_profile"]["id"], self.parent.pk)
        children = {c["id"]: c for c in user["children"]}
        self.assertEqual(set(children), {self.aziz.pk, self.malika.pk})
        self.assertEqual(
            children[self.aziz.pk]["class"],
            {"id": self.class_7b.pk, "name": "7-B", "grade_level": 7, "letter": "B"},
        )
        self.assertIsNone(children[self.malika.pk]["class"])
        self.assertEqual(children[self.aziz.pk]["brand"], "school")
        self.assertEqual(children[self.aziz.pk]["name"], "Aziz U")

    def test_me_for_parent_and_phone_update(self):
        self.api.force_authenticate(user=_reload(self.parent_user))
        res = self.api.patch(reverse("api_me"), {"phone": "+998901234567"}, format="json")
        self.assertEqual(res.status_code, 200)
        self.parent.refresh_from_db()
        self.assertEqual(self.parent.phone, "+998901234567")
        self.assertEqual(res.data["role_profile"]["phone"], "+998901234567")
        self.assertEqual(len(res.data["children"]), 2)

    def test_other_roles_get_role_and_empty_children(self):
        admin = _user("boss@example.com", "1")
        teacher = _user("teacher@example.com", "2")
        for user, role in ((admin, "admin"), (teacher, "teacher"), (self.aziz.admin, "student")):
            self.api.force_authenticate(user=_reload(user))
            res = self.api.get(reverse("api_me"))
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.data["role"], role)
            self.assertEqual(res.data["children"], [])


@override_settings(**_OVERRIDES)
class ParentChildDataAccessTests(_FamilyFixture, TestCase):
    """Access matrix (plan 8.2) for existing student endpoints opened to parents."""

    def setUp(self):
        self.make_fixture()
        self.api = APIClient()
        day = Attendance.objects.create(group=self.class_7b, date=date(2026, 10, 1))
        for student in (self.aziz, self.other):
            AttendanceReport.objects.create(
                student=student, attendance=day, status=AttendanceReport.PRESENT
            )
            StudentResult.objects.create(student=student, group=self.class_7b, test=30, exam=50)
            Invoice.objects.create(
                student=student,
                group=self.class_7b,
                period=date(2026, 10, 1),
                amount=500000,
                discount=0,
                due_date=date(2026, 10, 10),
            )
        self.aziz_invoice = Invoice.objects.get(student=self.aziz)
        self.other_invoice = Invoice.objects.get(student=self.other)

    def as_user(self, user):
        self.api.force_authenticate(user=_reload(user))

    def endpoints(self):
        return (
            reverse("api_attendance"),
            reverse("api_student_attendance_summary"),
            reverse("api_results"),
            reverse("api_invoices"),
        )

    def test_parent_reads_own_child(self):
        self.as_user(self.parent_user)
        for url in self.endpoints():
            with self.subTest(url=url):
                res = self.api.get(url, {"student": self.aziz.pk})
                self.assertEqual(res.status_code, 200, res.data)

    def test_parent_gets_404_for_other_child(self):
        self.as_user(self.parent_user)
        for url in self.endpoints():
            with self.subTest(url=url):
                res = self.api.get(url, {"student": self.other.pk})
                self.assertEqual(res.status_code, 404)

    def test_parent_with_two_children_must_choose(self):
        self.as_user(self.parent_user)
        for url in self.endpoints():
            with self.subTest(url=url):
                self.assertEqual(self.api.get(url).status_code, 400)
                self.assertEqual(self.api.get(url, {"student": "x"}).status_code, 400)

    def test_parent_with_one_child_may_leave_it_out(self):
        self.as_user(self.one_child_user)
        for url in self.endpoints():
            with self.subTest(url=url):
                self.assertEqual(self.api.get(url).status_code, 200)

    def test_data_is_only_the_chosen_child(self):
        self.as_user(self.parent_user)
        res = self.api.get(reverse("api_attendance"), {"student": self.aziz.pk})
        self.assertEqual(res.data["count"], 1)
        res = self.api.get(reverse("api_results"), {"student": self.aziz.pk})
        self.assertEqual([r["student"] for r in res.data["results"]], [self.aziz.pk])
        res = self.api.get(reverse("api_invoices"), {"student": self.aziz.pk})
        self.assertEqual([i["id"] for i in res.data["results"]], [self.aziz_invoice.pk])
        res = self.api.get(reverse("api_invoices"), {"student": self.malika.pk})
        self.assertEqual(res.data["results"], [])

    def test_invoice_detail(self):
        self.as_user(self.parent_user)
        ok = self.api.get(reverse("api_invoice_detail", args=[self.aziz_invoice.pk]))
        self.assertEqual(ok.status_code, 200)
        no = self.api.get(reverse("api_invoice_detail", args=[self.other_invoice.pk]))
        self.assertEqual(no.status_code, 404)

    def test_student_ignores_the_student_parameter(self):
        self.as_user(self.aziz.admin)
        res = self.api.get(reverse("api_attendance"), {"student": self.other.pk})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["count"], 1)
        res = self.api.get(reverse("api_results"), {"student": self.other.pk})
        self.assertEqual([r["student"] for r in res.data["results"]], [self.aziz.pk])

    def test_anonymous_is_rejected(self):
        for url in self.endpoints():
            with self.subTest(url=url):
                self.assertEqual(self.api.get(url).status_code, 401)

    def test_parent_cannot_write(self):
        self.as_user(self.parent_user)
        res = self.api.post(
            reverse("api_results"),
            {"student_id": self.aziz.pk, "group_id": self.class_7b.pk, "test": 40},
            format="json",
        )
        self.assertEqual(res.status_code, 403)
        res = self.api.post(reverse("api_attendance"), {}, format="json")
        self.assertEqual(res.status_code, 403)

    def test_parent_cannot_use_student_only_or_admin_endpoints(self):
        self.as_user(self.parent_user)
        for name in ("api_student_home", "api_student_settings", "api_admin_students"):
            with self.subTest(name=name):
                self.assertEqual(self.api.get(reverse(name)).status_code, 403)
