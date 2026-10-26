"""Tests for the Iceberg School brand layer (Phase 1).

See docs/plans/ICEBERG_SCHOOL_BRAND_PLAN.md. The key promise under test: with
the flag off — or for any Learning Center user — everything resolves to
"center", exactly as before; brand never changes what anyone can access.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.backends.db import SessionStore
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from main_app import branding
from main_app.models import Admin, Branch, Course, Enrollment, Group, Staff, Student

_BASE = dict(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    SECURE_SSL_REDIRECT=False,
)
ON = dict(_BASE, SCHOOL_BRAND_ENABLED=True)
OFF = dict(_BASE, SCHOOL_BRAND_ENABLED=False)


def _user(email, user_type, login_id=None, password="Str0ng-Passw0rd!"):
    return get_user_model().objects.create_user(
        email=email,
        password=password,
        first_name="T",
        last_name="U",
        user_type=user_type,
        gender="M",
        address="",
        profile_pic="",
        login_id=login_id,
    )


class BrandFixtureMixin:
    def setUp(self):
        self.factory = RequestFactory()
        self.center = Branch.objects.create(name="Chilonzor")
        self.school = Branch.objects.create(name="Iceberg School", brand=Branch.BRAND_SCHOOL)
        self.course = Course.objects.create(name="General")

        self.super_user = _user("super-brand@example.com", "1")  # super admin by default

        self.school_admin_user = _user("sa-brand@example.com", "1")
        sa = Admin.objects.get(admin=self.school_admin_user)
        sa.is_super_admin = False
        sa.save()
        sa.branches.set([self.school])

        self.mixed_admin_user = _user("ma-brand@example.com", "1")
        ma = Admin.objects.get(admin=self.mixed_admin_user)
        ma.is_super_admin = False
        ma.save()
        ma.branches.set([self.school, self.center])

        self.school_teacher_user = _user("st-brand@example.com", "2", "TCB001")
        teacher = Staff.objects.get(admin=self.school_teacher_user)
        teacher.branch = self.school
        teacher.save()

        self.school_student_user = _user("ss-brand@example.com", "3", "ICB001")
        student = Student.objects.get(admin=self.school_student_user)
        student.branch = self.school
        student.save()

        self.center_student_user = _user("cs-brand@example.com", "3", "ICB002")
        student = Student.objects.get(admin=self.center_student_user)
        student.branch = self.center
        student.save()

        # No explicit branch, but enrolled in a school class → effective branch is school.
        self.enrolled_student_user = _user("es-brand@example.com", "3", "ICB003")
        enrolled = Student.objects.get(admin=self.enrolled_student_user)
        group = Group.objects.create(
            name="7B", course=self.course, teacher=teacher, branch=self.school
        )
        Enrollment.objects.create(student=enrolled, group=group, is_active=True)

        self.loose_student_user = _user("ls-brand@example.com", "3", "ICB004")

        # Reload users so no stale profile is cached from the creation signal
        # (real requests always load the user fresh).
        for name in [n for n in vars(self) if n.endswith("_user")]:
            setattr(self, name, get_user_model().objects.get(pk=getattr(self, name).pk))

    def _request(self, user=None, path="/", data=None, cookies=None, session=None):
        request = self.factory.get(path, data or {})
        request.user = user or AnonymousUser()
        request.session = session if session is not None else SessionStore()
        if cookies:
            request.COOKIES.update(cookies)
        return request


class BranchBrandFieldTests(TestCase):
    def test_new_branch_defaults_to_center(self):
        self.assertEqual(Branch.objects.create(name="New").brand, Branch.BRAND_CENTER)

    def test_unknown_key_falls_back_to_center_config(self):
        self.assertEqual(branding.get_brand("nope").key, branding.CENTER)
        self.assertEqual(branding.get_brand(None).key, branding.CENTER)
        self.assertEqual(branding.get_brand("school").name, "Iceberg School")


class BrandResolverTests(BrandFixtureMixin, TestCase):
    def resolve(self, **kwargs):
        return branding.resolve_brand_key(self._request(**kwargs))

    @override_settings(**OFF)
    def test_flag_off_is_always_center(self):
        for user in (
            self.super_user,
            self.school_admin_user,
            self.school_teacher_user,
            self.school_student_user,
        ):
            self.assertEqual(self.resolve(user=user), "center")
        self.assertEqual(self.resolve(path="/school/"), "center")
        self.assertEqual(self.resolve(data={"brand": "school"}), "center")

    @override_settings(**ON)
    def test_users_get_their_branch_brand(self):
        self.assertEqual(self.resolve(user=self.school_student_user), "school")
        self.assertEqual(self.resolve(user=self.enrolled_student_user), "school")
        self.assertEqual(self.resolve(user=self.center_student_user), "center")
        self.assertEqual(self.resolve(user=self.loose_student_user), "center")
        self.assertEqual(self.resolve(user=self.school_teacher_user), "school")
        self.assertEqual(self.resolve(user=self.school_admin_user), "school")
        self.assertEqual(self.resolve(user=self.mixed_admin_user), "center")

    @override_settings(**ON)
    def test_super_admin_defaults_to_center_and_can_preview(self):
        self.assertEqual(self.resolve(user=self.super_user), "center")
        session = SessionStore()
        session[branding.SESSION_KEY] = "school"
        self.assertEqual(self.resolve(user=self.super_user, session=session), "school")
        session[branding.SESSION_KEY] = "bogus"
        self.assertEqual(self.resolve(user=self.super_user, session=session), "center")

    @override_settings(**ON)
    def test_anonymous_visitors(self):
        self.assertEqual(self.resolve(), "center")
        self.assertEqual(self.resolve(path="/school/"), "school")
        self.assertEqual(self.resolve(path="/school/admissions/"), "school")
        self.assertEqual(self.resolve(path="/schoolbus/"), "center")
        self.assertEqual(self.resolve(data={"brand": "school"}), "school")
        self.assertEqual(self.resolve(data={"brand": "evil"}), "center")
        self.assertEqual(self.resolve(cookies={branding.BRAND_COOKIE: "school"}), "school")
        self.assertEqual(self.resolve(cookies={branding.BRAND_COOKIE: "x"}), "center")

    @override_settings(**ON)
    def test_signed_in_user_ignores_query_and_cookie(self):
        self.assertEqual(
            self.resolve(
                user=self.center_student_user,
                data={"brand": "school"},
                cookies={branding.BRAND_COOKIE: "school"},
            ),
            "center",
        )

    @override_settings(**ON)
    def test_errors_fall_back_to_center(self):
        with patch.object(branding, "brand_for_user", side_effect=RuntimeError("boom")):
            with self.assertLogs("main_app.branding", level="ERROR"):
                self.assertEqual(self.resolve(user=self.school_student_user), "center")


class BrandContextTests(BrandFixtureMixin, TestCase):
    @override_settings(**OFF)
    def test_login_page_context_is_center_when_off(self):
        response = self.client.get(reverse("login_page"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["brand"].key, "center")

    @override_settings(**ON)
    def test_login_page_context_follows_query(self):
        response = self.client.get(reverse("login_page"), {"brand": "school"})
        self.assertEqual(response.context["brand"].key, "school")


@override_settings(**_BASE)
class BrandApiTests(BrandFixtureMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.api = APIClient()

    @override_settings(**OFF)
    def test_me_reports_center_when_off(self):
        self.api.force_authenticate(user=self.school_student_user)
        data = self.api.get("/api/v1/me/").data
        self.assertEqual(data["brand"], "center")
        self.assertEqual(data["brand_name"], "Iceberg Study Center")

    @override_settings(**ON)
    def test_me_reports_school_for_school_student(self):
        self.api.force_authenticate(user=self.school_student_user)
        data = self.api.get("/api/v1/me/").data
        self.assertEqual(data["brand"], "school")
        self.assertEqual(data["brand_name"], "Iceberg School")

    @override_settings(**ON)
    def test_login_response_includes_brand(self):
        res = self.api.post(
            "/api/v1/auth/login/",
            {"identifier": "ICB001", "password": "Str0ng-Passw0rd!"},
            format="json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["user"]["brand"], "school")

    def test_branch_lists_include_brand(self):
        self.api.force_authenticate(user=self.super_user)
        rows = self.api.get("/api/v1/admin/branches-manage/").data
        self.assertEqual({r["name"]: r["brand"] for r in rows}["Iceberg School"], "school")
        rows = self.api.get("/api/v1/admin/branches/").data
        rows = rows["results"] if isinstance(rows, dict) else rows
        self.assertIn("brand", rows[0])

    def test_only_super_admin_can_change_brand(self):
        url = f"/api/v1/admin/branches-manage/{self.school.id}/"
        self.api.force_authenticate(user=self.school_admin_user)
        self.assertEqual(self.api.patch(url, {"brand": "center"}, format="json").status_code, 403)
        self.school.refresh_from_db()
        self.assertEqual(self.school.brand, "school")

        self.api.force_authenticate(user=self.super_user)
        self.assertEqual(self.api.patch(url, {"brand": "nope"}, format="json").status_code, 400)
        res = self.api.patch(url, {"brand": "center"}, format="json")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["brand"], "center")

    def test_create_branch_with_brand(self):
        self.api.force_authenticate(user=self.super_user)
        url = "/api/v1/admin/branches-manage/"
        res = self.api.post(url, {"name": "Campus 2", "brand": "school"}, format="json")
        self.assertEqual(res.status_code, 201)
        self.assertEqual(Branch.objects.get(pk=res.data["id"]).brand, "school")
        self.assertEqual(
            self.api.post(url, {"name": "X", "brand": "bad"}, format="json").status_code, 400
        )
        res = self.api.post(url, {"name": "Campus 3"}, format="json")
        self.assertEqual(res.data["brand"], "center")

    @override_settings(**ON)
    def test_brand_does_not_widen_branch_access(self):
        self.api.force_authenticate(user=self.school_admin_user)
        rows = self.api.get("/api/v1/admin/branches-manage/").data
        self.assertEqual([r["name"] for r in rows], ["Iceberg School"])


@override_settings(**_BASE)
class BranchWebFormTests(BrandFixtureMixin, TestCase):
    def test_super_admin_can_set_brand(self):
        self.client.force_login(self.super_user)
        self.client.post(
            reverse("edit_branch", args=[self.center.id]),
            {"name": "Chilonzor", "address": "", "brand": "school"},
        )
        self.center.refresh_from_db()
        self.assertEqual(self.center.brand, "school")

    def test_branch_admin_cannot_change_brand(self):
        self.client.force_login(self.school_admin_user)
        self.client.post(
            reverse("edit_branch", args=[self.school.id]),
            {"name": "Iceberg School 2", "address": "", "brand": "center"},
        )
        self.school.refresh_from_db()
        self.assertEqual(self.school.name, "Iceberg School 2")  # other edits still work
        self.assertEqual(self.school.brand, "school")

    def test_manage_branch_shows_school_label_only_for_school(self):
        self.client.force_login(self.super_user)
        html = self.client.get(reverse("manage_branch")).content.decode()
        self.assertEqual(html.count("Iceberg School</span>"), 2)  # table badge + card chip
