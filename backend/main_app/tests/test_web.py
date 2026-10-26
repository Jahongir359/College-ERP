import re
from datetime import date
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from main_app.models import (
    Attendance,
    AttendanceReport,
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


class ProfileHubTests(TestCase):
    def setUp(self):
        UserModel = get_user_model()
        self.course = Course.objects.create(name="Profile Hub Course")
        self.admin = UserModel.objects.create_user(
            email="profile-admin@example.com",
            password="AdminPass123!",
            first_name="Ada",
            last_name="Admin",
            user_type="1",
            gender="F",
            address="HQ",
            profile_pic="",
        )
        self.staff_user = UserModel.objects.create_user(
            email="profile-staff@example.com",
            password="StaffPass123!",
            first_name="Theo",
            last_name="Teacher",
            user_type="2",
            gender="M",
            address="Branch",
            profile_pic="",
            login_id="TC90001",
        )
        self.student_user = UserModel.objects.create_user(
            email="profile-student@example.com",
            password="StudentPass123!",
            first_name="Sam",
            last_name="Student",
            user_type="3",
            gender="M",
            address="Home",
            profile_pic="",
            login_id="IC90001",
        )
        self.staff = Staff.objects.get(admin=self.staff_user)
        self.staff.course = self.course
        self.staff.specialization = "IELTS"
        self.staff.save()
        self.student = Student.objects.get(admin=self.student_user)
        self.student.course = self.course
        self.student.phone = "+998 90 000 00 00"
        self.student.save()

    @override_settings(**_BASE_OVERRIDES)
    def test_profile_hub_renders_for_all_roles(self):
        cases = [
            (self.admin, "Admin", "Administration"),
            (self.staff_user, "Teacher", "Teaching"),
            (self.student_user, "Student", "My Studies"),
        ]
        for user, role_label, role_section in cases:
            with self.subTest(role=role_label):
                self.client.force_login(user)
                response = self.client.get(reverse("profile_hub"))
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, "profile-hub")
                self.assertContains(response, role_label)
                self.assertContains(response, role_section)
                self.assertContains(response, "Theme / Appearance")
                self.assertContains(response, "Log Out")
                self.client.logout()

    @override_settings(**_BASE_OVERRIDES)
    def test_student_can_update_profile_from_hub(self):
        self.client.force_login(self.student_user)
        response = self.client.post(
            reverse("profile_hub"),
            {
                "first_name": "Samuel",
                "last_name": "Student",
                "gender": "M",
                "date_of_birth": "2005-05-10",
                "phone": "+998 90 111 22 33",
                "password": "",
            },
        )
        self.assertRedirects(response, reverse("profile_hub"), fetch_redirect_response=False)
        self.student_user.refresh_from_db()
        self.student.refresh_from_db()
        self.assertEqual(self.student_user.first_name, "Samuel")
        self.assertEqual(self.student.phone, "+998 90 111 22 33")


class AjaxJsonShapeTests(TestCase):
    def setUp(self):
        UserModel = get_user_model()
        self.course = Course.objects.create(name="General English")
        self.staff_user = UserModel.objects.create_user(
            email="ajax-staff@example.com",
            password="Pass123!",
            first_name="Ajax",
            last_name="Staff",
            user_type="2",
            gender="M",
            address="",
            profile_pic="",
            login_id="TC70001",
        )
        self.staff = Staff.objects.get(admin=self.staff_user)
        self.group = Group.objects.create(name="Ajax Group", course=self.course, teacher=self.staff)
        self.student_user = UserModel.objects.create_user(
            email="ajax-student@example.com",
            password="Pass123!",
            first_name="Ajax",
            last_name="Student",
            user_type="3",
            gender="F",
            address="",
            profile_pic="",
            login_id="IC70001",
        )
        self.student = Student.objects.get(admin=self.student_user)
        Enrollment.objects.create(student=self.student, group=self.group, is_active=True)
        self.attendance = Attendance.objects.create(group=self.group, date=date(2026, 1, 2))
        AttendanceReport.objects.create(
            attendance=self.attendance,
            student=self.student,
            status=AttendanceReport.PRESENT,
        )

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_staff_student_roster_ajax_returns_json_array(self):
        self.client.force_login(self.staff_user)
        response = self.client.post(reverse("get_students"), {"group": str(self.group.id)})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIsInstance(payload, list)
        self.assertEqual(payload[0]["id"], self.student.id)

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_attendance_date_ajax_returns_json_array(self):
        self.client.force_login(self.staff_user)
        response = self.client.post(reverse("get_attendance"), {"group": str(self.group.id)})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIsInstance(payload, list)
        self.assertEqual(payload[0]["id"], self.attendance.id)


class StaticReferenceTests(TestCase):
    def test_every_static_file_named_in_a_template_exists(self):
        # Production uses manifest static storage, where a missing file is a 500
        # (the APK download page broke this way).
        from pathlib import Path

        from django.contrib.staticfiles import finders

        templates = Path(__file__).resolve().parent.parent / "templates"
        missing = []
        for template in templates.rglob("*.html"):
            text = template.read_text(encoding="utf-8")
            for name in re.findall(r"\{%\s*static\s+['\"]([^'\"]+)['\"]", text):
                if not finders.find(name):
                    missing.append(f"{template.relative_to(templates)}: {name}")
        self.assertEqual(missing, [])


@override_settings(SECURE_SSL_REDIRECT=False)
class RemovedLegacyRoutesTests(TestCase):
    # The git-pull deploy webhook and the 2020 Firebase web push worker were removed.
    def test_legacy_routes_are_gone(self):
        for path in ("/api/deploy/flutter/", "/firebase-messaging-sw.js"):
            res = self.client.post(path) if "deploy" in path else self.client.get(path)
            self.assertIn(res.status_code, (302, 404), path)

    def test_download_page_without_apk_has_no_download_link(self):
        with patch("main_app.flutter_view.DOWNLOADS_DIR", "/nonexistent"):
            res = self.client.get("/download/")
        self.assertEqual(res.status_code, 200)
        self.assertNotContains(res, "/download/app.apk")
