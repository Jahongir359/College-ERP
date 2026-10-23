import json
import re
from datetime import date, timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse

from main_app.hod_views import _generate_login_id
from main_app.messaging import unread_message_count
from main_app.models import (
    Admin,
    Attendance,
    AttendanceReport,
    Assignment,
    Branch,
    ChatMessage,
    ChatReadState,
    ChatThread,
    Course,
    Enrollment,
    Group,
    RegistrationLead,
    Staff,
    Student,
)


_BASE_OVERRIDES = dict(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    # Disable SSL redirect so the test client (HTTP) reaches views without
    # being bounced to HTTPS (which then strips POST bodies on 301 redirect).
    SECURE_SSL_REDIRECT=False,
)


class LoginPageTests(TestCase):
    def setUp(self):
        UserModel = get_user_model()
        self.admin = UserModel.objects.create_user(
            email="admin@example.com",
            password="AdminPass123!",
            first_name="Test",
            last_name="Admin",
            user_type="1",
            gender="M",
            address="Test",
            profile_pic="",
        )
        self.staff = UserModel.objects.create_user(
            email="staff@example.com",
            password="StaffPass123!",
            first_name="Test",
            last_name="Staff",
            user_type="2",
            gender="M",
            address="Test",
            profile_pic="",
            login_id="TC500",
        )
        self.student = UserModel.objects.create_user(
            email="student@example.com",
            password="StudentPass123!",
            first_name="Test",
            last_name="Student",
            user_type="3",
            gender="M",
            address="Test",
            profile_pic="",
            login_id="IC1000",
        )

    @override_settings(**_BASE_OVERRIDES)
    def test_login_page_get_returns_200(self):
        response = self.client.get(reverse("login_page"))
        self.assertEqual(response.status_code, 200)

    @override_settings(**_BASE_OVERRIDES)
    def test_login_invalid_credentials_shows_error(self):
        response = self.client.post(
            reverse("user_login"),
            {
                "email": "nobody@example.com",
                "password": "wrongpassword",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"not found", response.content)

    @override_settings(**_BASE_OVERRIDES)
    def test_admin_login_redirects_to_admin_home(self):
        response = self.client.post(
            reverse("user_login"),
            {
                "identifier": "admin@example.com",
                "password": "AdminPass123!",
            },
        )
        self.assertRedirects(response, reverse("admin_home"), fetch_redirect_response=False)

    @override_settings(**_BASE_OVERRIDES)
    def test_staff_login_redirects_to_staff_home(self):
        response = self.client.post(
            reverse("user_login"),
            {
                "identifier": "TC500",
                "password": "StaffPass123!",
            },
        )
        self.assertRedirects(response, reverse("staff_home"), fetch_redirect_response=False)

    @override_settings(**_BASE_OVERRIDES)
    def test_student_login_redirects_to_student_home(self):
        response = self.client.post(
            reverse("user_login"),
            {
                "identifier": "IC1000",
                "password": "StudentPass123!",
            },
        )
        self.assertRedirects(response, reverse("student_home"), fetch_redirect_response=False)

    @override_settings(**_BASE_OVERRIDES)
    def test_no_role_confusion_admin_cannot_reach_student_home(self):
        # force_login bypasses auth backends (avoids axes request requirement).
        # We only need to test role-based routing here, not authentication.
        self.client.force_login(self.admin)
        response = self.client.get(reverse("student_home"))
        # Admin should be redirected away from student pages.
        self.assertNotEqual(response.status_code, 200)

    @override_settings(**_BASE_OVERRIDES)
    def test_unauthenticated_blocked_from_admin_home(self):
        response = self.client.get(reverse("admin_home"))
        self.assertNotEqual(response.status_code, 200)


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


class RegistrationLeadReceiverTests(TestCase):
    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_requires_configured_bearer_token(self):
        response = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps({"full_name": "Public Student", "phone": "+998901234567"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(RegistrationLead.objects.count(), 0)

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_stores_json_registration_lead(self):
        response = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps(
                {
                    "full_name": "Public Student",
                    "phone": "+998901234567",
                    "course": "IELTS Academic",
                    "source": "instagram",
                    "utm_campaign": "summer-intake",
                    "social_handle": "@publicstudent",
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer secret-token",
            HTTP_USER_AGENT="website-test-client",
            REMOTE_ADDR="127.0.0.5",
        )
        self.assertEqual(response.status_code, 201)
        lead = RegistrationLead.objects.get()
        self.assertEqual(lead.full_name, "Public Student")
        self.assertEqual(lead.phone, "+998901234567")
        self.assertEqual(lead.program, "IELTS Academic")
        self.assertEqual(lead.source, "instagram")
        self.assertEqual(lead.utm_campaign, "summer-intake")
        self.assertEqual(lead.social_handle, "@publicstudent")
        self.assertEqual(lead.user_agent, "website-test-client")

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_accepts_minimal_name_and_phone_payload(self):
        response = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps(
                {
                    "full_name": "Minimal Website Lead",
                    "phone": "+998901112233",
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer secret-token",
        )
        self.assertEqual(response.status_code, 201)
        lead = RegistrationLead.objects.get()
        self.assertEqual(lead.full_name, "Minimal Website Lead")
        self.assertEqual(lead.phone, "+998901112233")
        self.assertEqual(lead.program, "")
        self.assertEqual(lead.email, "")
        self.assertEqual(lead.parent_phone, "")
        self.assertEqual(lead.source, "website")

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_accepts_optional_website_fields(self):
        response = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps(
                {
                    "full_name": "Optional Website Lead",
                    "phone": "+998901112244",
                    "course": "General English",
                    "date_of_birth": "",
                    "parent_phone": "+998909998877",
                    "email": "lead@example.com",
                    "branch": "Main",
                    "preferred_schedule": "Evening",
                    "social_source": "instagram",
                    "social_handle": "@optional",
                    "utm_source": "meta",
                    "utm_medium": "paid-social",
                    "utm_campaign": "summer-intake",
                    "message": "Please call after 5pm",
                    "submitted_at": "2026-06-05T12:00:00Z",
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer secret-token",
        )
        self.assertEqual(response.status_code, 201)
        lead = RegistrationLead.objects.get()
        self.assertEqual(lead.program, "General English")
        self.assertEqual(lead.parent_phone, "+998909998877")
        self.assertEqual(lead.email, "lead@example.com")
        self.assertEqual(lead.branch, "Main")
        self.assertEqual(lead.preferred_schedule, "Evening")
        self.assertEqual(lead.source, "instagram")
        self.assertEqual(lead.social_handle, "@optional")
        self.assertEqual(lead.utm_source, "meta")
        self.assertEqual(lead.utm_medium, "paid-social")
        self.assertEqual(lead.utm_campaign, "summer-intake")
        self.assertEqual(lead.message, "Please call after 5pm")
        self.assertEqual(lead.raw_payload["date_of_birth"], "")
        self.assertEqual(lead.raw_payload["submitted_at"], "2026-06-05T12:00:00Z")

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_requires_name_and_phone_only(self):
        missing_name = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps({"phone": "+998901112233", "course": "Optional Course"}),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer secret-token",
        )
        self.assertEqual(missing_name.status_code, 400)
        self.assertEqual(missing_name.json()["detail"], "full_name is required.")

        missing_phone = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps(
                {
                    "full_name": "No Phone Lead",
                    "email": "lead@example.com",
                    "parent_phone": "+998909998877",
                    "date_of_birth": "2010-01-02",
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer secret-token",
        )
        self.assertEqual(missing_phone.status_code, 400)
        self.assertEqual(missing_phone.json()["detail"], "phone is required.")
        self.assertEqual(RegistrationLead.objects.count(), 0)

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_accepts_slashless_url_and_registration_token_header(self):
        response = self.client.post(
            "/public/registration-leads",
            data={
                "Full Name": "Website Form Student",
                "Phone Number": "+998977777777",
                "Course Name": "Speaking Club",
                "Preferred Time": "Evening",
            },
            HTTP_X_REGISTRATION_TOKEN="secret-token",
        )
        self.assertEqual(response.status_code, 201)
        lead = RegistrationLead.objects.get()
        self.assertEqual(lead.full_name, "Website Form Student")
        self.assertEqual(lead.phone, "+998977777777")
        self.assertEqual(lead.program, "Speaking Club")
        self.assertEqual(lead.preferred_schedule, "Evening")

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="secret-token")
    def test_receiver_accepts_text_plain_json_and_redacts_body_token(self):
        response = self.client.post(
            reverse("public_registration_leads"),
            data=json.dumps(
                {
                    "Name": "Loose Fetch Student",
                    "WhatsApp Number": "+998936666666",
                    "Selected Course": "General English",
                    "apiKey": "secret-token",
                }
            ),
            content_type="text/plain",
        )
        self.assertEqual(response.status_code, 201)
        lead = RegistrationLead.objects.get()
        self.assertEqual(lead.full_name, "Loose Fetch Student")
        self.assertEqual(lead.phone, "+998936666666")
        self.assertEqual(lead.program, "General English")
        self.assertEqual(lead.raw_payload["apiKey"], "[redacted]")

    @override_settings(**_BASE_OVERRIDES, REGISTRATION_LEADS_API_TOKEN="")
    def test_receiver_accepts_form_encoded_payload_when_token_not_configured(self):
        response = self.client.post(
            reverse("public_registration_leads"),
            data={
                "first_name": "Form",
                "last_name": "Lead",
                "phone": "+998900000001",
                "parent_phone": "+998991111111",
                "program": "General English",
            },
        )
        self.assertEqual(response.status_code, 201)
        lead = RegistrationLead.objects.get()
        self.assertEqual(lead.full_name, "Form Lead")
        self.assertEqual(lead.phone, "+998900000001")
        self.assertEqual(lead.parent_phone, "+998991111111")
        self.assertEqual(lead.program, "General English")

    @override_settings(**_BASE_OVERRIDES)
    def test_admin_can_view_registration_leads(self):
        UserModel = get_user_model()
        admin = UserModel.objects.create_user(
            email="lead-admin@example.com",
            password="AdminPass123!",
            first_name="Lead",
            last_name="Admin",
            user_type="1",
            gender="M",
            address="",
            profile_pic="",
        )
        RegistrationLead.objects.create(
            full_name="Dashboard Lead",
            phone="+998900000000",
            program="Speaking",
            source="facebook",
        )
        self.client.force_login(admin)
        response = self.client.get(reverse("manage_registration_leads"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Dashboard Lead")
        self.assertContains(response, "facebook")


class PasswordResetFlowTests(TestCase):
    @override_settings(**_BASE_OVERRIDES)
    def test_password_reset_end_to_end(self):
        user_model = get_user_model()
        user = user_model.objects.create_user(
            email="reset-flow@example.com",
            password="InitialPass123!",
            first_name="Reset",
            last_name="Flow",
            user_type="1",
            gender="M",
            address="Test Address",
            profile_pic="",
        )

        response = self.client.post("/accounts/password_reset/", {"email": user.email}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)

        body = mail.outbox[0].body
        match = re.search(r"https?://[^\s]+/accounts/reset/[^\s]+", body)
        self.assertIsNotNone(match)

        token_path = "/" + match.group(0).split("/", 3)[3]
        confirm_get_response = self.client.get(token_path, follow=True)
        final_path = confirm_get_response.wsgi_request.path

        new_password = "ChangedPass123!"
        confirm_post_response = self.client.post(
            final_path,
            {"new_password1": new_password, "new_password2": new_password},
            follow=True,
        )

        self.assertEqual(confirm_post_response.status_code, 200)
        user.refresh_from_db()
        self.assertTrue(user.check_password(new_password))


class LoginIdGeneratorTests(TestCase):
    """Birthday-based login_id generator: IC052401 etc."""

    def _make_user(self, login_id, dob=None, email=None, user_type="3"):
        UserModel = get_user_model()
        return UserModel.objects.create_user(
            email=email or f"{login_id.lower()}@iceberg.internal",
            password="x",
            first_name="X",
            last_name="Y",
            user_type=user_type,
            gender="M",
            address="",
            profile_pic="",
            login_id=login_id,
            date_of_birth=dob,
        )

    def test_student_id_encodes_birthday(self):
        lid = _generate_login_id("IC", date(2010, 5, 24))
        self.assertEqual(lid, "IC052401")

    def test_teacher_id_encodes_birthday(self):
        lid = _generate_login_id("TC", date(1985, 2, 12))
        self.assertEqual(lid, "TC021201")

    def test_suffix_increments_on_collision(self):
        dob = date(2009, 7, 7)
        self._make_user("IC070701", dob=dob)
        self._make_user("IC070702", dob=dob)
        self.assertEqual(_generate_login_id("IC", dob), "IC070703")

    def test_pads_month_and_day(self):
        # January 5 should be 0105, not 15.
        self.assertEqual(_generate_login_id("IC", date(2000, 1, 5)), "IC010501")

    def test_fallback_when_no_birthday(self):
        # Without DOB, falls back to sequential.
        lid = _generate_login_id("IC")
        self.assertTrue(lid.startswith("IC"))
        self.assertGreaterEqual(int(lid[2:]), 1000)

    def test_legacy_ids_do_not_collide(self):
        # Legacy formats (IC00005, IC1000, STU-0001) coexist with new format.
        self._make_user("IC00005")
        self._make_user("IC1000", email="legacy2@iceberg.internal")
        self._make_user("STU-0001", email="legacy3@iceberg.internal")
        new = _generate_login_id("IC", date(2012, 3, 15))
        self.assertEqual(new, "IC031501")


class LoginFlowResilienceTests(TestCase):
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="admin-login@example.com",
            password="AdminPass123!",
            first_name="Admin",
            last_name="User",
            user_type="1",
            gender="M",
            address="Admin Address",
            profile_pic="",
        )

    @override_settings(SECURE_SSL_REDIRECT=False)
    @patch("main_app.views.login", side_effect=Exception("session backend unavailable"))
    def test_login_failure_is_handled_without_500(self, _mock_login):
        response = self.client.post(
            "/doLogin/",
            {"email": self.user.email, "password": "AdminPass123!"},
            follow=False,
        )
        self.assertEqual(response.status_code, 302)
        # doLogin redirects to reverse('login_page') == '/login/' on failure.
        self.assertEqual(response["Location"], "/login/")


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


class StudentPrivacyTests(TestCase):
    """Students must not be able to access other students' group data."""

    def _make_user(self, email, user_type, login_id=None, dob=None):
        UserModel = get_user_model()
        return UserModel.objects.create_user(
            email=email,
            password="Pass123!",
            first_name="T",
            last_name="U",
            user_type=user_type,
            gender="M",
            address="",
            profile_pic="",
            login_id=login_id,
            date_of_birth=dob,
        )

    def setUp(self):
        self.course = Course.objects.create(name="General English")

        # Two separate teachers
        teacher_a_user = self._make_user("ta@iceberg.internal", "2", "TC50001")
        teacher_b_user = self._make_user("tb@iceberg.internal", "2", "TC50002")
        self.teacher_a = Staff.objects.get(admin=teacher_a_user)
        self.teacher_b = Staff.objects.get(admin=teacher_b_user)

        # Two separate groups
        self.group_a = Group.objects.create(
            name="Group A", course=self.course, teacher=self.teacher_a
        )
        self.group_b = Group.objects.create(
            name="Group B", course=self.course, teacher=self.teacher_b
        )

        # Student A → Group A only
        student_a_user = self._make_user(
            "ic10001@iceberg.internal", "3", "IC10001", date(2005, 5, 1)
        )
        self.student_a = Student.objects.get(admin=student_a_user)
        self.student_a.course = self.course
        self.student_a.save()
        Enrollment.objects.create(student=self.student_a, group=self.group_a, is_active=True)

        # Student B → Group B only
        student_b_user = self._make_user(
            "ic10002@iceberg.internal", "3", "IC10002", date(2005, 6, 1)
        )
        self.student_b = Student.objects.get(admin=student_b_user)
        self.student_b.course = self.course
        self.student_b.save()
        Enrollment.objects.create(student=self.student_b, group=self.group_b, is_active=True)

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_attendance_ajax_blocks_cross_group_access(self):
        """Student A cannot query attendance for Group B via the AJAX endpoint."""
        self.client.force_login(self.student_a.admin)
        response = self.client.post(
            reverse("student_view_attendance"),
            {
                "group": str(self.group_b.id),
                "start_date": "2026-01-01",
                "end_date": "2026-12-31",
            },
        )
        self.assertEqual(response.status_code, 403)

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_attendance_ajax_allows_own_group(self):
        """Student A can query attendance for Group A."""
        self.client.force_login(self.student_a.admin)
        response = self.client.post(
            reverse("student_view_attendance"),
            {
                "group": str(self.group_a.id),
                "start_date": "2026-01-01",
                "end_date": "2026-12-31",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_submit_assignment_blocks_cross_group(self):
        """Student A cannot submit an assignment belonging to Group B."""
        assignment = Assignment.objects.create(
            title="Test",
            group=self.group_b,
            due_date=date(2026, 12, 31),
            created_by=self.teacher_b,
        )
        self.client.force_login(self.student_a.admin)
        response = self.client.post(
            reverse("submit_assignment", args=[assignment.id]),
            {"note": "hacked"},
        )
        self.assertEqual(response.status_code, 403)

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_student_b_cannot_access_student_home_as_student_a(self):
        """Student B logged in sees their own dashboard, not Student A's."""
        self.client.force_login(self.student_b.admin)
        response = self.client.get(reverse("student_home"))
        self.assertEqual(response.status_code, 200)
        # Student B should NOT see Group A's name in their dashboard
        self.assertNotIn(b"Group A", response.content)


class GroupMessagingTests(TestCase):
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
        self.admin_user = self._make_user("chat-admin@iceberg.internal", "1")
        self.course = Course.objects.create(name="Messaging Course")

        self.teacher_a_user = self._make_user("chat-ta@iceberg.internal", "2", "TC81001")
        self.teacher_b_user = self._make_user("chat-tb@iceberg.internal", "2", "TC81002")
        self.teacher_a = Staff.objects.get(admin=self.teacher_a_user)
        self.teacher_b = Staff.objects.get(admin=self.teacher_b_user)

        self.group_a = Group.objects.create(
            name="Messaging Group A",
            course=self.course,
            teacher=self.teacher_a,
        )
        self.group_b = Group.objects.create(
            name="Messaging Group B",
            course=self.course,
            teacher=self.teacher_b,
        )

        self.student_a_user = self._make_user("chat-sa@iceberg.internal", "3", "IC81001")
        self.student_b_user = self._make_user("chat-sb@iceberg.internal", "3", "IC81002")
        self.student_a = Student.objects.get(admin=self.student_a_user)
        self.student_b = Student.objects.get(admin=self.student_b_user)
        Enrollment.objects.create(student=self.student_a, group=self.group_a, is_active=True)
        Enrollment.objects.create(student=self.student_b, group=self.group_b, is_active=True)

    def test_group_thread_created_when_group_created(self):
        self.assertTrue(ChatThread.objects.filter(group=self.group_a).exists())
        self.assertTrue(ChatThread.objects.filter(group=self.group_b).exists())

    @override_settings(**_BASE_OVERRIDES)
    def test_messages_mobile_hub_and_conversation_states_render(self):
        self.client.force_login(self.student_a_user)

        hub_response = self.client.get(reverse("messages"))
        self.assertEqual(hub_response.status_code, 200)
        self.assertContains(hub_response, 'class="ice-chat-app is-hub"')
        self.assertContains(hub_response, "Iceberg Chat")
        self.assertContains(hub_response, "Your group conversations and class channels.")
        self.assertContains(hub_response, "Messaging Group A")

        thread_response = self.client.get(reverse("message_thread", args=[self.group_a.id]))
        self.assertEqual(thread_response.status_code, 200)
        self.assertContains(thread_response, 'class="ice-chat-app is-conversation"')
        self.assertContains(thread_response, 'class="ice-chat-back"')

    @override_settings(**_BASE_OVERRIDES)
    def test_student_can_post_to_own_group_and_teacher_reads(self):
        self.client.force_login(self.student_a_user)
        response = self.client.post(
            reverse("message_thread", args=[self.group_a.id]),
            {"body": "Can we review the assignment tomorrow?"},
        )
        self.assertRedirects(
            response,
            reverse("message_thread", args=[self.group_a.id]) + "#latest",
            fetch_redirect_response=False,
        )
        self.assertTrue(
            ChatMessage.objects.filter(
                thread__group=self.group_a,
                sender=self.student_a_user,
                body="Can we review the assignment tomorrow?",
            ).exists()
        )

        self.client.force_login(self.teacher_a_user)
        response = self.client.get(reverse("message_thread", args=[self.group_a.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Can we review the assignment tomorrow?")

    @override_settings(**_BASE_OVERRIDES)
    def test_student_cannot_access_other_group_chat(self):
        self.client.force_login(self.student_a_user)
        response = self.client.get(reverse("message_thread", args=[self.group_b.id]))
        self.assertEqual(response.status_code, 403)

    @override_settings(**_BASE_OVERRIDES)
    def test_admin_can_access_all_group_chats_and_post(self):
        self.client.force_login(self.admin_user)
        response = self.client.post(
            reverse("message_thread", args=[self.group_b.id]),
            {"body": "Schedule update for Group B."},
        )
        self.assertRedirects(
            response,
            reverse("message_thread", args=[self.group_b.id]) + "#latest",
            fetch_redirect_response=False,
        )
        self.assertTrue(
            ChatMessage.objects.filter(
                thread__group=self.group_b,
                sender=self.admin_user,
                body="Schedule update for Group B.",
            ).exists()
        )

    @override_settings(**_BASE_OVERRIDES)
    def test_unread_count_excludes_own_messages_and_clears_on_read(self):
        thread = ChatThread.objects.get(group=self.group_a)
        ChatMessage.objects.create(
            thread=thread,
            sender=self.teacher_a_user,
            body="Please check the new material.",
        )
        ChatReadState.objects.create(thread=thread, user=self.teacher_a_user)

        self.assertEqual(unread_message_count(self.teacher_a_user), 0)
        self.assertEqual(unread_message_count(self.student_a_user), 1)

        self.client.force_login(self.student_a_user)
        response = self.client.get(reverse("message_thread", args=[self.group_a.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(unread_message_count(self.student_a_user), 0)


class BranchIsolationTests(TestCase):
    """Branch-first access control: super admin vs branch admin vs teacher vs student."""

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
        from main_app.models import Admin, Branch

        self.branch_a = Branch.objects.create(name="Branch A")
        self.branch_b = Branch.objects.create(name="Branch B")
        self.course = Course.objects.create(name="Branch Course")

        # Super admin (default flag is True).
        self.super_admin_user = self._make_user("super@iceberg.internal", "1")
        self.super_admin = Admin.objects.get(admin=self.super_admin_user)

        # Branch admin scoped to Branch A only. Mutate through the user's own
        # cached reverse accessor so is_super_admin reads back consistently
        # (the post_save signal pre-populates user.admin at creation time).
        self.branch_admin_user = self._make_user("ba@iceberg.internal", "1")
        self.branch_admin = self.branch_admin_user.admin
        self.branch_admin.is_super_admin = False
        self.branch_admin.save()
        self.branch_admin.branches.add(self.branch_a)

        # Teacher with one group in Branch A.
        self.teacher_a_user = self._make_user("bta@iceberg.internal", "2", "TC90001")
        self.teacher_a = Staff.objects.get(admin=self.teacher_a_user)
        self.teacher_a.branch = self.branch_a
        self.teacher_a.save()

        self.teacher_b_user = self._make_user("btb@iceberg.internal", "2", "TC90002")
        self.teacher_b = Staff.objects.get(admin=self.teacher_b_user)
        self.teacher_b.branch = self.branch_b
        self.teacher_b.save()

        self.group_a = Group.objects.create(
            name="Branch A Group", course=self.course, teacher=self.teacher_a, branch=self.branch_a
        )
        self.group_b = Group.objects.create(
            name="Branch B Group", course=self.course, teacher=self.teacher_b, branch=self.branch_b
        )

        self.student_a_user = self._make_user("bsa@iceberg.internal", "3", "IC90001")
        self.student_b_user = self._make_user("bsb@iceberg.internal", "3", "IC90002")
        self.student_a = Student.objects.get(admin=self.student_a_user)
        self.student_b = Student.objects.get(admin=self.student_b_user)
        self.student_a.branch = self.branch_a
        self.student_a.save()
        self.student_b.branch = self.branch_b
        self.student_b.save()
        Enrollment.objects.create(student=self.student_a, group=self.group_a, is_active=True)
        Enrollment.objects.create(student=self.student_b, group=self.group_b, is_active=True)

    # ── 1 & 9: super admin sees everything (and stays super after migration) ──
    def test_super_admin_sees_all(self):
        from main_app import branching

        self.assertTrue(branching.is_super_admin(self.super_admin_user))
        self.assertEqual(
            branching.filter_groups_for_user(self.super_admin_user, Group.objects.all()).count(), 2
        )
        self.assertEqual(
            branching.filter_students_for_user(
                self.super_admin_user, Student.objects.all()
            ).count(),
            2,
        )
        self.assertEqual(branching.get_accessible_branches(self.super_admin_user).count(), 2)

    # ── 2: branch admin sees only Branch A ──
    def test_branch_admin_scoped_to_branch_a(self):
        from main_app import branching

        self.assertFalse(branching.is_super_admin(self.branch_admin_user))
        groups = branching.filter_groups_for_user(self.branch_admin_user, Group.objects.all())
        self.assertEqual(list(groups), [self.group_a])
        students = branching.filter_students_for_user(self.branch_admin_user, Student.objects.all())
        self.assertEqual(list(students), [self.student_a])
        staff = branching.filter_staff_for_user(self.branch_admin_user, Staff.objects.all())
        self.assertIn(self.teacher_a, staff)
        self.assertNotIn(self.teacher_b, staff)

    @override_settings(**_BASE_OVERRIDES)
    def test_super_admin_can_assign_admin_to_dedicated_branch(self):
        self.client.force_login(self.super_admin_user)
        response = self.client.post(
            reverse("update_admin_branch_access", args=[self.branch_admin.id]),
            {"branches": [str(self.branch_b.id)]},
        )
        self.assertRedirects(response, reverse("manage_admin"), fetch_redirect_response=False)

        self.branch_admin.refresh_from_db()
        self.assertFalse(self.branch_admin.is_super_admin)
        self.assertEqual(list(self.branch_admin.branches.all()), [self.branch_b])

    @override_settings(**_BASE_OVERRIDES)
    def test_branch_admin_cannot_update_admin_branch_access(self):
        self.client.force_login(self.branch_admin_user)
        response = self.client.post(
            reverse("update_admin_branch_access", args=[self.super_admin.id]),
            {"branches": [str(self.branch_a.id)]},
        )
        self.assertRedirects(response, reverse("manage_admin"), fetch_redirect_response=False)

        self.super_admin.refresh_from_db()
        self.assertTrue(self.super_admin.is_super_admin)

    @override_settings(**_BASE_OVERRIDES)
    def test_cannot_demote_last_super_admin(self):
        from main_app.models import Admin

        Admin.objects.exclude(id=self.super_admin.id).update(is_super_admin=False)
        self.client.force_login(self.super_admin_user)
        response = self.client.post(
            reverse("update_admin_branch_access", args=[self.super_admin.id]),
            {"branches": [str(self.branch_a.id)]},
        )
        self.assertRedirects(response, reverse("manage_admin"), fetch_redirect_response=False)

        self.super_admin.refresh_from_db()
        self.assertTrue(self.super_admin.is_super_admin)
        self.assertEqual(self.super_admin.branches.count(), 0)

    # ── 3: branch admin cannot open Branch B group detail by URL ──
    @override_settings(**_BASE_OVERRIDES)
    def test_branch_admin_cannot_open_other_branch_group(self):
        self.client.force_login(self.branch_admin_user)
        response = self.client.get(reverse("admin_group_detail", args=[self.group_b.id]))
        self.assertRedirects(response, reverse("manage_group"), fetch_redirect_response=False)
        # Own branch group works.
        ok = self.client.get(reverse("admin_group_detail", args=[self.group_a.id]))
        self.assertEqual(ok.status_code, 200)

    # ── 4: branch admin cannot fetch Branch B attendance by forged POST ──
    @override_settings(**_BASE_OVERRIDES)
    def test_branch_admin_cannot_fetch_other_branch_attendance(self):
        attendance_b = Attendance.objects.create(group=self.group_b, date=date.today())
        self.client.force_login(self.branch_admin_user)
        forged = self.client.post(
            reverse("get_admin_attendance"), {"attendance_date_id": str(attendance_b.id)}
        )
        self.assertEqual(forged.status_code, 403)

    # ── 5: teacher sees only their groups ──
    def test_teacher_sees_only_own_groups(self):
        from main_app import branching

        groups = branching.filter_groups_for_user(self.teacher_a_user, Group.objects.all())
        self.assertEqual(list(groups), [self.group_a])

    # ── 6: student sees only own groups ──
    def test_student_sees_only_own_groups(self):
        from main_app import branching

        groups = branching.filter_groups_for_user(self.student_a_user, Group.objects.all())
        self.assertEqual(list(groups), [self.group_a])

    # ── 7: messaging respects branch admin scope ──
    def test_messaging_respects_branch_admin_scope(self):
        from main_app.messaging import accessible_groups_for_user

        super_groups = accessible_groups_for_user(self.super_admin_user)
        self.assertEqual(super_groups.count(), 2)
        ba_groups = accessible_groups_for_user(self.branch_admin_user)
        self.assertEqual(list(ba_groups), [self.group_a])

    # ── 8: enrollment form rejects cross-branch student/group ──
    def test_enrollment_form_rejects_branch_mismatch(self):
        from main_app.forms import EnrollmentForm

        form = EnrollmentForm(
            data={"group": self.group_a.id, "student": self.student_b.id, "is_active": "True"},
            user=self.super_admin_user,
        )
        self.assertFalse(form.is_valid())
        self.assertIn("group", form.errors)

    # ── 10: null-branch records don't crash management pages ──
    @override_settings(**_BASE_OVERRIDES)
    def test_null_branch_student_does_not_crash_pages(self):
        orphan_user = self._make_user("orphan@iceberg.internal", "3", "IC99999")
        orphan = Student.objects.get(admin=orphan_user)
        orphan.branch = None
        orphan.save()
        # Super admin manage_student renders without error.
        self.client.force_login(self.super_admin_user)
        response = self.client.get(reverse("manage_student"))
        self.assertEqual(response.status_code, 200)
        # Branch admin page also renders (orphan simply isn't shown).
        self.client.force_login(self.branch_admin_user)
        response = self.client.get(reverse("manage_student"))
        self.assertEqual(response.status_code, 200)

    # ── 11: branch admin cannot delete a student from another branch ──
    @override_settings(**_BASE_OVERRIDES)
    def test_branch_admin_cannot_delete_other_branch_student(self):
        self.client.force_login(self.branch_admin_user)
        response = self.client.post(reverse("delete_student", args=[self.student_b.id]))
        # Should redirect with an error, not delete.
        self.assertRedirects(response, reverse("manage_student"), fetch_redirect_response=False)
        self.assertTrue(Student.objects.filter(id=self.student_b.id).exists())

    # ── 12: branch admin cannot delete a teacher from another branch ──
    @override_settings(**_BASE_OVERRIDES)
    def test_branch_admin_cannot_delete_other_branch_teacher(self):
        self.client.force_login(self.branch_admin_user)
        response = self.client.post(reverse("delete_staff", args=[self.teacher_b.id]))
        self.assertRedirects(response, reverse("manage_staff"), fetch_redirect_response=False)
        self.assertTrue(Staff.objects.filter(id=self.teacher_b.id).exists())

    # ── 13: branch admin CAN delete a student from their own branch ──
    @override_settings(**_BASE_OVERRIDES)
    def test_branch_admin_can_delete_own_branch_student(self):
        self.client.force_login(self.branch_admin_user)
        student_id = self.student_a.id
        response = self.client.post(reverse("delete_student", args=[student_id]))
        self.assertRedirects(response, reverse("manage_student"), fetch_redirect_response=False)
        self.assertFalse(Student.objects.filter(id=student_id).exists())

    # ── 14: only super admin can access add_admin ──
    @override_settings(**_BASE_OVERRIDES)
    def test_only_super_admin_can_access_add_admin(self):
        # Super admin sees the page.
        self.client.force_login(self.super_admin_user)
        response = self.client.get(reverse("add_admin"))
        self.assertEqual(response.status_code, 200)

        # Branch admin is redirected.
        self.client.force_login(self.branch_admin_user)
        response = self.client.get(reverse("add_admin"))
        self.assertRedirects(response, reverse("admin_home"), fetch_redirect_response=False)

    # ── 15: super admin can create a new branch admin via add_admin ──
    @override_settings(**_BASE_OVERRIDES)
    def test_super_admin_can_create_branch_admin(self):
        from main_app.models import Admin

        self.client.force_login(self.super_admin_user)
        self.client.post(
            reverse("add_admin"),
            {
                "first_name": "New",
                "last_name": "Admin",
                "gender": "M",
                "address": "",
                "email": "newadmin@iceberg.internal",
                "password": "SecurePass1",
                "branches": [str(self.branch_a.id)],
            },
        )
        UserModel = get_user_model()
        self.assertTrue(UserModel.objects.filter(email="newadmin@iceberg.internal").exists())
        new_user = UserModel.objects.get(email="newadmin@iceberg.internal")
        new_admin = Admin.objects.get(admin=new_user)
        self.assertFalse(new_admin.is_super_admin)
        self.assertIn(self.branch_a, new_admin.branches.all())

    # ── 16: get_attendance blocks access to another branch's group ──
    @override_settings(**_BASE_OVERRIDES)
    def test_get_attendance_blocks_cross_branch_access(self):
        self.client.force_login(self.branch_admin_user)
        response = self.client.post(reverse("get_attendance"), {"group": str(self.group_b.id)})
        self.assertEqual(response.status_code, 403)

    # ── 17: registration leads filtering by branch ──
    def test_registration_leads_scoped_by_branch(self):
        from main_app import branching
        from main_app.models import RegistrationLead

        RegistrationLead.objects.create(
            full_name="Alice", email="alice@test.com", phone="1111", branch="Branch A"
        )
        RegistrationLead.objects.create(
            full_name="Bob", email="bob@test.com", phone="2222", branch="Branch B"
        )
        RegistrationLead.objects.create(
            full_name="Charlie", email="charlie@test.com", phone="3333", branch="branch a"
        )

        qs = RegistrationLead.objects.all()
        super_leads = branching.filter_registration_leads_for_user(self.super_admin_user, qs)
        self.assertEqual(super_leads.count(), 3)

        branch_leads = branching.filter_registration_leads_for_user(self.branch_admin_user, qs)
        self.assertEqual(branch_leads.count(), 2)
        names = set(branch_leads.values_list("full_name", flat=True))
        self.assertEqual(names, {"Alice", "Charlie"})


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


@override_settings(**_BASE_OVERRIDES)
class ApiObjectAuthTests(TestCase):
    """Object-level authorization on mobile API write paths — a teacher must not
    be able to act on groups they don't teach or students not in their group."""

    def _make_user(self, email, user_type, login_id):
        UserModel = get_user_model()
        return UserModel.objects.create_user(
            email=email, password="Pass123!", first_name="T", last_name="U",
            user_type=user_type, gender="M", address="", profile_pic="", login_id=login_id,
        )

    def setUp(self):
        from rest_framework.test import APIClient

        self.course = Course.objects.create(name="English")
        # Teacher A owns group A (with an enrolled student); teacher B owns group B.
        self.teacher_a = Staff.objects.get(admin=self._make_user("ta@iceberg.internal", "2", "TC80001"))
        self.teacher_b = Staff.objects.get(admin=self._make_user("tb@iceberg.internal", "2", "TC80002"))
        self.group_a = Group.objects.create(name="Group A", course=self.course, teacher=self.teacher_a)
        self.group_b = Group.objects.create(name="Group B", course=self.course, teacher=self.teacher_b)

        self.student_a = Student.objects.get(admin=self._make_user("ic80001@iceberg.internal", "3", "IC80001"))
        Enrollment.objects.create(student=self.student_a, group=self.group_a, is_active=True)
        # A student enrolled only in teacher B's group.
        self.student_b = Student.objects.get(admin=self._make_user("ic80002@iceberg.internal", "3", "IC80002"))
        Enrollment.objects.create(student=self.student_b, group=self.group_b, is_active=True)

        self.api = APIClient()
        self.api.force_authenticate(user=self.teacher_a.admin)

    def test_teacher_cannot_create_assignment_for_foreign_group(self):
        from main_app.models import Assignment

        res = self.api.post(
            "/api/v1/assignments/",
            {"title": "X", "description": "d", "group": self.group_b.id, "due_date": "2026-02-01"},
            format="json",
        )
        self.assertEqual(res.status_code, 403)
        self.assertFalse(Assignment.objects.filter(group=self.group_b).exists())

    def test_teacher_cannot_result_non_enrolled_student(self):
        from main_app.models import StudentResult

        # student_b is not enrolled in group_a (which teacher A owns).
        res = self.api.post(
            "/api/v1/results/",
            {"student_id": self.student_b.id, "group_id": self.group_a.id, "test": 10, "exam": 10},
            format="json",
        )
        self.assertEqual(res.status_code, 403)
        self.assertFalse(
            StudentResult.objects.filter(student=self.student_b, group=self.group_a).exists()
        )

    def test_attendance_drops_non_enrolled_student(self):
        from main_app.models import AttendanceReport

        res = self.api.post(
            "/api/v1/attendance/",
            {
                "group_id": self.group_a.id,
                "date": "2026-01-15",
                "records": [
                    {"student_id": self.student_a.id, "status": AttendanceReport.PRESENT},
                    {"student_id": self.student_b.id, "status": AttendanceReport.PRESENT},
                ],
            },
            format="json",
        )
        self.assertEqual(res.status_code, 200)
        # Enrolled student recorded; the foreign student silently dropped.
        self.assertTrue(AttendanceReport.objects.filter(student=self.student_a).exists())
        self.assertFalse(AttendanceReport.objects.filter(student=self.student_b).exists())


@override_settings(**_BASE_OVERRIDES)
class AttendanceIntegrityTests(TestCase):
    """DB-level guard against duplicate per-student attendance rows."""

    def _make_user(self, email, user_type, login_id):
        UserModel = get_user_model()
        return UserModel.objects.create_user(
            email=email, password="Pass123!", first_name="T", last_name="U",
            user_type=user_type, gender="M", address="", profile_pic="", login_id=login_id,
        )

    def test_duplicate_attendance_report_rejected(self):
        from django.db import IntegrityError, transaction
        from main_app.models import Attendance, AttendanceReport

        course = Course.objects.create(name="English")
        teacher = Staff.objects.get(admin=self._make_user("at@iceberg.internal", "2", "TC60001"))
        group = Group.objects.create(name="G", course=course, teacher=teacher)
        student = Student.objects.get(admin=self._make_user("ic60001@iceberg.internal", "3", "IC60001"))
        att = Attendance.objects.create(group=group, date=date(2026, 1, 10))
        AttendanceReport.objects.create(attendance=att, student=student, status=AttendanceReport.PRESENT)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                AttendanceReport.objects.create(
                    attendance=att, student=student, status=AttendanceReport.ABSENT
                )


@override_settings(**_BASE_OVERRIDES)
class MediaProtectionTests(TestCase):
    """Raw /media/results/ paths must not leak student result PDFs to anonymous
    users or across students; public assets stay reachable."""

    def _make_user(self, email, user_type, login_id):
        UserModel = get_user_model()
        return UserModel.objects.create_user(
            email=email, password="Pass123!", first_name="T", last_name="U",
            user_type=user_type, gender="M", address="", profile_pic="", login_id=login_id,
        )

    def setUp(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from main_app.models import ResultFile

        self.course = Course.objects.create(name="English")
        self.teacher = Staff.objects.get(admin=self._make_user("mt@iceberg.internal", "2", "TC70001"))
        self.group = Group.objects.create(name="G", course=self.course, teacher=self.teacher)
        self.enrolled_user = self._make_user("ic70001@iceberg.internal", "3", "IC70001")
        self.enrolled = Student.objects.get(admin=self.enrolled_user)
        Enrollment.objects.create(student=self.enrolled, group=self.group, is_active=True)
        self.outsider_user = self._make_user("ic70002@iceberg.internal", "3", "IC70002")

        self.rf = ResultFile.objects.create(
            group=self.group, title="Midterm", uploaded_by=self.teacher,
            file=SimpleUploadedFile("midterm.pdf", b"PDF-DATA"),
        )
        self.media_path = "/media/" + self.rf.file.name

    def test_anonymous_cannot_download_result_pdf(self):
        # Anonymous users are bounced to login by LoginCheckMiddleWare (302);
        # either way the file is never served.
        res = self.client.get(self.media_path)
        self.assertIn(res.status_code, (302, 404))
        self.assertNotEqual(res.status_code, 200)

    def test_enrolled_student_can_download_result_pdf(self):
        self.client.force_login(self.enrolled_user)
        res = self.client.get(self.media_path)
        self.assertEqual(res.status_code, 200)

    def test_other_student_cannot_download_result_pdf(self):
        self.client.force_login(self.outsider_user)
        self.assertEqual(self.client.get(self.media_path).status_code, 404)


@override_settings(**_BASE_OVERRIDES)
class ScoreValidationTests(TestCase):
    """Server-side enforcement of the grading scale (test ≤ 40, exam ≤ 60)."""

    def setUp(self):
        UserModel = get_user_model()
        self.teacher_user = UserModel.objects.create_user(
            email="scoreteacher@iceberg.internal",
            password="Pass123!",
            first_name="Score",
            last_name="Teacher",
            user_type="2",
            login_id="TC95001",
        )
        self.student_user = UserModel.objects.create_user(
            email="scorestudent@iceberg.internal",
            password="Pass123!",
            first_name="Score",
            last_name="Student",
            user_type="3",
            login_id="IC95001",
        )
        self.course = Course.objects.create(name="Score Course")
        self.teacher = Staff.objects.get(admin=self.teacher_user)
        self.student = Student.objects.get(admin=self.student_user)
        self.group = Group.objects.create(
            name="Score Group", course=self.course, teacher=self.teacher
        )
        Enrollment.objects.create(student=self.student, group=self.group, is_active=True)

    def test_add_result_rejects_out_of_scale_scores(self):
        from main_app.models import StudentResult

        self.client.force_login(self.teacher_user)
        self.client.post(
            reverse("staff_add_result"),
            {
                "student_list": str(self.student.id),
                "group": str(self.group.id),
                "test": "95",  # > 40
                "exam": "99",  # > 60
            },
        )
        self.assertFalse(
            StudentResult.objects.filter(student=self.student, group=self.group).exists()
        )

    def test_edit_result_rejects_out_of_scale_scores(self):
        from main_app.models import StudentResult

        StudentResult.objects.create(student=self.student, group=self.group, test=30, exam=50)
        self.client.force_login(self.teacher_user)
        self.client.post(
            reverse("edit_student_result"),
            {
                "group": str(self.group.id),
                "student": str(self.student.id),
                "test": "400",
                "exam": "600",
            },
        )
        result = StudentResult.objects.get(student=self.student, group=self.group)
        self.assertEqual(result.test, 30)
        self.assertEqual(result.exam, 50)

    def test_add_result_accepts_valid_scores(self):
        from main_app.models import StudentResult

        self.client.force_login(self.teacher_user)
        self.client.post(
            reverse("staff_add_result"),
            {
                "student_list": str(self.student.id),
                "group": str(self.group.id),
                "test": "35",
                "exam": "55",
            },
        )
        result = StudentResult.objects.get(student=self.student, group=self.group)
        self.assertEqual(result.test, 35)
        self.assertEqual(result.exam, 55)


@override_settings(**_BASE_OVERRIDES)
class StudentMobileApiTests(TestCase):
    """API endpoints added for the ICEBERG mobile app (student scope)."""

    maxDiff = None

    def _make_user(self, email, user_type, login_id=None, dob=None):
        UserModel = get_user_model()
        return UserModel.objects.create_user(
            email=email,
            password="Pass123!",
            first_name="T",
            last_name="U",
            user_type=user_type,
            gender="M",
            address="",
            profile_pic="",
            login_id=login_id,
            date_of_birth=dob,
        )

    def setUp(self):
        from rest_framework.test import APIClient

        self.course = Course.objects.create(name="General English")
        teacher_user = self._make_user("t-api@iceberg.internal", "2", "TC90001")
        self.teacher = Staff.objects.get(admin=teacher_user)
        self.group = Group.objects.create(
            name="API Group", course=self.course, teacher=self.teacher
        )
        self.other_group = Group.objects.create(
            name="Other Group", course=self.course, teacher=self.teacher
        )

        student_user = self._make_user("ic90001@iceberg.internal", "3", "IC90001", date(2005, 5, 1))
        self.student = Student.objects.get(admin=student_user)
        self.student.course = self.course
        self.student.save()
        Enrollment.objects.create(student=self.student, group=self.group, is_active=True)

        other_user = self._make_user("ic90002@iceberg.internal", "3", "IC90002", date(2005, 6, 1))
        self.other_student = Student.objects.get(admin=other_user)
        Enrollment.objects.create(
            student=self.other_student, group=self.other_group, is_active=True
        )

        self.api = APIClient()
        self.api.force_authenticate(user=student_user)

    # ── Settings ─────────────────────────────────────────────────────────

    def test_settings_defaults_and_patch(self):
        res = self.api.get("/api/v1/student/settings/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["accent"], "ice")
        self.assertEqual(res.json()["theme"], "system")
        self.assertTrue(res.json()["notifications"]["assignments"])

        res = self.api.patch(
            "/api/v1/student/settings/",
            {"theme": "dark", "accent": "cyan", "notifications": {"payments": False}},
            format="json",
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["theme"], "dark")
        self.assertEqual(body["accent"], "cyan")
        self.assertFalse(body["notifications"]["payments"])
        self.assertTrue(body["notifications"]["assignments"])

        self.student.refresh_from_db()
        self.assertEqual(self.student.theme, Student.THEME_DARK)

    def test_settings_rejects_unknown_values(self):
        res = self.api.patch("/api/v1/student/settings/", {"accent": "magenta"}, format="json")
        self.assertEqual(res.status_code, 400)

    def test_settings_blocked_for_teacher(self):
        from rest_framework.test import APIClient

        api = APIClient()
        api.force_authenticate(user=self.teacher.admin)
        self.assertEqual(api.get("/api/v1/student/settings/").status_code, 403)

    # ── Attendance summary ───────────────────────────────────────────────

    def test_attendance_summary_counts_streak_and_calendar(self):
        today = date.today()
        statuses = [
            (today - timedelta(days=4), AttendanceReport.ABSENT),
            (today - timedelta(days=3), AttendanceReport.PRESENT),
            (today - timedelta(days=2), AttendanceReport.LATE),
            (today - timedelta(days=1), AttendanceReport.PRESENT),
        ]
        for d, s in statuses:
            att = Attendance.objects.create(group=self.group, date=d)
            AttendanceReport.objects.create(attendance=att, student=self.student, status=s)

        res = self.api.get("/api/v1/student/attendance/summary/")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["streak_days"], 3)  # absence 4 days ago breaks it
        self.assertEqual(body["absent_count"], 1)
        self.assertEqual(body["late_count"], 1)
        self.assertEqual(body["present_count"], 2)
        self.assertEqual(len(body["weekly_trend"]), 12)
        self.assertEqual(body["groups"][0]["name"], "API Group")
        # Calendar contains only current-month rows
        for row in body["days"]:
            self.assertTrue(row["date"].startswith(body["month"]))

    def test_attendance_summary_is_own_data_only(self):
        att = Attendance.objects.create(group=self.other_group, date=date.today())
        AttendanceReport.objects.create(
            attendance=att, student=self.other_student, status=AttendanceReport.PRESENT
        )
        res = self.api.get("/api/v1/student/attendance/summary/")
        self.assertEqual(res.json()["total_count"], 0)

    # ── Result files ─────────────────────────────────────────────────────

    def test_result_files_scoping_and_download(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from main_app.models import ResultFile

        group_file = ResultFile.objects.create(
            group=self.group,
            title="Midterm Results",
            uploaded_by=self.teacher,
            file=SimpleUploadedFile("midterm.pdf", b"PDF-DATA"),
        )
        personal_other = ResultFile.objects.create(
            group=self.other_group,
            student=self.other_student,
            title="Private Report",
            uploaded_by=self.teacher,
            file=SimpleUploadedFile("private.pdf", b"SECRET"),
        )

        res = self.api.get("/api/v1/result-files/")
        self.assertEqual(res.status_code, 200)
        titles = [f["title"] for f in res.json()["files"]]
        self.assertIn("Midterm Results", titles)
        self.assertNotIn("Private Report", titles)

        dl = self.api.get(f"/api/v1/result-files/{group_file.id}/download/")
        self.assertEqual(dl.status_code, 200)
        self.assertEqual(b"".join(dl.streaming_content), b"PDF-DATA")

        denied = self.api.get(f"/api/v1/result-files/{personal_other.id}/download/")
        self.assertEqual(denied.status_code, 404)

    # ── Leaderboard scopes ───────────────────────────────────────────────

    def test_leaderboard_group_scope_reranks_and_flags_me(self):
        from main_app.models import LeaderboardSeason, LeaderboardSnapshot

        season = LeaderboardSeason.objects.create(name="Test Season", start_date=date.today())
        LeaderboardSnapshot.objects.create(
            season=season, student=self.other_student, rank=1, score=99.0
        )
        LeaderboardSnapshot.objects.create(season=season, student=self.student, rank=2, score=88.0)

        res = self.api.get("/api/v1/leaderboard/?scope=group")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        # Other student is in a different group → filtered out, I re-rank to #1
        self.assertEqual(len(body["entries"]), 1)
        self.assertEqual(body["entries"][0]["rank"], 1)
        self.assertTrue(body["entries"][0]["is_me"])
        self.assertEqual(body["my_rank"], 1)

        res_all = self.api.get("/api/v1/leaderboard/")
        self.assertEqual(len(res_all.json()["entries"]), 2)

    # ── Dashboard enrichment ─────────────────────────────────────────────

    def test_dashboard_includes_mobile_fields(self):
        from django.utils import timezone as tz
        from main_app.models import (
            Invoice,
            Notification,
            StudentResult,
            VocabularyDay,
            VocabularyDayWord,
        )

        Assignment.objects.create(
            title="Essay",
            group=self.group,
            due_date=date.today() + timedelta(days=3),
            created_by=self.teacher,
        )
        Notification.objects.create(recipient=self.student.admin, message="hello", is_read=False)
        day = VocabularyDay.objects.create(
            group=self.group,
            day_number=1,
            release_at=tz.now() - timedelta(hours=1),
            created_by=self.teacher,
        )
        VocabularyDayWord.objects.create(day=day, word="see", meaning="ko'rmoq")
        Invoice.objects.create(
            student=self.student,
            group=self.group,
            period=date.today().replace(day=1),
            amount=1_000_000,
            due_date=date.today() + timedelta(days=5),
        )

        # Performance trend = last 8 graded results (one per group, since
        # StudentResult is unique per student+group). Seed 9 groups+results
        # to verify the dashboard caps the trend at the 8 most recent.
        for i in range(9):
            grp = Group.objects.create(
                name=f"Trend Group {i}", course=self.course, teacher=self.teacher
            )
            Enrollment.objects.create(student=self.student, group=grp, is_active=True)
            StudentResult.objects.create(
                student=self.student, group=grp, test=30, exam=50
            )

        res = self.api.get("/api/v1/student/home/")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["pending_assignments"], 1)
        self.assertEqual(len(body["assignments_preview"]), 1)
        self.assertEqual(body["unread_notifications"], 1)
        self.assertEqual(body["new_vocab_words"], 1)
        self.assertEqual(len(body["performance_trend"]), 8)
        self.assertEqual(body["performance_trend"][0]["attendance_pct"], 80.0)
        self.assertEqual(body["balance_due"], 1_000_000)
        self.assertIsNotNone(body["balance_due_date"])

    # ── Profile: phone + emoji avatar ────────────────────────────────────

    def test_me_patch_phone_and_avatar(self):
        res = self.api.patch(
            "/api/v1/me/", {"phone": "+998901234567", "avatar": "🧑‍🎓"}, format="json"
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["avatar"], "🧑‍🎓")
        self.student.refresh_from_db()
        self.assertEqual(self.student.phone, "+998901234567")

    # ── Chat attachments ─────────────────────────────────────────────────

    def test_chat_post_with_attachment(self):
        from django.core.files.uploadedfile import SimpleUploadedFile

        res = self.api.post(
            f"/api/v1/messages/{self.group.id}/",
            {"message": "see attached", "attachment": SimpleUploadedFile("notes.pdf", b"X")},
            format="multipart",
        )
        self.assertEqual(res.status_code, 201)
        body = res.json()
        self.assertEqual(body["attachment_name"], "notes.pdf")
        self.assertIsNotNone(body["attachment_url"])


@override_settings(**_BASE_OVERRIDES)
class AdminManagementTests(TestCase):
    """Recovery Admin promotes admins to super; super admins edit credentials."""

    def setUp(self):
        UserModel = get_user_model()
        self.branch = Branch.objects.create(name="Central")

        # Permanent top-level recovery account (marked by is_superuser).
        self.recovery_user = UserModel.objects.create_user(
            email="recovery-mgmt@example.com",
            password="RecoveryPass123!",
            first_name="Rec",
            last_name="Overy",
            user_type="1",
        )
        self.recovery_user.is_superuser = True
        self.recovery_user.save(update_fields=["is_superuser"])

        # A second, ordinary super admin (signal makes new admins super).
        self.super_user = UserModel.objects.create_user(
            email="super-mgmt@example.com",
            password="SuperPass123!",
            first_name="Su",
            last_name="Per",
            user_type="1",
        )

        # A branch admin (demoted from the default super state).
        self.branch_user = UserModel.objects.create_user(
            email="branch-mgmt@example.com",
            password="BranchPass123!",
            first_name="Bree",
            last_name="Anch",
            user_type="1",
        )
        self.branch_admin = Admin.objects.get(admin=self.branch_user)
        self.branch_admin.is_super_admin = False
        self.branch_admin.branches.set([self.branch])
        self.branch_admin.save()

    def test_recovery_can_promote_branch_admin_to_super(self):
        self.client.force_login(self.recovery_user)
        self.client.post(
            reverse("update_admin_branch_access", args=[self.branch_admin.id]),
            {"is_super_admin": "on"},
        )
        self.branch_admin.refresh_from_db()
        self.assertTrue(self.branch_admin.is_super_admin)
        # Recovery admin keeps super status — multiple super admins coexist.
        self.assertTrue(Admin.objects.get(admin=self.recovery_user).is_super_admin)
        self.assertEqual(self.branch_admin.branches.count(), 0)

    def test_any_super_admin_can_promote_to_super(self):
        self.client.force_login(self.super_user)
        self.client.post(
            reverse("update_admin_branch_access", args=[self.branch_admin.id]),
            {"is_super_admin": "on"},
        )
        self.branch_admin.refresh_from_db()
        self.assertTrue(self.branch_admin.is_super_admin)

    def test_cannot_demote_last_super_admin(self):
        # Reduce to a single super admin, then try to demote it.
        Admin.objects.exclude(admin=self.super_user).update(is_super_admin=False)
        super_admin = Admin.objects.get(admin=self.super_user)
        self.client.force_login(self.super_user)
        self.client.post(
            reverse("update_admin_branch_access", args=[super_admin.id]),
            {"branches": [self.branch.id]},  # no is_super_admin → demote attempt
        )
        super_admin.refresh_from_db()
        self.assertTrue(super_admin.is_super_admin)

    def test_super_admin_can_edit_admin_credentials(self):
        self.client.force_login(self.super_user)
        response = self.client.post(
            reverse("edit_admin", args=[self.branch_admin.id]),
            {
                "first_name": "Brenda",
                "last_name": "Branch",
                "email": "new-branch@example.com",
                "password": "BrandNewPass1",
            },
        )
        self.assertRedirects(response, reverse("manage_admin"), fetch_redirect_response=False)
        self.branch_user.refresh_from_db()
        self.assertEqual(self.branch_user.first_name, "Brenda")
        self.assertEqual(self.branch_user.email, "new-branch@example.com")
        self.assertTrue(self.branch_user.check_password("BrandNewPass1"))

    def test_edit_admin_blank_password_keeps_current(self):
        self.client.force_login(self.super_user)
        self.client.post(
            reverse("edit_admin", args=[self.branch_admin.id]),
            {
                "first_name": "Bree",
                "last_name": "Anch",
                "email": "branch-mgmt@example.com",
                "password": "",
            },
        )
        self.branch_user.refresh_from_db()
        self.assertTrue(self.branch_user.check_password("BranchPass123!"))

    def test_super_admin_can_change_recovery_credentials(self):
        recovery_admin = Admin.objects.get(admin=self.recovery_user)
        self.client.force_login(self.super_user)
        response = self.client.post(
            reverse("edit_admin", args=[recovery_admin.id]),
            {
                "first_name": "Rec",
                "last_name": "Overy",
                "email": "new-recovery@example.com",
                "password": "FreshRecovery1",
            },
        )
        self.assertRedirects(response, reverse("manage_admin"), fetch_redirect_response=False)
        self.recovery_user.refresh_from_db()
        # Email/password changed on the one account; old credentials no longer work.
        self.assertEqual(self.recovery_user.email, "new-recovery@example.com")
        self.assertTrue(self.recovery_user.check_password("FreshRecovery1"))
        self.assertFalse(self.recovery_user.check_password("RecoveryPass123!"))
        # No duplicate account was created at the old address.
        self.assertFalse(
            get_user_model().objects.filter(email__iexact="recovery-mgmt@example.com").exists()
        )

    def test_super_admin_can_delete_recovery(self):
        recovery_admin = Admin.objects.get(admin=self.recovery_user)
        self.client.force_login(self.super_user)
        self.client.post(reverse("delete_admin", args=[recovery_admin.id]))
        self.assertFalse(get_user_model().objects.filter(pk=self.recovery_user.pk).exists())

    def test_login_rejects_old_recovery_credentials_after_change(self):
        """The reported bug: change recovery creds, but old ones still log in.
        Drives the real login endpoint to prove old creds are now rejected."""
        recovery_admin = Admin.objects.get(admin=self.recovery_user)
        self.client.force_login(self.super_user)
        self.client.post(
            reverse("edit_admin", args=[recovery_admin.id]),
            {
                "first_name": "Rec",
                "last_name": "Overy",
                "email": "moved-recovery@example.com",
                "password": "FreshRecovery1",
            },
        )
        self.client.logout()

        # OLD email + OLD password must NOT authenticate (and must not resurrect).
        self.client.post(
            reverse("user_login"),
            {"identifier": "recovery-mgmt@example.com", "password": "RecoveryPass123!"},
        )
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertFalse(
            get_user_model().objects.filter(email__iexact="recovery-mgmt@example.com").exists()
        )

        # NEW credentials work.
        self.client.post(
            reverse("user_login"),
            {"identifier": "moved-recovery@example.com", "password": "FreshRecovery1"},
        )
        self.assertEqual(str(self.client.session.get("_auth_user_id")), str(self.recovery_user.pk))

    def test_edit_admin_rejects_duplicate_email(self):
        self.client.force_login(self.super_user)
        self.client.post(
            reverse("edit_admin", args=[self.branch_admin.id]),
            {
                "first_name": "Bree",
                "last_name": "Anch",
                "email": "super-mgmt@example.com",  # already used by super_user
                "password": "",
            },
        )
        self.branch_user.refresh_from_db()
        self.assertEqual(self.branch_user.email, "branch-mgmt@example.com")

    def test_manage_admin_page_renders_for_recovery(self):
        self.client.force_login(self.recovery_user)
        response = self.client.get(reverse("manage_admin"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Recovery Admin")
        # Edit link is present for editable admins.
        self.assertContains(response, reverse("edit_admin", args=[self.branch_admin.id]))

    def test_edit_admin_page_renders(self):
        self.client.force_login(self.super_user)
        response = self.client.get(reverse("edit_admin", args=[self.branch_admin.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "branch-mgmt@example.com")
        self.assertContains(response, "Save Changes")


@override_settings(**_BASE_OVERRIDES)
class RecoveryAdminSeedingTests(TestCase):
    """Credential changes to the recovery account must persist — the env-based
    seeder/login-fallback must not silently revert them."""

    def setUp(self):
        from main_app.apps import create_recovery_admin_access

        self.seed = create_recovery_admin_access
        UserModel = get_user_model()
        # post_migrate seeds the recovery account; fall back to creating it.
        self.recovery = UserModel.objects.filter(is_superuser=True).order_by("id").first()
        if self.recovery is None:
            create_recovery_admin_access(sender=None)
            self.recovery = UserModel.objects.filter(is_superuser=True).order_by("id").first()

    def test_reseed_does_not_reset_changed_password(self):
        UserModel = get_user_model()
        self.recovery.set_password("ChangedByUser1")
        self.recovery.save()

        self.seed(sender=None)  # simulate a deploy / login-fallback re-seed

        self.recovery.refresh_from_db()
        self.assertTrue(self.recovery.check_password("ChangedByUser1"))
        self.assertFalse(self.recovery.check_password("iceberg"))  # weak default gone
        # No duplicate recovery account was created.
        self.assertEqual(UserModel.objects.filter(is_superuser=True).count(), 1)

    def test_reseed_does_not_recreate_after_email_change(self):
        UserModel = get_user_model()
        self.recovery.email = "new-recovery@example.com"
        self.recovery.save()

        self.seed(sender=None)

        # The seeder must not recreate a stale duplicate at the default address.
        self.assertFalse(
            UserModel.objects.filter(email__iexact="iceberg.edu.center@gmail.com").exists()
        )
        self.assertEqual(UserModel.objects.filter(is_superuser=True).count(), 1)

    def test_bootstrap_creates_recovery_when_missing(self):
        UserModel = get_user_model()
        UserModel.objects.filter(is_superuser=True).delete()
        self.assertEqual(UserModel.objects.filter(is_superuser=True).count(), 0)

        self.seed(sender=None)

        recovery = UserModel.objects.filter(is_superuser=True).first()
        self.assertIsNotNone(recovery)
        self.assertEqual(recovery.email, "iceberg.edu.center@gmail.com")


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


class StaticReferenceTests(TestCase):
    def test_every_static_file_named_in_a_template_exists(self):
        # Production uses manifest static storage, where a missing file is a 500
        # (the APK download page broke this way).
        from pathlib import Path

        from django.contrib.staticfiles import finders

        templates = Path(__file__).resolve().parent / "templates"
        missing = []
        for template in templates.rglob("*.html"):
            text = template.read_text(encoding="utf-8")
            for name in re.findall(r"\{%\s*static\s+['\"]([^'\"]+)['\"]", text):
                if not finders.find(name):
                    missing.append(f"{template.relative_to(templates)}: {name}")
        self.assertEqual(missing, [])
