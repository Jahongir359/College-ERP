from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from main_app.models import (
    Admin,
    Attendance,
    AttendanceReport,
    Assignment,
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
            StudentResult.objects.create(student=self.student, group=grp, test=30, exam=50)

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
                "password": "Tundra-Lantern-42",
            },
        )
        self.assertRedirects(response, reverse("manage_admin"), fetch_redirect_response=False)
        self.recovery_user.refresh_from_db()
        # Email/password changed on the one account; old credentials no longer work.
        self.assertEqual(self.recovery_user.email, "new-recovery@example.com")
        self.assertTrue(self.recovery_user.check_password("Tundra-Lantern-42"))
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
                "password": "Tundra-Lantern-42",
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
            {"identifier": "moved-recovery@example.com", "password": "Tundra-Lantern-42"},
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
