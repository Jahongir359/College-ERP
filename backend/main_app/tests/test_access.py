import json
from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from main_app.models import (
    Admin,
    Attendance,
    AttendanceReport,
    Assignment,
    Branch,
    ChatMessage,
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
        from main_app.models import Branch

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


@override_settings(**_BASE_OVERRIDES)
class ApiObjectAuthTests(TestCase):
    """Object-level authorization on mobile API write paths — a teacher must not
    be able to act on groups they don't teach or students not in their group."""

    def _make_user(self, email, user_type, login_id):
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
        )

    def setUp(self):
        from rest_framework.test import APIClient

        self.course = Course.objects.create(name="English")
        # Teacher A owns group A (with an enrolled student); teacher B owns group B.
        self.teacher_a = Staff.objects.get(
            admin=self._make_user("ta@iceberg.internal", "2", "TC80001")
        )
        self.teacher_b = Staff.objects.get(
            admin=self._make_user("tb@iceberg.internal", "2", "TC80002")
        )
        self.group_a = Group.objects.create(
            name="Group A", course=self.course, teacher=self.teacher_a
        )
        self.group_b = Group.objects.create(
            name="Group B", course=self.course, teacher=self.teacher_b
        )

        self.student_a = Student.objects.get(
            admin=self._make_user("ic80001@iceberg.internal", "3", "IC80001")
        )
        Enrollment.objects.create(student=self.student_a, group=self.group_a, is_active=True)
        # A student enrolled only in teacher B's group.
        self.student_b = Student.objects.get(
            admin=self._make_user("ic80002@iceberg.internal", "3", "IC80002")
        )
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
class MediaProtectionTests(TestCase):
    """Raw /media/results/ paths must not leak student result PDFs to anonymous
    users or across students; public assets stay reachable."""

    def _make_user(self, email, user_type, login_id):
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
        )

    def setUp(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from main_app.models import ResultFile

        self.course = Course.objects.create(name="English")
        self.teacher = Staff.objects.get(
            admin=self._make_user("mt@iceberg.internal", "2", "TC70001")
        )
        self.group = Group.objects.create(name="G", course=self.course, teacher=self.teacher)
        self.enrolled_user = self._make_user("ic70001@iceberg.internal", "3", "IC70001")
        self.enrolled = Student.objects.get(admin=self.enrolled_user)
        Enrollment.objects.create(student=self.enrolled, group=self.group, is_active=True)
        self.outsider_user = self._make_user("ic70002@iceberg.internal", "3", "IC70002")

        self.rf = ResultFile.objects.create(
            group=self.group,
            title="Midterm",
            uploaded_by=self.teacher,
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
class AuditSecurityFixTests(TestCase):
    """Regression tests for the 2026-10 code-audit fixes (XSS, quiz scores,
    private media, branch scoping, shared settings, passwords)."""

    def _make_user(self, email, user_type, login_id=None):
        return get_user_model().objects.create_user(
            email=email,
            password="Pass123!",
            first_name="T",
            last_name="U",
            user_type=user_type,
            gender="M",
            address="",
            profile_pic="",
            login_id=login_id,
        )

    def setUp(self):
        from rest_framework.test import APIClient

        self.branch_a = Branch.objects.create(name="Audit A")
        self.branch_b = Branch.objects.create(name="Audit B")
        self.course = Course.objects.create(name="Audit English")

        self.super_user = self._make_user("asuper@iceberg.internal", "1")
        self.ba_user = self._make_user("aba@iceberg.internal", "1")
        self.ba_user.admin.is_super_admin = False
        self.ba_user.admin.save()
        self.ba_user.admin.branches.add(self.branch_a)

        self.teacher_a = Staff.objects.get(admin=self._make_user("ata@x.internal", "2", "TC60001"))
        self.teacher_a.branch = self.branch_a
        self.teacher_a.save()
        self.teacher_b = Staff.objects.get(admin=self._make_user("atb@x.internal", "2", "TC60002"))
        self.teacher_b.branch = self.branch_b
        self.teacher_b.save()
        self.group_a = Group.objects.create(
            name="AG", course=self.course, teacher=self.teacher_a, branch=self.branch_a
        )
        self.group_b = Group.objects.create(
            name="BG", course=self.course, teacher=self.teacher_b, branch=self.branch_b
        )

        self.student_a_user = self._make_user("asa@x.internal", "3", "IC60001")
        self.student_a = Student.objects.get(admin=self.student_a_user)
        self.student_a.branch = self.branch_a
        self.student_a.save()
        self.student_b_user = self._make_user("asb@x.internal", "3", "IC60002")
        self.student_b = Student.objects.get(admin=self.student_b_user)
        self.student_b.branch = self.branch_b
        self.student_b.save()
        Enrollment.objects.create(student=self.student_a, group=self.group_a, is_active=True)
        Enrollment.objects.create(student=self.student_b, group=self.group_b, is_active=True)

        self.api = APIClient()

    # ── S1: script-context JSON escaping ────────────────────────────────────
    def test_js_json_filter_cannot_close_script_tag(self):
        from main_app.templatetags.json_tags import js_json

        out = js_json(json.dumps({"name": "</script><script>alert(1)</script>"}))
        self.assertNotIn("<", out)
        self.assertNotIn(">", out)
        self.assertEqual(json.loads(out)["name"], "</script><script>alert(1)</script>")

    def test_leaderboard_page_escapes_student_name(self):
        self.student_a_user.first_name = "</script><b>x"
        self.student_a_user.save()
        self.client.force_login(self.student_a_user)
        res = self.client.get(reverse("student_leaderboard"))
        self.assertEqual(res.status_code, 200)
        self.assertNotIn(b"</script><b>x", res.content)

    # ── S2: quiz score tampering ────────────────────────────────────────────
    def _vocab_day(self, group):
        from main_app.models import VocabularyDay, VocabularyDayWord

        day = VocabularyDay.objects.create(
            group=group,
            day_number=1,
            release_at=timezone.now() - timedelta(days=1),
            created_by=group.teacher,
        )
        for i in range(4):
            VocabularyDayWord.objects.create(day=day, word=f"w{i}", meaning=f"m{i}")
        return day

    def test_quiz_result_rejects_inflated_score(self):
        from main_app.models import VocabularyQuizResult

        day = self._vocab_day(self.group_a)
        self.api.force_authenticate(user=self.student_a_user)
        url = f"/api/v1/vocabulary/{day.id}/quiz-result/"
        self.assertEqual(self.api.post(url, {"correct": 1000, "total": 1}).status_code, 400)
        self.assertEqual(self.api.post(url, {"correct": 5, "total": 4}).status_code, 400)
        self.assertFalse(VocabularyQuizResult.objects.exists())
        res = self.api.post(url, {"correct": 3, "total": 4})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["score"], 75.0)

    def test_quiz_result_requires_enrollment(self):
        day = self._vocab_day(self.group_b)
        self.api.force_authenticate(user=self.student_a_user)
        res = self.api.post(f"/api/v1/vocabulary/{day.id}/quiz-result/", {"correct": 4, "total": 4})
        self.assertEqual(res.status_code, 403)

    # ── S3: private media ───────────────────────────────────────────────────
    def test_submission_and_chat_files_are_not_public(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from main_app.models import Submission
        from rest_framework_simplejwt.tokens import AccessToken

        assignment = Assignment.objects.create(
            title="HW", group=self.group_a, due_date=date.today(), created_by=self.teacher_a
        )
        sub = Submission.objects.create(
            assignment=assignment,
            student=self.student_a,
            file=SimpleUploadedFile("essay.txt", b"secret homework"),
        )
        msg = ChatMessage.objects.create(
            thread=ChatThread.objects.get(group=self.group_a),
            sender=self.student_a_user,
            attachment=SimpleUploadedFile("photo.png", b"PNGDATA"),
        )
        sub_path = "/media/" + sub.file.name
        chat_path = "/media/" + msg.attachment.name

        # Anonymous → not served.
        self.assertEqual(self.client.get(sub_path).status_code, 404)
        self.assertEqual(self.client.get(chat_path).status_code, 404)
        # Another branch's student → not served.
        self.client.force_login(self.student_b_user)
        self.assertEqual(self.client.get(sub_path).status_code, 404)
        self.assertEqual(self.client.get(chat_path).status_code, 404)
        # Owner (session) and the group's teacher → served.
        self.client.force_login(self.student_a_user)
        self.assertEqual(self.client.get(sub_path).status_code, 200)
        self.assertEqual(self.client.get(chat_path).status_code, 200)
        self.client.logout()
        # Mobile app: JWT bearer token, no session.
        token = str(AccessToken.for_user(self.teacher_a.admin))
        res = self.client.get(sub_path, HTTP_AUTHORIZATION=f"Bearer {token}")
        self.assertEqual(res.status_code, 200)

    # ── S4: branch-admin scope in the API and notifications ─────────────────
    def test_branch_admin_cannot_read_other_branch_lead(self):
        lead_b = RegistrationLead.objects.create(full_name="Lead B", branch="Audit B")
        lead_a = RegistrationLead.objects.create(full_name="Lead A", branch="Audit A")
        self.api.force_authenticate(user=self.ba_user)
        self.assertEqual(self.api.get(f"/api/v1/admin/leads/{lead_b.id}/").status_code, 404)
        self.assertEqual(self.api.get(f"/api/v1/admin/leads/{lead_a.id}/").status_code, 200)
        names = [row["full_name"] for row in self.api.get("/api/v1/admin/leads/").data["results"]]
        self.assertEqual(names, ["Lead A"])

    def test_branch_admin_cannot_create_student_in_other_branch(self):
        self.api.force_authenticate(user=self.ba_user)
        payload = {"first_name": "New", "password": "Str0ng-Passw0rd", "branch": self.branch_b.id}
        res = self.api.post("/api/v1/admin/students/", payload, format="json")
        self.assertEqual(res.status_code, 403)
        res = self.api.patch(
            f"/api/v1/admin/students/{self.student_a.id}/",
            {"branch": self.branch_b.id},
            format="json",
        )
        self.assertEqual(res.status_code, 400)
        self.student_a.refresh_from_db()
        self.assertEqual(self.student_a.branch, self.branch_a)

    def test_branch_admin_cannot_delete_other_branch_story(self):
        from main_app.models import DashboardStory

        story = DashboardStory.objects.create(title="B only", created_by=self.super_user)
        story.target_groups.set([self.group_b])
        self.api.force_authenticate(user=self.ba_user)
        self.assertEqual(self.api.delete(f"/api/v1/stories/{story.id}/").status_code, 403)
        self.assertTrue(DashboardStory.objects.filter(id=story.id).exists())

    def test_teacher_story_never_becomes_school_wide(self):
        from main_app.models import DashboardStory

        self.api.force_authenticate(user=self.teacher_a.admin)
        res = self.api.post(
            "/api/v1/stories/create/",
            {"title": "Hi", "target_group_ids": [self.group_b.id]},
            format="json",
        )
        self.assertEqual(res.status_code, 201)
        story = DashboardStory.objects.get(id=res.data["id"])
        self.assertEqual(list(story.target_groups.all()), [self.group_a])

    def test_branch_admin_cannot_notify_other_branch_student(self):
        from main_app.models import Notification

        self.client.force_login(self.ba_user)
        res = self.client.post(
            reverse("send_student_notification"),
            {"id": self.student_b_user.id, "message": "hello"},
        )
        self.assertEqual(res.status_code, 404)
        self.assertFalse(Notification.objects.filter(recipient=self.student_b_user).exists())

    def test_admin_result_upload_scoped_and_no_crash(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from main_app.models import ResultFile

        self.api.force_authenticate(user=self.ba_user)
        res = self.api.post(
            "/api/v1/upload/",
            {"file": SimpleUploadedFile("r.pdf", b"PDF"), "group_id": self.group_b.id},
            format="multipart",
        )
        self.assertEqual(res.status_code, 404)
        res = self.api.post(
            "/api/v1/upload/",
            {"file": SimpleUploadedFile("r.pdf", b"PDF"), "group_id": self.group_a.id},
            format="multipart",
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(ResultFile.objects.get(id=res.data["id"]).uploaded_by, self.teacher_a)

    def test_api_group_delete_does_not_crash(self):
        empty = Group.objects.create(name="Empty", course=self.course, branch=self.branch_a)
        self.api.force_authenticate(user=self.ba_user)
        res = self.api.delete(f"/api/v1/admin/groups-manage/{self.group_a.id}/")
        self.assertEqual(res.status_code, 400)  # has an enrolled student
        res = self.api.delete(f"/api/v1/admin/groups-manage/{empty.id}/")
        self.assertEqual(res.status_code, 204)

    # ── S5: web attendance limited to enrolled students ─────────────────────
    def test_web_attendance_drops_foreign_student(self):
        self.client.force_login(self.teacher_a.admin)
        rows = [
            {"id": self.student_a.id, "status": AttendanceReport.ABSENT},
            {"id": self.student_b.id, "status": AttendanceReport.ABSENT},
        ]
        res = self.client.post(
            reverse("save_attendance"),
            {"group": self.group_a.id, "date": "2026-01-10", "student_ids": json.dumps(rows)},
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(AttendanceReport.objects.filter(student=self.student_a).exists())
        self.assertFalse(AttendanceReport.objects.filter(student=self.student_b).exists())

    # ── S6: shared settings are super-admin only ────────────────────────────
    def test_branch_admin_cannot_change_shared_settings(self):
        self.client.force_login(self.ba_user)
        self.client.post(reverse("add_course"), {"name": "Sneaky"})
        self.assertFalse(Course.objects.filter(name="Sneaky").exists())
        self.client.post(reverse("toggle_course_active", args=[self.course.id]))
        self.course.refresh_from_db()
        self.assertTrue(self.course.is_active)

        self.api.force_authenticate(user=self.ba_user)
        res = self.api.post("/api/v1/admin/courses/", {"name": "Sneaky"}, format="json")
        self.assertEqual(res.status_code, 403)

    def test_toggle_course_requires_post(self):
        self.client.force_login(self.super_user)
        self.assertEqual(
            self.client.get(reverse("toggle_course_active", args=[self.course.id])).status_code,
            405,
        )

    # ── S7: password strength ───────────────────────────────────────────────
    def test_api_change_password_rejects_weak_password(self):
        self.api.force_authenticate(user=self.student_a_user)
        res = self.api.post(
            "/api/v1/me/change-password/",
            {
                "old_password": "Pass123!",
                "new_password": "12345678",
                "confirm_password": "12345678",
            },
            format="json",
        )
        self.assertEqual(res.status_code, 400)
        self.student_a_user.refresh_from_db()
        self.assertTrue(self.student_a_user.check_password("Pass123!"))

    # ── Bug: deleting a populated branch orphaned its records ───────────────
    def test_cannot_delete_branch_with_students(self):
        self.client.force_login(self.super_user)
        self.client.post(reverse("delete_branch", args=[self.branch_b.id]))
        self.assertTrue(Branch.objects.filter(id=self.branch_b.id).exists())
