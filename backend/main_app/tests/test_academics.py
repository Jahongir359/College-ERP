from datetime import date

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


@override_settings(**_BASE_OVERRIDES)
class AttendanceIntegrityTests(TestCase):
    """DB-level guard against duplicate per-student attendance rows."""

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

    def test_duplicate_attendance_report_rejected(self):
        from django.db import IntegrityError, transaction

        course = Course.objects.create(name="English")
        teacher = Staff.objects.get(admin=self._make_user("at@iceberg.internal", "2", "TC60001"))
        group = Group.objects.create(name="G", course=course, teacher=teacher)
        student = Student.objects.get(
            admin=self._make_user("ic60001@iceberg.internal", "3", "IC60001")
        )
        att = Attendance.objects.create(group=group, date=date(2026, 1, 10))
        AttendanceReport.objects.create(
            attendance=att, student=student, status=AttendanceReport.PRESENT
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                AttendanceReport.objects.create(
                    attendance=att, student=student, status=AttendanceReport.ABSENT
                )


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
