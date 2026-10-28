"""School daily register (plan task P2.2)."""

from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from main_app import branching
from main_app.models import (
    Admin,
    Attendance,
    AttendanceReport,
    Branch,
    ClassSubject,
    Enrollment,
    Group,
    Parent,
    ParentChild,
    Session,
    Staff,
    Student,
    Subject,
)
from main_app.school import register_summaries, seed_school_subjects

_OVERRIDES = dict(SECURE_SSL_REDIRECT=False)


def _user(email, user_type, first="T", last="U"):
    return get_user_model().objects.create_user(
        email=email, password="Pass12345!", first_name=first, last_name=last, user_type=user_type
    )


def _reload(user):
    return get_user_model().objects.get(pk=user.pk)


def _teacher(email, branch, first="T"):
    staff = Staff.objects.get(admin=_user(email, "2", first))
    staff.branch = branch
    staff.save()
    return staff


def _pupil(email, group, first, last):
    student = Student.objects.get(admin=_user(email, "3", first, last))
    Enrollment.objects.create(student=student, group=group)
    return student


@override_settings(**_OVERRIDES)
class _RegisterFixture(TestCase):
    def setUp(self):
        self.today = timezone.localdate()
        self.school = Branch.objects.create(name="School", brand=Branch.BRAND_SCHOOL)
        self.other_school = Branch.objects.create(name="School 2", brand=Branch.BRAND_SCHOOL)
        self.course, _ = seed_school_subjects()
        # An academic year around today, so "today" is always a valid register day.
        self.year = Session.objects.create(
            name="Year",
            start_year=self.today - timedelta(days=120),
            end_year=self.today + timedelta(days=120),
        )
        self.homeroom = _teacher("home@example.com", self.school, "Nodira")
        self.subject_teacher = _teacher("maths@example.com", self.school, "Jasur")
        self.outsider = _teacher("far@example.com", self.other_school)
        self.class_3a = self.make_class("3-A", self.school, self.homeroom)
        self.class_other = self.make_class("5-B", self.other_school, self.outsider)
        ClassSubject.objects.create(
            group=self.class_3a,
            subject=Subject.objects.get(course=self.course, name="Matematika"),
            teacher=self.subject_teacher,
        )
        self.aziz = _pupil("aziz@example.com", self.class_3a, "Aziz", "Karimov")
        self.bekzod = _pupil("bekzod@example.com", self.class_3a, "Bekzod", "Aliyev")
        self.madina = _pupil("madina@example.com", self.class_3a, "Madina", "Rasulova")
        self.far_pupil = _pupil("farpupil@example.com", self.class_other, "Kamola", "Yoqubova")
        self.parent = _user("mum@example.com", "4")
        ParentChild.objects.create(parent=Parent.objects.get(admin=self.parent), student=self.aziz)

        self.super_admin = _user("boss@example.com", "1")
        self.branch_admin = _user("office@example.com", "1")
        profile = Admin.objects.get(admin=self.branch_admin)
        profile.is_super_admin = False
        profile.save()
        profile.branches.set([self.school])
        self.api = APIClient()

    def make_class(self, name, branch, teacher):
        return Group.objects.create(
            name=name,
            course=self.course,
            branch=branch,
            teacher=teacher,
            kind=Group.KIND_CLASS,
            grade_level=int(name.split("-")[0]),
            letter=name.split("-")[1],
            session=self.year,
        )

    def url(self, group=None, day=None):
        group = group or self.class_3a
        return reverse("api_school_register", args=[group.pk, str(day or self.today)])

    def as_user(self, user):
        if user is None:
            self.api.force_authenticate(user=None)
        else:
            self.api.force_authenticate(user=_reload(user))

    def save(self, user, records, **kwargs):
        self.as_user(user)
        return self.api.post(self.url(**kwargs), {"records": records}, format="json")


class RegisterAccessTests(_RegisterFixture):
    """Access matrix (plan 8.2) for school/register/."""

    def test_reading(self):
        cases = [
            ("super admin", self.super_admin, self.class_other, 200, False),
            ("admin own branch", self.branch_admin, self.class_3a, 200, False),
            ("admin other branch", self.branch_admin, self.class_other, 404, None),
            ("homeroom teacher", self.homeroom.admin, self.class_3a, 200, True),
            ("subject teacher", self.subject_teacher.admin, self.class_3a, 200, False),
            ("teacher of another class", self.outsider.admin, self.class_3a, 404, None),
            ("pupil of the class", self.aziz.admin, self.class_3a, 404, None),
            ("parent of a pupil", self.parent, self.class_3a, 404, None),
            ("anonymous", None, self.class_3a, 401, None),
        ]
        for name, user, group, expected, can_edit in cases:
            with self.subTest(name):
                self.as_user(user)
                res = self.api.get(self.url(group))
                self.assertEqual(res.status_code, expected)
                if can_edit is not None:
                    self.assertEqual(res.data["can_edit"], can_edit)

    def test_saving_is_for_the_homeroom_teacher_only(self):
        cases = [
            ("homeroom teacher", self.homeroom.admin, 200),
            ("subject teacher", self.subject_teacher.admin, 403),
            ("admin own branch", self.branch_admin, 403),
            ("super admin", self.super_admin, 403),
            ("teacher of another class", self.outsider.admin, 404),
            ("pupil", self.aziz.admin, 404),
            ("parent", self.parent, 404),
            ("anonymous", None, 401),
        ]
        for name, user, expected in cases:
            with self.subTest(name):
                self.assertEqual(self.save(user, []).status_code, expected)
        self.assertEqual(Attendance.objects.count(), 1)

    def test_course_groups_have_no_register(self):
        ielts = Group.objects.create(name="IELTS", course=self.course, branch=self.school)
        self.as_user(self.super_admin)
        self.assertEqual(self.api.get(self.url(ielts)).status_code, 404)
        self.assertFalse(branching.user_can_take_register(self.homeroom.admin, ielts))


class RegisterFlowTests(_RegisterFixture):
    def test_everyone_is_present_until_saved(self):
        self.as_user(self.homeroom.admin)
        res = self.api.get(self.url())
        self.assertFalse(res.data["taken"])
        self.assertEqual(res.data["counts"], {"present": 3, "late": 0, "absent": 0})
        self.assertEqual(
            [(s["name"], s["status"], s["saved"]) for s in res.data["students"]],
            [
                ("Bekzod Aliyev", "present", False),
                ("Aziz Karimov", "present", False),
                ("Madina Rasulova", "present", False),
            ],
        )
        self.assertEqual(res.data["students"][0]["initials"], "AB")

    def test_save_late_and_absent_others_present(self):
        res = self.save(
            self.homeroom.admin,
            [
                {"student_id": self.bekzod.pk, "status": "late", "arrival_time": "08:12"},
                {"student_id": self.madina.pk, "status": "absent", "note": "Kasal"},
            ],
        )
        self.assertEqual(res.status_code, 200, res.data)
        self.assertTrue(res.data["taken"])
        self.assertEqual(res.data["taken_by"], "Nodira U")
        self.assertEqual(res.data["counts"], {"present": 1, "late": 1, "absent": 1})
        by_id = {s["student_id"]: s for s in res.data["students"]}
        self.assertEqual(by_id[self.bekzod.pk]["arrival_time"], "08:12")
        self.assertEqual(by_id[self.madina.pk]["note"], "Kasal")
        self.assertEqual(by_id[self.aziz.pk]["status"], "present")
        self.assertTrue(all(s["saved"] for s in res.data["students"]))

    def test_saving_again_replaces_the_day_and_keeps_one_register(self):
        self.save(self.homeroom.admin, [{"student_id": self.aziz.pk, "status": "absent"}])
        res = self.save(
            self.homeroom.admin,
            [{"student_id": self.aziz.pk, "status": "present", "arrival_time": "08:30"}],
        )
        self.assertEqual(res.data["counts"], {"present": 3, "late": 0, "absent": 0})
        report = AttendanceReport.objects.get(student=self.aziz)
        self.assertEqual(report.status, AttendanceReport.PRESENT)
        self.assertIsNone(report.arrival_time)  # only late pupils keep an arrival time
        self.assertEqual(Attendance.objects.filter(group=self.class_3a).count(), 1)
        self.assertEqual(AttendanceReport.objects.count(), 3)

    def test_pupil_who_left_the_class_drops_off_a_resaved_register(self):
        self.save(self.homeroom.admin, [])
        Enrollment.objects.filter(student=self.madina).update(is_active=False)
        res = self.save(self.homeroom.admin, [])
        self.assertEqual(len(res.data["students"]), 2)
        self.assertFalse(AttendanceReport.objects.filter(student=self.madina).exists())

    def test_validation(self):
        base = {"student_id": self.aziz.pk, "status": "late", "arrival_time": "08:12"}
        cases = [
            ("bad status", [{**base, "status": "sick"}], {}),
            ("bad time", [{**base, "arrival_time": "8 o'clock"}], {}),
            ("pupil of another class", [{**base, "student_id": self.far_pupil.pk}], {}),
            ("note too long", [{**base, "note": "x" * 201}], {}),
            ("not a list", "everyone", {}),
            ("future date", [], {"day": self.today + timedelta(days=1)}),
            ("outside the year", [], {"day": self.year.start_year - timedelta(days=1)}),
        ]
        for name, records, kwargs in cases:
            with self.subTest(name):
                self.as_user(self.homeroom.admin)
                res = self.api.post(self.url(**kwargs), {"records": records}, format="json")
                self.assertEqual(res.status_code, 400, res.data)
        self.as_user(self.homeroom.admin)
        bad_day = reverse("api_school_register", args=[self.class_3a.pk, "24-10-2026"])
        self.assertEqual(self.api.get(bad_day).status_code, 400)
        self.assertFalse(Attendance.objects.exists())

    def test_past_day_can_be_corrected(self):
        yesterday = self.today - timedelta(days=1)
        res = self.save(self.homeroom.admin, [], day=yesterday)
        self.assertEqual(res.status_code, 200, res.data)
        self.as_user(self.homeroom.admin)
        self.assertTrue(self.api.get(self.url(day=yesterday)).data["can_edit"])

    def test_family_sees_arrival_time_and_note_for_their_child(self):
        self.save(
            self.homeroom.admin,
            [
                {
                    "student_id": self.aziz.pk,
                    "status": "late",
                    "arrival_time": "08:12",
                    "note": "Avtobus",
                }
            ],
        )
        self.as_user(self.parent)
        res = self.api.get(reverse("api_attendance"))
        self.assertEqual(res.status_code, 200)
        row = res.data["results"][0]
        self.assertEqual((row["status"], row["arrival_time"], row["note"]), (2, "08:12", "Avtobus"))


class RegisterSummaryTests(_RegisterFixture):
    def test_summary_per_class_for_the_classes_page(self):
        self.save(self.homeroom.admin, [{"student_id": self.aziz.pk, "status": "absent"}])
        classes = branching.filter_classes_for_user(_reload(self.super_admin), Group.objects.all())
        summary = register_summaries(classes, self.today)
        self.assertEqual(
            summary[self.class_3a.pk], {"taken": True, "present": 2, "late": 0, "absent": 1}
        )
        self.assertEqual(
            summary[self.class_other.pk], {"taken": False, "present": 0, "late": 0, "absent": 0}
        )
        other_day = register_summaries(classes, date(2000, 1, 3))
        self.assertFalse(other_day[self.class_3a.pk]["taken"])
