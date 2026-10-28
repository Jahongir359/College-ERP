"""School gradebook marks (plan task P2.4)."""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from main_app import branching
from main_app.models import (
    Admin,
    Branch,
    ClassSubject,
    Enrollment,
    Group,
    Mark,
    Parent,
    ParentChild,
    Session,
    Staff,
    Student,
    Subject,
    Term,
)
from main_app.school import seed_school_subjects

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
class _MarksFixture(TestCase):
    def setUp(self):
        self.today = timezone.localdate()
        self.school = Branch.objects.create(name="School", brand=Branch.BRAND_SCHOOL)
        self.other_school = Branch.objects.create(name="School 2", brand=Branch.BRAND_SCHOOL)
        self.course, _ = seed_school_subjects()
        # An academic year around today with a holiday between the two quarters.
        self.year = Session.objects.create(
            name="Year",
            start_year=self.today - timedelta(days=120),
            end_year=self.today + timedelta(days=120),
        )
        self.q1 = Term.objects.create(
            session=self.year,
            number=1,
            start_date=self.today - timedelta(days=120),
            end_date=self.today - timedelta(days=61),
        )
        self.q2 = Term.objects.create(
            session=self.year,
            number=2,
            start_date=self.today - timedelta(days=50),
            end_date=self.today + timedelta(days=120),
        )
        self.holiday = self.today - timedelta(days=55)

        self.homeroom = _teacher("home@example.com", self.school, "Nodira")
        self.maths_teacher = _teacher("maths@example.com", self.school, "Jasur")
        self.english_teacher = _teacher("english@example.com", self.school, "Laylo")
        self.outsider = _teacher("far@example.com", self.other_school)
        self.class_3a = self.make_class("3-A", self.school, self.homeroom)
        self.class_other = self.make_class("5-B", self.other_school, self.outsider)
        self.maths = self.make_subject(self.class_3a, "Matematika", self.maths_teacher)
        self.english = self.make_subject(self.class_3a, "Ingliz tili", self.english_teacher)
        self.other_maths = self.make_subject(self.class_other, "Matematika", self.outsider)

        self.aziz = _pupil("aziz@example.com", self.class_3a, "Aziz", "Karimov")
        self.bekzod = _pupil("bekzod@example.com", self.class_3a, "Bekzod", "Aliyev")
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

    def make_subject(self, group, name, teacher):
        return ClassSubject.objects.create(
            group=group, subject=Subject.objects.get(course=self.course, name=name), teacher=teacher
        )

    def mark(self, student, cs, value, day=None, kind=Mark.KIND_LESSON):
        return Mark.objects.create(
            student=student, class_subject=cs, value=value, date=day or self.today, kind=kind
        )

    def as_user(self, user):
        self.api.force_authenticate(user=_reload(user) if user else None)

    def get(self, user, **params):
        self.as_user(user)
        return self.api.get(reverse("api_school_marks"), params)

    def save(self, user, records, cs=None, day=None, **extra):
        self.as_user(user)
        body = {
            "class_subject": (cs or self.maths).pk,
            "date": str(day or self.today),
            "records": records,
            **extra,
        }
        return self.api.post(reverse("api_school_marks"), body, format="json")


class MarkAccessTests(_MarksFixture):
    """Access matrix (plan 8.2) for school/marks/."""

    def test_reading_a_class_subject(self):
        cases = [
            ("super admin", self.super_admin, self.other_maths, 200, False),
            ("admin own branch", self.branch_admin, self.maths, 200, False),
            ("admin other branch", self.branch_admin, self.other_maths, 404, None),
            ("subject teacher", self.maths_teacher.admin, self.maths, 200, True),
            ("teacher of another subject", self.english_teacher.admin, self.maths, 404, None),
            ("homeroom teacher", self.homeroom.admin, self.maths, 404, None),
            ("teacher of another branch", self.outsider.admin, self.maths, 404, None),
        ]
        for name, user, cs, expected, can_edit in cases:
            with self.subTest(name):
                res = self.get(user, class_subject=cs.pk)
                self.assertEqual(res.status_code, expected)
                if can_edit is not None:
                    self.assertEqual(res.data["can_edit"], can_edit)

    def test_anonymous_gets_401(self):
        self.assertEqual(self.get(None).status_code, 401)
        self.assertEqual(self.save(None, []).status_code, 401)

    def test_teacher_and_admin_must_name_a_class_subject(self):
        self.assertEqual(self.get(self.maths_teacher.admin).status_code, 400)
        self.assertEqual(self.get(self.branch_admin, class_subject="x").status_code, 400)

    def test_saving(self):
        cases = [
            ("subject teacher", self.maths_teacher.admin, 200),
            ("admin own branch", self.branch_admin, 403),
            ("super admin", self.super_admin, 403),
            ("teacher of another subject", self.english_teacher.admin, 404),
            ("homeroom teacher", self.homeroom.admin, 404),
            ("teacher of another branch", self.outsider.admin, 404),
            ("pupil", self.aziz.admin, 404),
            ("parent", self.parent, 404),
        ]
        for name, user, expected in cases:
            with self.subTest(name):
                res = self.save(user, [{"student_id": self.aziz.pk, "value": 5}])
                self.assertEqual(res.status_code, expected)
        self.assertEqual(Mark.objects.count(), 1)
        self.assertEqual(Mark.objects.get().given_by, self.maths_teacher)

    def test_teacher_limited_to_own_class_subject(self):
        record = [{"student_id": self.aziz.pk, "value": 5}]
        res = self.save(self.maths_teacher.admin, record, cs=self.english)
        self.assertEqual(res.status_code, 404)
        self.assertFalse(Mark.objects.exists())

    def test_old_teacher_loses_access_when_subject_changes_hands(self):
        self.maths.teacher = self.english_teacher
        self.maths.save()
        res = self.save(self.maths_teacher.admin, [{"student_id": self.aziz.pk, "value": 5}])
        self.assertEqual(res.status_code, 404)

    def test_pupil_sees_only_own_marks(self):
        self.mark(self.aziz, self.maths, 5)
        self.mark(self.bekzod, self.maths, 2)
        res = self.get(self.aziz.admin, student=self.bekzod.pk)  # ?student is ignored for pupils
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["student"]["id"], self.aziz.pk)
        values = [m["value"] for s in res.data["subjects"] for m in s["marks"]]
        self.assertEqual(values, [5])

    def test_parent_sees_only_own_child(self):
        self.mark(self.aziz, self.maths, 4)
        self.mark(self.far_pupil, self.other_maths, 3)
        res = self.get(self.parent)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["student"]["id"], self.aziz.pk)
        self.assertEqual(self.get(self.parent, student=self.aziz.pk).status_code, 200)
        for other in (self.bekzod, self.far_pupil):
            with self.subTest(other.admin.first_name):
                self.assertEqual(self.get(self.parent, student=other.pk).status_code, 404)


class MarkSavingTests(_MarksFixture):
    def test_values_outside_2_to_5_are_rejected(self):
        for value in (0, 1, 6, 10, -3, "5", 4.5, True, [5]):
            with self.subTest(value=value):
                res = self.save(
                    self.maths_teacher.admin, [{"student_id": self.aziz.pk, "value": value}]
                )
                self.assertEqual(res.status_code, 400)
                self.assertIn("0", res.data["records"])
        self.assertFalse(Mark.objects.exists())

    def test_one_bad_record_saves_nothing(self):
        res = self.save(
            self.maths_teacher.admin,
            [{"student_id": self.aziz.pk, "value": 5}, {"student_id": self.bekzod.pk, "value": 7}],
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(list(res.data["records"]), ["1"])
        self.assertFalse(Mark.objects.exists())

    def test_database_refuses_values_outside_2_to_5(self):
        for value in (1, 6):
            with self.subTest(value=value), self.assertRaises(IntegrityError):
                with transaction.atomic():
                    self.mark(self.aziz, self.maths, value)

    def test_save_update_and_remove(self):
        teacher = self.maths_teacher.admin
        res = self.save(
            teacher,
            [
                {"student_id": self.aziz.pk, "value": 5, "comment": " Yaxshi "},
                {"student_id": self.bekzod.pk, "value": 3},
            ],
        )
        self.assertEqual(res.status_code, 200)
        rows = {r["student_id"]: r["marks"] for r in res.data["students"]}
        self.assertEqual(rows[self.aziz.pk][0]["value"], 5)
        self.assertEqual(rows[self.aziz.pk][0]["comment"], "Yaxshi")
        self.assertEqual(res.data["term"]["id"], self.q2.pk)

        # Saving again changes Aziz, removes Bekzod's mark and keeps nothing extra.
        self.save(teacher, [{"student_id": self.aziz.pk, "value": 4}])
        self.save(teacher, [{"student_id": self.bekzod.pk, "value": None}])
        self.assertEqual(list(Mark.objects.values_list("student_id", "value")), [(self.aziz.pk, 4)])

    def test_a_test_mark_on_the_same_day_is_separate(self):
        teacher = self.maths_teacher.admin
        self.save(teacher, [{"student_id": self.aziz.pk, "value": 5}])
        res = self.save(teacher, [{"student_id": self.aziz.pk, "value": 3}], kind="test")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(
            sorted(Mark.objects.values_list("kind", "value")), [("lesson", 5), ("test", 3)]
        )
        self.assertEqual(self.save(teacher, [], kind="quiz").status_code, 400)

    def test_dates(self):
        teacher = self.maths_teacher.admin
        record = [{"student_id": self.aziz.pk, "value": 5}]
        cases = [
            ("future", self.today + timedelta(days=1), 400),
            ("before the year", self.year.start_year - timedelta(days=1), 400),
            ("holiday between quarters", self.holiday, 400),
            ("first quarter", self.q1.start_date, 200),
            ("bad format", "28.10.2026", 400),
        ]
        for name, day, expected in cases:
            with self.subTest(name):
                self.assertEqual(self.save(teacher, record, day=day).status_code, expected)

    def test_pupil_must_be_in_the_class(self):
        res = self.save(self.maths_teacher.admin, [{"student_id": self.far_pupil.pk, "value": 5}])
        self.assertEqual(res.status_code, 400)
        Enrollment.objects.filter(student=self.bekzod).update(is_active=False)
        res = self.save(self.maths_teacher.admin, [{"student_id": self.bekzod.pk, "value": 5}])
        self.assertEqual(res.status_code, 400)
        self.assertFalse(Mark.objects.exists())


class MarkReadingTests(_MarksFixture):
    def test_child_view_by_subject_and_quarter(self):
        self.mark(self.aziz, self.maths, 5)
        self.mark(self.aziz, self.maths, 4, day=self.today - timedelta(days=1))
        self.mark(self.aziz, self.maths, 3, day=self.q1.start_date)
        res = self.get(self.aziz.admin)
        self.assertEqual(res.data["class"]["id"], self.class_3a.pk)
        self.assertEqual(res.data["term"]["id"], self.q2.pk)
        self.assertEqual([t["number"] for t in res.data["terms"]], [1, 2])
        subjects = {s["subject"]: [m["value"] for m in s["marks"]] for s in res.data["subjects"]}
        # Every subject of the class is listed, even without marks; oldest mark first.
        self.assertEqual(subjects, {"Ingliz tili": [], "Matematika": [4, 5]})

        res = self.get(self.aziz.admin, term=self.q1.pk)
        subjects = {s["subject"]: [m["value"] for m in s["marks"]] for s in res.data["subjects"]}
        self.assertEqual(subjects["Matematika"], [3])

    def test_quarter_of_another_year_is_not_found(self):
        other_year = Session.objects.create(
            start_year=self.year.end_year + timedelta(days=1),
            end_year=self.year.end_year + timedelta(days=300),
        )
        far = Term.objects.create(
            session=other_year,
            number=1,
            start_date=other_year.start_year,
            end_date=other_year.start_year + timedelta(days=60),
        )
        self.assertEqual(self.get(self.aziz.admin, term=far.pk).status_code, 404)
        self.assertEqual(
            self.get(
                self.maths_teacher.admin, class_subject=self.maths.pk, term=far.pk
            ).status_code,
            404,
        )
        self.assertEqual(self.get(self.aziz.admin, term="q1").status_code, 400)

    def test_class_subject_view_lists_every_pupil(self):
        self.mark(self.aziz, self.maths, 5)
        self.mark(self.aziz, self.english, 2)
        res = self.get(self.branch_admin, class_subject=self.maths.pk)
        self.assertEqual(res.data["class_subject"]["subject"], "Matematika")
        rows = {r["name"]: [m["value"] for m in r["marks"]] for r in res.data["students"]}
        self.assertEqual(rows, {"Bekzod Aliyev": [], "Aziz Karimov": [5]})

    def test_pupil_without_a_class(self):
        loner = Student.objects.get(admin=_user("loner@example.com", "3"))
        res = self.get(loner.admin)
        self.assertEqual(res.status_code, 200)
        self.assertIsNone(res.data["class"])
        self.assertEqual(res.data["subjects"], [])


class FilterMarksForUserTests(_MarksFixture):
    def setUp(self):
        super().setUp()
        self.aziz_maths = self.mark(self.aziz, self.maths, 5)
        self.aziz_english = self.mark(self.aziz, self.english, 4)
        self.bekzod_maths = self.mark(self.bekzod, self.maths, 3)
        self.far_mark = self.mark(self.far_pupil, self.other_maths, 2)

    def visible(self, user):
        return set(branching.filter_marks_for_user(_reload(user), Mark.objects.all()))

    def test_each_role(self):
        everyone = {self.aziz_maths, self.aziz_english, self.bekzod_maths, self.far_mark}
        cases = [
            ("super admin", self.super_admin, everyone),
            ("branch admin", self.branch_admin, everyone - {self.far_mark}),
            ("maths teacher", self.maths_teacher.admin, {self.aziz_maths, self.bekzod_maths}),
            ("homeroom teacher", self.homeroom.admin, set()),
            ("other branch teacher", self.outsider.admin, {self.far_mark}),
            ("pupil", self.aziz.admin, {self.aziz_maths, self.aziz_english}),
            ("parent", self.parent, {self.aziz_maths, self.aziz_english}),
        ]
        for name, user, expected in cases:
            with self.subTest(name):
                self.assertEqual(self.visible(user), expected)

    def test_admin_without_branches_sees_nothing(self):
        lonely = _user("lonely@example.com", "1")
        profile = Admin.objects.get(admin=lonely)
        profile.is_super_admin = False
        profile.save()
        self.assertEqual(self.visible(lonely), set())
