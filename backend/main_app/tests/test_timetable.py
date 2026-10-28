"""Bell periods and the school timetable (plan task P2.1)."""

from datetime import date, time

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.forms import modelform_factory
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from main_app import branching
from main_app.models import (
    Admin,
    BellPeriod,
    Branch,
    ClassSubject,
    Course,
    Enrollment,
    Group,
    Lesson,
    LessonClashError,
    Parent,
    ParentChild,
    Session,
    Staff,
    Student,
    Subject,
)
from main_app.school import seed_school_subjects

_OVERRIDES = dict(SECURE_SSL_REDIRECT=False)

# A Monday inside the 2026–2027 academic year of the fixture.
MONDAY = date(2026, 10, 19)


def _user(email, user_type, first="T"):
    return get_user_model().objects.create_user(
        email=email, password="Pass12345!", first_name=first, last_name="U", user_type=user_type
    )


def _reload(user):
    return get_user_model().objects.get(pk=user.pk)


def _teacher(email, name, branch):
    staff = Staff.objects.get(admin=_user(email, "2", name))
    staff.branch = branch
    staff.save()
    return staff


class _TimetableFixture:
    def make_fixture(self):
        self.school = Branch.objects.create(name="School", brand=Branch.BRAND_SCHOOL)
        self.other_school = Branch.objects.create(name="School 2", brand=Branch.BRAND_SCHOOL)
        self.course, _ = seed_school_subjects()
        self.year = Session.objects.create(
            name="2026–2027", start_year=date(2026, 9, 1), end_year=date(2027, 6, 30)
        )
        self.class_7b = self.make_class("7-B", "B", self.school, room="12")
        self.class_4b = self.make_class("4-B", "B", self.school, room="8")
        self.class_other = self.make_class("5-A", "A", self.other_school, room="12")
        self.maths = Subject.objects.get(course=self.course, name="Matematika")
        self.english = Subject.objects.get(course=self.course, name="Ingliz tili")
        self.dilnoza = _teacher("dilnoza@example.com", "Dilnoza", self.school)
        self.kamola = _teacher("kamola@example.com", "Kamola", self.school)
        self.p1 = self.period(self.school, 1, time(8, 0), time(8, 45))
        self.p2 = self.period(self.school, 2, time(8, 55), time(9, 40))
        self.other_p1 = self.period(self.other_school, 1, time(8, 30), time(9, 15))
        self.maths_7b = ClassSubject.objects.create(
            group=self.class_7b, subject=self.maths, teacher=self.dilnoza
        )
        self.english_7b = ClassSubject.objects.create(
            group=self.class_7b, subject=self.english, teacher=self.kamola
        )
        self.english_4b = ClassSubject.objects.create(
            group=self.class_4b, subject=self.english, teacher=self.kamola
        )
        self.maths_other = ClassSubject.objects.create(
            group=self.class_other, subject=self.maths, teacher=self.dilnoza
        )

    def make_class(self, name, letter, branch, room=""):
        return Group.objects.create(
            name=name,
            course=self.course,
            branch=branch,
            kind=Group.KIND_CLASS,
            grade_level=int(name.split("-")[0]),
            letter=letter,
            session=self.year,
            room=room,
        )

    def period(self, branch, number, start, end):
        return BellPeriod.objects.create(
            branch=branch, number=number, start_time=start, end_time=end
        )

    def lesson(self, class_subject, weekday, period, **extra):
        lesson = Lesson(
            group=class_subject.group,
            class_subject=class_subject,
            weekday=weekday,
            period=period,
            **extra,
        )
        lesson.full_clean()
        lesson.save()
        return lesson


class BellPeriodModelTests(_TimetableFixture, TestCase):
    def setUp(self):
        self.make_fixture()

    def test_end_must_be_after_start(self):
        with self.assertRaises(ValidationError) as ctx:
            BellPeriod(
                branch=self.school, number=3, start_time=time(10, 0), end_time=time(9, 0)
            ).full_clean()
        self.assertIn("end_time", ctx.exception.message_dict)

    def test_periods_in_one_branch_must_not_overlap(self):
        with self.assertRaises(ValidationError) as ctx:
            BellPeriod(
                branch=self.school, number=3, start_time=time(8, 30), end_time=time(9, 0)
            ).full_clean()
        self.assertIn("start_time", ctx.exception.message_dict)
        # The same times are fine in another branch.
        BellPeriod(
            branch=self.other_school, number=2, start_time=time(9, 20), end_time=time(10, 0)
        ).full_clean()

    def test_number_is_unique_per_branch(self):
        with self.assertRaises(ValidationError):
            BellPeriod(
                branch=self.school, number=1, start_time=time(12, 0), end_time=time(12, 45)
            ).full_clean()

    def test_learning_center_branches_have_no_bell_periods(self):
        center = Branch.objects.create(name="Center")
        with self.assertRaises(ValidationError) as ctx:
            BellPeriod(
                branch=center, number=1, start_time=time(8, 0), end_time=time(8, 45)
            ).full_clean()
        self.assertIn("branch", ctx.exception.message_dict)


class LessonModelTests(_TimetableFixture, TestCase):
    def setUp(self):
        self.make_fixture()

    def test_valid_lesson_and_room_fallback(self):
        lesson = self.lesson(self.maths_7b, 1, self.p1)
        self.assertEqual(lesson.effective_room, "12")
        lesson.room = "Sport zali"
        self.assertEqual(lesson.effective_room, "Sport zali")

    def test_invalid_combinations(self):
        course_group = Group.objects.create(name="IELTS", course=self.course, branch=self.school)
        cases = {
            "group": dict(group=course_group, class_subject=self.maths_7b, period=self.p1),
            "class_subject": dict(group=self.class_4b, class_subject=self.maths_7b, period=self.p1),
            "period": dict(group=self.class_7b, class_subject=self.maths_7b, period=self.other_p1),
            "valid_to": dict(
                group=self.class_7b,
                class_subject=self.maths_7b,
                period=self.p1,
                valid_from=date(2026, 11, 1),
                valid_to=date(2026, 10, 1),
            ),
        }
        for field, kwargs in cases.items():
            with self.subTest(field=field), self.assertRaises(ValidationError) as ctx:
                Lesson(weekday=1, **kwargs).full_clean()
            self.assertIn(field, ctx.exception.message_dict)

    def test_weekday_must_be_monday_to_saturday(self):
        for weekday in (0, 7):
            with self.subTest(weekday=weekday), self.assertRaises(ValidationError):
                Lesson(
                    group=self.class_7b,
                    class_subject=self.maths_7b,
                    weekday=weekday,
                    period=self.p1,
                ).full_clean()

    def test_is_on_respects_weekday_valid_dates_and_year(self):
        lesson = self.lesson(
            self.maths_7b, 1, self.p1, valid_from=date(2026, 10, 1), valid_to=date(2026, 12, 31)
        )
        self.assertTrue(lesson.is_on(MONDAY))
        self.assertFalse(lesson.is_on(date(2026, 10, 20)))  # Tuesday
        self.assertFalse(lesson.is_on(date(2026, 9, 28)))  # before valid_from
        self.assertFalse(lesson.is_on(date(2027, 1, 4)))  # after valid_to
        open_ended = self.lesson(self.english_7b, 1, self.p2)
        self.assertFalse(open_ended.is_on(date(2027, 9, 6)))  # next academic year

    def test_deleting_a_used_period_is_blocked(self):
        from django.db.models import ProtectedError

        self.lesson(self.maths_7b, 1, self.p1)
        with self.assertRaises(ProtectedError):
            self.p1.delete()


class LessonClashTests(_TimetableFixture, TestCase):
    def setUp(self):
        self.make_fixture()
        self.first = self.lesson(self.maths_7b, 1, self.p1)

    def clash_kinds(self, **kwargs):
        lesson = Lesson(group=kwargs["class_subject"].group, **kwargs)
        lesson.clean_fields()
        with self.assertRaises(LessonClashError) as ctx:
            lesson.clean()  # full_clean() re-wraps it as a plain ValidationError
        return {kind for kind, _ in ctx.exception.clashes}

    def test_class_cannot_have_two_lessons_at_once(self):
        kinds = self.clash_kinds(class_subject=self.english_7b, weekday=1, period=self.p1)
        self.assertEqual(kinds, {"class", "room"})

    def test_teacher_cannot_teach_two_classes_at_once(self):
        maths_4b = ClassSubject.objects.create(
            group=self.class_4b, subject=self.maths, teacher=self.dilnoza
        )
        kinds = self.clash_kinds(class_subject=maths_4b, weekday=1, period=self.p1)
        self.assertEqual(kinds, {"teacher"})

    def test_teacher_clash_across_branches_by_time(self):
        # Other branch's period 1 is 08:30–09:15, overlapping 08:00–08:45.
        kinds = self.clash_kinds(class_subject=self.maths_other, weekday=1, period=self.other_p1)
        self.assertEqual(kinds, {"teacher"})

    def test_room_clash_only_inside_one_branch(self):
        kinds = self.clash_kinds(
            class_subject=self.english_4b, weekday=1, period=self.p1, room="12"
        )
        self.assertEqual(kinds, {"room"})
        # Room "12" in another branch is another room.
        self.maths_other.teacher = None
        self.maths_other.save()
        self.lesson(self.maths_other, 1, self.other_p1)

    def test_no_clash_on_other_day_period_or_dates(self):
        self.lesson(self.english_7b, 2, self.p1)
        self.lesson(self.english_7b, 1, self.p2)
        self.first.valid_to = date(2026, 12, 31)
        self.first.save()
        self.lesson(self.english_7b, 1, self.p1, valid_from=date(2027, 1, 1), room="Kutubxona")

    def test_editing_a_lesson_does_not_clash_with_itself(self):
        self.first.room = "Sport zali"
        self.first.full_clean()

    def test_clash_shows_as_form_error_in_django_admin(self):
        form_class = modelform_factory(Lesson, fields="__all__")
        maths_4b = ClassSubject.objects.create(
            group=self.class_4b, subject=self.maths, teacher=self.dilnoza
        )
        form = form_class(
            data={
                "group": self.class_4b.pk,
                "class_subject": maths_4b.pk,
                "weekday": 1,
                "period": self.p1.pk,
                "room": "",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("7-B", " ".join(form.non_field_errors()))


class TimetableBranchingTests(_TimetableFixture, TestCase):
    def setUp(self):
        self.make_fixture()
        self.l7b = self.lesson(self.maths_7b, 1, self.p1)
        self.l4b = self.lesson(self.english_4b, 1, self.p2)
        self.l_other = self.lesson(self.maths_other, 2, self.other_p1)

    def visible(self, user):
        return set(branching.filter_lessons_for_user(_reload(user), Lesson.objects.all()))

    def test_scope_per_role(self):
        student = Student.objects.get(admin=_user("kid@example.com", "3"))
        Enrollment.objects.create(student=student, group=self.class_7b)
        parent_user = _user("mum@example.com", "4")
        ParentChild.objects.create(parent=Parent.objects.get(admin=parent_user), student=student)
        homeroom = _teacher("home@example.com", "Home", self.school)
        self.class_4b.teacher = homeroom
        self.class_4b.save()

        # Kamola teaches English in 7-B (no lesson yet) and 4-B: she sees both classes.
        self.assertEqual(self.visible(self.kamola.admin), {self.l7b, self.l4b})
        # Dilnoza teaches maths in 7-B and in the other branch's 5-A.
        self.assertEqual(self.visible(self.dilnoza.admin), {self.l7b, self.l_other})
        self.assertEqual(self.visible(homeroom.admin), {self.l4b})
        self.assertEqual(self.visible(student.admin), {self.l7b})
        self.assertEqual(self.visible(parent_user), {self.l7b})
        self.assertEqual(self.visible(_user("stranger@example.com", "3")), set())
        self.assertEqual(self.visible(_user("p2@example.com", "4")), set())

    def test_branch_admin_sees_own_branch_only(self):
        office = _user("office@example.com", "1")
        profile = Admin.objects.get(admin=office)
        profile.is_super_admin = False
        profile.save()
        profile.branches.set([self.school])
        self.assertEqual(self.visible(office), {self.l7b, self.l4b})
        periods = branching.filter_bell_periods_for_user(_reload(office), BellPeriod.objects.all())
        self.assertEqual(set(periods), {self.p1, self.p2})
        self.assertFalse(
            branching.filter_bell_periods_for_user(
                _reload(self.kamola.admin), BellPeriod.objects.all()
            ).exists()
        )


class _ApiFixture(_TimetableFixture):
    def make_api_fixture(self):
        self.make_fixture()
        self.api = APIClient()
        self.super_admin = _user("boss@example.com", "1")
        self.branch_admin = _user("office@example.com", "1")
        profile = Admin.objects.get(admin=self.branch_admin)
        profile.is_super_admin = False
        profile.save()
        profile.branches.set([self.school])

    def as_user(self, user):
        self.api.force_authenticate(user=_reload(user))


@override_settings(**_OVERRIDES)
class BellPeriodApiTests(_ApiFixture, TestCase):
    def setUp(self):
        self.make_api_fixture()

    def test_branch_admin_manages_periods(self):
        self.as_user(self.branch_admin)
        url = reverse("api_admin_bell_periods")
        res = self.api.post(
            url,
            {"branch_id": self.school.pk, "number": 3, "start_time": "09:50", "end_time": "10:35"},
            format="json",
        )
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(res.data["start_time"], "09:50")
        res = self.api.get(url)
        self.assertEqual([p["number"] for p in res.data], [1, 2, 3])

        detail = reverse("api_admin_bell_period_detail", args=[res.data[2]["id"]])
        res = self.api.patch(detail, {"end_time": "10:30"}, format="json")
        self.assertEqual(res.status_code, 200, res.data)
        self.assertEqual(res.data["end_time"], "10:30")
        self.assertEqual(self.api.delete(detail).status_code, 204)

    def test_validation(self):
        self.as_user(self.branch_admin)
        url = reverse("api_admin_bell_periods")
        for body in (
            {"number": 3, "start_time": "25:00", "end_time": "10:00"},
            {"number": 3, "start_time": "08:30", "end_time": "09:00"},  # overlaps period 1
            {"number": 1, "start_time": "12:00", "end_time": "12:45"},  # number taken
        ):
            with self.subTest(body=body):
                res = self.api.post(url, {"branch_id": self.school.pk, **body}, format="json")
                self.assertEqual(res.status_code, 400)

    def test_period_in_use_cannot_be_deleted(self):
        self.lesson(self.maths_7b, 1, self.p1)
        self.as_user(self.branch_admin)
        res = self.api.delete(reverse("api_admin_bell_period_detail", args=[self.p1.pk]))
        self.assertEqual(res.status_code, 400)

    def test_access(self):
        self.as_user(self.branch_admin)
        res = self.api.get(reverse("api_admin_bell_periods"))
        self.assertEqual({p["id"] for p in res.data}, {self.p1.pk, self.p2.pk})
        other = reverse("api_admin_bell_period_detail", args=[self.other_p1.pk])
        self.assertEqual(self.api.get(other).status_code, 404)
        res = self.api.post(
            reverse("api_admin_bell_periods"),
            {
                "branch_id": self.other_school.pk,
                "number": 5,
                "start_time": "13:00",
                "end_time": "13:45",
            },
            format="json",
        )
        self.assertEqual(res.status_code, 404)

        self.api.force_authenticate(user=None)
        self.assertEqual(self.api.get(reverse("api_admin_bell_periods")).status_code, 401)
        for user in (
            self.dilnoza.admin,
            _user("kid@example.com", "3"),
            _user("p@example.com", "4"),
        ):
            with self.subTest(user=user.email):
                self.as_user(user)
                self.assertEqual(self.api.get(reverse("api_admin_bell_periods")).status_code, 403)


@override_settings(**_OVERRIDES)
class LessonApiTests(_ApiFixture, TestCase):
    def setUp(self):
        self.make_api_fixture()

    def list_url(self, group):
        return reverse("api_admin_class_lessons", args=[group.pk])

    def test_branch_admin_adds_lists_updates_and_removes(self):
        self.as_user(self.branch_admin)
        res = self.api.post(
            self.list_url(self.class_7b),
            {"class_subject_id": self.maths_7b.pk, "weekday": 1, "period_id": self.p1.pk},
            format="json",
        )
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(res.data["subject_name"], "Matematika")
        self.assertEqual(res.data["teacher_name"], "Dilnoza U")
        self.assertEqual(res.data["room"], "")
        self.assertEqual(res.data["class_room"], "12")
        lesson_id = res.data["id"]

        res = self.api.get(self.list_url(self.class_7b))
        self.assertEqual([r["id"] for r in res.data], [lesson_id])

        detail = reverse("api_admin_lesson_detail", args=[lesson_id])
        res = self.api.patch(
            detail, {"period_id": self.p2.pk, "room": "Kutubxona", "valid_to": "2026-12-31"}
        )
        self.assertEqual(res.status_code, 200, res.data)
        self.assertEqual(res.data["period"]["number"], 2)
        self.assertEqual(res.data["room"], "Kutubxona")
        self.assertEqual(str(res.data["valid_to"]), "2026-12-31")
        self.assertEqual(self.api.delete(detail).status_code, 204)

    def test_clash_is_reported_with_details(self):
        self.lesson(self.english_7b, 1, self.p1)
        self.as_user(self.branch_admin)
        res = self.api.post(
            self.list_url(self.class_4b),
            {"class_subject_id": self.english_4b.pk, "weekday": 1, "period_id": self.p1.pk},
            format="json",
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(
            [(c["kind"], c["class_name"]) for c in res.data["clashes"]], [("teacher", "7-B")]
        )
        self.assertIn("7-B", res.data["detail"])

    def test_validation(self):
        self.as_user(self.branch_admin)
        url = self.list_url(self.class_7b)
        base = {"class_subject_id": self.maths_7b.pk, "weekday": 1, "period_id": self.p1.pk}
        cases = [
            ({**base, "weekday": 7}, 400),
            ({**base, "valid_from": "not-a-date"}, 400),
            ({k: v for k, v in base.items() if k != "period_id"}, 400),
            ({**base, "class_subject_id": self.english_4b.pk}, 404),  # subject of another class
            ({**base, "period_id": self.other_p1.pk}, 404),  # period of another branch
        ]
        for body, expected in cases:
            with self.subTest(body=body):
                self.assertEqual(self.api.post(url, body, format="json").status_code, expected)

    def test_access(self):
        lesson = self.lesson(self.maths_other, 1, self.other_p1)
        self.as_user(self.branch_admin)
        self.assertEqual(self.api.get(self.list_url(self.class_other)).status_code, 404)
        detail = reverse("api_admin_lesson_detail", args=[lesson.pk])
        self.assertEqual(self.api.get(detail).status_code, 404)
        self.assertEqual(self.api.patch(detail, {"room": "1"}).status_code, 404)
        self.assertEqual(self.api.delete(detail).status_code, 404)

        self.as_user(self.super_admin)
        self.assertEqual(self.api.get(detail).status_code, 200)

        self.api.force_authenticate(user=None)
        self.assertEqual(self.api.get(self.list_url(self.class_7b)).status_code, 401)
        for user in (
            self.dilnoza.admin,
            _user("kid@example.com", "3"),
            _user("p@example.com", "4"),
        ):
            with self.subTest(user=user.email):
                self.as_user(user)
                self.assertEqual(self.api.get(self.list_url(self.class_7b)).status_code, 403)


@override_settings(**_OVERRIDES)
class TimetableApiTests(_ApiFixture, TestCase):
    """Access matrix (plan 8.2) and week contents for school/timetable/."""

    def setUp(self):
        self.make_api_fixture()
        self.l_7b_mon = self.lesson(self.maths_7b, 1, self.p2)
        self.l_7b_mon_early = self.lesson(self.english_7b, 1, self.p1, room="Kutubxona")
        self.l_4b = self.lesson(self.english_4b, 2, self.p1)
        self.l_other = self.lesson(self.maths_other, 3, self.other_p1)

        self.student = Student.objects.get(admin=_user("kid@example.com", "3", "Aziza"))
        Enrollment.objects.create(student=self.student, group=self.class_7b)
        self.other_student = Student.objects.get(admin=_user("kid2@example.com", "3"))
        Enrollment.objects.create(student=self.other_student, group=self.class_4b)
        self.parent = _user("mum@example.com", "4")
        ParentChild.objects.create(
            parent=Parent.objects.get(admin=self.parent), student=self.student
        )

    def get(self, user, **params):
        if user is None:
            self.api.force_authenticate(user=None)
        else:
            self.as_user(user)
        params.setdefault("date", MONDAY.isoformat())
        return self.api.get(reverse("api_school_timetable"), params)

    @staticmethod
    def lesson_ids(res):
        return {lesson["id"] for day in res.data["days"] for lesson in day["lessons"]}

    def test_access_matrix(self):
        mine = {self.l_7b_mon.pk, self.l_7b_mon_early.pk}
        cases = [
            ("admin own branch", self.branch_admin, {"class": self.class_7b.pk}, 200, mine),
            ("admin other branch", self.branch_admin, {"class": self.class_other.pk}, 404, None),
            ("admin without class", self.branch_admin, {}, 400, None),
            (
                "super admin",
                self.super_admin,
                {"class": self.class_other.pk},
                200,
                {self.l_other.pk},
            ),
            (
                "teacher own class",
                self.kamola.admin,
                {"class": self.class_4b.pk},
                200,
                {self.l_4b.pk},
            ),
            ("teacher other class", self.kamola.admin, {"class": self.class_other.pk}, 404, None),
            ("student self", self.student.admin, {}, 200, mine),
            (
                "student asks other class",
                self.student.admin,
                {"class": self.class_4b.pk},
                200,
                mine,
            ),
            ("parent own child", self.parent, {"student": self.student.pk}, 200, mine),
            ("parent other child", self.parent, {"student": self.other_student.pk}, 404, None),
            ("anonymous", None, {}, 401, None),
        ]
        for name, user, params, expected, lessons in cases:
            with self.subTest(name):
                res = self.get(user, **params)
                self.assertEqual(res.status_code, expected, res.data)
                if lessons is not None:
                    self.assertEqual(self.lesson_ids(res), lessons)

    def test_teacher_default_is_own_lessons_in_all_classes(self):
        res = self.get(self.kamola.admin)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(self.lesson_ids(res), {self.l_7b_mon_early.pk, self.l_4b.pk})
        self.assertIsNone(res.data["class"])
        res = self.get(self.dilnoza.admin)
        self.assertEqual(self.lesson_ids(res), {self.l_7b_mon.pk, self.l_other.pk})

    def test_week_shape_order_and_room(self):
        res = self.get(self.student.admin, date="2026-10-22")  # a Thursday
        self.assertEqual(str(res.data["week_start"]), "2026-10-19")
        self.assertEqual(str(res.data["week_end"]), "2026-10-24")
        self.assertEqual(res.data["class"]["name"], "7-B")
        self.assertEqual([d["weekday"] for d in res.data["days"]], [1, 2, 3, 4, 5, 6])
        monday = res.data["days"][0]["lessons"]
        self.assertEqual([lesson["period"]["number"] for lesson in monday], [1, 2])
        self.assertEqual(monday[0]["room"], "Kutubxona")
        self.assertEqual(monday[1]["room"], "12")
        self.assertEqual(monday[1]["period"]["start_time"], "08:55")
        self.assertEqual(monday[1]["teacher_name"], "Dilnoza U")

    def test_valid_dates_and_academic_year(self):
        self.l_7b_mon.valid_to = date(2026, 10, 18)
        self.l_7b_mon.save()
        res = self.get(self.student.admin)
        self.assertEqual(self.lesson_ids(res), {self.l_7b_mon_early.pk})
        res = self.get(self.student.admin, date="2027-09-06")  # next academic year
        self.assertEqual(self.lesson_ids(res), set())

    def test_bad_date_and_parent_child_choice(self):
        self.assertEqual(self.get(self.student.admin, date="19-10-2026").status_code, 400)
        # With one child the parent may leave ?student= out.
        self.assertEqual(self.get(self.parent).status_code, 200)
        ParentChild.objects.create(
            parent=Parent.objects.get(admin=self.parent), student=self.other_student
        )
        self.assertEqual(self.get(self.parent).status_code, 400)
        res = self.get(self.parent, student=self.other_student.pk)
        self.assertEqual(self.lesson_ids(res), {self.l_4b.pk})

    def test_learning_center_student_gets_an_empty_week(self):
        center = Branch.objects.create(name="Center")
        ielts = Group.objects.create(
            name="IELTS", course=Course.objects.create(name="IELTS"), branch=center
        )
        lc_student = Student.objects.get(admin=_user("lc@example.com", "3"))
        Enrollment.objects.create(student=lc_student, group=ielts)
        res = self.get(lc_student.admin)
        self.assertEqual(res.status_code, 200)
        self.assertIsNone(res.data["class"])
        self.assertEqual(self.lesson_ids(res), set())
