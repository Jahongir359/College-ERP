"""School quarter and year grades (plan task P2.5)."""

from datetime import timedelta
from decimal import Decimal

from django.db import IntegrityError, transaction
from django.urls import reverse

from main_app import branching
from main_app.models import Enrollment, TermGrade
from main_app.school import suggested_grade

from .test_marks import _MarksFixture, _reload


class _TermGradesFixture(_MarksFixture):
    def grade(self, student, cs, value, term=None):
        return TermGrade.objects.create(student=student, class_subject=cs, term=term, value=value)

    def get(self, user, **params):
        self.as_user(user)
        return self.api.get(reverse("api_school_term_grades"), params)

    def save(self, user, records, cs=None, term=None):
        self.as_user(user)
        body = {
            "class_subject": (cs or self.maths).pk,
            "term": term if term is not None else self.q2.pk,
            "records": records,
        }
        return self.api.post(reverse("api_school_term_grades"), body, format="json")


class SuggestedGradeTests(_TermGradesFixture):
    def test_rounds_half_up(self):
        cases = [
            ([5, 4, 4], Decimal("4.33"), 4),
            ([5, 4], Decimal("4.50"), 5),
            ([3, 4], Decimal("3.50"), 4),
            ([2, 3, 2], Decimal("2.33"), 2),
            ([5], Decimal("5.00"), 5),
            ([], None, None),
            ([None, 4], Decimal("4.00"), 4),
        ]
        for values, average, grade in cases:
            with self.subTest(values=values):
                self.assertEqual(suggested_grade(values), (average, grade))


class TermGradeAccessTests(_TermGradesFixture):
    """Access matrix (plan 8.2) for school/term-grades/."""

    def test_reading_a_class_subject(self):
        cases = [
            ("super admin", self.super_admin, self.other_maths, 200, True),
            ("admin own branch", self.branch_admin, self.maths, 200, True),
            ("admin other branch", self.branch_admin, self.other_maths, 404, None),
            ("subject teacher", self.maths_teacher.admin, self.maths, 200, True),
            ("teacher of another subject", self.english_teacher.admin, self.maths, 404, None),
            ("homeroom teacher", self.homeroom.admin, self.maths, 404, None),
            ("teacher of another branch", self.outsider.admin, self.maths, 404, None),
        ]
        for name, user, cs, expected, can_edit in cases:
            with self.subTest(name):
                res = self.get(user, class_subject=cs.pk, term="year")
                self.assertEqual(res.status_code, expected)
                if can_edit is not None:
                    self.assertEqual(res.data["can_edit"], can_edit)

    def test_anonymous_gets_401(self):
        self.assertEqual(self.get(None).status_code, 401)
        self.assertEqual(self.save(None, []).status_code, 401)

    def test_saving(self):
        cases = [
            ("subject teacher", self.maths_teacher.admin, 200),
            ("admin own branch", self.branch_admin, 200),
            ("super admin", self.super_admin, 200),
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
        grade = TermGrade.objects.get()
        self.assertEqual(grade.given_by, self.super_admin)  # the last one to save

    def test_admin_of_another_branch_cannot_save(self):
        res = self.save(
            self.branch_admin,
            [{"student_id": self.far_pupil.pk, "value": 5}],
            cs=self.other_maths,
            term="year",
        )
        self.assertEqual(res.status_code, 404)
        self.assertFalse(TermGrade.objects.exists())

    def test_pupil_and_parent_see_only_own_child(self):
        self.grade(self.aziz, self.maths, 5, self.q1)
        self.grade(self.bekzod, self.maths, 2, self.q1)
        for name, user, params in [
            ("pupil", self.aziz.admin, {"student": self.bekzod.pk}),  # ignored for pupils
            ("parent", self.parent, {}),
        ]:
            with self.subTest(name):
                res = self.get(user, **params)
                self.assertEqual(res.status_code, 200)
                self.assertEqual(res.data["student"]["id"], self.aziz.pk)
                maths = next(s for s in res.data["subjects"] if s["subject"] == "Matematika")
                self.assertEqual([q["value"] for q in maths["quarters"]], [5, None])
        for other in (self.bekzod, self.far_pupil):
            with self.subTest(other=other.admin.first_name):
                self.assertEqual(self.get(self.parent, student=other.pk).status_code, 404)

    def test_filter_term_grades_for_user(self):
        mine = self.grade(self.aziz, self.maths, 5, self.q1)
        english = self.grade(self.aziz, self.english, 4, self.q1)
        far = self.grade(self.far_pupil, self.other_maths, 3)
        cases = [
            ("super admin", self.super_admin, {mine, english, far}),
            ("branch admin", self.branch_admin, {mine, english}),
            ("maths teacher", self.maths_teacher.admin, {mine}),
            ("homeroom teacher", self.homeroom.admin, set()),
            ("pupil", self.aziz.admin, {mine, english}),
            ("parent", self.parent, {mine, english}),
            ("other pupil", self.bekzod.admin, set()),
        ]
        for name, user, expected in cases:
            with self.subTest(name):
                visible = branching.filter_term_grades_for_user(
                    _reload(user), TermGrade.objects.all()
                )
                self.assertEqual(set(visible), expected)


class TermGradeSavingTests(_TermGradesFixture):
    def test_values_outside_2_to_5_are_rejected(self):
        for value in (0, 1, 6, "5", 4.5, True):
            with self.subTest(value=value):
                res = self.save(
                    self.maths_teacher.admin, [{"student_id": self.aziz.pk, "value": value}]
                )
                self.assertEqual(res.status_code, 400)
        self.assertFalse(TermGrade.objects.exists())

    def test_database_refuses_values_outside_2_to_5(self):
        for value in (1, 6):
            with self.subTest(value=value), self.assertRaises(IntegrityError):
                with transaction.atomic():
                    self.grade(self.aziz, self.maths, value, self.q1)

    def test_one_grade_per_pupil_subject_and_period(self):
        self.grade(self.aziz, self.maths, 5, self.q1)
        self.grade(self.aziz, self.maths, 4)
        for term in (self.q1, None):
            with self.subTest(term=term), self.assertRaises(IntegrityError):
                with transaction.atomic():
                    self.grade(self.aziz, self.maths, 3, term)

    def test_save_change_and_not_graded(self):
        teacher = self.maths_teacher.admin
        res = self.save(
            teacher,
            [
                {"student_id": self.aziz.pk, "value": 4},
                {"student_id": self.bekzod.pk, "value": None},
            ],
        )
        self.assertEqual(res.status_code, 200)
        rows = {r["student_id"]: r for r in res.data["students"]}
        self.assertEqual((rows[self.aziz.pk]["value"], rows[self.aziz.pk]["saved"]), (4, True))
        self.assertEqual(
            (rows[self.bekzod.pk]["value"], rows[self.bekzod.pk]["saved"]), (None, True)
        )

        self.save(teacher, [{"student_id": self.aziz.pk, "value": 5}])
        self.assertEqual(
            sorted(TermGrade.objects.values_list("student_id", "term_id", "value")),
            sorted([(self.aziz.pk, self.q2.pk, 5), (self.bekzod.pk, self.q2.pk, None)]),
        )

    def test_year_grade_is_separate_from_quarters(self):
        teacher = self.maths_teacher.admin
        self.save(teacher, [{"student_id": self.aziz.pk, "value": 4}])
        res = self.save(teacher, [{"student_id": self.aziz.pk, "value": 5}], term="year")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["term"], "year")
        self.assertEqual(
            sorted(TermGrade.objects.values_list("term_id", "value"), key=str),
            sorted([(self.q2.pk, 4), (None, 5)], key=str),
        )

    def test_bad_period_and_pupils(self):
        teacher = self.maths_teacher.admin
        record = [{"student_id": self.aziz.pk, "value": 5}]
        self.assertEqual(self.save(teacher, record, term="spring").status_code, 400)
        self.assertEqual(self.save(teacher, record, term=999999).status_code, 404)
        res = self.save(teacher, [{"student_id": self.far_pupil.pk, "value": 5}])
        self.assertEqual(res.status_code, 400)
        Enrollment.objects.filter(student=self.bekzod).update(is_active=False)
        res = self.save(teacher, [{"student_id": self.bekzod.pk, "value": 5}])
        self.assertEqual(res.status_code, 400)
        self.assertFalse(TermGrade.objects.exists())


class TermGradeSuggestionTests(_TermGradesFixture):
    def test_quarter_suggestion_from_that_quarters_marks(self):
        self.mark(self.aziz, self.maths, 5)
        self.mark(self.aziz, self.maths, 4, day=self.today - timedelta(days=1))
        self.mark(self.aziz, self.maths, 2, day=self.q1.start_date)  # another quarter
        self.mark(self.aziz, self.english, 2)  # another subject
        res = self.get(self.maths_teacher.admin, class_subject=self.maths.pk, term=self.q2.pk)
        self.assertEqual(res.status_code, 200)
        rows = {r["student_id"]: r for r in res.data["students"]}
        self.assertEqual(rows[self.aziz.pk]["marks"], [4, 5])  # oldest first
        self.assertEqual(rows[self.aziz.pk]["suggestion"], {"average": "4.50", "grade": 5})
        self.assertFalse(rows[self.aziz.pk]["saved"])
        self.assertEqual(rows[self.bekzod.pk]["suggestion"], {"average": None, "grade": None})

    def test_year_suggestion_from_quarter_grades(self):
        self.grade(self.aziz, self.maths, 5, self.q1)
        self.grade(self.aziz, self.maths, 4, self.q2)
        self.grade(self.bekzod, self.maths, None, self.q1)  # not graded is left out
        res = self.get(self.branch_admin, class_subject=self.maths.pk, term="year")
        rows = {r["student_id"]: r for r in res.data["students"]}
        self.assertEqual(rows[self.aziz.pk]["suggestion"], {"average": "4.50", "grade": 5})
        self.assertEqual([q["value"] for q in rows[self.aziz.pk]["quarters"]], [5, 4])
        self.assertEqual(rows[self.bekzod.pk]["suggestion"]["grade"], None)

    def test_parents_never_see_suggestions(self):
        self.mark(self.aziz, self.maths, 5)
        res = self.get(self.parent)
        maths = next(s for s in res.data["subjects"] if s["subject"] == "Matematika")
        self.assertEqual(set(maths), {"class_subject_id", "subject", "quarters", "year"})
        self.assertEqual([q["value"] for q in maths["quarters"]], [None, None])

    def test_teacher_needs_a_class_subject_and_period(self):
        teacher = self.maths_teacher.admin
        self.assertEqual(self.get(teacher).status_code, 400)
        self.assertEqual(self.get(teacher, class_subject=self.maths.pk).status_code, 400)
