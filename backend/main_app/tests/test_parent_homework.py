"""Parents read one child's homework through assignments/?student= (plan P4.4, P4.8)."""

from datetime import date

from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from main_app.models import Assignment, Enrollment, Group, Staff, Submission

from .test_parents import _OVERRIDES, _FamilyFixture, _reload, _user


@override_settings(**_OVERRIDES)
class ParentHomeworkTests(_FamilyFixture, TestCase):
    def setUp(self):
        self.make_fixture()
        self.api = APIClient()
        self.teacher_user = _user("teacher@example.com", "2", first="Gulnora", last="Karimova")
        self.teacher = Staff.objects.get(admin=self.teacher_user)
        self.class_5a = Group.objects.create(
            name="5-A",
            course=self.course,
            branch=self.school,
            kind=Group.KIND_CLASS,
            grade_level=5,
            letter="A",
            session=self.year,
        )
        # aziz is in 7-B (fixture); other is in 5-A.
        Enrollment.objects.create(student=self.other, group=self.class_5a)
        self.hw_7b = Assignment.objects.create(
            title="Read pages 10-12",
            description="Chapter 2",
            group=self.class_7b,
            due_date=date(2026, 11, 2),
            created_by=self.teacher,
        )
        self.hw_5a = Assignment.objects.create(
            title="Exercise 4",
            group=self.class_5a,
            due_date=date(2026, 11, 3),
            created_by=self.teacher,
        )
        # Aziz handed in work with a grade and a private note: none of it may reach parents.
        Submission.objects.create(
            assignment=self.hw_7b, student=self.aziz, note="my private note", grade=5
        )
        self.url = reverse("api_assignments")

    def as_user(self, user):
        self.api.force_authenticate(user=_reload(user))

    def titles(self, res):
        return [row["title"] for row in res.data["results"]]

    def test_parent_reads_own_childs_homework(self):
        self.as_user(self.parent_user)
        res = self.api.get(self.url, {"student": self.aziz.pk})
        self.assertEqual(res.status_code, 200, res.data)
        self.assertEqual(self.titles(res), ["Read pages 10-12"])

    def test_no_submission_data_or_other_pupils_leak(self):
        self.as_user(self.parent_user)
        row = self.api.get(self.url, {"student": self.aziz.pk}).data["results"][0]
        self.assertIsNone(row["status"])
        self.assertEqual(
            set(row),
            {
                "id",
                "title",
                "description",
                "group",
                "group_name",
                "subject_name",
                "due_date",
                "created_by_name",
                "created_at",
                "status",
            },
        )
        body = str(self.api.get(self.url, {"student": self.aziz.pk}).content)
        self.assertNotIn("my private note", body)
        self.assertNotIn("Exercise 4", body)

    def test_another_familys_child_is_404(self):
        self.as_user(self.parent_user)
        self.assertEqual(self.api.get(self.url, {"student": self.other.pk}).status_code, 404)

    def test_child_without_a_class_gets_an_empty_list(self):
        self.as_user(self.parent_user)
        res = self.api.get(self.url, {"student": self.malika.pk})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["results"], [])

    def test_student_param_missing_or_bad(self):
        # The child is always named: no ?student is 404 for every parent.
        for user in (self.parent_user, self.one_child_user, self.lonely_user):
            self.as_user(user)
            self.assertEqual(self.api.get(self.url).status_code, 404)
        self.as_user(self.parent_user)
        self.assertEqual(self.api.get(self.url, {"student": "x"}).status_code, 400)
        self.as_user(self.one_child_user)
        res = self.api.get(self.url, {"student": self.aziz.pk})
        self.assertEqual(self.titles(res), ["Read pages 10-12"])

    def test_parent_cannot_write(self):
        self.as_user(self.parent_user)
        res = self.api.post(
            self.url,
            {"title": "x", "group": self.class_7b.pk, "due_date": "2026-11-05"},
            format="json",
        )
        self.assertEqual(res.status_code, 403)
        detail = reverse("api_assignment_detail", args=[self.hw_7b.pk])
        self.assertEqual(self.api.get(detail).status_code, 404)
        self.assertIn(self.api.put(detail, {"title": "x"}, format="json").status_code, (403, 405))
        self.assertIn(self.api.delete(detail).status_code, (403, 405))
        submit = reverse("api_submit_assignment", args=[self.hw_7b.pk])
        self.assertEqual(self.api.post(submit, {"note": "x"}).status_code, 403)
        self.assertEqual(Assignment.objects.count(), 2)
        self.assertEqual(self.hw_7b.submission_set.count(), 1)

    def test_student_and_teacher_results_unchanged(self):
        """Regression: the parent branch leaves students' and teachers' lists as they were."""
        self.as_user(self.aziz.admin)
        res = self.api.get(self.url)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["count"], 1)
        row = dict(res.data["results"][0])
        row.pop("created_at")
        self.assertEqual(
            row,
            {
                "id": self.hw_7b.pk,
                "title": "Read pages 10-12",
                "description": "Chapter 2",
                "group": self.class_7b.pk,
                "group_name": "7-B",
                "subject_name": None,
                "due_date": "2026-11-02",
                "created_by_name": "Gulnora Karimova",
                "status": "graded",
            },
        )

        self.as_user(self.teacher_user)
        res = self.api.get(self.url)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(self.titles(res), ["Exercise 4", "Read pages 10-12"])
        self.assertEqual({row["status"] for row in res.data["results"]}, {None})
