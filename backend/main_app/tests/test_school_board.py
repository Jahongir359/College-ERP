"""School board, the School admin's home page on the web (P3.8)."""

import re
from datetime import date
from unittest import mock

from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from main_app.models import (
    Attendance,
    Branch,
    ClassSubject,
    Enrollment,
    Parent,
    ParentChild,
    Session,
    Subject,
    Term,
)

from .test_school_admin_pages import _SchoolFixture, _user

TODAY = date(2026, 10, 28)


def _today():
    return mock.patch("django.utils.timezone.localdate", return_value=TODAY)


def _count(html, name):
    match = re.search(rf'data-count="{name}">(\d+)<', html)
    return int(match.group(1)) if match else None


class SchoolBoardTests(_SchoolFixture):
    def setUp(self):
        super().setUp()
        Term.objects.create(
            session=self.year,
            number=1,
            name="1-chorak",
            start_date=date(2026, 9, 2),
            end_date=date(2026, 11, 3),
        )
        # Own branch: 7-B (homeroom Nodira) and 8-A (no homeroom teacher), 3 pupils.
        self.class_8a = self.make_class(self.school, 8, "A")
        self.subject_teacher = self.staff("sardor@example.com", "Sardor", self.school)
        ClassSubject.objects.create(
            group=self.class_8a,
            subject=Subject.objects.create(name="English", course=self.course),
            teacher=self.subject_teacher,
        )
        self.pupils = [
            self.enrol(self.student(f"kid{i}@example.com", f"Kid{i}", self.school), group)
            for i, group in enumerate([self.class_7b, self.class_7b, self.class_8a])
        ]
        # Two parents: one signed in, one never; the third pupil has none.
        self.mum = self.parent("mum@example.com", self.pupils[0])
        self.dad = self.parent("dad@example.com", self.pupils[1])
        self.mum.admin.last_login = timezone.now()
        self.mum.admin.save(update_fields=["last_login"])
        # 7-B took today's register, 8-A didn't.
        Attendance.objects.create(group=self.class_7b, date=TODAY)
        # The other School branch: one class, one pupil, one parent.
        far_teacher = self.staff("far@example.com", "Far", self.other_school)
        self.class_far.teacher = far_teacher
        self.class_far.save()
        far_kid = self.enrol(
            self.student("far-kid@example.com", "Far", self.other_school), self.class_far
        )
        self.parent("far-mum@example.com", far_kid)

    def enrol(self, student, group):
        Enrollment.objects.create(student=student, group=group, is_active=True)
        return student

    def parent(self, email, child):
        parent = Parent.objects.get(admin=_user(email, "4"))
        ParentChild.objects.create(parent=parent, student=child)
        return parent

    def board(self, user):
        self.client.force_login(user)
        with _today():
            return self.html(reverse("school_board"))

    def test_branch_admin_sees_only_their_branch(self):
        html = self.board(self.school_admin)
        self.assertEqual(_count(html, "pupils"), 3)
        self.assertEqual(_count(html, "classes"), 2)
        self.assertEqual(_count(html, "teachers"), 2)  # homeroom + subject teacher
        self.assertEqual(_count(html, "parents"), 2)
        self.assertEqual(_count(html, "never-signed-in"), 1)
        self.assertEqual(_count(html, "no-parent"), 1)
        self.assertIn("1 / 2", html)
        self.assertIn(reverse("school_class_detail", args=[self.class_8a.pk]), html)
        self.assertNotIn(reverse("school_class_detail", args=[self.class_7b.pk]), html)
        self.assertNotIn(reverse("school_class_detail", args=[self.class_far.pk]), html)
        self.assertNotIn("Far", html)
        self.assertIn("2026–2027", html)
        self.assertIn("1-chorak", html)

    def test_super_admin_sees_every_school_branch(self):
        html = self.board(self.super_admin)
        self.assertEqual(_count(html, "pupils"), 4)
        self.assertEqual(_count(html, "classes"), 3)
        self.assertEqual(_count(html, "teachers"), 3)
        self.assertEqual(_count(html, "parents"), 3)
        self.assertIn(reverse("school_class_detail", args=[self.class_far.pk]), html)

    def test_quick_links(self):
        html = self.board(self.school_admin)
        for name in ["school_classes", "school_timetable", "school_bells", "school_parents"]:
            self.assertIn(reverse(name), html)

    def test_other_roles_are_refused_and_anonymous_goes_to_login(self):
        url = reverse("school_board")
        student = self.pupils[0]
        cases = [
            (self.teacher.admin, reverse("staff_home")),
            (student.admin, reverse("student_home")),
            (self.mum.admin, "/app/"),
        ]
        for user, home in cases:
            with self.subTest(user=user.email):
                self.client.force_login(user)
                self.assertRedirects(self.client.get(url), home, fetch_redirect_response=False)
        self.client.logout()
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response["Location"])

    def test_sidebar_links_the_board_for_school_admins_only(self):
        self.client.force_login(self.school_admin)
        self.assertIn(reverse("school_board"), self.html(reverse("admin_home")))
        self.client.force_login(self.center_admin)
        self.assertNotIn(reverse("school_board"), self.html(reverse("admin_home")))


class SchoolBoardEmptyStateTests(_SchoolFixture):
    def test_no_school_branch(self):
        html = self.html_as(self.center_admin)
        self.assertIn('data-board-empty="no-school"', html)
        self.assertNotIn('data-count="pupils"', html)

    def test_no_classes(self):
        self.class_7b.delete()
        html = self.html_as(self.school_admin)
        self.assertIn('data-board-empty="no-classes"', html)
        self.assertEqual(_count(html, "classes"), 0)
        self.assertIn(reverse("school_class_add"), html)

    def test_no_current_year(self):
        Session.objects.update(
            is_current=False, start_year=date(2020, 9, 1), end_year=date(2021, 6, 30)
        )
        html = self.html_as(self.school_admin)
        self.assertIn('data-board-empty="no-year"', html)
        self.assertIn(reverse("school_years"), html)
        self.assertEqual(_count(html, "classes"), 0)

    def test_center_brand_branch_is_not_a_school(self):
        Branch.objects.filter(brand=Branch.BRAND_SCHOOL).update(brand=Branch.BRAND_CENTER)
        html = self.html_as(self.super_admin)
        self.assertIn('data-board-empty="no-school"', html)

    def html_as(self, user):
        self.client.force_login(user)
        with _today():
            return self.html(reverse("school_board"))


@override_settings(LANGUAGE_CODE="uz")
class SchoolBoardLanguageTests(_SchoolFixture):
    def test_uzbek_and_russian(self):
        for lang, title, register in [
            ("uz", "Maktab paneli", "Bugungi davomat"),
            ("ru", "Панель школы", "Журнал за сегодня"),
        ]:
            with self.subTest(lang=lang):
                self.school_admin.language = lang
                self.school_admin.save(update_fields=["language"])
                self.client.force_login(self.school_admin)
                with _today():
                    html = self.html(reverse("school_board"))
                self.assertIn(title, html)
                self.assertIn(register, html)
