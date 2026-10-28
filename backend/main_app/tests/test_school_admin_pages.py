"""Maktab admin web pages: classes, their students and subjects, years and quarters (P3.1)."""

from datetime import date

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from main_app.models import (
    Admin,
    Branch,
    ClassSubject,
    Course,
    Enrollment,
    Group,
    Parent,
    ParentChild,
    Session,
    Staff,
    Student,
    Subject,
    Term,
)
from main_app.school import school_course

PASSWORD = "Pass12345!"


def _user(email, user_type, first="T", last="U"):
    return get_user_model().objects.create_user(
        email=email, password=PASSWORD, first_name=first, last_name=last, user_type=user_type
    )


@override_settings(SECURE_SSL_REDIRECT=False)
class _SchoolFixture(TestCase):
    def setUp(self):
        self.school = Branch.objects.create(name="School", brand=Branch.BRAND_SCHOOL)
        self.other_school = Branch.objects.create(name="School 2", brand=Branch.BRAND_SCHOOL)
        self.center = Branch.objects.create(name="Center")
        self.year = Session.objects.create(
            name="2026–2027",
            start_year=date(2026, 9, 1),
            end_year=date(2027, 6, 30),
            is_current=True,
        )
        self.course = school_course()
        self.super_admin = _user("boss@example.com", "1")
        self.school_admin = self.branch_admin("office@example.com", self.school)
        self.center_admin = self.branch_admin("center@example.com", self.center)
        self.teacher = self.staff("nodira@example.com", "Nodira", self.school)
        self.class_7b = self.make_class(self.school, 7, "B", teacher=self.teacher)
        self.class_far = self.make_class(self.other_school, 7, "A")

    def branch_admin(self, email, branch):
        user = _user(email, "1")
        profile = Admin.objects.get(admin=user)
        profile.is_super_admin = False
        profile.save()
        profile.branches.set([branch])
        return user

    def staff(self, email, first, branch):
        staff = Staff.objects.get(admin=_user(email, "2", first=first))
        staff.branch = branch
        staff.save()
        return staff

    def student(self, email, first, branch):
        student = Student.objects.get(admin=_user(email, "3", first=first))
        student.branch = branch
        student.save()
        return student

    def make_class(self, branch, grade, letter, teacher=None):
        return Group.objects.create(
            name=f"{grade}-{letter}",
            course=self.course,
            branch=branch,
            kind=Group.KIND_CLASS,
            grade_level=grade,
            letter=letter,
            session=self.year,
            teacher=teacher,
        )

    def html(self, url):
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        return response.content.decode()


class SchoolNavTests(_SchoolFixture):
    def test_maktab_menu_only_for_admins_with_a_school_branch(self):
        self.client.force_login(self.school_admin)
        self.assertIn(reverse("school_classes"), self.html(reverse("admin_home")))
        self.client.force_login(self.center_admin)
        self.assertNotIn(reverse("school_classes"), self.html(reverse("admin_home")))


class SchoolPageAccessTests(_SchoolFixture):
    def test_admins_see_their_branches_classes_only(self):
        self.client.force_login(self.school_admin)
        html = self.html(reverse("school_classes"))
        self.assertIn(reverse("school_class_detail", args=[self.class_7b.pk]), html)
        self.assertNotIn(reverse("school_class_detail", args=[self.class_far.pk]), html)
        far = reverse("school_class_detail", args=[self.class_far.pk])
        self.assertEqual(self.client.get(far).status_code, 404)
        self.assertEqual(
            self.client.get(reverse("school_class_edit", args=[self.class_far.pk])).status_code, 404
        )

        self.client.force_login(self.super_admin)
        html = self.html(reverse("school_classes"))
        self.assertIn(reverse("school_class_detail", args=[self.class_far.pk]), html)

    def test_other_roles_are_sent_away(self):
        urls = [
            reverse("school_classes"),
            reverse("school_class_add"),
            reverse("school_class_detail", args=[self.class_7b.pk]),
            reverse("school_years"),
        ]
        student = self.student("kid@example.com", "Aziz", self.school)
        parent = _user("mum@example.com", "4")
        cases = [
            (self.teacher.admin, reverse("staff_home")),
            (student.admin, reverse("student_home")),
            (parent, "/app/"),
        ]
        for user, home in cases:
            self.client.force_login(user)
            for url in urls:
                with self.subTest(user=user.email, url=url):
                    self.assertRedirects(self.client.get(url), home, fetch_redirect_response=False)
        self.client.logout()
        for url in urls:
            with self.subTest(user="anonymous", url=url):
                self.assertEqual(self.client.get(url).status_code, 302)
                self.assertIn("login", self.client.get(url)["Location"])

    def test_actions_need_post(self):
        self.client.force_login(self.school_admin)
        url = reverse("school_class_student_add", args=[self.class_7b.pk])
        self.assertEqual(self.client.get(url).status_code, 405)


class ClassFormPageTests(_SchoolFixture):
    def post_class(self, **data):
        payload = {
            "branch": self.school.pk,
            "session": self.year.pk,
            "grade_level": 5,
            "letter": "a",
            "teacher": self.teacher.pk,
            "course": self.course.pk,
            "room": "12",
            "capacity": 26,
            "monthly_fee": "",
        }
        payload.update(data)
        return self.client.post(reverse("school_class_add"), payload)

    def test_create_a_class(self):
        self.client.force_login(self.school_admin)
        html = self.html(reverse("school_class_add"))
        self.assertIn(f'value="{self.year.pk}" selected', html)  # current year preselected
        response = self.post_class()
        group = Group.objects.get(name="5-A")
        self.assertRedirects(response, reverse("school_class_detail", args=[group.pk]))
        self.assertEqual(group.kind, Group.KIND_CLASS)
        self.assertEqual((group.grade_level, group.letter), (5, "A"))
        self.assertEqual(group.teacher, self.teacher)

    def test_duplicate_and_wrong_branch_are_refused(self):
        self.client.force_login(self.school_admin)
        response = self.post_class(grade_level=7, letter="b")
        self.assertEqual(response.status_code, 200)
        self.assertIn("7-B", response.content.decode())
        self.assertEqual(Group.objects.filter(name="7-B", branch=self.school).count(), 1)
        for branch in (self.center, self.other_school):  # not a school / not theirs
            response = self.post_class(branch=branch.pk)
            self.assertEqual(response.status_code, 200)
        self.assertFalse(Group.objects.filter(name="5-A").exists())

    def test_edit_a_class(self):
        self.client.force_login(self.school_admin)
        other_teacher = self.staff("jasur@example.com", "Jasur", self.school)
        url = reverse("school_class_edit", args=[self.class_7b.pk])
        self.html(url)
        self.client.post(
            url,
            {
                "branch": self.school.pk,
                "session": self.year.pk,
                "grade_level": 7,
                "letter": "B",
                "teacher": other_teacher.pk,
                "course": self.course.pk,
                "capacity": 30,
            },
        )
        self.class_7b.refresh_from_db()
        self.assertEqual(self.class_7b.teacher, other_teacher)
        self.assertEqual(self.class_7b.capacity, 30)


class ClassStudentsAndSubjectsTests(_SchoolFixture):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.school_admin)
        self.detail = reverse("school_class_detail", args=[self.class_7b.pk])
        self.aziz = self.student("aziz@example.com", "Aziz", self.school)

    def test_add_and_remove_a_student(self):
        self.assertIn("Aziz", self.html(self.detail))  # offered in the picker
        url = reverse("school_class_student_add", args=[self.class_7b.pk])
        self.assertRedirects(self.client.post(url, {"student": self.aziz.pk}), self.detail)
        self.assertTrue(
            Enrollment.objects.filter(
                student=self.aziz, group=self.class_7b, is_active=True
            ).exists()
        )
        mum = Parent.objects.get(admin=_user("mum@example.com", "4"))
        ParentChild.objects.create(parent=mum, student=self.aziz)
        self.html(self.detail)

        remove = reverse("school_class_student_remove", args=[self.class_7b.pk, self.aziz.pk])
        self.client.post(remove)
        enrollment = Enrollment.objects.get(student=self.aziz, group=self.class_7b)
        self.assertFalse(enrollment.is_active)  # kept for history

        self.client.post(url, {"student": self.aziz.pk})  # back again: re-activated
        enrollment.refresh_from_db()
        self.assertTrue(enrollment.is_active)

    def test_one_class_per_year_and_branch_rules(self):
        class_7a = self.make_class(self.school, 7, "A")
        Enrollment.objects.create(student=self.aziz, group=class_7a)
        url = reverse("school_class_student_add", args=[self.class_7b.pk])
        self.client.post(url, {"student": self.aziz.pk})
        self.assertFalse(Enrollment.objects.filter(student=self.aziz, group=self.class_7b).exists())

        far_kid = self.student("far@example.com", "Far", self.other_school)
        self.client.post(url, {"student": far_kid.pk})
        self.assertFalse(Enrollment.objects.filter(student=far_kid).exists())

    def test_subjects_add_edit_remove(self):
        maths = Subject.objects.get(course=self.course, name="Matematika")
        url = reverse("school_class_subject_add", args=[self.class_7b.pk])
        self.client.post(url, {"subject": maths.pk, "teacher": self.teacher.pk, "weekly_hours": 5})
        cs = ClassSubject.objects.get(group=self.class_7b, subject=maths)
        self.assertEqual((cs.teacher, cs.weekly_hours), (self.teacher, 5))
        self.assertIn("Matematika", self.html(self.detail))

        edit = reverse("school_class_subject_edit", args=[self.class_7b.pk, cs.pk])
        self.client.post(edit, {f"cs{cs.pk}-teacher": "", f"cs{cs.pk}-weekly_hours": 4})
        cs.refresh_from_db()
        self.assertEqual((cs.teacher, cs.weekly_hours), (None, 4))
        self.client.post(edit, {f"cs{cs.pk}-teacher": "", f"cs{cs.pk}-weekly_hours": 40})
        cs.refresh_from_db()
        self.assertEqual(cs.weekly_hours, 4)

        ielts = Subject.objects.create(name="IELTS", course=Course.objects.create(name="English"))
        self.client.post(
            url, {"subject": ielts.pk, "weekly_hours": 2}
        )  # not in this class's course
        self.assertFalse(ClassSubject.objects.filter(subject=ielts).exists())

        remove = reverse("school_class_subject_remove", args=[self.class_7b.pk, cs.pk])
        self.client.post(remove)
        self.assertFalse(ClassSubject.objects.filter(pk=cs.pk).exists())


class SchoolYearPageTests(_SchoolFixture):
    def add_quarter(self, number, start, end):
        prefix = f"y{self.year.pk}"
        return self.client.post(
            reverse("school_term_add", args=[self.year.pk]),
            {
                f"{prefix}-number": number,
                f"{prefix}-name": "",
                f"{prefix}-start_date": start,
                f"{prefix}-end_date": end,
            },
        )

    def test_super_admin_manages_quarters(self):
        self.client.force_login(self.super_admin)
        self.html(reverse("school_years"))
        self.add_quarter(1, "2026-09-02", "2026-11-03")
        term = Term.objects.get(session=self.year, number=1)
        self.assertEqual(term.name, "1-chorak")
        self.add_quarter(2, "2026-11-01", "2026-12-26")  # overlaps quarter 1
        self.assertFalse(Term.objects.filter(number=2).exists())
        self.add_quarter(2, "2026-11-10", "2026-12-26")
        self.assertTrue(Term.objects.filter(number=2).exists())

        edit = reverse("school_term_edit", args=[term.pk])
        p = f"t{term.pk}"
        self.client.post(
            edit,
            {
                f"{p}-number": 1,
                f"{p}-name": "1-chorak",
                f"{p}-start_date": "2026-09-02",
                f"{p}-end_date": "2026-11-02",
            },
        )
        term.refresh_from_db()
        self.assertEqual(term.end_date, date(2026, 11, 2))

        self.client.post(reverse("school_term_delete", args=[term.pk]))
        self.assertFalse(Term.objects.filter(pk=term.pk).exists())

    def test_make_another_year_current(self):
        next_year = Session.objects.create(
            name="2027–2028", start_year=date(2027, 9, 1), end_year=date(2028, 6, 30)
        )
        self.client.force_login(self.super_admin)
        self.client.post(reverse("school_year_make_current", args=[next_year.pk]))
        self.assertEqual(Session.current(), next_year)

    def test_branch_admins_can_only_read(self):
        self.client.force_login(self.school_admin)
        html = self.html(reverse("school_years"))
        self.assertNotIn(reverse("school_term_add", args=[self.year.pk]), html)
        self.add_quarter(1, "2026-09-02", "2026-11-03")
        self.assertFalse(Term.objects.exists())
        next_year = Session.objects.create(
            name="2027–2028", start_year=date(2027, 9, 1), end_year=date(2028, 6, 30)
        )
        self.client.post(reverse("school_year_make_current", args=[next_year.pk]))
        self.assertEqual(Session.current(), self.year)


class SchoolPageTranslationTests(_SchoolFixture):
    def test_classes_page_in_russian_and_uzbek(self):
        self.client.force_login(self.school_admin)
        self.client.post(reverse("set_language"), {"language": "ru", "next": "/"})
        html = self.html(reverse("school_classes"))
        self.assertIn("Классы", html)
        self.assertIn("Классный руководитель", html)
        self.client.post(reverse("set_language"), {"language": "uz", "next": "/"})
        html = self.html(reverse("school_classes"))
        self.assertIn("Sinflar", html)
        self.assertIn("Sinf rahbari", html)
