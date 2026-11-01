"""Web admin audit fixes (2026-10-31): B1 branch on new students and teachers,
M1 teachers on the group form, and the class page minors."""

from django.urls import reverse

from main_app.models import Admin, Enrollment, Group, Staff, Student

from .test_school_admin_pages import _SchoolFixture, _user


def _person(**extra):
    data = {
        "first_name": "Test",
        "last_name": "Person",
        "gender": "M",
        "date_of_birth": "2012-05-05",
        "address": "Chilonzor 9",
        "password": "Strong-Pass-2026!",
    }
    data.update(extra)
    return data


class _Fixture(_SchoolFixture):
    def setUp(self):
        super().setUp()
        self.multi_admin = _user("multi@example.com", "1")
        profile = Admin.objects.get(admin=self.multi_admin)
        profile.is_super_admin = False
        profile.save()
        profile.branches.set([self.school, self.center])

    def add_student(self, user, **extra):
        self.client.force_login(user)
        data = _person(course=self.course.pk, status=Student.STATUS_ACTIVE, **extra)
        return self.client.post(reverse("add_student"), data)

    def add_staff(self, user, **extra):
        self.client.force_login(user)
        return self.client.post(reverse("add_staff"), _person(course=self.course.pk, **extra))

    def newest_student(self):
        return Student.objects.order_by("-pk").first()

    def newest_staff(self):
        return Staff.objects.order_by("-pk").first()


class NewStudentBranchTests(_Fixture):
    def test_branch_admin_with_one_branch_gets_it_and_sees_the_student(self):
        before = Student.objects.count()
        res = self.add_student(self.school_admin)  # no branch in the POST, as the old page sent
        self.assertRedirects(res, reverse("add_student"), fetch_redirect_response=False)
        self.assertEqual(Student.objects.count(), before + 1)
        student = self.newest_student()
        self.assertEqual(student.branch, self.school)
        listed = self.client.get(reverse("manage_student"))
        self.assertContains(listed, student.admin.login_id)

    def test_forged_branch_is_ignored_for_a_one_branch_admin(self):
        res = self.add_student(self.school_admin, branch=self.center.pk)
        self.assertEqual(res.status_code, 302)
        self.assertEqual(self.newest_student().branch, self.school)

    def test_admin_of_several_branches_must_choose_one_of_theirs(self):
        before = Student.objects.count()
        res = self.add_student(self.multi_admin)
        self.assertEqual(res.status_code, 200)
        self.assertFormError(res.context["form"], "branch", "Choose a branch.")
        res = self.add_student(self.multi_admin, branch=self.other_school.pk)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.context["form"].errors["branch"])
        self.assertEqual(Student.objects.count(), before)
        self.add_student(self.multi_admin, branch=self.center.pk)
        self.assertEqual(self.newest_student().branch, self.center)

    def test_super_admin_must_choose(self):
        before = Student.objects.count()
        res = self.add_student(self.super_admin)
        self.assertEqual(res.status_code, 200)
        self.assertFormError(res.context["form"], "branch", "Choose a branch.")
        self.assertEqual(Student.objects.count(), before)
        self.add_student(self.super_admin, branch=self.other_school.pk)
        self.assertEqual(self.newest_student().branch, self.other_school)

    def test_the_page_shows_the_branch_field(self):
        self.client.force_login(self.multi_admin)
        html = self.html(reverse("add_student"))
        self.assertIn('name="branch"', html)
        self.assertIn(">School<", html)
        self.assertNotIn(">School 2<", html)


class NewTeacherBranchTests(_Fixture):
    def test_branch_admin_with_one_branch_gets_it_and_sees_the_teacher(self):
        res = self.add_staff(self.school_admin)
        self.assertRedirects(res, reverse("add_staff"), fetch_redirect_response=False)
        staff = self.newest_staff()
        self.assertEqual(staff.branch, self.school)
        listed = self.client.get(reverse("manage_staff"))
        self.assertContains(listed, staff.admin.login_id)

    def test_forged_branch_is_ignored_and_super_admin_must_choose(self):
        self.add_staff(self.school_admin, branch=self.center.pk)
        self.assertEqual(self.newest_staff().branch, self.school)
        before = Staff.objects.count()
        res = self.add_staff(self.super_admin)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(Staff.objects.count(), before)
        res = self.add_staff(self.multi_admin, branch=self.other_school.pk)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(Staff.objects.count(), before)


class EditKeepsTheBranchTests(_Fixture):
    def edit_student_data(self, student, **extra):
        return _person(
            first_name=student.admin.first_name,
            course=self.course.pk,
            status=Student.STATUS_ACTIVE,
            password="",
            **extra,
        )

    def test_branch_admin_cannot_clear_or_move_a_student(self):
        student = self.student("pupil@example.com", "Aziz", self.school)
        self.client.force_login(self.school_admin)
        url = reverse("edit_student", args=[student.pk])
        for data in [
            self.edit_student_data(student),  # branch left out
            self.edit_student_data(student, branch=self.center.pk),  # forged
        ]:
            res = self.client.post(url, data)
            self.assertRedirects(res, url, fetch_redirect_response=False)
        student.refresh_from_db()
        self.assertEqual(student.branch, self.school)

    def test_several_branch_admin_cannot_clear_or_escape(self):
        student = self.student("pupil@example.com", "Aziz", self.school)
        self.client.force_login(self.multi_admin)
        url = reverse("edit_student", args=[student.pk])
        res = self.client.post(url, self.edit_student_data(student, branch=""))
        self.assertEqual(res.status_code, 200)
        res = self.client.post(url, self.edit_student_data(student, branch=self.other_school.pk))
        self.assertEqual(res.status_code, 200)
        student.refresh_from_db()
        self.assertEqual(student.branch, self.school)
        res = self.client.post(url, self.edit_student_data(student, branch=self.center.pk))
        self.assertRedirects(res, url, fetch_redirect_response=False)
        student.refresh_from_db()
        self.assertEqual(student.branch, self.center)

    def test_teacher_edit_keeps_the_branch(self):
        self.client.force_login(self.school_admin)
        url = reverse("edit_staff", args=[self.teacher.pk])
        data = _person(first_name="Nodira", course=self.course.pk, password="")
        for post in [data, {**data, "branch": self.center.pk}]:
            res = self.client.post(url, post)
            self.assertRedirects(res, url, fetch_redirect_response=False)
        self.teacher.refresh_from_db()
        self.assertEqual(self.teacher.branch, self.school)


class GroupTeacherScopeTests(_Fixture):
    def group_data(self, **extra):
        data = {
            "name": "QA cross-branch",
            "course": self.course.pk,
            "capacity": 12,
            "schedule": "Mon 10:00",
            "room": "1",
        }
        data.update(extra)
        return data

    def test_center_admin_sees_and_assigns_only_their_teachers(self):
        center_teacher = self.staff("center-t@example.com", "Laylo", self.center)
        self.client.force_login(self.center_admin)
        html = self.html(reverse("add_group"))
        self.assertIn("Laylo", html)
        self.assertNotIn("Nodira", html)  # the School teacher

        res = self.client.post(reverse("add_group"), self.group_data(teacher=self.teacher.pk))
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.context["form"].errors["teacher"])
        self.assertFalse(Group.objects.filter(name="QA cross-branch").exists())

        self.client.post(reverse("add_group"), self.group_data(teacher=center_teacher.pk))
        group = Group.objects.get(name="QA cross-branch")
        self.assertEqual((group.teacher, group.branch), (center_teacher, self.center))

    def test_edit_keeps_the_current_teacher_but_refuses_a_new_foreign_one(self):
        center_teacher = self.staff("center-t@example.com", "Laylo", self.center)
        group = Group.objects.create(
            name="Old", course=self.course, branch=self.center, teacher=center_teacher
        )
        self.client.force_login(self.center_admin)
        url = reverse("edit_group", args=[group.pk])
        res = self.client.post(url, self.group_data(name="Old", teacher=self.teacher.pk))
        self.assertEqual(res.status_code, 200)
        group.refresh_from_db()
        self.assertEqual(group.teacher, center_teacher)


class ClassPageMinorTests(_Fixture):
    def test_pupil_already_in_a_class_gets_a_clear_message(self):
        pupil = self.student("madina@example.com", "Madina", self.school)
        other = self.make_class(self.school, 7, "C")
        Enrollment.objects.create(student=pupil, group=other, is_active=True)
        self.client.force_login(self.school_admin)
        detail = reverse("school_class_detail", args=[self.class_7b.pk])
        self.assertNotIn("Madina", self.html(detail))  # not offered
        res = self.client.post(
            reverse("school_class_student_add", args=[self.class_7b.pk]),
            {"student": pupil.pk},
            follow=True,
        )
        self.assertContains(res, "already in class 7-C")
        self.assertNotContains(res, "Select a valid choice")

    def test_help_texts_are_translated(self):
        self.school_admin.language = "uz"
        self.school_admin.save(update_fields=["language"])
        self.client.force_login(self.school_admin)
        html = self.html(reverse("school_class_add"))
        self.assertIn("Faqat maktab sinflari uchun", html)
        self.assertIn("Sinf xonasi yoki xona raqami", html)
        self.assertNotIn("Classroom or room number", html)

    def test_no_match_message_only_when_there_are_classes_to_search(self):
        self.client.force_login(self.school_admin)
        html = self.html(reverse("school_classes"))
        self.assertIn("data-manage-empty-state hidden", html)
        Group.objects.filter(kind=Group.KIND_CLASS).delete()
        html = self.html(reverse("school_classes"))
        self.assertNotIn("No classes found", html)
        self.assertIn("No classes yet", html)
