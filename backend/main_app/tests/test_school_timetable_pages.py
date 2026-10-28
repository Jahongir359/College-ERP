"""Maktab admin web pages: bell times and the class timetable editor (P3.2)."""

from datetime import date, time

from django.urls import reverse

from main_app.models import BellPeriod, ClassSubject, Lesson, Subject

from .test_school_admin_pages import _SchoolFixture


class _TimetableFixture(_SchoolFixture):
    def setUp(self):
        super().setUp()
        self.p1 = BellPeriod.objects.create(
            branch=self.school, number=1, start_time=time(8, 0), end_time=time(8, 45)
        )
        self.p2 = BellPeriod.objects.create(
            branch=self.school, number=2, start_time=time(8, 55), end_time=time(9, 40)
        )
        self.maths = ClassSubject.objects.create(
            group=self.class_7b,
            subject=Subject.objects.get(course=self.course, name="Matematika"),
            teacher=self.teacher,
            weekly_hours=5,
        )
        self.url = f"{reverse('school_timetable')}?class={self.class_7b.pk}"

    def save_week(self, cells, start="2026-09-01", group=None):
        group = group or self.class_7b
        data = {"start": start}
        for (weekday, period), cs in cells.items():
            data[f"cell-{weekday}-{period.pk}"] = cs.pk if cs else ""
        return self.client.post(f"{reverse('school_timetable')}?class={group.pk}", data)


class BellTimesPageTests(_TimetableFixture):
    def post_add(self, branch, number, start, end):
        prefix = f"b{branch.pk}"
        return self.client.post(
            reverse("school_bell_add", args=[branch.pk]),
            {f"{prefix}-number": number, f"{prefix}-start_time": start, f"{prefix}-end_time": end},
        )

    def test_branch_admin_manages_own_school_bells(self):
        self.client.force_login(self.school_admin)
        html = self.html(reverse("school_bells"))
        self.assertIn(f'id="branch-{self.school.pk}"', html)
        self.assertNotIn(f'id="branch-{self.other_school.pk}"', html)
        self.assertNotIn(f'id="branch-{self.center.pk}"', html)

        self.post_add(self.school, 3, "09:50", "10:35")
        self.assertTrue(BellPeriod.objects.filter(branch=self.school, number=3).exists())
        self.post_add(self.school, 3, "11:00", "11:45")  # number taken
        self.post_add(self.school, 4, "10:00", "10:40")  # overlaps period 3
        self.assertEqual(BellPeriod.objects.filter(branch=self.school).count(), 3)

        edit = reverse("school_bell_edit", args=[self.p2.pk])
        p = f"p{self.p2.pk}"
        self.client.post(
            edit, {f"{p}-number": 2, f"{p}-start_time": "09:00", f"{p}-end_time": "09:45"}
        )
        self.p2.refresh_from_db()
        self.assertEqual(self.p2.start_time, time(9, 0))

        self.client.post(reverse("school_bell_delete", args=[self.p2.pk]))
        self.assertFalse(BellPeriod.objects.filter(pk=self.p2.pk).exists())

    def test_other_branches_are_out_of_reach(self):
        far = BellPeriod.objects.create(
            branch=self.other_school, number=1, start_time=time(8, 0), end_time=time(8, 45)
        )
        self.client.force_login(self.school_admin)
        self.assertEqual(self.post_add(self.other_school, 2, "09:00", "09:45").status_code, 404)
        self.assertEqual(self.post_add(self.center, 1, "09:00", "09:45").status_code, 404)
        self.assertEqual(
            self.client.post(reverse("school_bell_delete", args=[far.pk])).status_code, 404
        )

    def test_period_in_use_is_not_deleted(self):
        Lesson.objects.create(
            group=self.class_7b, class_subject=self.maths, weekday=1, period=self.p1
        )
        self.client.force_login(self.school_admin)
        self.client.post(reverse("school_bell_delete", args=[self.p1.pk]))
        self.assertTrue(BellPeriod.objects.filter(pk=self.p1.pk).exists())

    def test_translated_overlap_message(self):
        self.client.force_login(self.school_admin)
        self.client.post(reverse("set_language"), {"language": "ru", "next": "/"})
        response = self.post_add(self.school, 4, "08:10", "08:30")
        html = self.client.get(response["Location"]).content.decode()
        self.assertIn("Звонки одного филиала не должны пересекаться.", html)


class TimetableEditorTests(_TimetableFixture):
    def test_grid_shows_periods_days_and_subjects(self):
        self.client.force_login(self.school_admin)
        html = self.html(self.url)
        self.assertIn("08:55", html)
        self.assertIn("Saturday", html)
        self.assertIn(f'name="cell-1-{self.p1.pk}"', html)
        self.assertIn("Matematika", html)

    def test_save_a_week_for_the_whole_year(self):
        self.client.force_login(self.school_admin)
        response = self.save_week({(1, self.p1): self.maths, (3, self.p2): self.maths})
        self.assertEqual(response.status_code, 302)
        lessons = Lesson.objects.filter(group=self.class_7b)
        self.assertEqual(lessons.count(), 2)
        self.assertTrue(all(lesson.valid_from is None for lesson in lessons))

        self.save_week({(1, self.p1): None, (3, self.p2): self.maths})  # clear Monday
        self.assertEqual(list(lessons.values_list("weekday", flat=True)), [3])
        self.assertIn("Matematika 1/5", self.html(self.url + "&start=2026-09-01"))

    def test_mid_year_change_keeps_earlier_weeks(self):
        old = Lesson.objects.create(
            group=self.class_7b, class_subject=self.maths, weekday=1, period=self.p1
        )
        english = ClassSubject.objects.create(
            group=self.class_7b,
            subject=Subject.objects.get(course=self.course, name="Ingliz tili"),
            weekly_hours=3,
        )
        self.client.force_login(self.school_admin)
        self.save_week({(1, self.p1): english}, start="2026-11-09")
        old.refresh_from_db()
        self.assertEqual(old.valid_to, date(2026, 11, 8))
        new = Lesson.objects.get(group=self.class_7b, class_subject=english)
        self.assertEqual(new.valid_from, date(2026, 11, 9))
        self.assertTrue(old.is_on(date(2026, 11, 2)))
        self.assertTrue(new.is_on(date(2026, 11, 9)))

    def test_teacher_clash_saves_nothing_and_shows_the_cell(self):
        class_7a = self.make_class(self.school, 7, "A")
        other_maths = ClassSubject.objects.create(
            group=class_7a, subject=self.maths.subject, teacher=self.teacher, weekly_hours=5
        )
        Lesson.objects.create(group=class_7a, class_subject=other_maths, weekday=2, period=self.p1)
        self.client.force_login(self.school_admin)
        response = self.save_week({(1, self.p1): self.maths, (2, self.p1): self.maths})
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        self.assertIn("school-cell--clash", html)
        self.assertIn("Teacher busy: 7-A", html)
        self.assertFalse(Lesson.objects.filter(group=self.class_7b).exists())

    def test_date_outside_the_year_is_refused(self):
        self.client.force_login(self.school_admin)
        self.save_week({(1, self.p1): self.maths}, start="2027-08-01")
        self.assertFalse(Lesson.objects.exists())

    def test_admins_of_other_branches_get_404(self):
        self.client.force_login(self.school_admin)
        far = f"{reverse('school_timetable')}?class={self.class_far.pk}"
        self.assertEqual(self.client.get(far).status_code, 404)
        self.client.force_login(self.teacher.admin)
        self.assertRedirects(
            self.client.get(self.url), reverse("staff_home"), fetch_redirect_response=False
        )


class TeacherChangeClashTests(_TimetableFixture):
    def test_new_teacher_busy_at_a_lesson_time_is_refused(self):
        jasur = self.staff("jasur@example.com", "Jasur", self.school)
        class_7a = self.make_class(self.school, 7, "A")
        physics = ClassSubject.objects.create(
            group=class_7a,
            subject=Subject.objects.get(course=self.course, name="Fizika"),
            teacher=jasur,
            weekly_hours=2,
        )
        Lesson.objects.create(group=class_7a, class_subject=physics, weekday=1, period=self.p1)
        Lesson.objects.create(
            group=self.class_7b, class_subject=self.maths, weekday=1, period=self.p1
        )
        self.client.force_login(self.school_admin)
        p = f"cs{self.maths.pk}"
        url = reverse("school_class_subject_edit", args=[self.class_7b.pk, self.maths.pk])
        self.client.post(url, {f"{p}-teacher": jasur.pk, f"{p}-weekly_hours": 5})
        self.maths.refresh_from_db()
        self.assertEqual(self.maths.teacher, self.teacher)

        Lesson.objects.filter(group=class_7a).delete()
        self.client.post(url, {f"{p}-teacher": jasur.pk, f"{p}-weekly_hours": 5})
        self.maths.refresh_from_db()
        self.assertEqual(self.maths.teacher, jasur)
