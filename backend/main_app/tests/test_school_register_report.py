"""Admin web register report (plan task P3.7, mockup 19)."""

import csv
import io
from datetime import time, timedelta

from django.urls import reverse
from django.utils import translation

from main_app.models import Attendance, AttendanceReport

from .test_register import _RegisterFixture, _pupil


class _ReportFixture(_RegisterFixture):
    def setUp(self):
        super().setUp()
        self.class_4b = self.make_class("4-B", self.school, self.subject_teacher)
        _pupil("lola@example.com", self.class_4b, "Lola", "Nazarova")
        # 3-A took today's register: Aziz late at 08:12 by bus, Bekzod absent, Madina present.
        self.register = Attendance.objects.create(
            group=self.class_3a, date=self.today, taken_by=self.homeroom
        )
        for student, status, arrival, note in [
            (self.aziz, AttendanceReport.LATE, time(8, 12), "Avtobus"),
            (self.bekzod, AttendanceReport.ABSENT, None, "Kasal"),
            (self.madina, AttendanceReport.PRESENT, None, ""),
        ]:
            AttendanceReport.objects.create(
                attendance=self.register,
                student=student,
                status=status,
                arrival_time=arrival,
                note=note,
            )
        # The other branch took its register too.
        far = Attendance.objects.create(group=self.class_other, date=self.today)
        AttendanceReport.objects.create(
            attendance=far, student=self.far_pupil, status=AttendanceReport.ABSENT, note="Far"
        )

    def page(self, user, **params):
        self.client.force_login(user)
        return self.client.get(reverse("school_register_report"), params)

    def rows(self, res):
        return {r["group"].name: r for r in res.context["rows"]}


class RegisterReportAccessTests(_ReportFixture):
    def test_branch_admin_sees_own_branch_only(self):
        res = self.page(self.branch_admin)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(set(self.rows(res)), {"3-A", "4-B"})
        names = [p.student.admin.first_name for p in res.context["pupils"]]
        self.assertNotIn("Kamola", names)
        self.assertNotContains(res, "Far")
        # Asking for another branch's class falls back to the own classes.
        res = self.page(self.branch_admin, **{"class": self.class_other.pk})
        self.assertEqual(set(self.rows(res)), {"3-A", "4-B"})

    def test_super_admin_sees_every_branch(self):
        res = self.page(self.super_admin)
        self.assertEqual(set(self.rows(res)), {"3-A", "4-B", "5-B"})
        self.assertTrue(res.context["show_branch"])

    def test_other_roles_get_no_page(self):
        url = reverse("school_register_report")
        cases = [
            (self.homeroom.admin, reverse("staff_home")),
            (self.aziz.admin, reverse("student_home")),
            (self.parent, "/app/"),
        ]
        for user, home in cases:
            with self.subTest(user=user.email):
                self.client.force_login(user)
                self.assertRedirects(self.client.get(url), home, fetch_redirect_response=False)
                res = self.client.get(url, {"export": "csv"})
                self.assertRedirects(res, home, fetch_redirect_response=False)
        self.client.logout()
        res = self.client.get(url)
        self.assertEqual(res.status_code, 302)
        self.assertIn("login", res["Location"])

    def test_sidebar_link_for_school_admins(self):
        res = self.page(self.branch_admin)
        self.assertContains(res, reverse("school_register_report"))


class RegisterReportContentTests(_ReportFixture):
    def test_counts_rate_and_not_taken(self):
        res = self.page(self.branch_admin)
        rows = self.rows(res)
        a = rows["3-A"]
        self.assertTrue(a["taken"])
        self.assertEqual((a["pupils"], a["present"], a["late"], a["absent"]), (3, 1, 1, 1))
        self.assertEqual(a["rate"], 67)  # present + late of 3
        self.assertEqual(a["teacher"], self.homeroom.admin.get_full_name())
        self.assertIsNotNone(a["taken_at"])
        b = rows["4-B"]
        self.assertFalse(b["taken"])
        self.assertIsNone(b["rate"])
        ctx = res.context
        self.assertEqual(
            (ctx["taken_count"], ctx["present"], ctx["late"], ctx["absent"]), (1, 1, 1, 1)
        )
        self.assertEqual(ctx["rate"], 67)

    def test_absent_first_then_late_with_arrival_time_and_note(self):
        res = self.page(self.branch_admin)
        pupils = [(p.student.admin.first_name, p.status) for p in res.context["pupils"]]
        self.assertEqual(
            pupils, [("Bekzod", AttendanceReport.ABSENT), ("Aziz", AttendanceReport.LATE)]
        )
        self.assertContains(res, "08:12")
        self.assertContains(res, "Avtobus")
        self.assertContains(res, "Kasal")

    def test_class_filter(self):
        res = self.page(self.branch_admin, **{"class": self.class_4b.pk})
        self.assertEqual(set(self.rows(res)), {"4-B"})
        self.assertEqual(res.context["pupils"], [])

    def test_another_day_and_a_bad_date(self):
        res = self.page(self.branch_admin, date=str(self.today - timedelta(days=1)))
        self.assertEqual(res.context["taken_count"], 0)
        self.assertEqual(res.context["pupils"], [])
        res = self.page(self.branch_admin, date="yesterday")
        self.assertEqual(res.context["day"], self.today)
        # A date outside the academic year has no classes.
        res = self.page(self.branch_admin, date=str(self.year.end_year + timedelta(days=1)))
        self.assertEqual(res.context["rows"], [])

    def test_uzbek_and_russian(self):
        for lang, title, late in [
            ("uz", "Davomat hisoboti", "Kechikdi"),
            ("ru", "Отчёт о посещаемости", "Опоздание"),
        ]:
            with self.subTest(lang=lang):
                self.branch_admin.language = lang
                self.branch_admin.save(update_fields=["language"])
                res = self.page(self.branch_admin)
                self.assertContains(res, title)
                self.assertContains(res, late)  # the per-pupil badge (context "one pupil")


class RegisterReportCsvTests(_ReportFixture):
    def csv(self, user, **params):
        res = self.page(user, export="csv", **params)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res["Content-Type"], "text/csv; charset=utf-8")
        self.assertIn(f"register-{self.today:%Y-%m-%d}.csv", res["Content-Disposition"])
        text = res.content.decode("utf-8")
        self.assertTrue(text.startswith("﻿"))
        return list(csv.reader(io.StringIO(text.lstrip("﻿"))))

    def test_same_rows_as_the_page(self):
        with translation.override("en"):
            rows = self.csv(self.branch_admin)
        blank = rows.index([])
        classes, pupils = rows[:blank], rows[blank + 1 :]
        self.assertEqual(classes[0][:3], ["Date", "Class", "Homeroom teacher"])
        by_class = {r[1]: r for r in classes[1:]}
        self.assertEqual(set(by_class), {"3-A", "4-B"})
        self.assertEqual(by_class["3-A"][2:4], [self.homeroom.admin.get_full_name(), "3"])
        self.assertEqual(by_class["3-A"][5:], ["1", "1", "1", "67"])
        self.assertEqual(by_class["4-B"][4:], ["Not taken", "", "", "", ""])
        self.assertEqual(pupils[0], ["Date", "Class", "Student", "Status", "Arrival time", "Note"])
        self.assertEqual(
            [r[2:] for r in pupils[1:]],
            [
                ["Bekzod Aliyev", "Absent", "", "Kasal"],
                ["Aziz Karimov", "Late", "08:12", "Avtobus"],
            ],
        )

    def test_scoped_and_filtered(self):
        rows = self.csv(self.branch_admin, **{"class": self.class_3a.pk})
        text = str(rows)
        self.assertIn("3-A", text)
        self.assertNotIn("4-B", text)
        self.assertNotIn("5-B", text)
        self.assertNotIn("Kamola", text)
        self.assertIn("5-B", str(self.csv(self.super_admin)))
