"""School page header and navbar year chip (P3.6, mockup 16)."""

from datetime import date
from unittest import mock

from django.test import override_settings
from django.utils import translation
from django.urls import reverse

from main_app.context_processors import school_period_label
from main_app.models import Parent, ParentChild, Session, Term

from .test_school_admin_pages import _SchoolFixture, _user

TODAY = date(2026, 10, 28)


def _today():
    return mock.patch("django.utils.timezone.localdate", return_value=TODAY)


class SchoolPeriodLabelTests(_SchoolFixture):
    def test_current_year_and_the_quarter_today_falls_in(self):
        Term.objects.create(
            session=self.year,
            number=1,
            name="1-chorak",
            start_date=date(2026, 9, 2),
            end_date=date(2026, 11, 3),
        )
        Term.objects.create(
            session=self.year,
            number=2,
            name="2-chorak",
            start_date=date(2026, 11, 10),
            end_date=date(2026, 12, 26),
        )
        with _today():
            self.assertEqual(school_period_label(), "2026–2027 · Quarter 1")
            # The chip follows the language, not the term's free-text name.
            for language, label in (("uz", "1-chorak"), ("ru", "1-я четверть")):
                with translation.override(language):
                    self.assertEqual(school_period_label(), f"2026–2027 · {label}")

    def test_holiday_keeps_the_last_started_quarter_and_unnamed_falls_back(self):
        Term.objects.create(
            session=self.year,
            number=1,
            start_date=date(2026, 9, 2),
            end_date=date(2026, 10, 20),
        )
        with _today():
            self.assertEqual(school_period_label(), "2026–2027 · Quarter 1")

    def test_year_only_before_the_first_quarter_and_empty_without_a_year(self):
        with _today():
            self.assertEqual(school_period_label(), "2026–2027")
        with mock.patch.object(Session, "current", return_value=None):
            self.assertEqual(school_period_label(), "")


@override_settings(SCHOOL_BRAND_ENABLED=True)
class SchoolPageHeaderTests(_SchoolFixture):
    def setUp(self):
        super().setUp()
        Term.objects.create(
            session=self.year,
            number=1,
            name="1-chorak",
            start_date=date(2026, 9, 2),
            end_date=date(2026, 11, 3),
        )

    def test_school_pages_show_eyebrow_one_title_and_the_chip(self):
        self.client.force_login(self.school_admin)
        child = self.student("aziz@example.com", "Aziz", self.school)
        parent = Parent.objects.get(admin=_user("mum@example.com", "4"))
        ParentChild.objects.create(parent=parent, student=child)
        urls = [
            reverse("school_classes"),
            reverse("school_class_detail", args=[self.class_7b.pk]),
            reverse("school_class_add"),
            reverse("school_years"),
            reverse("school_timetable"),
            reverse("school_bells"),
            reverse("school_parents"),
            reverse("school_parent_detail", args=[parent.pk]),
            reverse("school_register_report"),
            reverse("school_board"),
        ]
        for url in urls:
            with self.subTest(url=url), _today():
                html = self.html(url)
                self.assertIn('class="page-eyebrow"', html)
                self.assertNotIn("ice-manage-hero__title", html)
                self.assertIn('class="navbar-period-chip">2026–2027 · Quarter 1<', html)

    def test_actions_move_into_the_page_header(self):
        self.client.force_login(self.school_admin)
        html = self.html(reverse("school_classes"))
        self.assertIn('class="page-actions"', html)
        self.assertIn(reverse("school_class_add"), html)

    def test_center_admin_sees_no_chip_or_eyebrow(self):
        self.client.force_login(self.center_admin)
        with _today():
            html = self.html(reverse("admin_home"))
        self.assertNotIn("navbar-period-chip", html)
        # The Study Center home has its own eyebrow and actions since P3.9c (16d).
        self.assertNotIn("navbar-brand-logo", html)  # the School wordmark
        self.assertIn('class="navbar-logo-text">ICEBERG<', html)  # unchanged Center wordmark

    @override_settings(SCHOOL_BRAND_ENABLED=False)
    def test_no_chip_while_the_school_brand_is_off(self):
        self.client.force_login(self.school_admin)
        with _today():
            html = self.html(reverse("school_classes"))
        self.assertNotIn("navbar-period-chip", html)

    @override_settings(SCHOOL_BRAND_ENABLED=False)
    def test_period_is_not_queried_on_center_branded_pages(self):
        # The admin sees a School branch (Maktab nav on) but the page is
        # Center-branded: the year/quarter lookup must never run.
        self.client.force_login(self.school_admin)
        with mock.patch("main_app.context_processors.school_period_label") as label:
            self.html(reverse("admin_home"))
        label.assert_not_called()

    def test_period_is_looked_up_once_on_school_pages(self):
        self.client.force_login(self.school_admin)
        with mock.patch(
            "main_app.context_processors.school_period_label", return_value="2026–2027"
        ) as label:
            html = self.html(reverse("school_classes"))
        label.assert_called_once()
        self.assertIn("2026–2027", html)
