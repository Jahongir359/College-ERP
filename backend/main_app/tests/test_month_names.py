"""Month names follow the page language (web audit M3) and the sign-in footer
follows the brand (web audit minor 4)."""

import json
from datetime import date
from decimal import Decimal
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from main_app.models import Admin, Branch, Course, Invoice, Student

TODAY = date(2026, 10, 28)

# What Django's own catalogs give for October in each language.
LONG = {"en": "October 2026", "uz": "Oktabr 2026", "ru": "Октябрь 2026"}
SHORT = {
    "en": ["May", "Jun", "Jul", "Aug", "Sep", "Oct"],
    "ru": ["Май", "Июн", "Июл", "Авг", "Сен", "Окт"],
}


def _today():
    return mock.patch("django.utils.timezone.localdate", return_value=TODAY)


@override_settings(SECURE_SSL_REDIRECT=False)
class MonthNameTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_user(
            email="boss@example.com",
            password="Pass12345!",
            user_type="1",
            first_name="B",
            last_name="A",
        )
        self.client.force_login(self.admin)

    def use(self, lang):
        self.admin.language = lang
        self.admin.save(update_fields=["language"])

    def test_dashboard_chart_months_follow_the_language(self):
        for lang in ["en", "uz", "ru"]:
            with self.subTest(lang=lang), _today():
                self.use(lang)
                response = self.client.get(reverse("admin_home"))
                self.assertEqual(response.status_code, 200)
                labels = json.loads(response.context["monthly_chart_json"])["labels"]
                self.assertEqual(len(labels), 6)
                if lang in SHORT:
                    self.assertEqual(labels, SHORT[lang])
                else:
                    self.assertEqual(labels[-1], "Okt")
                branch_labels = json.loads(response.context["branch_chart_json"])["labels"]
                self.assertEqual(branch_labels, labels)

    def test_payments_month_follows_the_language(self):
        branch = Branch.objects.create(name="Center")
        student = Student.objects.get(
            admin=get_user_model().objects.create_user(
                email="kid@example.com",
                password="Pass12345!",
                user_type="3",
                first_name="K",
                last_name="D",
            )
        )
        student.branch = branch
        student.save()
        course = Course.objects.create(name="English")
        Invoice.objects.create(
            student=student,
            period=date(2026, 10, 1),
            amount=Decimal("100000"),
            due_date=date(2026, 10, 10),
        )
        del course
        for lang in ["en", "uz", "ru"]:
            with self.subTest(lang=lang):
                self.use(lang)
                html = self.client.get(
                    reverse("admin_payments") + "?month=2026-10"
                ).content.decode()
                # The page eyebrow names the month (P3.9c header).
                self.assertIn(f'class="page-eyebrow">{LONG[lang]}</p>', html)
                # The invoice's mobile card shows the month in the same language.
                self.assertIn(f"· {LONG[lang]}</div>", html)
                others = [v for k, v in LONG.items() if k != lang]
                for other in others:
                    self.assertNotIn(other, html)


ON = dict(SCHOOL_BRAND_ENABLED=True, SECURE_SSL_REDIRECT=False)


@override_settings(**ON)
class LoginFooterTests(TestCase):
    def footer(self):
        html = self.client.get(reverse("login_page")).content.decode()
        return html.split('<p class="footer">', 1)[1].split("</p>", 1)[0]

    def test_center_footer_is_unchanged(self):
        self.assertTrue(self.footer().endswith("Iceberg Study Center"))

    def test_school_admin_sees_the_school_footer_after_signing_out(self):
        school = Branch.objects.create(name="School", brand=Branch.BRAND_SCHOOL)
        user = get_user_model().objects.create_user(
            email="office@example.com",
            password="Pass12345!",
            user_type="1",
            first_name="O",
            last_name="F",
        )
        profile = Admin.objects.get(admin=user)
        profile.is_super_admin = False
        profile.save()
        profile.branches.set([school])
        # Signing in through the form remembers the School brand for this browser.
        response = self.client.post(
            reverse("user_login"), {"email": "office@example.com", "password": "Pass12345!"}
        )
        self.assertEqual(response.cookies["iceberg_brand"].value, "school")
        self.client.post(reverse("user_logout"))
        footer = self.footer()
        self.assertIn("Iceberg School", footer)
        self.assertNotIn("Study Center", footer.split("·")[0])

    def test_school_link_shows_the_school_footer(self):
        self.client.get(reverse("login_page") + "?brand=school")
        self.assertIn("Iceberg School ·", self.footer())
