"""Tests for the Iceberg School brand on sign-in and account recovery (Phase 3).

See docs/plans/ICEBERG_SCHOOL_BRAND_PLAN.md. Learning Center pages must render
as before; School visitors get the School look, remembered in a cookie.
"""

import re
from pathlib import Path

from django.contrib.auth import get_user_model
from django.contrib.staticfiles import finders
from django.core import mail
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from main_app import branding
from main_app.models import Branch, Student

_BASE = dict(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    SECURE_SSL_REDIRECT=False,
)
ON = dict(_BASE, SCHOOL_BRAND_ENABLED=True)
OFF = dict(_BASE, SCHOOL_BRAND_ENABLED=False)
COOKIE = branding.BRAND_COOKIE


def _student(email, login_id, branch):
    user = get_user_model().objects.create_user(
        email=email,
        password="Str0ng-Passw0rd!",
        first_name="T",
        last_name="U",
        user_type="3",
        gender="M",
        address="",
        profile_pic="",
        login_id=login_id,
    )
    student = Student.objects.get(admin=user)
    student.branch = branch
    student.save()
    return get_user_model().objects.get(pk=user.pk)


class AuthBrandFixture(TestCase):
    def setUp(self):
        self.center = Branch.objects.create(name="Chilonzor")
        self.school = Branch.objects.create(name="Iceberg School", brand=Branch.BRAND_SCHOOL)
        self.school_student = _student("school-kid@example.com", "ICA001", self.school)
        self.center_student = _student("center-kid@example.com", "ICA002", self.center)

    def login_html(self, **params):
        response = self.client.get(reverse("login_page"), params)
        self.assertEqual(response.status_code, 200)
        return response, response.content.decode()


class LoginPageBrandTests(AuthBrandFixture):
    def assert_center_login(self, html):
        self.assertIn('data-brand="center"', html)
        self.assertNotIn("brand-school-auth.css", html)
        self.assertIn("<title>ICEBERG — Sign In</title>", html)
        self.assertIn('<meta name="theme-color" content="#0C1F45">', html)
        self.assertIn('alt="ICEBERG Study Center"', html)
        self.assertIn("Sign in to continue", html)
        self.assertIn("Iceberg Study Center</p>", html)
        self.assertNotIn("Iceberg School", html)

    @override_settings(**OFF)
    def test_flag_off_login_is_learning_center_and_sets_no_cookie(self):
        response, html = self.login_html(brand="school")
        self.assert_center_login(html)
        self.assertNotIn(COOKIE, response.cookies)

    @override_settings(**ON)
    def test_flag_on_default_login_is_learning_center(self):
        response, html = self.login_html()
        self.assert_center_login(html)
        self.assertNotIn(COOKIE, response.cookies)

    @override_settings(**ON)
    def test_school_login_look_and_cookie(self):
        response, html = self.login_html(brand="school")
        self.assertIn('data-brand="school"', html)
        self.assertIn("dist/css/brand-school-auth.css", html)
        self.assertIn("<title>Iceberg School — Sign In</title>", html)
        self.assertIn('<meta name="theme-color" content="#4C0909">', html)
        self.assertIn("img/brand/school/crest-white", html)
        self.assertIn('alt="Iceberg School"', html)
        self.assertIn("Sign in to Iceberg School", html)
        self.assertIn("?brand=center", html)  # way back to the Learning Center sign-in
        self.assertNotIn('alt="ICEBERG Study Center"', html)

        cookie = response.cookies[COOKIE]
        self.assertEqual(cookie.value, "school")
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")

    @override_settings(**ON)
    def test_cookie_keeps_school_until_switched_back(self):
        self.login_html(brand="school")
        response, html = self.login_html()  # no query — cookie decides
        self.assertIn('data-brand="school"', html)
        self.assertNotIn(COOKIE, response.cookies)  # unchanged, not re-set

        response, html = self.login_html(brand="center")
        self.assertIn('data-brand="center"', html)
        self.assertEqual(response.cookies[COOKIE].value, "center")

    @override_settings(**ON)
    def test_bad_brand_value_is_ignored(self):
        response, html = self.login_html(brand="<script>")
        self.assertIn('data-brand="center"', html)
        self.assertNotIn(COOKIE, response.cookies)


class SignedInCookieTests(AuthBrandFixture):
    @override_settings(**ON)
    def test_school_user_cookie_survives_logout(self):
        self.client.force_login(self.school_student)
        response = self.client.get(reverse("student_home"))
        self.assertEqual(response.cookies[COOKIE].value, "school")

        self.client.post(reverse("user_logout"))
        _, html = self.login_html()
        self.assertIn('data-brand="school"', html)

    @override_settings(**ON)
    def test_center_user_resets_school_cookie(self):
        self.client.cookies[COOKIE] = "school"
        self.client.force_login(self.center_student)
        response = self.client.get(reverse("student_home"))
        self.assertEqual(response.cookies[COOKIE].value, "center")

    @override_settings(**ON)
    def test_api_and_static_paths_never_set_cookie(self):
        response = self.client.get("/api/v1/me/", {"brand": "school"})
        self.assertNotIn(COOKIE, response.cookies)

    @override_settings(**OFF)
    def test_flag_off_signed_in_sets_no_cookie(self):
        self.client.force_login(self.school_student)
        response = self.client.get(reverse("student_home"))
        self.assertNotIn(COOKIE, response.cookies)


class RecoveryPageBrandTests(AuthBrandFixture):
    @override_settings(**ON)
    def test_recovery_pages_follow_the_cookie(self):
        html = self.client.get(reverse("forgot_password")).content.decode()
        self.assertIn('data-brand="center"', html)
        self.assertIn("STUDY CENTER", html)
        self.assertNotIn("brand-school-auth.css", html)

        self.client.cookies[COOKIE] = "school"
        for name in ("forgot_password", "verify_reset_code"):
            html = self.client.get(reverse(name)).content.decode()
            self.assertIn('data-brand="school"', html, name)
            self.assertIn(">SCHOOL<", html, name)
            self.assertIn("brand-school-auth.css", html, name)
            self.assertIn("Iceberg School", html, name)

    @override_settings(**OFF)
    def test_recovery_page_unchanged_when_off(self):
        self.client.cookies[COOKIE] = "school"
        html = self.client.get(reverse("forgot_password")).content.decode()
        self.assertIn('data-brand="center"', html)
        self.assertIn(">STUDY CENTER<", html)
        self.assertIn("Iceberg Study Center", html)
        self.assertNotIn("Iceberg School", html)


class ResetEmailBrandTests(AuthBrandFixture):
    def request_code(self, email):
        mail.outbox.clear()
        self.client.post(reverse("forgot_password"), {"email": email})
        self.assertEqual(len(mail.outbox), 1)
        return mail.outbox[0].subject

    @override_settings(**ON)
    def test_subject_uses_the_users_brand(self):
        self.assertEqual(
            self.request_code("school-kid@example.com"), "Iceberg School — Password Reset Code"
        )
        self.assertEqual(
            self.request_code("center-kid@example.com"),
            "Iceberg Study Center — Password Reset Code",
        )

    @override_settings(**OFF)
    def test_subject_unchanged_when_off(self):
        self.assertEqual(
            self.request_code("school-kid@example.com"),
            "Iceberg Study Center — Password Reset Code",
        )


class AuthStylesheetTests(SimpleTestCase):
    PREFIX = 'html[data-brand="school"]'

    def setUp(self):
        path = finders.find("dist/css/brand-school-auth.css")
        self.assertIsNotNone(path, "brand-school-auth.css must be a static file")
        self.css = re.sub(r"/\*.*?\*/", "", Path(path).read_text(), flags=re.S)

    def test_every_selector_is_scoped_to_school(self):
        keyframe_step = re.compile(r"^(from|to|[\d.]+%)(\s*,\s*[\d.]+%)*$")
        for raw in re.findall(r"([^{};]+)\{", self.css):
            selector = raw.strip()
            if selector.startswith("@") or keyframe_step.match(selector):
                continue
            for part in selector.split(","):
                self.assertTrue(part.strip().startswith(self.PREFIX), f"unscoped: {part.strip()}")

    def test_never_targets_center(self):
        self.assertNotIn('data-brand="center"', self.css)

    def test_crest_image_exists(self):
        self.assertIsNotNone(finders.find("dist/img/brand/school/crest-white.png"))
