"""Web language switch and translations (plan task P3.0, decision D17).

Needs compiled translations: run ``python manage.py compilemessages`` first
(CI and the Docker build do).
"""

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import translation

from main_app.school_forms import ParentChildForm, ParentForm

_OVERRIDES = dict(SECURE_SSL_REDIRECT=False)
PASSWORD = "Pass12345!"
COOKIE = settings.LANGUAGE_COOKIE_NAME


def _user(email, user_type, login_id=None):
    return get_user_model().objects.create_user(
        email=email,
        password=PASSWORD,
        first_name="T",
        last_name="U",
        user_type=user_type,
        login_id=login_id,
    )


@override_settings(**_OVERRIDES)
class LanguageSwitchTests(TestCase):
    def setUp(self):
        self.admin = _user("boss@example.com", "1")

    def switch(self, language, next_url="/login/"):
        return self.client.post(reverse("set_language"), {"language": language, "next": next_url})

    def test_english_by_default_and_browser_language_is_ignored(self):
        html = self.client.get(reverse("login_page"), HTTP_ACCEPT_LANGUAGE="ru").content.decode()
        self.assertIn('<html lang="en"', html)
        self.assertIn("Welcome back", html)
        self.assertIn('value="uz"', html)  # the switch is on the sign-in page

    def test_sign_in_page_switches_and_remembers_in_a_cookie(self):
        response = self.switch("ru")
        self.assertRedirects(response, "/login/", fetch_redirect_response=False)
        self.assertEqual(response.cookies[COOKIE].value, "ru")
        html = self.client.get(reverse("login_page")).content.decode()
        self.assertIn('<html lang="ru"', html)
        self.assertIn("С возвращением", html)
        self.assertIn("Войти", html)

        self.switch("uz")
        html = self.client.get(reverse("login_page")).content.decode()
        self.assertIn("Xush kelibsiz", html)

    def test_unknown_language_and_foreign_next_are_ignored(self):
        response = self.switch("de")
        self.assertNotIn(COOKIE, response.cookies)
        response = self.switch("ru", next_url="https://evil.example.com/")
        self.assertEqual(response["Location"], "/")

    def test_switch_needs_post(self):
        self.assertEqual(self.client.get(reverse("set_language")).status_code, 405)

    def test_admin_choice_is_saved_and_translates_the_menu(self):
        self.client.force_login(self.admin)
        html = self.client.get(reverse("admin_home")).content.decode()
        self.assertIn("Students", html)
        self.assertIn('action="/language/"', html)  # admins get the header switch

        self.switch("ru", next_url=reverse("admin_home"))
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.language, "ru")
        html = self.client.get(reverse("admin_home")).content.decode()
        self.assertIn('<html lang="ru"', html)
        for text in ("Ученики", "Учителя", "Платежи", "Выйти"):
            self.assertIn(text, html)

    def test_saved_language_follows_the_user_to_another_browser(self):
        self.admin.language = "uz"
        self.admin.save()
        other_browser = self.client_class()
        other_browser.force_login(self.admin)
        html = other_browser.get(reverse("admin_home")).content.decode()
        self.assertIn("Oʻquvchilar", html)
        self.assertIn("Toʻlovlar", html)

    def test_language_picked_before_sign_in_becomes_the_users(self):
        self.switch("ru")
        response = self.client.post(
            reverse("user_login"), {"identifier": "boss@example.com", "password": PASSWORD}
        )
        self.assertEqual(response.status_code, 302)
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.language, "ru")

    def test_a_saved_language_is_not_overwritten_by_the_cookie(self):
        self.admin.language = "uz"
        self.admin.save()
        self.switch("ru")
        self.client.post(
            reverse("user_login"), {"identifier": "boss@example.com", "password": PASSWORD}
        )
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.language, "uz")

    def test_sign_in_errors_are_translated(self):
        self.switch("ru")
        response = self.client.post(
            reverse("user_login"),
            {"identifier": "boss@example.com", "password": "wrong"},
            follow=True,
        )
        self.assertIn("Неверный пароль.", response.content.decode())

    def test_teachers_have_no_header_switch(self):
        teacher = _user("teacher@example.com", "2", login_id="TC0001")
        self.client.force_login(teacher)
        html = self.client.get(reverse("staff_home")).content.decode()
        self.assertNotIn('action="/language/"', html)


@override_settings(**_OVERRIDES, SCHOOL_BRAND_ENABLED=True)
class SchoolTranslationTests(TestCase):
    def test_school_sign_in_page_in_uzbek(self):
        self.client.post(reverse("set_language"), {"language": "uz", "next": "/login/"})
        html = self.client.get(reverse("login_page") + "?brand=school").content.decode()
        self.assertIn('data-brand="school"', html)
        self.assertIn("Iceberg School ga kirish", html)

    def test_school_parent_forms_are_translated(self):
        admin = _user("boss@example.com", "1")
        with translation.override("ru"):
            parent_form = ParentForm(user=admin).as_p()
            link_form = ParentChildForm(user=admin).as_p()
        self.assertIn("Номер телефона", parent_form)
        self.assertIn("Опекун", link_form)
        with translation.override("uz"):
            self.assertIn("Telefon raqami", ParentForm(user=admin).as_p())


class TranslationCatalogTests(TestCase):
    """Every string marked for translation has an Uzbek and a Russian text."""

    def test_no_untranslated_strings(self):
        from pathlib import Path

        for language in ("uz", "ru"):
            po = Path(settings.LOCALE_PATHS[0]) / language / "LC_MESSAGES" / "django.po"
            entries = po.read_text(encoding="utf-8").split("\n\n")[1:]  # skip the header
            empty = [e for e in entries if e.rstrip().endswith('msgstr ""')]
            self.assertEqual(empty, [], f"untranslated in {language}")
            self.assertNotIn("#, fuzzy", po.read_text(encoding="utf-8"))
