"""Minimum app version the app checks before login (plan task P4.12)."""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

_OVERRIDES = dict(
    SECURE_SSL_REDIRECT=False,
    MIN_APP_VERSION="",
    MIN_APP_VERSION_ANDROID="",
    MIN_APP_VERSION_IOS="",
    APP_STORE_URL_ANDROID="",
    APP_STORE_URL_IOS="",
)
PLAY = "https://play.google.com/store/apps/details?id=uz.iceberg.app"
APPLE = "https://apps.apple.com/app/id123"


@override_settings(**_OVERRIDES)
class AppVersionTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.url = reverse("api_app_version")

    def get(self):
        res = self.api.get(self.url)
        self.assertEqual(res.status_code, 200)
        return res.json()

    def test_url(self):
        self.assertEqual(self.url, "/api/v1/app/version/")

    @override_settings(MIN_APP_VERSION="1.2.0", APP_STORE_URL_ANDROID=PLAY, APP_STORE_URL_IOS=APPLE)
    def test_anonymous_gets_the_minimum_and_store_links(self):
        self.assertEqual(
            self.get(),
            {
                "min_app_version": "1.2.0",
                "android": {"min_app_version": "1.2.0", "store_url": PLAY},
                "ios": {"min_app_version": "1.2.0", "store_url": APPLE},
            },
        )

    @override_settings(MIN_APP_VERSION="1.2.0", MIN_APP_VERSION_IOS="1.1.0")
    def test_a_platform_value_overrides_the_shared_one(self):
        data = self.get()
        self.assertEqual(data["min_app_version"], "1.2.0")
        self.assertEqual(data["android"]["min_app_version"], "1.2.0")
        self.assertEqual(data["ios"]["min_app_version"], "1.1.0")

    @override_settings(MIN_APP_VERSION_ANDROID="1.3.0")
    def test_a_platform_value_alone(self):
        data = self.get()
        self.assertEqual(data["android"]["min_app_version"], "1.3.0")
        self.assertEqual(data["ios"]["min_app_version"], "0.0.0")
        self.assertEqual(data["min_app_version"], "0.0.0")

    def test_default_never_asks_for_an_update(self):
        self.assertEqual(
            self.get(),
            {
                "min_app_version": "0.0.0",
                "android": {"min_app_version": "0.0.0", "store_url": ""},
                "ios": {"min_app_version": "0.0.0", "store_url": ""},
            },
        )

    def test_malformed_setting_is_ignored(self):
        for value in ("1.2", "v1.2.0", "1.2.0+3", "latest", "1.2.0 "):
            with self.subTest(value=value), override_settings(MIN_APP_VERSION=value):
                with self.assertLogs("main_app.api.views.app_version", "WARNING"):
                    data = self.get()
                self.assertEqual(data["min_app_version"], "0.0.0")
                self.assertEqual(data["android"]["min_app_version"], "0.0.0")

    @override_settings(MIN_APP_VERSION="1.2.0", MIN_APP_VERSION_ANDROID="2.0")
    def test_malformed_platform_value_falls_back_to_the_shared_one(self):
        with self.assertLogs("main_app.api.views.app_version", "WARNING"):
            data = self.get()
        self.assertEqual(data["android"]["min_app_version"], "1.2.0")

    @override_settings(MIN_APP_VERSION="2.0.0")
    def test_a_bad_or_expired_token_does_not_block_the_check(self):
        self.api.credentials(HTTP_AUTHORIZATION="Bearer not-a-real-token")
        self.assertEqual(self.get()["min_app_version"], "2.0.0")

    def test_login_check_middleware_lets_anonymous_visitors_through(self):
        # A plain Django client (no DRF helpers, no session) is what the
        # middleware sees from a phone before login: no redirect to /login/.
        res = Client().get(self.url)
        self.assertEqual(res.status_code, 200)
        self.assertNotIn("Location", res.headers)

    def test_signed_in_users_get_the_same_answer(self):
        user = get_user_model().objects.create_user(
            email="parent@example.com", password="Pass12345!", user_type="4"
        )
        self.api.force_authenticate(user=user)
        self.get()
        web = Client()
        web.force_login(user)
        self.assertEqual(web.get(self.url).status_code, 200)  # a parent's web session too

    def test_read_only(self):
        self.assertEqual(self.api.post(self.url, {}).status_code, 405)
