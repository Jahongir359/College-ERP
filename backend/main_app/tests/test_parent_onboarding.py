"""Parent onboarding (PL.1): printed login letters and the first-login password change."""

from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from main_app import parents
from main_app.models import CustomUser

from .test_school_admin_pages import PASSWORD
from .test_school_parent_pages import _ParentFixture


def _flag(user):
    return CustomUser.objects.get(pk=user.pk).must_change_password


class PasswordFlagTests(_ParentFixture):
    def test_office_set_passwords_must_be_changed(self):
        self.assertTrue(_flag(self.mum.admin))  # new parent: the office chose the password
        self.mum.admin.must_change_password = False
        self.mum.admin.save()
        parents.update_parent(self.mum, first_name="Nodira")  # no password: flag untouched
        self.assertFalse(_flag(self.mum.admin))
        self.client.force_login(self.school_admin)
        self.client.post(reverse("school_parent_reset_password", args=[self.mum.pk]))
        self.assertTrue(_flag(self.mum.admin))

    def test_admin_api_password_reset_sets_the_flag(self):
        self.mum.admin.must_change_password = False
        self.mum.admin.save()
        api = APIClient()
        api.force_authenticate(user=self.school_admin)
        url = reverse("api_admin_parent_detail", args=[self.mum.pk])
        self.assertEqual(api.patch(url, {"password": "Another-pass-77"}).status_code, 200)
        self.assertTrue(_flag(self.mum.admin))


class FirstLoginApiTests(_ParentFixture):
    def login(self, identifier, password=PASSWORD):
        api = APIClient()
        response = api.post(
            reverse("api_login"), {"identifier": identifier, "password": password}, format="json"
        )
        self.assertEqual(response.status_code, 200, response.content)
        api.credentials(HTTP_AUTHORIZATION=f"Bearer {response.data['access']}")
        return api, response.data["user"]

    def test_parent_must_change_password_before_using_the_api(self):
        api, user = self.login(self.mum.admin.login_id)
        self.assertTrue(user["must_change_password"])
        response = api.get(reverse("api_notifications"))
        self.assertEqual(response.status_code, 403)
        # The exact body the app's P4.3 screen relies on.
        self.assertEqual(
            response.json(),
            {
                "detail": "Change your password before continuing.",
                "code": "password_change_required",
            },
        )
        self.assertTrue(api.get(reverse("api_me")).data["must_change_password"])

        new = "My-own-pass-2026"
        response = api.post(
            reverse("api_change_password"),
            {"old_password": PASSWORD, "new_password": new, "confirm_password": new},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(_flag(self.mum.admin))
        self.assertEqual(api.get(reverse("api_notifications")).status_code, 200)
        self.assertFalse(api.get(reverse("api_me")).data["must_change_password"])

    def test_a_wrong_old_password_keeps_the_flag(self):
        api, _user = self.login(self.mum.admin.login_id)
        response = api.post(
            reverse("api_change_password"),
            {
                "old_password": "nope",
                "new_password": "My-own-pass-2026",
                "confirm_password": "My-own-pass-2026",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertTrue(_flag(self.mum.admin))

    def test_users_without_the_flag_are_not_affected(self):
        self.teacher.admin.login_id = "TC900"
        self.teacher.admin.save()
        api, user = self.login("TC900")
        self.assertFalse(user["must_change_password"])
        self.assertEqual(api.get(reverse("api_notifications")).status_code, 200)

    def test_logout_works_before_the_change(self):
        api = APIClient()
        tokens = api.post(
            reverse("api_login"),
            {"identifier": self.mum.admin.login_id, "password": PASSWORD},
            format="json",
        ).data
        api.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        self.assertEqual(
            api.post(reverse("api_logout"), {"refresh": tokens["refresh"]}).status_code, 200
        )


class PasswordChangeGateTests(_ParentFixture):
    """The global DRF auth class (api/authentication.py): only flagged users are held back."""

    def jwt(self, identifier, password=PASSWORD):
        api = APIClient()
        tokens = api.post(
            reverse("api_login"), {"identifier": identifier, "password": password}, format="json"
        )
        self.assertEqual(tokens.status_code, 200, tokens.content)
        api.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens.data['access']}")
        return api, tokens.data

    def test_other_roles_and_unflagged_parents_are_not_affected(self):
        student = self.aziz.admin
        student.login_id = "IC900"
        student.save()
        self.teacher.admin.login_id = "TC900"
        self.teacher.admin.save()
        CustomUser.objects.filter(pk=self.far_parent.admin_id).update(must_change_password=False)
        cases = [
            (
                "admin",
                self.school_admin.email,
                [reverse("api_notifications"), reverse("api_admin_parents")],
            ),
            ("teacher", "TC900", [reverse("api_notifications")]),
            ("student", "IC900", [reverse("api_notifications")]),
            ("parent", self.far_parent.admin.login_id, [reverse("api_notifications")]),
        ]
        for role, identifier, urls in cases:
            api, tokens = self.jwt(identifier)
            self.assertFalse(tokens["user"]["must_change_password"])
            for url in urls:
                with self.subTest(role=role, url=url):
                    self.assertEqual(api.get(url).status_code, 200)

    def test_a_flagged_parent_reaches_only_the_allow_list(self):
        api, tokens = self.jwt(self.mum.admin.login_id)
        for url in (reverse("api_notifications"), reverse("api_groups")):
            with self.subTest(url=url):
                response = api.get(url)
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.json()["code"], "password_change_required")
        self.assertEqual(api.get(reverse("api_me")).status_code, 200)
        self.assertEqual(api.get(reverse("api_app_version")).status_code, 200)
        response = api.post(reverse("api_fcm_token"), {"token": "device-1"}, format="json")
        self.assertEqual(response.status_code, 200)

        # The refresh token keeps working, and the new access token is still held back.
        refreshed = APIClient().post(
            reverse("token_refresh"), {"refresh": tokens["refresh"]}, format="json"
        )
        self.assertEqual(refreshed.status_code, 200)
        again = APIClient()
        again.credentials(HTTP_AUTHORIZATION=f"Bearer {refreshed.data['access']}")
        self.assertEqual(again.get(reverse("api_notifications")).status_code, 403)
        self.assertEqual(again.get(reverse("api_me")).status_code, 200)

    def test_web_login_sends_the_parent_to_the_app(self):
        """The web session isn't gated itself: parents land on /app/, the app's web
        build, which uses the API and so meets the same password change."""
        response = self.client.post(
            reverse("user_login"),
            {"identifier": self.mum.admin.login_id, "password": PASSWORD},
        )
        self.assertRedirects(response, "/app/", fetch_redirect_response=False)
        # A session cookie is not an API login: the gate can't be skipped that way.
        self.assertEqual(self.client.get(reverse("api_notifications")).status_code, 401)


class LoginLetterTests(_ParentFixture):
    def letter(self, parent, **data):
        return self.client.post(reverse("school_parent_letter", args=[parent.pk]), data)

    def test_letter_has_login_new_password_and_qr(self):
        self.client.force_login(self.school_admin)
        response = self.letter(self.mum)
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        letter = response.context["letters"][0]
        self.assertIn(self.mum.admin.login_id, html)
        self.assertIn(letter["password"], html)
        self.assertTrue(
            CustomUser.objects.get(pk=self.mum.admin_id).check_password(letter["password"])
        )
        self.assertTrue(_flag(self.mum.admin))
        self.assertIn("<svg", html)
        self.assertIn("http://testserver/download/", html)
        self.assertIn("Aziz", html)
        self.assertIn("7-B", html)
        self.assertIn("no-cache", response["Cache-Control"])

    @override_settings(
        APP_DOWNLOAD_URL="https://iceberglc.com/app",
        APP_STORE_URL_ANDROID="https://play.google.com/store/apps/details?id=uz.iceberg",
    )
    def test_store_links_come_from_settings(self):
        self.client.force_login(self.school_admin)
        html = self.letter(self.mum).content.decode()
        self.assertIn("https://iceberglc.com/app", html)
        self.assertNotIn("http://testserver/download/", html)
        self.assertIn("Google Play", html)
        self.assertNotIn("App Store", html)

    def test_letter_in_the_chosen_language(self):
        self.client.force_login(self.school_admin)
        self.assertIn("Временный пароль", self.letter(self.mum, language="ru").content.decode())
        self.assertIn("Vaqtinchalik parol", self.letter(self.mum, language="uz").content.decode())
        self.assertIn("Temporary password", self.letter(self.mum, language="xx").content.decode())

    def test_letter_access(self):
        self.client.force_login(self.school_admin)
        url = reverse("school_parent_letter", args=[self.mum.pk])
        self.assertEqual(self.client.get(url).status_code, 405)
        self.assertEqual(self.letter(self.far_parent).status_code, 404)
        self.assertTrue(
            CustomUser.objects.get(pk=self.far_parent.admin_id).check_password(PASSWORD)
        )
        self.client.force_login(self.teacher.admin)
        self.assertEqual(self.letter(self.mum).status_code, 302)
        self.assertTrue(CustomUser.objects.get(pk=self.mum.admin_id).check_password(PASSWORD))

    def test_hidden_children_are_not_printed(self):
        parents.link_child(self.far_parent, self.aziz, "father")
        self.client.force_login(self.school_admin)
        html = self.letter(self.far_parent).content.decode()
        self.assertIn("Aziz", html)
        self.assertNotIn("Farrux", html)

    def test_parent_page_offers_the_letter(self):
        self.client.force_login(self.school_admin)
        html = self.html(self.detail(self.mum))
        self.assertIn(reverse("school_parent_letter", args=[self.mum.pk]), html)


class ClassLettersTests(_ParentFixture):
    def setUp(self):
        super().setUp()
        self.dad = parents.create_parent(
            "Rustam", "Karimov", "+998 93 444 55 66", PASSWORD, self.aziz, "father"
        )
        CustomUser.objects.filter(pk=self.dad.admin_id).update(last_login=timezone.now())
        self.url = reverse("school_class_parent_letters", args=[self.class_7b.pk])

    def test_letters_only_for_parents_who_never_signed_in(self):
        self.client.force_login(self.school_admin)
        html = self.html(reverse("school_parents") + f"?class={self.class_7b.pk}")
        self.assertIn(self.url, html)
        self.assertIn("1 parent in 7-B has not signed in yet.", html)

        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 200)
        printed = [letter["parent"].pk for letter in response.context["letters"]]
        self.assertEqual(printed, [self.mum.pk])
        dad = CustomUser.objects.get(pk=self.dad.admin_id)
        self.assertTrue(dad.check_password(PASSWORD))  # already uses the app: untouched

    def test_nothing_to_print_goes_back_to_the_list(self):
        CustomUser.objects.filter(pk=self.mum.admin_id).update(last_login=timezone.now())
        self.client.force_login(self.school_admin)
        response = self.client.post(self.url)
        self.assertRedirects(
            response,
            reverse("school_parents") + f"?class={self.class_7b.pk}",
            fetch_redirect_response=False,
        )

    def test_another_branchs_class_is_404(self):
        self.client.force_login(self.school_admin)
        url = reverse("school_class_parent_letters", args=[self.class_far.pk])
        self.assertEqual(self.client.post(url).status_code, 404)
        self.assertTrue(
            CustomUser.objects.get(pk=self.far_parent.admin_id).check_password(PASSWORD)
        )
        self.assertEqual(self.client.get(self.url).status_code, 405)
