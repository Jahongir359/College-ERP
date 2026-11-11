"""Parents' password reset by SMS code, the login SMS and the reset log (PL.2, D13, D14)."""

import re
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from main_app import branching, parents_sms
from main_app.models import CustomUser, PasswordResetLog, SmsResetCode

from .test_school_admin_pages import PASSWORD
from .test_school_parent_pages import _ParentFixture

PHONE = "+998 90 111 22 33"  # the mum's phone in the fixture
NEW = "My-own-pass-2026"


class _SmsFixture(_ParentFixture):
    def setUp(self):
        super().setUp()
        cache.clear()  # the per-address throttle
        patcher = mock.patch("main_app.payments._send_sms", return_value=True)
        self.send = patcher.start()
        self.addCleanup(patcher.stop)
        self.api = APIClient()
        self.login_id = self.mum.admin.login_id

    def ask(self, login_id=None, phone=PHONE):
        return self.api.post(
            reverse("api_password_reset"),
            {"login_id": login_id or self.login_id, "phone": phone},
            format="json",
        )

    def confirm(self, code, password=NEW, login_id=None):
        return self.api.post(
            reverse("api_password_reset_confirm"),
            {"login_id": login_id or self.login_id, "code": code, "new_password": password},
            format="json",
        )

    def sent_code(self):
        return re.search(r"\b(\d{6})\b", self.send.call_args.args[1]).group(1)

    def can_sign_in(self, password):
        response = APIClient().post(
            reverse("api_login"),
            {"identifier": self.login_id, "password": password},
            format="json",
        )
        return response.status_code == 200


class ResetRequestTests(_SmsFixture):
    def test_matching_login_and_phone_get_a_code_by_sms(self):
        response = self.ask(phone="901112233")  # compared by digits
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.send.call_count, 1)
        phone, text = self.send.call_args.args
        self.assertEqual(phone, PHONE)
        entry = SmsResetCode.objects.get(user=self.mum.admin)
        self.assertNotIn(self.sent_code(), entry.code_hash)  # stored hashed
        self.assertNotIn(PASSWORD, text)

    def test_answer_is_the_same_whoever_asks(self):
        right = self.ask()
        for response in (
            self.ask(phone="+998 90 000 00 00"),  # wrong phone
            self.ask(login_id="PR999999"),  # nobody
            self.ask(login_id=self.teacher.admin.login_id or "ST1"),  # not a parent
        ):
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), right.json())
        self.assertEqual(self.send.call_count, 1)
        self.assertEqual(SmsResetCode.objects.count(), 1)

    def test_missing_fields_and_no_token_needed(self):
        self.assertEqual(self.api.post(reverse("api_password_reset"), {}).status_code, 400)
        self.api.credentials(HTTP_AUTHORIZATION="Bearer not-a-token")
        self.assertEqual(self.ask().status_code, 200)  # a stale token doesn't block it

    def test_disabled_parent_gets_no_code(self):
        CustomUser.objects.filter(pk=self.mum.admin.pk).update(is_active=False)
        self.assertEqual(self.ask().status_code, 200)
        self.send.assert_not_called()

    def test_one_code_a_minute_and_five_a_day_per_phone(self):
        self.ask()
        self.ask()  # too soon
        self.assertEqual(self.send.call_count, 1)
        for _ in range(parents_sms.MAX_PER_DAY + 2):
            SmsResetCode.objects.update(
                created_at=timezone.now() - timedelta(seconds=parents_sms.RESEND_SECONDS + 1)
            )
            self.ask()
        self.assertEqual(self.send.call_count, parents_sms.MAX_PER_DAY)

    def test_sms_is_in_the_parents_language(self):
        CustomUser.objects.filter(pk=self.mum.admin.pk).update(language="ru")
        self.ask()
        self.assertIn("код", self.send.call_args.args[1])

    def test_too_many_requests_from_one_address(self):
        for _ in range(20):
            self.assertEqual(self.ask(login_id="PR999999").status_code, 200)
        self.assertEqual(self.ask().status_code, 429)


class ResetConfirmTests(_SmsFixture):
    def test_code_sets_the_new_password(self):
        refresh = (
            APIClient()
            .post(
                reverse("api_login"),
                {"identifier": self.login_id, "password": PASSWORD},
                format="json",
            )
            .data["refresh"]
        )
        self.ask()
        response = self.confirm(self.sent_code())
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(self.can_sign_in(NEW))
        self.assertFalse(self.can_sign_in(PASSWORD))
        user = CustomUser.objects.get(pk=self.mum.admin.pk)
        self.assertFalse(user.must_change_password)  # their own choice: no forced change
        log = PasswordResetLog.objects.get(user=user)
        self.assertEqual((log.method, log.by), (PasswordResetLog.METHOD_SMS, None))
        # Old sign-ins stop working.
        again = APIClient().post(reverse("token_refresh"), {"refresh": refresh}, format="json")
        self.assertEqual(again.status_code, 401)
        # The code works once.
        self.assertEqual(self.confirm(self.sent_code(), "Another-pass-77").status_code, 400)
        self.assertTrue(self.can_sign_in(NEW))

    def test_wrong_code_is_refused_and_five_tries_kill_the_code(self):
        self.ask()
        code = self.sent_code()
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(parents_sms.MAX_ATTEMPTS):
            response = self.confirm(wrong)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json()["code"], "invalid_code")
        self.assertEqual(SmsResetCode.objects.get().attempts, parents_sms.MAX_ATTEMPTS)
        self.assertEqual(self.confirm(code).status_code, 400)  # now dead
        self.assertTrue(self.can_sign_in(PASSWORD))

    def test_expired_code_and_unknown_login_are_refused_alike(self):
        self.ask()
        code = self.sent_code()
        unknown = self.confirm(code, login_id="PR999999")
        SmsResetCode.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        expired = self.confirm(code)
        self.assertEqual((unknown.status_code, expired.status_code), (400, 400))
        self.assertEqual(unknown.json(), expired.json())
        self.assertTrue(self.can_sign_in(PASSWORD))

    def test_only_the_newest_code_counts(self):
        self.ask()
        first = self.sent_code()
        SmsResetCode.objects.update(created_at=timezone.now() - timedelta(minutes=2))
        self.ask()
        second = self.sent_code()
        if first != second:
            self.assertEqual(self.confirm(first).status_code, 400)
        self.assertEqual(self.confirm(second).status_code, 200)

    def test_weak_password_is_refused_and_keeps_the_code(self):
        self.ask()
        response = self.confirm(self.sent_code(), password="123")
        self.assertEqual(response.status_code, 400)
        self.assertIn("new_password", response.json())
        self.assertEqual(SmsResetCode.objects.get().attempts, 0)
        self.assertEqual(self.confirm(self.sent_code()).status_code, 200)

    def test_another_parents_code_does_not_work(self):
        self.ask()
        response = self.confirm(self.sent_code(), login_id=self.far_parent.admin.login_id)
        self.assertEqual(response.status_code, 400)


class ResetLogTests(_SmsFixture):
    def test_office_letter_and_api_resets_are_logged_with_the_admin(self):
        self.client.force_login(self.school_admin)
        self.client.post(reverse("school_parent_reset_password", args=[self.mum.pk]))
        self.client.post(reverse("school_parent_letter", args=[self.mum.pk]), {"language": "uz"})
        api = APIClient()
        api.force_authenticate(user=self.school_admin)
        api.patch(
            reverse("api_admin_parent_detail", args=[self.mum.pk]), {"password": "Another-pass-77"}
        )
        api.patch(reverse("api_admin_parent_detail", args=[self.mum.pk]), {"first_name": "Nodi"})
        logs = PasswordResetLog.objects.filter(user=self.mum.admin).order_by("pk")
        self.assertEqual(
            [(log.method, log.by) for log in logs],
            [
                (PasswordResetLog.METHOD_OFFICE, self.school_admin),
                (PasswordResetLog.METHOD_LETTER, self.school_admin),
                (PasswordResetLog.METHOD_API, self.school_admin),
            ],
        )

    def test_parent_page_lists_the_resets(self):
        self.client.force_login(self.school_admin)
        page = self.client.get(self.detail(self.mum)).content.decode()
        self.assertIn("No password resets yet.", page)
        self.client.post(reverse("school_parent_reset_password", args=[self.mum.pk]))
        page = self.client.get(self.detail(self.mum)).content.decode()
        self.assertNotIn("No password resets yet.", page)
        self.assertIn("school-resets", page)

    def test_log_scope(self):
        self.client.force_login(self.super_admin)
        for parent in (self.mum, self.far_parent):
            self.client.post(reverse("school_parent_reset_password", args=[parent.pk]))
        everything = PasswordResetLog.objects.all()

        def seen(user):
            user = CustomUser.objects.get(pk=user.pk)  # as a request loads it
            return {
                log.user_id for log in branching.filter_password_resets_for_user(user, everything)
            }

        self.assertEqual(seen(self.super_admin), {self.mum.admin.pk, self.far_parent.admin.pk})
        self.assertEqual(seen(self.school_admin), {self.mum.admin.pk})
        self.assertEqual(seen(self.center_admin), set())
        self.assertEqual(seen(self.teacher.admin), set())
        self.assertEqual(seen(self.mum.admin), set())


class LoginSmsTests(_SmsFixture):
    def url(self, parent):
        return reverse("school_parent_login_sms", args=[parent.pk])

    def test_office_sends_the_login_id_and_never_a_password(self):
        self.client.force_login(self.school_admin)
        response = self.client.post(self.url(self.mum))
        self.assertRedirects(response, self.detail(self.mum))
        phone, text = self.send.call_args.args
        self.assertEqual(phone, PHONE)
        self.assertIn(self.login_id, text)
        self.assertIn("/download/", text)
        self.assertTrue(self.can_sign_in(PASSWORD))  # nothing was reset
        self.assertFalse(PasswordResetLog.objects.exists())

    def test_failure_is_shown(self):
        self.send.return_value = False
        self.client.force_login(self.school_admin)
        page = self.client.post(self.url(self.mum), follow=True).content.decode()
        self.assertIn("The SMS was not sent.", page)

    def test_access(self):
        self.client.force_login(self.school_admin)
        self.assertEqual(self.client.get(self.url(self.mum)).status_code, 405)
        self.assertEqual(self.client.post(self.url(self.far_parent)).status_code, 404)
        for user in (self.center_admin,):
            self.client.force_login(user)
            self.assertEqual(self.client.post(self.url(self.mum)).status_code, 404)
        for user in (self.teacher.admin, self.mum.admin):
            self.client.force_login(user)
            self.assertNotEqual(self.client.post(self.url(self.mum)).status_code, 200)
        self.client.logout()
        self.assertEqual(self.client.post(self.url(self.mum)).status_code, 302)
        self.send.assert_not_called()
