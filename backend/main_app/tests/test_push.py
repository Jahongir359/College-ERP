"""Push notifications through FCM HTTP v1 (P2.8). The HTTP call is always mocked."""

import json
from unittest import mock

import requests
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from main_app import push
from main_app.models import (
    ChatMessage,
    ChatThread,
    Course,
    DeviceToken,
    Enrollment,
    Group,
    Notification,
    Parent,
    ParentChild,
    Staff,
    Student,
)

FAKE_ACCOUNT = json.dumps({"type": "service_account", "project_id": "iceberg-test"})
PUSH_ON = dict(
    FCM_SERVICE_ACCOUNT_JSON=FAKE_ACCOUNT, FCM_SEND_INLINE=True, SECURE_SSL_REDIRECT=False
)


def _response(status_code=200, body=None):
    response = mock.Mock(status_code=status_code, text=json.dumps(body or {}))
    response.json.return_value = body or {}
    return response


def _make_user(email, user_type, login_id=None, language=""):
    user = get_user_model().objects.create_user(
        email=email,
        password="Pass123!",
        first_name="Push",
        last_name="User",
        user_type=user_type,
        gender="M",
        address="",
        profile_pic="",
        login_id=login_id,
    )
    if language:
        user.language = language
        user.save(update_fields=["language"])
    return user


class PushTestCase(TestCase):
    def setUp(self):
        token_patch = mock.patch.object(push, "_access_token", return_value="oauth-token")
        token_patch.start()
        self.addCleanup(token_patch.stop)
        post_patch = mock.patch.object(push, "_post", return_value=_response())
        self.post = post_patch.start()
        self.addCleanup(post_patch.stop)

    def sent(self):
        """[(token, title, body, data), ...] of every mocked FCM call."""
        out = []
        for call in self.post.call_args_list:
            url, payload, access_token = call.args
            self.assertEqual(
                url, "https://fcm.googleapis.com/v1/projects/iceberg-test/messages:send"
            )
            self.assertEqual(access_token, "oauth-token")
            msg = payload["message"]
            out.append(
                (
                    msg["token"],
                    msg["notification"]["title"],
                    msg["notification"]["body"],
                    msg["data"],
                )
            )
        return out


@override_settings(**PUSH_ON)
class NotificationPushTests(PushTestCase):
    def setUp(self):
        super().setUp()
        self.user = _make_user("push-student@iceberg.internal", "3", "ST91001")
        DeviceToken.objects.create(user=self.user, token="phone-1", platform="android")
        DeviceToken.objects.create(user=self.user, token="tablet-1", platform="ios")

    def test_new_notification_is_pushed_to_every_device_after_commit(self):
        with self.captureOnCommitCallbacks(execute=True):
            n = Notification.objects.create(
                recipient=self.user, category=Notification.ATTENDANCE, message="Absent today"
            )
            self.post.assert_not_called()
        sent = self.sent()
        self.assertEqual({s[0] for s in sent}, {"phone-1", "tablet-1"})
        token, title, body, data = sent[0]
        self.assertEqual((title, body), ("Attendance", "Absent today"))
        self.assertEqual(data, {"type": "notification", "category": "attendance", "id": str(n.pk)})

    def test_bulk_created_notifications_are_pushed(self):
        other = _make_user("push-other@iceberg.internal", "3", "ST91002")
        DeviceToken.objects.create(user=other, token="other-phone")
        with self.captureOnCommitCallbacks(execute=True):
            Notification.objects.bulk_create(
                [
                    Notification(recipient=self.user, message="Homework 1"),
                    Notification(recipient=other, message="Homework 1"),
                ]
            )
        self.assertEqual({s[0] for s in self.sent()}, {"phone-1", "tablet-1", "other-phone"})

    def test_title_uses_the_recipients_language(self):
        ru = _make_user("push-ru@iceberg.internal", "3", "ST91003", language="ru")
        uz = _make_user("push-uz@iceberg.internal", "3", "ST91004", language="uz")
        DeviceToken.objects.create(user=ru, token="ru-phone")
        DeviceToken.objects.create(user=uz, token="uz-phone")
        with self.captureOnCommitCallbacks(execute=True):
            for user in (ru, uz):
                Notification.objects.create(
                    recipient=user, category=Notification.PAYMENT, message="..."
                )
        titles = {s[0]: s[1] for s in self.sent()}
        self.assertEqual(titles["ru-phone"], "Оплата")
        self.assertEqual(titles["uz-phone"], "Toʻlov")

    def test_saving_an_existing_notification_again_does_not_push(self):
        with self.captureOnCommitCallbacks(execute=True):
            n = Notification.objects.create(recipient=self.user, message="Once")
        self.post.reset_mock()
        with self.captureOnCommitCallbacks(execute=True):
            n.is_read = True
            n.save()
        self.post.assert_not_called()

    def test_user_without_devices_gets_nothing(self):
        bare = _make_user("push-bare@iceberg.internal", "3", "ST91005")
        with self.captureOnCommitCallbacks(execute=True):
            Notification.objects.create(recipient=bare, message="Hi")
        self.post.assert_not_called()

    def test_dead_tokens_are_deleted(self):
        self.post.side_effect = [
            _response(404),
            _response(400, {"error": {"details": [{"errorCode": "UNREGISTERED"}]}}),
        ]
        with self.captureOnCommitCallbacks(execute=True):
            Notification.objects.create(recipient=self.user, message="Hi")
        self.assertFalse(DeviceToken.objects.filter(user=self.user).exists())

    def test_other_errors_keep_the_token_and_do_not_raise(self):
        self.post.side_effect = [_response(500), requests.ConnectionError("down")]
        with self.assertLogs("main_app.push", "WARNING") as logs:
            with self.captureOnCommitCallbacks(execute=True):
                Notification.objects.create(recipient=self.user, message="Hi")
        self.assertEqual(len(logs.records), 2)
        self.assertEqual(DeviceToken.objects.filter(user=self.user).count(), 2)

    def test_notify_users_accepts_callables(self):
        with self.captureOnCommitCallbacks(execute=True):
            push.notify_users(
                [self.user], "Title", lambda u: f"Hello {u.first_name}", {"type": "absence"}
            )
        self.assertEqual(
            {s[2] for s in self.sent()},
            {"Hello Push"},
        )
        self.assertEqual(self.sent()[0][3], {"type": "absence"})


class PushDisabledTests(PushTestCase):
    @override_settings(FCM_SERVICE_ACCOUNT_JSON="", FCM_SEND_INLINE=True)
    def test_no_credentials_means_no_push(self):
        user = _make_user("push-off@iceberg.internal", "3", "ST91006")
        DeviceToken.objects.create(user=user, token="phone-off")
        with self.captureOnCommitCallbacks(execute=True):
            Notification.objects.create(recipient=user, message="Hi")
            push.notify_users([user], "T", "B")
        self.post.assert_not_called()

    @override_settings(FCM_SERVICE_ACCOUNT_JSON="", FCM_SEND_INLINE=True)
    def test_no_credentials_still_saves_the_notification_and_warns_once(self):
        user = _make_user("push-off2@iceberg.internal", "3", "ST91007")
        with mock.patch.object(push, "_warned_off", False):
            with self.assertLogs("main_app.push", "WARNING") as logs:
                with self.captureOnCommitCallbacks(execute=True):
                    Notification.objects.create(recipient=user, message="One")
                    Notification.objects.create(recipient=user, message="Two")
        self.assertEqual(len(logs.records), 1)
        self.assertEqual(Notification.objects.filter(recipient=user).count(), 2)

    @override_settings(FCM_SERVICE_ACCOUNT_JSON="{not json", FCM_SEND_INLINE=True)
    def test_broken_credentials_mean_no_push(self):
        with self.assertLogs("main_app.push", "ERROR"):
            self.assertFalse(push.push_enabled())


@override_settings(**PUSH_ON)
class ChatPushTests(PushTestCase):
    def setUp(self):
        super().setUp()
        self.teacher_user = _make_user("push-teacher@iceberg.internal", "2", "TC91001")
        self.teacher = Staff.objects.get(admin=self.teacher_user)
        self.group = Group.objects.create(
            name="Push Group",
            course=Course.objects.create(name="Push Course"),
            teacher=self.teacher,
        )
        self.thread = ChatThread.objects.get(group=self.group)
        self.sender_user = _make_user("push-s1@iceberg.internal", "3", "ST91011")
        self.peer_user = _make_user("push-s2@iceberg.internal", "3", "ST91012")
        self.left_user = _make_user("push-s3@iceberg.internal", "3", "ST91013")
        for user, active in (
            (self.sender_user, True),
            (self.peer_user, True),
            (self.left_user, False),
        ):
            Enrollment.objects.create(
                student=Student.objects.get(admin=user), group=self.group, is_active=active
            )
        for user in (self.teacher_user, self.sender_user, self.peer_user, self.left_user):
            DeviceToken.objects.create(user=user, token=f"dev-{user.login_id}")

    def test_message_reaches_teacher_and_active_classmates_not_sender(self):
        with self.captureOnCommitCallbacks(execute=True):
            ChatMessage.objects.create(thread=self.thread, sender=self.sender_user, body="Hello")
        sent = self.sent()
        self.assertEqual({s[0] for s in sent}, {"dev-TC91001", "dev-ST91012"})
        self.assertEqual(sent[0][1], "Push Group")
        self.assertEqual(sent[0][2], "Push User: Hello")
        self.assertEqual(sent[0][3], {"type": "chat", "group_id": str(self.group.pk)})

    def test_api_send_pushes(self):
        api = APIClient()
        api.force_authenticate(user=self.teacher_user)
        with self.captureOnCommitCallbacks(execute=True):
            response = api.post(
                reverse("api_message_thread", args=[self.group.id]), {"message": "Test tomorrow"}
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual({s[0] for s in self.sent()}, {"dev-ST91011", "dev-ST91012"})


@override_settings(SECURE_SSL_REDIRECT=False)
class FcmTokenApiTests(TestCase):
    def setUp(self):
        self.user = _make_user("push-api@iceberg.internal", "4")
        self.api = APIClient()
        self.api.force_authenticate(user=self.user)
        self.url = reverse("api_fcm_token")

    def test_register_and_forget_token(self):
        response = self.api.post(self.url, {"token": "abc", "platform": "ios"}, format="json")
        self.assertEqual(response.status_code, 200)
        device = DeviceToken.objects.get(token="abc")
        self.assertEqual((device.user, device.platform), (self.user, "ios"))

        response = self.api.delete(self.url, {"token": "abc"}, format="json")
        self.assertEqual(response.status_code, 204)
        self.assertFalse(DeviceToken.objects.filter(token="abc").exists())

    def test_same_token_registered_twice_is_one_row(self):
        self.api.post(self.url, {"token": "abc"}, format="json")
        self.api.post(self.url, {"token": "abc", "platform": "android"}, format="json")
        self.assertEqual(DeviceToken.objects.filter(token="abc").count(), 1)

    def test_token_moves_to_the_user_signed_in_now(self):
        self.api.post(self.url, {"token": "shared-phone"}, format="json")
        other = _make_user("push-api2@iceberg.internal", "4")
        api2 = APIClient()
        api2.force_authenticate(user=other)
        api2.post(self.url, {"token": "shared-phone"}, format="json")
        self.assertEqual(DeviceToken.objects.get(token="shared-phone").user, other)

    def test_cannot_delete_someone_elses_token(self):
        other = _make_user("push-api3@iceberg.internal", "4")
        DeviceToken.objects.create(user=other, token="theirs")
        self.api.delete(self.url, {"token": "theirs"}, format="json")
        self.assertTrue(DeviceToken.objects.filter(token="theirs").exists())

    def test_bad_platform_rejected(self):
        response = self.api.post(self.url, {"token": "abc", "platform": "nokia"}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_requires_login(self):
        response = APIClient().post(self.url, {"token": "abc"}, format="json")
        self.assertEqual(response.status_code, 401)


@override_settings(**PUSH_ON)
class ParentChatPushTests(PushTestCase):
    """Teacher ↔ parent threads (P2.6) have no group: teacher plus the pupil's parents."""

    def setUp(self):
        super().setUp()
        self.teacher_user = _make_user("push-pt-teacher@iceberg.internal", "2", "TC92001")
        self.teacher = Staff.objects.get(admin=self.teacher_user)
        self.pupil_user = _make_user("push-pt-pupil@iceberg.internal", "3", "ST92001")
        self.pupil = Student.objects.get(admin=self.pupil_user)
        self.mum = _make_user("push-pt-mum@iceberg.internal", "4")
        self.dad = _make_user("push-pt-dad@iceberg.internal", "4")
        self.stranger = _make_user("push-pt-other@iceberg.internal", "4")
        for parent in (self.mum, self.dad):
            ParentChild.objects.create(parent=Parent.objects.get(admin=parent), student=self.pupil)
        self.thread = ChatThread.objects.create(
            kind=ChatThread.KIND_PARENT, student=self.pupil, teacher=self.teacher
        )
        for user in (self.teacher_user, self.pupil_user, self.mum, self.dad, self.stranger):
            DeviceToken.objects.create(user=user, token=f"dev-{user.email}")

    def _send(self, sender, body="Hello"):
        with self.captureOnCommitCallbacks(execute=True):
            ChatMessage.objects.create(thread=self.thread, sender=sender, body=body)
        return self.sent()

    def test_parent_message_reaches_teacher_and_other_parent(self):
        sent = self._send(self.mum)
        self.assertEqual(
            {s[0] for s in sent},
            {"dev-push-pt-teacher@iceberg.internal", "dev-push-pt-dad@iceberg.internal"},
        )
        self.assertEqual(sent[0][1], "Push User")
        self.assertEqual(sent[0][3], {"type": "parent_chat", "thread_id": str(self.thread.pk)})

    def test_teacher_message_reaches_both_parents_only(self):
        sent = self._send(self.teacher_user)
        self.assertEqual(
            {s[0] for s in sent},
            {"dev-push-pt-mum@iceberg.internal", "dev-push-pt-dad@iceberg.internal"},
        )

    def test_push_error_never_breaks_saving(self):
        with mock.patch.object(push, "push_chat_message", side_effect=RuntimeError("bug")):
            with self.assertLogs("main_app.push", "ERROR"):
                msg = ChatMessage.objects.create(thread=self.thread, sender=self.mum, body="Hi")
        self.assertTrue(ChatMessage.objects.filter(pk=msg.pk).exists())
        with mock.patch.object(push, "push_notifications", side_effect=RuntimeError("bug")):
            with self.assertLogs("main_app.push", "ERROR"):
                Notification.objects.create(recipient=self.mum, message="Hi")
                Notification.objects.bulk_create([Notification(recipient=self.dad, message="Hi")])
        self.assertEqual(Notification.objects.filter(message="Hi").count(), 2)
