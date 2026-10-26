from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from main_app.messaging import unread_message_count
from main_app.models import (
    ChatMessage,
    ChatReadState,
    ChatThread,
    Course,
    Enrollment,
    Group,
    Staff,
    Student,
)


_BASE_OVERRIDES = dict(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    # Disable SSL redirect so the test client (HTTP) reaches views without
    # being bounced to HTTPS (which then strips POST bodies on 301 redirect).
    SECURE_SSL_REDIRECT=False,
)


class GroupMessagingTests(TestCase):
    def _make_user(self, email, user_type, login_id=None):
        UserModel = get_user_model()
        return UserModel.objects.create_user(
            email=email,
            password="Pass123!",
            first_name="Test",
            last_name="User",
            user_type=user_type,
            gender="M",
            address="",
            profile_pic="",
            login_id=login_id,
        )

    def setUp(self):
        self.admin_user = self._make_user("chat-admin@iceberg.internal", "1")
        self.course = Course.objects.create(name="Messaging Course")

        self.teacher_a_user = self._make_user("chat-ta@iceberg.internal", "2", "TC81001")
        self.teacher_b_user = self._make_user("chat-tb@iceberg.internal", "2", "TC81002")
        self.teacher_a = Staff.objects.get(admin=self.teacher_a_user)
        self.teacher_b = Staff.objects.get(admin=self.teacher_b_user)

        self.group_a = Group.objects.create(
            name="Messaging Group A",
            course=self.course,
            teacher=self.teacher_a,
        )
        self.group_b = Group.objects.create(
            name="Messaging Group B",
            course=self.course,
            teacher=self.teacher_b,
        )

        self.student_a_user = self._make_user("chat-sa@iceberg.internal", "3", "IC81001")
        self.student_b_user = self._make_user("chat-sb@iceberg.internal", "3", "IC81002")
        self.student_a = Student.objects.get(admin=self.student_a_user)
        self.student_b = Student.objects.get(admin=self.student_b_user)
        Enrollment.objects.create(student=self.student_a, group=self.group_a, is_active=True)
        Enrollment.objects.create(student=self.student_b, group=self.group_b, is_active=True)

    def test_group_thread_created_when_group_created(self):
        self.assertTrue(ChatThread.objects.filter(group=self.group_a).exists())
        self.assertTrue(ChatThread.objects.filter(group=self.group_b).exists())

    @override_settings(**_BASE_OVERRIDES)
    def test_messages_mobile_hub_and_conversation_states_render(self):
        self.client.force_login(self.student_a_user)

        hub_response = self.client.get(reverse("messages"))
        self.assertEqual(hub_response.status_code, 200)
        self.assertContains(hub_response, 'class="ice-chat-app is-hub"')
        self.assertContains(hub_response, "Iceberg Chat")
        self.assertContains(hub_response, "Your group conversations and class channels.")
        self.assertContains(hub_response, "Messaging Group A")

        thread_response = self.client.get(reverse("message_thread", args=[self.group_a.id]))
        self.assertEqual(thread_response.status_code, 200)
        self.assertContains(thread_response, 'class="ice-chat-app is-conversation"')
        self.assertContains(thread_response, 'class="ice-chat-back"')

    @override_settings(**_BASE_OVERRIDES)
    def test_student_can_post_to_own_group_and_teacher_reads(self):
        self.client.force_login(self.student_a_user)
        response = self.client.post(
            reverse("message_thread", args=[self.group_a.id]),
            {"body": "Can we review the assignment tomorrow?"},
        )
        self.assertRedirects(
            response,
            reverse("message_thread", args=[self.group_a.id]) + "#latest",
            fetch_redirect_response=False,
        )
        self.assertTrue(
            ChatMessage.objects.filter(
                thread__group=self.group_a,
                sender=self.student_a_user,
                body="Can we review the assignment tomorrow?",
            ).exists()
        )

        self.client.force_login(self.teacher_a_user)
        response = self.client.get(reverse("message_thread", args=[self.group_a.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Can we review the assignment tomorrow?")

    @override_settings(**_BASE_OVERRIDES)
    def test_student_cannot_access_other_group_chat(self):
        self.client.force_login(self.student_a_user)
        response = self.client.get(reverse("message_thread", args=[self.group_b.id]))
        self.assertEqual(response.status_code, 403)

    @override_settings(**_BASE_OVERRIDES)
    def test_admin_can_access_all_group_chats_and_post(self):
        self.client.force_login(self.admin_user)
        response = self.client.post(
            reverse("message_thread", args=[self.group_b.id]),
            {"body": "Schedule update for Group B."},
        )
        self.assertRedirects(
            response,
            reverse("message_thread", args=[self.group_b.id]) + "#latest",
            fetch_redirect_response=False,
        )
        self.assertTrue(
            ChatMessage.objects.filter(
                thread__group=self.group_b,
                sender=self.admin_user,
                body="Schedule update for Group B.",
            ).exists()
        )

    @override_settings(**_BASE_OVERRIDES)
    def test_unread_count_excludes_own_messages_and_clears_on_read(self):
        thread = ChatThread.objects.get(group=self.group_a)
        ChatMessage.objects.create(
            thread=thread,
            sender=self.teacher_a_user,
            body="Please check the new material.",
        )
        ChatReadState.objects.create(thread=thread, user=self.teacher_a_user)

        self.assertEqual(unread_message_count(self.teacher_a_user), 0)
        self.assertEqual(unread_message_count(self.student_a_user), 1)

        self.client.force_login(self.student_a_user)
        response = self.client.get(reverse("message_thread", args=[self.group_a.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(unread_message_count(self.student_a_user), 0)
