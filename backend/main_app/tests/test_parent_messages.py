"""Teacher ↔ parent messages (plan task P2.6): threads per student and teacher,
the access matrix of plan 8.2 and the branching helpers behind it."""

import shutil
import tempfile
from datetime import date

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import IntegrityError, transaction
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from main_app import branching
from main_app.models import (
    Admin,
    Branch,
    ChatMessage,
    ChatThread,
    ClassSubject,
    Enrollment,
    Group,
    Parent,
    ParentChild,
    Session,
    Staff,
    Student,
    Subject,
)
from main_app.school import seed_school_subjects

_OVERRIDES = dict(SECURE_SSL_REDIRECT=False)


def _user(email, user_type, first="T"):
    return get_user_model().objects.create_user(
        email=email, password="Pass12345!", first_name=first, last_name="U", user_type=user_type
    )


def _reload(user):
    return get_user_model().objects.get(pk=user.pk)


class _ParentMessagesFixture:
    """School with 7-B (homeroom and maths Dilnoza, English Kamola) and 4-B
    (homeroom Rustam). Aziza in 7-B has two parents; Bek in 4-B has one."""

    def make_fixture(self):
        self.school = Branch.objects.create(name="School", brand=Branch.BRAND_SCHOOL)
        self.other_school = Branch.objects.create(name="School 2", brand=Branch.BRAND_SCHOOL)
        self.course, _ = seed_school_subjects()
        year = Session.objects.create(
            name="2026–2027", start_year=date(2026, 9, 1), end_year=date(2027, 6, 30)
        )
        self.dilnoza = self.teacher("dilnoza@example.com", "Dilnoza")
        self.kamola = self.teacher("kamola@example.com", "Kamola")
        self.rustam = self.teacher("rustam@example.com", "Rustam")
        self.class_7b = Group.objects.create(
            name="7-B",
            course=self.course,
            branch=self.school,
            kind=Group.KIND_CLASS,
            grade_level=7,
            letter="B",
            session=year,
            teacher=self.dilnoza,
        )
        self.class_4b = Group.objects.create(
            name="4-B",
            course=self.course,
            branch=self.school,
            kind=Group.KIND_CLASS,
            grade_level=4,
            letter="B",
            session=year,
            teacher=self.rustam,
        )
        ClassSubject.objects.create(
            group=self.class_7b,
            subject=Subject.objects.get(course=self.course, name="Matematika"),
            teacher=self.dilnoza,
        )
        ClassSubject.objects.create(
            group=self.class_7b,
            subject=Subject.objects.get(course=self.course, name="Ingliz tili"),
            teacher=self.kamola,
        )

        self.aziza_user = _user("aziza@example.com", "3", "Aziza")
        self.aziza = Student.objects.get(admin=self.aziza_user)
        self.bek = Student.objects.get(admin=_user("bek@example.com", "3", "Bek"))
        self.lonely = Student.objects.get(admin=_user("lonely@example.com", "3", "Lola"))
        for student, group in (
            (self.aziza, self.class_7b),
            (self.bek, self.class_4b),
            (self.lonely, self.class_7b),
        ):
            student.branch = self.school
            student.save()
            Enrollment.objects.create(student=student, group=group)

        self.mum = self.parent("mum@example.com", self.aziza)
        self.dad = self.parent("dad@example.com", self.aziza)
        self.other_parent = self.parent("other@example.com", self.bek)

        self.branch_admin = self.admin("office@example.com", self.school)
        self.other_admin = self.admin("office2@example.com", self.other_school)

    def teacher(self, email, name):
        staff = Staff.objects.get(admin=_user(email, "2", name))
        staff.branch = self.school
        staff.save()
        return staff

    def parent(self, email, child):
        user = _user(email, "4")
        ParentChild.objects.create(parent=Parent.objects.get(admin=user), student=child)
        return user

    def admin(self, email, branch):
        user = _user(email, "1")
        profile = Admin.objects.get(admin=user)
        profile.is_super_admin = False
        profile.save()
        profile.branches.set([branch])
        return user

    def thread(self, student, teacher):
        return ChatThread.objects.create(
            kind=ChatThread.KIND_PARENT, student=student, teacher=teacher
        )


class ParentThreadModelTests(_ParentMessagesFixture, TestCase):
    def setUp(self):
        self.make_fixture()

    def test_one_thread_per_student_and_teacher(self):
        self.thread(self.aziza, self.kamola)
        with self.assertRaises(IntegrityError), transaction.atomic():
            self.thread(self.aziza, self.kamola)
        # Another teacher of the same child gets their own thread.
        self.thread(self.aziza, self.dilnoza)

    def test_message_str_works_for_parent_and_group_threads(self):
        parent_msg = ChatMessage.objects.create(
            thread=self.thread(self.aziza, self.kamola), sender=self.mum, body="Salom"
        )
        self.assertIn("Parents chat", str(parent_msg))
        group_msg = ChatMessage.objects.create(
            thread=self.class_7b.chat_thread, sender=self.dilnoza.admin, body="Hi"
        )
        self.assertIn("7-B", str(group_msg))

    def test_group_threads_still_one_per_group(self):
        self.assertTrue(ChatThread.objects.filter(group=self.class_7b, kind="group").exists())
        self.assertEqual(str(self.thread(self.aziza, self.kamola))[:12], "Parents chat")


class ParentThreadBranchingTests(_ParentMessagesFixture, TestCase):
    def setUp(self):
        self.make_fixture()
        self.kamola_thread = self.thread(self.aziza, self.kamola)
        self.rustam_thread = self.thread(self.bek, self.rustam)

    def visible(self, user):
        return set(
            branching.filter_parent_threads_for_user(_reload(user), ChatThread.objects.all())
        )

    def test_teachers_for_student_are_homeroom_and_subject_teachers(self):
        self.assertEqual(
            set(branching.teachers_for_student(self.aziza)), {self.dilnoza, self.kamola}
        )
        self.assertEqual(set(branching.teachers_for_student(self.bek)), {self.rustam})

    def test_teachers_for_student_ignore_old_and_archived_classes(self):
        Enrollment.objects.filter(student=self.bek).update(is_active=False)
        self.assertFalse(branching.teachers_for_student(self.bek).exists())
        self.class_7b.is_archived = True
        self.class_7b.save()
        self.assertFalse(branching.teachers_for_student(self.aziza).exists())

    def test_who_sees_which_thread(self):
        self.assertEqual(self.visible(self.mum), {self.kamola_thread})
        self.assertEqual(self.visible(self.dad), {self.kamola_thread})
        self.assertEqual(self.visible(self.other_parent), {self.rustam_thread})
        self.assertEqual(self.visible(self.kamola.admin), {self.kamola_thread})
        self.assertEqual(self.visible(self.dilnoza.admin), set())
        self.assertEqual(self.visible(self.aziza_user), set())
        self.assertEqual(self.visible(self.branch_admin), {self.kamola_thread, self.rustam_thread})
        self.assertEqual(self.visible(self.other_admin), set())

    def test_group_threads_are_never_parent_threads(self):
        self.assertNotIn(self.class_7b.chat_thread, self.visible(self.branch_admin))

    def test_only_the_teacher_and_the_parents_post(self):
        thread = self.kamola_thread
        self.assertTrue(branching.user_can_post_in_parent_thread(_reload(self.mum), thread))
        self.assertTrue(branching.user_can_post_in_parent_thread(self.kamola.admin, thread))
        self.assertFalse(branching.user_can_post_in_parent_thread(self.dilnoza.admin, thread))
        self.assertFalse(
            branching.user_can_post_in_parent_thread(_reload(self.other_parent), thread)
        )
        self.assertFalse(
            branching.user_can_post_in_parent_thread(_reload(self.branch_admin), thread)
        )

    def test_subject_teacher_may_message_about_student(self):
        self.assertTrue(branching.user_can_message_about_student(self.kamola.admin, self.aziza))
        self.assertFalse(branching.user_can_message_about_student(self.kamola.admin, self.bek))
        self.assertFalse(branching.user_can_message_about_student(self.aziza_user, self.aziza))


@override_settings(**_OVERRIDES)
class ParentMessagesApiTests(_ParentMessagesFixture, TestCase):
    def setUp(self):
        self.make_fixture()
        self.api = APIClient()

    def as_user(self, user):
        self.api.force_authenticate(user=_reload(user))

    def list_url(self):
        return reverse("api_parent_threads")

    def detail_url(self, thread):
        return reverse("api_parent_thread", args=[thread.pk])

    def contacts_url(self):
        return reverse("api_parent_thread_contacts")

    # ── Access matrix (plan 8.2) ───────────────────────────────────────────

    def test_anonymous_gets_401(self):
        thread = self.thread(self.aziza, self.kamola)
        for method, url in (
            ("get", self.list_url()),
            ("post", self.list_url()),
            ("get", self.contacts_url()),
            ("get", self.detail_url(thread)),
            ("post", self.detail_url(thread)),
        ):
            with self.subTest(method=method, url=url):
                self.assertEqual(getattr(self.api, method)(url).status_code, 401)

    def test_student_gets_403(self):
        thread = self.thread(self.aziza, self.kamola)
        self.as_user(self.aziza_user)
        self.assertEqual(self.api.get(self.list_url()).status_code, 403)
        self.assertEqual(
            self.api.post(
                self.list_url(), {"student": self.aziza.pk, "teacher": self.kamola.pk}
            ).status_code,
            403,
        )
        self.assertEqual(self.api.get(self.contacts_url()).status_code, 403)
        self.assertEqual(self.api.get(self.detail_url(thread)).status_code, 403)
        self.assertEqual(self.api.post(self.detail_url(thread), {"message": "hi"}).status_code, 403)

    def test_parent_of_another_child_gets_404(self):
        thread = self.thread(self.aziza, self.kamola)
        self.as_user(self.other_parent)
        self.assertEqual(self.api.get(self.detail_url(thread)).status_code, 404)
        self.assertEqual(self.api.post(self.detail_url(thread), {"message": "hi"}).status_code, 404)
        self.assertEqual(self.api.get(self.list_url(), {"student": self.aziza.pk}).status_code, 404)
        self.assertEqual(
            self.api.get(self.contacts_url(), {"student": self.aziza.pk}).status_code, 404
        )
        response = self.api.post(
            self.list_url(), {"student": self.aziza.pk, "teacher": self.kamola.pk}
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.api.get(self.list_url()).json()["threads"], [])

    def test_other_teacher_gets_404(self):
        thread = self.thread(self.aziza, self.kamola)
        for teacher in (self.dilnoza, self.rustam):
            self.as_user(teacher.admin)
            with self.subTest(teacher=teacher.admin.first_name):
                self.assertEqual(self.api.get(self.detail_url(thread)).status_code, 404)

    def test_branch_admin_reads_but_does_not_write(self):
        thread = self.thread(self.aziza, self.kamola)
        self.as_user(self.branch_admin)
        response = self.api.get(self.detail_url(thread))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["thread"]["can_post"])
        self.assertEqual(self.api.post(self.detail_url(thread), {"message": "hi"}).status_code, 403)
        self.assertEqual(
            self.api.post(
                self.list_url(), {"student": self.aziza.pk, "teacher": self.kamola.pk}
            ).status_code,
            403,
        )
        self.as_user(self.other_admin)
        self.assertEqual(self.api.get(self.detail_url(thread)).status_code, 404)

    # ── Parents ────────────────────────────────────────────────────────────

    def test_parent_contacts_are_the_child_teachers_homeroom_first(self):
        self.as_user(self.mum)
        response = self.api.get(self.contacts_url())
        self.assertEqual(response.status_code, 200)
        teachers = response.json()["teachers"]
        self.assertEqual([t["id"] for t in teachers], [self.dilnoza.pk, self.kamola.pk])
        self.assertTrue(teachers[0]["is_homeroom"])
        self.assertEqual(teachers[0]["subjects"], ["Matematika"])
        self.assertEqual(teachers[1]["subjects"], ["Ingliz tili"])
        self.assertFalse(teachers[1]["is_homeroom"])
        self.assertEqual(response.json()["student"]["class"]["name"], "7-B")

    def test_parent_opens_one_shared_thread_with_a_teacher(self):
        self.as_user(self.mum)
        body = {"student": self.aziza.pk, "teacher": self.kamola.pk}
        first = self.api.post(self.list_url(), body)
        self.assertEqual(first.status_code, 201)
        self.assertTrue(first.json()["can_post"])
        self.assertEqual(len(first.json()["parents"]), 2)
        again = self.api.post(self.list_url(), body)
        self.assertEqual(again.status_code, 200)
        self.assertEqual(again.json()["id"], first.json()["id"])

        self.as_user(self.dad)
        threads = self.api.get(self.list_url()).json()["threads"]
        self.assertEqual([t["id"] for t in threads], [first.json()["id"]])

    def test_parent_cannot_write_to_a_teacher_who_does_not_teach_the_child(self):
        self.as_user(self.mum)
        response = self.api.post(
            self.list_url(), {"student": self.aziza.pk, "teacher": self.rustam.pk}
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChatThread.objects.filter(kind="parent").exists())

    def test_parent_needs_teacher_and_student(self):
        self.as_user(self.mum)
        self.assertEqual(self.api.post(self.list_url(), {}).status_code, 400)
        self.assertEqual(
            self.api.post(self.list_url(), {"student": self.aziza.pk}).status_code, 400
        )
        self.assertEqual(
            self.api.post(self.list_url(), {"student": "x", "teacher": 1}).status_code, 400
        )

    def test_conversation_and_read_state(self):
        thread = self.thread(self.aziza, self.kamola)
        self.as_user(self.mum)
        sent = self.api.post(self.detail_url(thread), {"message": "  Salom!  "})
        self.assertEqual(sent.status_code, 201)
        self.assertEqual(sent.json()["message"], "Salom!")
        self.assertEqual(sent.json()["sender_role"], "parent")
        self.assertEqual(self.api.post(self.detail_url(thread), {"message": "  "}).status_code, 400)

        self.as_user(self.kamola.admin)
        listed = self.api.get(self.list_url()).json()["threads"]
        self.assertEqual(listed[0]["unread_count"], 1)
        self.assertEqual(listed[0]["last_message"], "Salom!")
        messages = self.api.get(self.detail_url(thread)).json()["messages"]
        self.assertFalse(messages[0]["is_mine"])
        self.assertEqual(self.api.get(self.list_url()).json()["threads"][0]["unread_count"], 0)
        reply = self.api.post(self.detail_url(thread), {"message": "Va alaykum assalom"})
        self.assertEqual(reply.json()["sender_role"], "teacher")

        # The other parent sees both messages, none of them theirs.
        self.as_user(self.dad)
        self.assertEqual(self.api.get(self.list_url()).json()["threads"][0]["unread_count"], 2)
        messages = self.api.get(self.detail_url(thread)).json()["messages"]
        self.assertEqual([m["is_mine"] for m in messages], [False, False])

    def test_parent_with_two_children_filters_by_student(self):
        ParentChild.objects.create(parent=Parent.objects.get(admin=self.mum), student=self.bek)
        self.thread(self.aziza, self.kamola)
        bek_thread = self.thread(self.bek, self.rustam)
        self.as_user(self.mum)
        self.assertEqual(len(self.api.get(self.list_url()).json()["threads"]), 2)
        threads = self.api.get(self.list_url(), {"student": self.bek.pk}).json()["threads"]
        self.assertEqual([t["id"] for t in threads], [bek_thread.pk])
        # Two children: contacts needs to know which one.
        self.assertEqual(self.api.get(self.contacts_url()).status_code, 400)

    # ── Teachers ───────────────────────────────────────────────────────────

    def test_subject_teacher_starts_a_thread_with_the_parents(self):
        self.as_user(self.kamola.admin)
        response = self.api.post(self.list_url(), {"student": self.aziza.pk})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["teacher"]["id"], self.kamola.pk)
        # A teacher can't open a thread in another teacher's name.
        response = self.api.post(
            self.list_url(), {"student": self.aziza.pk, "teacher": self.dilnoza.pk}
        )
        self.assertEqual(response.json()["teacher"]["id"], self.kamola.pk)

    def test_teacher_cannot_message_about_a_student_they_do_not_teach(self):
        self.as_user(self.kamola.admin)
        self.assertEqual(self.api.post(self.list_url(), {"student": self.bek.pk}).status_code, 404)

    def test_student_without_parent_cannot_get_a_thread(self):
        self.as_user(self.dilnoza.admin)
        self.assertEqual(
            self.api.post(self.list_url(), {"student": self.lonely.pk}).status_code, 400
        )

    def test_teacher_contacts_are_their_students_with_parents(self):
        thread = self.thread(self.aziza, self.dilnoza)
        self.as_user(self.dilnoza.admin)
        students = self.api.get(self.contacts_url()).json()["students"]
        self.assertEqual(
            [(s["id"], s["thread_id"]) for s in students], [(self.aziza.pk, thread.pk)]
        )
        self.as_user(self.kamola.admin)
        students = self.api.get(self.contacts_url()).json()["students"]
        self.assertEqual([(s["id"], s["thread_id"]) for s in students], [(self.aziza.pk, None)])

    def test_group_chat_list_is_unchanged(self):
        self.thread(self.aziza, self.dilnoza)
        self.as_user(self.dilnoza.admin)
        threads = self.api.get(reverse("api_messages")).json()["threads"]
        self.assertEqual([t["group_id"] for t in threads], [self.class_7b.pk])


@override_settings(**_OVERRIDES)
class ParentThreadAttachmentTests(_ParentMessagesFixture, TestCase):
    """``chat_attachments/`` is a protected media prefix (media_views.py)."""

    def setUp(self):
        self.media = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.media, ignore_errors=True)
        settings_override = override_settings(MEDIA_ROOT=self.media)
        settings_override.enable()
        self.addCleanup(settings_override.disable)
        self.make_fixture()

    def attachment_url(self, thread, sender):
        msg = ChatMessage.objects.create(
            thread=thread,
            sender=sender,
            attachment=SimpleUploadedFile("note.png", b"PNGDATA"),
        )
        return "/media/" + msg.attachment.name

    def status_for(self, user, url):
        self.client.force_login(_reload(user))
        return self.client.get(url).status_code

    def test_parent_thread_attachment_only_for_its_teacher_and_parents(self):
        url = self.attachment_url(self.thread(self.aziza, self.kamola), self.mum)
        self.assertEqual(self.client.get(url).status_code, 404)
        for user in (self.kamola.admin, self.mum, self.dad, self.branch_admin):
            with self.subTest(user=user.email):
                self.assertEqual(self.status_for(user, url), 200)
        for user in (
            self.other_parent,
            self.dilnoza.admin,
            self.rustam.admin,
            self.aziza_user,
            self.other_admin,
        ):
            with self.subTest(user=user.email):
                self.assertEqual(self.status_for(user, url), 404)

    def test_group_chat_attachment_is_unchanged(self):
        url = self.attachment_url(self.class_7b.chat_thread, self.dilnoza.admin)
        self.assertEqual(self.status_for(self.dilnoza.admin, url), 200)
        self.assertEqual(self.status_for(self.aziza_user, url), 200)
        self.assertEqual(self.status_for(self.mum, url), 404)
        self.assertEqual(self.status_for(self.rustam.admin, url), 404)
