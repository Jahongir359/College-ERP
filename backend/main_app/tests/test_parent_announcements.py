"""Class announcements reach parents: stories and notifications (plan task P2.7)."""

from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from main_app import branching
from main_app.models import (
    Admin,
    Branch,
    DashboardStory,
    Enrollment,
    Group,
    Notification,
    Parent,
    ParentChild,
)

from .test_parents import _OVERRIDES, _FamilyFixture, _reload, _user


@override_settings(**_OVERRIDES)
class ParentStoryTests(_FamilyFixture, TestCase):
    """Parents see school-wide stories and those aimed at their children's groups."""

    def setUp(self):
        self.make_fixture()
        self.api = APIClient()
        self.class_8a = Group.objects.create(
            name="8-A",
            course=self.course,
            branch=self.school,
            kind=Group.KIND_CLASS,
            grade_level=8,
            letter="A",
            session=self.year,
        )
        Enrollment.objects.create(student=self.other, group=self.class_8a)
        boss = _user("boss@example.com", "1")
        self.everyone = DashboardStory.objects.create(title="Everyone", created_by=boss)
        self.for_7b = DashboardStory.objects.create(title="7-B trip", created_by=boss)
        self.for_7b.target_groups.set([self.class_7b])
        self.for_8a = DashboardStory.objects.create(title="8-A trip", created_by=boss)
        self.for_8a.target_groups.set([self.class_8a])

    def titles_for(self, user):
        self.api.force_authenticate(user=_reload(user))
        res = self.api.get(reverse("api_stories"))
        self.assertEqual(res.status_code, 200)
        return {story["title"] for story in res.data}

    def test_parent_sees_own_childs_class_and_school_wide(self):
        self.assertEqual(self.titles_for(self.parent_user), {"Everyone", "7-B trip"})

    def test_parent_without_children_sees_only_school_wide(self):
        self.assertEqual(self.titles_for(self.lonely_user), {"Everyone"})

    def test_inactive_enrollment_hides_class_story(self):
        Enrollment.objects.filter(student=self.aziz).update(is_active=False)
        self.assertEqual(self.titles_for(self.parent_user), {"Everyone"})

    def test_student_view_is_unchanged(self):
        self.assertEqual(self.titles_for(self.aziz.admin), {"Everyone", "7-B trip"})
        self.assertEqual(self.titles_for(self.other.admin), {"Everyone", "8-A trip"})


@override_settings(**_OVERRIDES)
class ParentNotificationTests(_FamilyFixture, TestCase):
    """``admin/send-notification/`` reaches parents of the targeted students."""

    def setUp(self):
        self.make_fixture()
        self.api = APIClient()
        self.boss = _user("boss@example.com", "1")
        self.other_parent_user = _user("otherdad@example.com", "4", login_id="PAR0004")
        ParentChild.objects.create(
            parent=Parent.objects.get(admin=self.other_parent_user), student=self.other
        )

        self.center = Branch.objects.create(name="Center")
        self.center_admin = _user("center@example.com", "1")
        profile = Admin.objects.get(admin=self.center_admin)
        profile.is_super_admin = False
        profile.save()
        profile.branches.set([self.center])

    def send(self, user, **data):
        self.api.force_authenticate(user=_reload(user))
        payload = {"title": "Meeting", "body": "Saturday 10:00"} | data
        return self.api.post(reverse("api_admin_send_notification"), payload, format="json")

    def recipients(self):
        return set(Notification.objects.values_list("recipient__email", flat=True))

    def test_class_announcement_reaches_students_and_their_parents(self):
        res = self.send(self.boss, target="all", group_id=self.class_7b.pk)
        self.assertEqual(res.status_code, 201, res.data)
        recipients = self.recipients()
        self.assertTrue({"aziz@example.com", "mum@example.com", "dad@example.com"} <= recipients)
        self.assertFalse({"other@example.com", "otherdad@example.com"} & recipients)
        self.assertEqual(
            set(Notification.objects.values_list("category", flat=True)),
            {Notification.ANNOUNCEMENT},
        )

    def test_parents_target_skips_students(self):
        self.send(self.boss, target="parents", group_id=self.class_7b.pk)
        self.assertEqual(self.recipients(), {"mum@example.com", "dad@example.com"})

    def test_students_target_skips_parents(self):
        self.send(self.boss, target="students", group_id=self.class_7b.pk)
        self.assertEqual(self.recipients(), {"aziz@example.com"})

    def test_parent_with_two_targeted_children_gets_one_notification(self):
        Enrollment.objects.create(student=self.malika, group=self.class_7b)
        self.send(self.boss, target="parents", group_id=self.class_7b.pk)
        self.assertEqual(Notification.objects.filter(recipient=self.parent_user).count(), 1)

    def test_branch_admin_reaches_only_parents_in_their_branches(self):
        self.send(self.center_admin, target="parents")
        self.assertEqual(self.recipients(), set())

    def test_parent_reads_the_announcement(self):
        self.send(self.boss, target="parents", group_id=self.class_7b.pk)
        self.api.force_authenticate(user=_reload(self.parent_user))
        res = self.api.get(reverse("api_notifications"))
        self.assertEqual(res.status_code, 200)
        self.assertEqual([n["message"] for n in res.data["results"]], ["Meeting: Saturday 10:00"])

    def test_parent_cannot_send(self):
        res = self.send(self.parent_user, target="parents")
        self.assertEqual(res.status_code, 403)
        self.assertFalse(Notification.objects.exists())


class ParentUserIdsTests(_FamilyFixture, TestCase):
    def setUp(self):
        self.make_fixture()

    def test_parents_follow_the_given_students(self):
        from main_app.models import Student

        ids = set(branching.parent_user_ids_for_students(Student.objects.filter(pk=self.aziz.pk)))
        self.assertEqual(ids, {self.parent_user.pk, self.one_child_user.pk})
        self.assertEqual(
            set(branching.parent_user_ids_for_students(Student.objects.filter(pk=self.other.pk))),
            set(),
        )
