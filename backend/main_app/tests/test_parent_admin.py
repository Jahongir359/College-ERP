"""Admin tools for parents: create, edit, link children (plan task P1.7)."""

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from main_app import branching, parents
from main_app.models import Admin, Branch, Parent, ParentChild, Staff, Student
from main_app.school_forms import ParentChildForm, ParentForm

_OVERRIDES = dict(SECURE_SSL_REDIRECT=False)
PASSWORD = "Pass12345!"


def _user(email, user_type, first="T", last="U"):
    return get_user_model().objects.create_user(
        email=email, password=PASSWORD, first_name=first, last_name=last, user_type=user_type
    )


def _reload(user):
    return get_user_model().objects.get(pk=user.pk)


class _Fixture:
    """A School and a Study Center branch, each with an admin and a child."""

    def make_fixture(self):
        self.school = Branch.objects.create(name="School", brand=Branch.BRAND_SCHOOL)
        self.center = Branch.objects.create(name="Center")
        self.super_admin = _user("boss@example.com", "1")
        self.school_admin = self.branch_admin("office@example.com", self.school)
        self.center_admin = self.branch_admin("center@example.com", self.center)
        self.aziz = self.student("aziz@example.com", "Aziz", self.school)
        self.malika = self.student("malika@example.com", "Malika", self.school)
        self.bobur = self.student("bobur@example.com", "Bobur", self.center)

    def branch_admin(self, email, branch):
        user = _user(email, "1")
        profile = Admin.objects.get(admin=user)
        profile.is_super_admin = False
        profile.save()
        profile.branches.set([branch])
        return user

    def student(self, email, first, branch):
        student = Student.objects.get(admin=_user(email, "3", first=first))
        student.branch = branch
        student.save()
        return student

    def make_parent(self, phone="+998 90 111 22 33", child=None, relation="mother"):
        return parents.create_parent(
            first_name="Dilnoza",
            last_name="K",
            phone=phone,
            password=PASSWORD,
            student=child or self.aziz,
            relation=relation,
        )


class ParentServiceTests(_Fixture, TestCase):
    def setUp(self):
        self.make_fixture()

    def test_create_makes_a_parent_login_linked_to_the_child(self):
        parent = self.make_parent()
        user = parent.admin
        self.assertEqual(user.user_type, "4")
        self.assertEqual(user.login_id, "PR500")
        self.assertTrue(user.check_password(PASSWORD))
        self.assertEqual(parent.phone, "+998 90 111 22 33")
        self.assertEqual(list(parent.children.all()), [self.aziz])
        second = self.make_parent(phone="+998 90 999 88 77", child=self.malika)
        self.assertEqual(second.admin.login_id, "PR501")

    def test_parent_can_log_in_with_the_new_login_id(self):
        parent = self.make_parent()
        res = APIClient().post(
            reverse("api_login"),
            {"identifier": parent.admin.login_id, "password": PASSWORD},
            format="json",
            secure=True,
        )
        self.assertEqual(res.status_code, 200, res.data)
        self.assertEqual(res.data["user"]["role"], "parent")

    def test_one_primary_contact_per_child(self):
        mum = self.make_parent()
        dad = self.make_parent(phone="+998 91 000 00 00", relation="father")
        parents.link_child(mum, self.aziz, "mother", is_primary=True)
        parents.link_child(dad, self.aziz, "father", is_primary=True)
        primary = ParentChild.objects.filter(student=self.aziz, is_primary=True)
        self.assertEqual([link.parent for link in primary], [dad])

    def test_phone_match_ignores_formatting(self):
        parent = self.make_parent(phone="+998 (90) 111-22-33")
        self.assertEqual(parents.parent_with_phone("998901112233"), parent)
        self.assertIsNone(parents.parent_with_phone("998901112233", exclude_pk=parent.pk))
        self.assertEqual(parents.parent_with_phone("90 111 22 33"), parent)
        self.assertIsNone(parents.parent_with_phone("123"))


class ParentFormTests(_Fixture, TestCase):
    def setUp(self):
        self.make_fixture()

    def form(self, user, instance=None, **data):
        base = {"first_name": "Dilnoza", "phone": "+998 90 111 22 33", "password": PASSWORD}
        base.update(data)
        return ParentForm(base, user=_reload(user), instance=instance)

    def test_password_required_on_create_and_checked(self):
        self.assertIn("password", self.form(self.school_admin, password="").errors)
        self.assertIn("password", self.form(self.school_admin, password="123").errors)
        self.assertTrue(self.form(self.school_admin).is_valid())

    def test_blank_password_keeps_it_on_edit(self):
        parent = self.make_parent()
        form = self.form(self.school_admin, instance=parent, password="")
        self.assertTrue(form.is_valid(), form.errors)

    def test_duplicate_phone_names_the_parent_when_visible(self):
        parent = self.make_parent()
        errors = self.form(self.school_admin, phone="998901112233").errors["phone"]
        self.assertIn(parent.admin.login_id, errors[0])

    def test_duplicate_phone_hides_the_parent_of_another_branch(self):
        parent = self.make_parent()
        errors = self.form(self.center_admin, phone="998901112233").errors["phone"]
        self.assertNotIn(parent.admin.login_id, errors[0])

    def test_child_choices_are_the_admins_branch_only(self):
        choices = set(ParentChildForm(user=_reload(self.school_admin)).fields["student"].queryset)
        self.assertEqual(choices, {self.aziz, self.malika})
        form = ParentChildForm(
            {"student": self.bobur.pk, "relation": "mother"}, user=_reload(self.school_admin)
        )
        self.assertIn("student", form.errors)


class ParentBranchingTests(_Fixture, TestCase):
    def setUp(self):
        self.make_fixture()
        self.school_parent = self.make_parent()
        self.center_parent = self.make_parent(phone="+998 93 000 00 00", child=self.bobur)

    def visible(self, user):
        return set(branching.filter_parents_for_user(_reload(user), Parent.objects.all()))

    def test_scope_per_role(self):
        both = {self.school_parent, self.center_parent}
        self.assertEqual(self.visible(self.super_admin), both)
        self.assertEqual(self.visible(self.school_admin), {self.school_parent})
        self.assertEqual(self.visible(self.center_admin), {self.center_parent})
        self.assertEqual(self.visible(self.school_parent.admin), {self.school_parent})
        self.assertEqual(self.visible(self.aziz.admin), set())
        self.assertEqual(self.visible(_user("teacher@example.com", "2")), set())

    def test_parent_with_children_in_two_branches_is_seen_by_both(self):
        parents.link_child(self.school_parent, self.bobur, "mother")
        self.assertIn(self.school_parent, self.visible(self.center_admin))
        links = parents.visible_links(_reload(self.center_admin), self.school_parent)
        self.assertEqual([link.student for link in links], [self.bobur])


@override_settings(**_OVERRIDES)
class ParentApiTests(_Fixture, TestCase):
    def setUp(self):
        self.make_fixture()
        self.api = APIClient()

    def as_user(self, user):
        self.api.force_authenticate(user=_reload(user))

    def create(self, **data):
        payload = {
            "first_name": "Dilnoza",
            "last_name": "K",
            "phone": "+998 90 111 22 33",
            "password": PASSWORD,
            "student_id": self.aziz.pk,
            "relation": "mother",
            "is_primary": True,
        }
        payload.update(data)
        return self.api.post(reverse("api_admin_parents"), payload, format="json")

    def detail(self, parent):
        return reverse("api_admin_parent_detail", args=[parent.pk])

    def test_branch_admin_creates_a_parent_with_a_child(self):
        self.as_user(self.school_admin)
        res = self.create()
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(res.data["login_id"], "PR500")
        self.assertEqual(res.data["children"][0]["student_id"], self.aziz.pk)
        self.assertTrue(res.data["children"][0]["is_primary"])
        self.assertFalse(res.data["has_other_children"])
        self.assertNotIn("password", res.data)

    def test_create_rejects_bad_input_without_making_a_login(self):
        self.as_user(self.school_admin)
        res = self.create(student_id=self.bobur.pk, password="123", phone="")
        self.assertEqual(res.status_code, 400)
        self.assertEqual(set(res.data), {"student", "password", "phone"})
        self.assertFalse(Parent.objects.exists())
        self.assertEqual(self.create(relation="uncle").status_code, 400)
        self.assertFalse(Parent.objects.exists())

    def test_duplicate_phone_is_refused(self):
        self.as_user(self.school_admin)
        self.create()
        res = self.create(student_id=self.malika.pk, phone="998901112233")
        self.assertEqual(res.status_code, 400)
        self.assertIn("phone", res.data)
        self.assertEqual(Parent.objects.count(), 1)

    def test_list_is_scoped_and_searchable(self):
        school_parent = self.make_parent()
        self.make_parent(phone="+998 93 000 00 00", child=self.bobur)
        self.as_user(self.school_admin)
        res = self.api.get(reverse("api_admin_parents"))
        self.assertEqual([p["id"] for p in res.data], [school_parent.pk])
        res = self.api.get(reverse("api_admin_parents"), {"search": "PR500"})
        self.assertEqual(len(res.data), 1)
        res = self.api.get(reverse("api_admin_parents"), {"search": "nobody"})
        self.assertEqual(res.data, [])
        self.as_user(self.super_admin)
        self.assertEqual(len(self.api.get(reverse("api_admin_parents")).data), 2)

    def test_edit_and_reset_password(self):
        parent = self.make_parent()
        self.as_user(self.school_admin)
        res = self.api.patch(
            self.detail(parent), {"last_name": "Karimova", "password": "NewPass987!"}, format="json"
        )
        self.assertEqual(res.status_code, 200, res.data)
        self.assertEqual(res.data["last_name"], "Karimova")
        self.assertEqual(res.data["phone"], "+998 90 111 22 33")
        parent.admin.refresh_from_db()
        self.assertTrue(parent.admin.check_password("NewPass987!"))
        res = self.api.patch(self.detail(parent), {"first_name": "Lola"}, format="json")
        parent.admin.refresh_from_db()
        self.assertTrue(parent.admin.check_password("NewPass987!"))

    def test_other_branch_parent_is_not_found(self):
        parent = self.make_parent()
        self.as_user(self.center_admin)
        self.assertEqual(self.api.get(self.detail(parent)).status_code, 404)
        self.assertEqual(
            self.api.patch(self.detail(parent), {"first_name": "X"}, format="json").status_code,
            404,
        )
        self.assertEqual(self.api.delete(self.detail(parent)).status_code, 404)
        url = reverse("api_admin_parent_children", args=[parent.pk])
        res = self.api.post(url, {"student_id": self.bobur.pk}, format="json")
        self.assertEqual(res.status_code, 404)
        self.assertEqual(parent.child_links.count(), 1)

    def test_link_update_and_unlink_children(self):
        parent = self.make_parent()
        self.as_user(self.school_admin)
        url = reverse("api_admin_parent_children", args=[parent.pk])
        res = self.api.post(
            url, {"student_id": self.malika.pk, "relation": "mother"}, format="json"
        )
        self.assertEqual(res.status_code, 201, res.data)
        self.assertEqual(
            {c["student_id"] for c in res.data["children"]}, {self.aziz.pk, self.malika.pk}
        )
        res = self.api.post(url, {"student_id": self.bobur.pk}, format="json")
        self.assertEqual(res.status_code, 400)

        child_url = reverse("api_admin_parent_child_detail", args=[parent.pk, self.malika.pk])
        res = self.api.patch(child_url, {"is_primary": True}, format="json")
        self.assertEqual(res.status_code, 200, res.data)
        self.assertTrue(res.data["is_primary"])
        self.assertEqual(res.data["relation"], "mother")
        res = self.api.patch(child_url, {"is_primary": "false"}, format="json")
        self.assertFalse(res.data["is_primary"])

        self.assertEqual(self.api.delete(child_url).status_code, 204)
        self.assertEqual(list(parent.children.all()), [self.aziz])
        self.assertTrue(get_user_model().objects.filter(pk=parent.admin_id).exists())

    def test_link_by_login_needs_the_matching_phone(self):
        parent = self.make_parent()
        self.as_user(self.center_admin)
        url = reverse("api_admin_parent_link_by_login")
        payload = {"login_id": "pr500", "student_id": self.bobur.pk, "relation": "mother"}
        res = self.api.post(url, {**payload, "phone": "+998 90 000 00 00"}, format="json")
        self.assertEqual(res.status_code, 404)
        self.assertEqual(self.api.post(url, payload, format="json").status_code, 404)
        self.assertEqual(parent.child_links.count(), 1)

        res = self.api.post(url, {**payload, "phone": "998901112233"}, format="json")
        self.assertEqual(res.status_code, 201, res.data)
        # The center admin sees only their own child, and that there are others.
        self.assertEqual([c["student_id"] for c in res.data["children"]], [self.bobur.pk])
        self.assertTrue(res.data["has_other_children"])
        self.assertEqual(set(parent.children.all()), {self.aziz, self.bobur})

    def test_delete_is_refused_while_other_branches_have_children(self):
        parent = self.make_parent()
        parents.link_child(parent, self.bobur, "mother")
        self.as_user(self.center_admin)
        self.assertEqual(self.api.delete(self.detail(parent)).status_code, 403)
        self.assertTrue(Parent.objects.filter(pk=parent.pk).exists())

        self.as_user(self.super_admin)
        self.assertEqual(self.api.delete(self.detail(parent)).status_code, 204)
        self.assertFalse(get_user_model().objects.filter(pk=parent.admin_id).exists())
        self.assertFalse(ParentChild.objects.exists())
        self.assertTrue(Student.objects.filter(pk=self.aziz.pk).exists())

    def test_only_admins_may_use_the_parent_api(self):
        parent = self.make_parent()
        teacher = Staff.objects.get(admin=_user("teacher@example.com", "2")).admin
        urls = [
            reverse("api_admin_parents"),
            self.detail(parent),
            reverse("api_admin_parent_children", args=[parent.pk]),
            reverse("api_admin_parent_child_detail", args=[parent.pk, self.aziz.pk]),
            reverse("api_admin_parent_link_by_login"),
        ]
        for user in (teacher, self.aziz.admin, parent.admin):
            self.as_user(user)
            for url in urls:
                with self.subTest(user=user.email, url=url):
                    self.assertEqual(self.api.get(url).status_code, 403)
                    self.assertEqual(self.api.post(url, {}, format="json").status_code, 403)
        self.api.force_authenticate(user=None)
        for url in urls:
            with self.subTest(user="anonymous", url=url):
                self.assertEqual(self.api.get(url).status_code, 401)
