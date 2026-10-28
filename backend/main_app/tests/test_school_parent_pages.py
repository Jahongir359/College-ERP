"""Maktab admin web pages for parents: list, new parent, parent page, link by login ID (P3.3)."""

from django.urls import reverse

from main_app import parents
from main_app.models import CustomUser, Enrollment, Parent, ParentChild

from .test_school_admin_pages import PASSWORD, _SchoolFixture


def _has_password(user, password):
    return CustomUser.objects.get(pk=user.pk).check_password(password)


class _ParentFixture(_SchoolFixture):
    def setUp(self):
        super().setUp()
        self.aziz = self.student("aziz@example.com", "Aziz", self.school)
        Enrollment.objects.create(student=self.aziz, group=self.class_7b, is_active=True)
        self.far_kid = self.student("far@example.com", "Farrux", self.other_school)
        Enrollment.objects.create(student=self.far_kid, group=self.class_far, is_active=True)
        self.mum = parents.create_parent(
            "Nodira", "Karimova", "+998 90 111 22 33", PASSWORD, self.aziz, "mother", True
        )
        self.far_parent = parents.create_parent(
            "Jamshid", "Usmonov", "+998 97 333 10 20", PASSWORD, self.far_kid, "father", True
        )

    def detail(self, parent):
        return reverse("school_parent_detail", args=[parent.pk])

    def post_new(self, **data):
        payload = {
            "action": "new",
            "first_name": "Zarina",
            "last_name": "Hamidova",
            "phone": "+998 90 777 88 99",
            "password": "Strong-pass-42",
            "child-student": self.aziz.pk,
            "child-relation": "guardian",
        }
        payload.update(data)
        return self.client.post(reverse("school_parents"), payload)


class ParentPageAccessTests(_ParentFixture):
    def test_maktab_menu_links_to_parents(self):
        self.client.force_login(self.school_admin)
        self.assertIn(reverse("school_parents"), self.html(reverse("admin_home")))

    def test_branch_admin_sees_only_their_branches_parents(self):
        self.client.force_login(self.school_admin)
        html = self.html(reverse("school_parents"))
        self.assertIn(self.detail(self.mum), html)
        self.assertNotIn(self.detail(self.far_parent), html)
        self.assertNotIn("Jamshid", html)

        self.client.force_login(self.super_admin)
        self.assertIn(self.detail(self.far_parent), self.html(reverse("school_parents")))

    def test_another_branchs_parent_is_404_everywhere(self):
        self.client.force_login(self.school_admin)
        pk, kid = self.far_parent.pk, self.far_kid.pk
        self.assertEqual(self.client.get(self.detail(self.far_parent)).status_code, 404)
        posts = [
            reverse("school_parent_detail", args=[pk]),
            reverse("school_parent_reset_password", args=[pk]),
            reverse("school_parent_delete", args=[pk]),
            reverse("school_parent_child_add", args=[pk]),
            reverse("school_parent_child_edit", args=[pk, kid]),
            reverse("school_parent_child_remove", args=[pk, kid]),
        ]
        for url in posts:
            with self.subTest(url=url):
                self.assertEqual(self.client.post(url, {"first_name": "X"}).status_code, 404)
        self.assertTrue(CustomUser.objects.filter(pk=self.far_parent.admin_id).exists())
        self.assertTrue(_has_password(self.far_parent.admin, PASSWORD))

    def test_other_roles_are_sent_away(self):
        urls = [reverse("school_parents"), self.detail(self.mum)]
        cases = [
            (self.teacher.admin, reverse("staff_home")),
            (self.aziz.admin, reverse("student_home")),
            (self.mum.admin, "/app/"),
        ]
        for user, home in cases:
            self.client.force_login(user)
            for url in urls:
                with self.subTest(user=user.email, url=url):
                    self.assertRedirects(self.client.get(url), home, fetch_redirect_response=False)
        self.client.logout()
        for url in urls:
            with self.subTest(user="anonymous", url=url):
                self.assertIn("login", self.client.get(url)["Location"])

    def test_actions_need_post(self):
        self.client.force_login(self.school_admin)
        for name in ("school_parent_reset_password", "school_parent_delete"):
            with self.subTest(name=name):
                url = reverse(name, args=[self.mum.pk])
                self.assertEqual(self.client.get(url).status_code, 405)


class ParentListPageTests(_ParentFixture):
    def test_list_shows_children_with_class_and_main_contact(self):
        self.client.force_login(self.school_admin)
        html = self.html(reverse("school_parents"))
        self.assertIn(self.mum.admin.login_id, html)
        self.assertIn("Aziz · 7-B", html)
        self.assertIn("fa-star", html)

    def test_search_and_class_filter(self):
        dad = parents.create_parent(
            "Rustam", "Karimov", "+998 93 444 55 66", PASSWORD, self.aziz, "father"
        )
        other = self.student("sardor@example.com", "Sardor", self.school)
        lonely = parents.create_parent(
            "Feruza", "Nazarova", "+998 91 222 77 88", PASSWORD, other, "mother"
        )
        self.client.force_login(self.school_admin)
        url = reverse("school_parents")
        html = self.html(url + "?q=Rustam")
        self.assertIn(self.detail(dad), html)
        self.assertNotIn(self.detail(self.mum), html)
        html = self.html(url + "?q=444 55")
        self.assertIn(self.detail(dad), html)
        html = self.html(url + f"?q={lonely.admin.login_id}")
        self.assertIn(self.detail(lonely), html)
        self.assertNotIn(self.detail(dad), html)
        html = self.html(url + f"?class={self.class_7b.pk}")
        self.assertIn(self.detail(self.mum), html)
        self.assertNotIn(self.detail(lonely), html)
        # Another branch's class is not a valid filter: the list stays unfiltered.
        html = self.html(url + f"?class={self.class_far.pk}")
        self.assertIn(self.detail(lonely), html)
        self.assertNotIn(self.detail(self.far_parent), html)

    def test_children_in_another_branch_show_only_as_a_count(self):
        parents.link_child(self.far_parent, self.aziz, "father")
        self.client.force_login(self.school_admin)
        html = self.html(reverse("school_parents"))
        self.assertIn(self.detail(self.far_parent), html)
        self.assertIn("+1 in another branch", html)
        self.assertNotIn("Farrux", html)
        self.assertNotIn("Farrux", self.html(self.detail(self.far_parent)))

    def test_create_parent_with_first_child(self):
        self.client.force_login(self.school_admin)
        response = self.post_new(**{"child-is_primary": "on"})
        parent = Parent.objects.get(admin__first_name="Zarina")
        self.assertRedirects(response, self.detail(parent), fetch_redirect_response=False)
        self.assertTrue(parent.admin.login_id.startswith("PR"))
        self.assertEqual(parent.admin.user_type, "4")
        link = ParentChild.objects.get(parent=parent)
        self.assertEqual(
            (link.student, link.relation, link.is_primary), (self.aziz, "guardian", True)
        )
        self.assertFalse(ParentChild.objects.get(parent=self.mum).is_primary)
        self.assertTrue(_has_password(parent.admin, "Strong-pass-42"))

    def test_create_refuses_a_used_phone_and_another_branchs_child(self):
        self.client.force_login(self.school_admin)
        html = self.post_new(phone="90 111-22-33").content.decode()
        self.assertIn(self.mum.admin.login_id, html)  # the admin's own parent is named
        html = self.post_new(phone="+998 97 333 10 20").content.decode()
        self.assertNotIn(self.far_parent.admin.login_id, html)  # another branch's is not
        self.assertNotIn("Jamshid", html)
        self.post_new(**{"child-student": self.far_kid.pk})
        self.assertFalse(Parent.objects.filter(admin__first_name="Zarina").exists())


class LinkByLoginTests(_ParentFixture):
    def post_link(self, login_id, phone, student=None):
        return self.client.post(
            reverse("school_parents"),
            {
                "action": "link",
                "link-login_id": login_id,
                "link-phone": phone,
                "link-student": (student or self.aziz).pk,
                "link-relation": "father",
            },
            follow=True,
        )

    def test_matching_login_and_phone_links_the_child(self):
        self.client.force_login(self.school_admin)
        response = self.post_link(self.far_parent.admin.login_id.lower(), "97 333 10 20")
        self.assertRedirects(response, self.detail(self.far_parent))
        self.assertTrue(ParentChild.objects.filter(parent=self.far_parent, student=self.aziz))
        html = response.content.decode()
        self.assertIn("Aziz", html)
        self.assertNotIn("Farrux", html)  # the other branch's child stays hidden

    def test_a_mismatch_says_only_parent_not_found(self):
        self.client.force_login(self.school_admin)
        login = self.far_parent.admin.login_id
        for login_id, phone in [
            (login, "+998 90 000 00 00"),
            ("PR999", "+998 97 333 10 20"),
            ("", ""),
        ]:
            with self.subTest(login_id=login_id, phone=phone):
                html = self.post_link(login_id, phone).content.decode()
                if login_id:
                    self.assertIn("Parent not found", html)
                self.assertNotIn("Jamshid", html)
                self.assertNotIn("Usmonov", html)
                self.assertNotIn(self.detail(self.far_parent), html)
        self.assertFalse(ParentChild.objects.filter(parent=self.far_parent, student=self.aziz))

    def test_only_the_admins_own_children_can_be_linked(self):
        self.client.force_login(self.school_admin)
        self.post_link(self.mum.admin.login_id, self.mum.phone, student=self.far_kid)
        self.assertFalse(ParentChild.objects.filter(parent=self.mum, student=self.far_kid))


class ParentDetailPageTests(_ParentFixture):
    def test_edit_details_keeps_the_password(self):
        self.client.force_login(self.school_admin)
        response = self.client.post(
            self.detail(self.mum),
            {"first_name": "Nodira", "last_name": "Karimova-Ali", "phone": "+998 90 555 00 11"},
        )
        self.assertRedirects(response, self.detail(self.mum), fetch_redirect_response=False)
        self.mum.refresh_from_db()
        self.assertEqual(self.mum.admin.last_name, "Karimova-Ali")
        self.assertEqual(self.mum.phone, "+998 90 555 00 11")
        self.assertTrue(_has_password(self.mum.admin, PASSWORD))

    def test_reset_password_shows_a_new_one_once(self):
        self.client.force_login(self.school_admin)
        response = self.client.post(reverse("school_parent_reset_password", args=[self.mum.pk]))
        self.assertEqual(response.status_code, 200)
        password = response.context["new_password"]
        self.assertGreaterEqual(len(password), 10)
        self.assertIn(password, response.content.decode())
        self.assertTrue(_has_password(self.mum.admin, password))
        self.assertFalse(_has_password(self.mum.admin, PASSWORD))
        # Not kept anywhere: the next page view doesn't show it.
        self.assertNotIn(password, self.html(self.detail(self.mum)))

    def test_link_edit_and_unlink_children(self):
        sister = self.student("madina@example.com", "Madina", self.school)
        self.client.force_login(self.school_admin)
        self.client.post(
            reverse("school_parent_child_add", args=[self.mum.pk]),
            {"child-student": sister.pk, "child-relation": "mother", "child-is_primary": "on"},
        )
        link = ParentChild.objects.get(parent=self.mum, student=sister)
        self.assertTrue(link.is_primary)

        dad = parents.create_parent(
            "Rustam", "Karimov", "+998 93 444 55 66", PASSWORD, sister, "father"
        )
        self.client.post(
            reverse("school_parent_child_edit", args=[dad.pk, sister.pk]),
            {f"l{sister.pk}-relation": "guardian", f"l{sister.pk}-is_primary": "on"},
        )
        dad_link = ParentChild.objects.get(parent=dad, student=sister)
        self.assertEqual((dad_link.relation, dad_link.is_primary), ("guardian", True))
        link.refresh_from_db()
        self.assertFalse(link.is_primary)  # one main contact per child

        response = self.client.post(
            reverse("school_parent_child_remove", args=[self.mum.pk, sister.pk])
        )
        self.assertRedirects(response, self.detail(self.mum), fetch_redirect_response=False)
        self.assertFalse(ParentChild.objects.filter(parent=self.mum, student=sister).exists())

        # Unlinking the admin's last child of a parent goes back to the list.
        response = self.client.post(
            reverse("school_parent_child_remove", args=[self.mum.pk, self.aziz.pk])
        )
        self.assertRedirects(response, reverse("school_parents"), fetch_redirect_response=False)
        self.assertTrue(Parent.objects.filter(pk=self.mum.pk).exists())

    def test_delete_is_refused_while_children_are_in_another_branch(self):
        parents.link_child(self.far_parent, self.aziz, "father")
        self.client.force_login(self.school_admin)
        self.client.post(reverse("school_parent_delete", args=[self.far_parent.pk]))
        self.assertTrue(Parent.objects.filter(pk=self.far_parent.pk).exists())

        response = self.client.post(reverse("school_parent_delete", args=[self.mum.pk]))
        self.assertRedirects(response, reverse("school_parents"), fetch_redirect_response=False)
        self.assertFalse(CustomUser.objects.filter(pk=self.mum.admin_id).exists())
        self.assertTrue(type(self.aziz).objects.filter(pk=self.aziz.pk).exists())


class ParentPageTranslationTests(_ParentFixture):
    def test_parent_pages_in_russian_and_uzbek(self):
        self.client.force_login(self.school_admin)
        for language, words in (
            ("ru", ["Родители", "Новый родитель", "Сбросить пароль"]),
            ("uz", ["Ota-onalar", "Yangi ota-ona", "Parolni tiklash"]),
        ):
            self.client.post(reverse("set_language"), {"language": language, "next": "/"})
            html = self.html(reverse("school_parents")) + self.html(self.detail(self.mum))
            for word in words:
                with self.subTest(language=language, word=word):
                    self.assertIn(word, html)
