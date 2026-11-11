"""Admin web shell (P3.9, D19): one shell for both brands, the School-only menu
and landing, the avatar menu, and nothing changed for teachers."""

from unittest import mock

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse

from main_app import branching
from main_app.models import Admin, Branch

from .test_school_admin_pages import PASSWORD, _SchoolFixture

ON = dict(SCHOOL_BRAND_ENABLED=True, SECURE_SSL_REDIRECT=False)


@override_settings(**ON)
class AdminShellTests(_SchoolFixture):
    def page(self, user, url=None):
        self.client.force_login(user)
        response = self.client.get(url or reverse("admin_home"))
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def sidebar(self, html):
        return html.split('id="erpnext-sidebar"', 1)[1].split("</aside>", 1)[0]

    # ── who is School-only ────────────────────────────────────────────────
    def test_school_only_admin_helper(self):
        def school_only(user):
            # A fresh user, as on a request (the fixture caches the old profile).
            return branching.is_school_only_admin(get_user_model().objects.get(pk=user.pk))

        self.assertTrue(school_only(self.school_admin))
        self.assertFalse(school_only(self.center_admin))
        self.assertFalse(school_only(self.super_admin))
        mixed = self.branch_admin("mixed@example.com", self.school)
        Admin.objects.get(admin=mixed).branches.add(self.center)
        self.assertFalse(school_only(mixed))
        no_branch = self.branch_admin("none@example.com", self.school)
        Admin.objects.get(admin=no_branch).branches.clear()
        self.assertFalse(school_only(no_branch))
        self.assertFalse(school_only(self.teacher.admin))

    # ── landing ───────────────────────────────────────────────────────────
    def login(self, email):
        return self.client.post(reverse("user_login"), {"email": email, "password": PASSWORD})

    def test_school_only_admin_lands_on_the_school_board(self):
        self.assertRedirects(
            self.login("office@example.com"), reverse("school_board"), fetch_redirect_response=False
        )
        # Already signed in: the login page sends them to the board too.
        response = self.client.get(reverse("login_page"))
        self.assertRedirects(response, reverse("school_board"), fetch_redirect_response=False)

    def test_other_admins_land_on_the_admin_dashboard(self):
        for email in ("center@example.com", "boss@example.com"):
            with self.subTest(email=email):
                self.client.logout()
                self.assertRedirects(
                    self.login(email), reverse("admin_home"), fetch_redirect_response=False
                )

    # ── sidebar ───────────────────────────────────────────────────────────
    def test_school_only_admin_gets_the_short_school_menu(self):
        nav = self.sidebar(self.page(self.school_admin, reverse("school_classes")))
        for name in (
            "school_board",
            "manage_student",
            "manage_staff",
            "school_classes",
            "school_timetable",
            "school_register_report",
            "school_parents",
            "school_bells",
            "school_years",
            "admin_payments",
            "messages",
        ):
            self.assertIn(f'href="{reverse(name)}"', nav, name)
        for name in (
            "manage_group",
            "manage_course",
            "manage_registration_leads",
            "admin_leaderboard_settings",
            "manage_stories",
            "manage_vocabulary_days",
        ):
            self.assertNotIn(f'href="{reverse(name)}"', nav, name)
        self.assertIn('class="sidebar-brand"', nav)
        self.assertIn(f'href="{reverse("school_board")}"', nav.split("nav-section", 1)[0])

    def test_study_center_and_super_admins_keep_the_full_menu(self):
        for user in (self.center_admin, self.super_admin):
            with self.subTest(user=user.email):
                nav = self.sidebar(self.page(user))
                for name in ("manage_group", "manage_course", "manage_registration_leads"):
                    self.assertIn(f'href="{reverse(name)}"', nav, name)
                self.assertIn("Study Center", nav.split("nav-section", 1)[0])

    def test_sidebar_has_no_sign_out_box_for_admins(self):
        html = self.page(self.center_admin)
        self.assertNotIn("sidebar-logout-btn", html)
        self.assertNotIn('class="animated-logout logout-btn"', html)

    # ── topbar ────────────────────────────────────────────────────────────
    def test_avatar_menu_holds_profile_language_theme_and_sign_out(self):
        for user in (self.school_admin, self.center_admin):
            with self.subTest(user=user.email):
                html = self.page(user)
                menu = html.split('class="dropdown-menu dropdown-menu-end admin-account-menu"', 1)[
                    1
                ]
                menu = menu.split("</nav>", 1)[0]
                self.assertIn(f'href="{reverse("profile_hub")}"', menu)
                self.assertIn(f'action="{reverse("set_language")}"', menu)
                self.assertIn('id="navbar-theme-toggle"', menu)
                self.assertIn(f'action="{reverse("user_logout")}"', menu)
                self.assertIn('id="admin-account-btn"', html)
                self.assertIn(">TU<", html)  # initials of the fixture users

    def test_topbar_chip(self):
        self.assertIn('<span class="admin-chip">Center</span>', self.page(self.center_admin))
        self.assertIn('<span class="admin-chip">All branches</span>', self.page(self.super_admin))
        two = self.branch_admin("two@example.com", self.center)
        Admin.objects.get(admin=two).branches.add(Branch.objects.create(name="Center 2"))
        self.assertNotIn("admin-chip", self.page(two))

    # ── shell markers ─────────────────────────────────────────────────────
    def test_admin_pages_load_the_shell_in_both_brands(self):
        school = self.page(self.school_admin, reverse("school_classes"))
        center = self.page(self.center_admin)
        for html, brand in ((school, "school"), (center, "center")):
            self.assertIn(f'data-brand="{brand}" data-shell="admin"', html)
            self.assertIn("dist/css/admin-shell.css", html)
        self.assertIn("family=Fraunces", school)
        self.assertNotIn("family=Fraunces", center)

    def test_teacher_pages_do_not_get_the_shell(self):
        self.client.force_login(self.teacher.admin)
        html = self.client.get(reverse("staff_home")).content.decode()
        self.assertNotIn("data-shell", html)
        self.assertNotIn("admin-shell.css", html)
        self.assertIn("sidebar-logout-btn", html)

    def test_center_admin_pages_run_no_school_only_query(self):
        self.client.force_login(self.center_admin)
        with mock.patch.object(branching, "is_school_only_admin") as helper:
            self.client.get(reverse("admin_home"))
        helper.assert_not_called()


class AdminShellCssTests(_SchoolFixture):
    def test_every_selector_is_scoped_to_the_admin_shell(self):
        import re
        from pathlib import Path

        from django.conf import settings

        css = (Path(settings.BASE_DIR) / "main_app/static/dist/css/admin-shell.css").read_text(
            encoding="utf-8"
        )
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        for block in re.findall(r"([^{}]+)\{[^{}]*\}", css):
            for selector in block.split(","):
                selector = selector.strip()
                if not selector or selector.startswith("@"):
                    continue
                self.assertTrue(selector.startswith('html[data-shell="admin"]'), selector)
