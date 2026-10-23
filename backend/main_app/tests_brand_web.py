"""Phase 2 web brand layer: data-brand hook, school stylesheet, logos, titles.

The Learning Center must render as before (only data-brand="center" added);
School users get data-brand="school", brand-school.css and the School logo.
See docs/plans/ICEBERG_SCHOOL_BRAND_PLAN.md sections 7 and 10.3.
"""

from django.test import TestCase, override_settings

from .tests_branding import BrandFixtureMixin

SCHOOL_CSS = "dist/css/brand-school.css"
# Sign-in and recovery pages are Phase 3's and use their own stylesheet.
SCHOOL_AUTH_CSS = "dist/css/brand-school-auth.css"
_WEB = dict(SECURE_SSL_REDIRECT=False)


@override_settings(**_WEB)
class BrandWebLayerTests(BrandFixtureMixin, TestCase):
    def _get(self, user, url, **extra):
        if user is not None:
            self.client.force_login(user)
        return self.client.get(url, **extra).content.decode()

    def assertCenter(self, html):
        self.assertIn('data-brand="center"', html)
        self.assertNotIn(SCHOOL_CSS, html)
        self.assertNotIn("brand/school/", html)

    def assertSchool(self, html):
        self.assertIn('data-brand="school"', html)
        self.assertEqual(html.count(SCHOOL_CSS), 1)

    def assertSchoolAuth(self, html):
        self.assertIn('data-brand="school"', html)
        self.assertEqual(html.count(SCHOOL_AUTH_CSS), 1)
        self.assertNotIn(SCHOOL_CSS, html)

    @override_settings(SCHOOL_BRAND_ENABLED=False)
    def test_flag_off_school_student_sees_center(self):
        html = self._get(self.school_student_user, "/student/home/")
        self.assertCenter(html)
        self.assertIn('<span class="navbar-center-name">ICEBERG STUDY CENTER</span>', html)
        self.assertIn('<meta name="theme-color" content="#06343A">', html)
        self.assertIn("Dashboard — Iceberg Study Center", html)

    @override_settings(SCHOOL_BRAND_ENABLED=True)
    def test_flag_on_center_student_unchanged(self):
        html = self._get(self.center_student_user, "/student/home/")
        self.assertCenter(html)
        self.assertIn('src="/static/dist/img/logo.png" alt="ICEBERG"', html)
        self.assertIn('<meta name="theme-color" content="#06343A">', html)

    @override_settings(SCHOOL_BRAND_ENABLED=True)
    def test_school_student_gets_school_layer(self):
        html = self._get(self.school_student_user, "/student/home/")
        self.assertSchool(html)
        self.assertIn('<span class="navbar-center-name">ICEBERG SCHOOL</span>', html)
        self.assertIn(
            'src="/static/dist/img/brand/school/crest-white.png" alt="Iceberg School"', html
        )
        self.assertIn('<meta name="theme-color" content="#4C0909">', html)
        self.assertIn("Dashboard — Iceberg School", html)
        self.assertNotIn("Iceberg Study Center", html.split("</head>")[0])

    @override_settings(SCHOOL_BRAND_ENABLED=True)
    def test_school_css_loads_after_base_inline_styles(self):
        html = self._get(self.school_student_user, "/student/home/")
        head = html.split("</head>")[0]
        # base.html's inline <style> uses !important; the brand sheet must follow it.
        self.assertGreater(
            head.index(SCHOOL_CSS), head.rindex("</style>", 0, head.index(SCHOOL_CSS))
        )

    @override_settings(SCHOOL_BRAND_ENABLED=True)
    def test_school_teacher_and_admin_dashboards(self):
        self.assertSchool(self._get(self.school_teacher_user, "/staff/home/"))
        self.client.logout()
        self.assertSchool(self._get(self.school_admin_user, "/admin/home/"))

    @override_settings(SCHOOL_BRAND_ENABLED=True)
    def test_mixed_branch_admin_stays_center(self):
        self.assertCenter(self._get(self.mixed_admin_user, "/admin/home/"))

    @override_settings(SCHOOL_BRAND_ENABLED=True)
    def test_login_page_brand(self):
        self.assertCenter(self._get(None, "/login/"))
        html = self._get(None, "/login/?brand=school")
        self.assertSchoolAuth(html)
        self.assertIn("<title>Iceberg School — Sign In</title>", html)
        self.assertIn("brand/school/crest-white.png", html)

    @override_settings(SCHOOL_BRAND_ENABLED=True)
    def test_password_recovery_page_brand(self):
        self.assertCenter(self._get(None, "/forgot-password/"))
        html = self._get(None, "/forgot-password/?brand=school")
        self.assertSchoolAuth(html)
        self.assertIn('<div class="brand-sub">SCHOOL</div>', html)

    @override_settings(SCHOOL_BRAND_ENABLED=True, DEBUG=False)
    def test_error_page_brand(self):
        html = self._get(self.school_student_user, "/no-such-page-xyz/")
        self.assertSchool(html)
        self.assertIn("404 · Iceberg School", html)
        self.client.logout()
        self.assertCenter(self._get(None, "/no-such-page-xyz/"))

    @override_settings(SCHOOL_BRAND_ENABLED=True)
    def test_download_page_brand_hook(self):
        self.assertCenter(self._get(None, "/download/"))
        self.assertSchool(self._get(None, "/download/?brand=school"))
