"""Static checks for the Iceberg School brand layer (Phase 2 assets).

These guard the plan's core safety property — Learning Center pages must be
untouched — at the file level, independent of brand resolution.
See docs/plans/ICEBERG_SCHOOL_BRAND_PLAN.md sections 5.4 and 7.2.
"""

import re
from pathlib import Path

from django.conf import settings
from django.contrib.staticfiles import finders
from django.test import SimpleTestCase

SCHOOL_PREFIX = 'html[data-brand="school"]'
SCHOOL_LOGOS = [
    "crest-maroon.png",
    "crest-white.png",
    "logo-h-maroon.png",
    "logo-h-white.png",
    "logo-v-maroon.png",
    "logo-v-white.png",
]


def _selectors(css):
    """Yield every selector in ``css`` (comments stripped; @media unwrapped)."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    for match in re.finditer(r"([^{};]+)\{", css):
        prelude = match.group(1).strip()
        if not prelude or prelude.startswith("@"):
            continue
        for selector in prelude.split(","):
            yield " ".join(selector.split())


class SchoolBrandStylesheetTests(SimpleTestCase):
    def setUp(self):
        path = finders.find("dist/css/brand-school.css")
        self.assertIsNotNone(path, "brand-school.css missing from static files")
        self.css = Path(path).read_text(encoding="utf-8")

    def test_every_selector_is_scoped_to_school(self):
        selectors = list(_selectors(self.css))
        self.assertGreater(len(selectors), 50)
        unscoped = [s for s in selectors if not s.startswith(SCHOOL_PREFIX)]
        self.assertEqual(
            unscoped, [], "brand-school.css selectors must start with " + SCHOOL_PREFIX
        )

    def test_never_targets_center_brand(self):
        rules = re.sub(r"/\*.*?\*/", "", self.css, flags=re.S)
        self.assertNotIn('data-brand="center"', rules)

    def test_defines_plan_tokens(self):
        for token, value in [
            ("--brand-primary", "#4C0909"),
            ("--brand-primary-hover", "#7A1F1F"),
            ("--brand-primary-deep", "#2E0505"),
            ("--brand-tint", "#F8F1F0"),
            ("--brand-bg", "#FBF7F6"),
            ("--brand-text", "#1F1515"),
            ("--brand-muted", "#5A4747"),
        ]:
            self.assertRegex(self.css, rf"{re.escape(token)}:\s*{re.escape(value)};")

    def test_defines_design_rule_tokens(self):
        """PD.1: gold highlight, type scale, spacing and shapes (app plan 6.2)."""
        for token, value in [
            ("--brand-gold", "#C9973F"),
            ("--brand-gold-ink", "#8A5A12"),
            ("--brand-gold-soft", "#E9C77E"),
            ("--brand-text-display", "28px"),
            ("--brand-text-title", "22px"),
            ("--brand-text-heading", "18px"),
            ("--brand-text-body", "16px"),
            ("--brand-text-label", "14px"),
            ("--brand-text-caption", "12px"),
            ("--brand-space-xxs", "4px"),
            ("--brand-space-md", "16px"),
            ("--brand-space-xxl", "32px"),
            ("--brand-tap-min", "48px"),
            ("--brand-radius-card", "24px"),
            ("--brand-radius-chip", "14px"),
            ("--brand-radius-sheet", "32px"),
        ]:
            self.assertRegex(self.css, rf"{re.escape(token)}:\s*{re.escape(value)};")
        # Dark mode reads gold text in the soft gold.
        self.assertRegex(self.css, r"--brand-gold-ink:\s*#E9C77E;")


class SchoolBrandLogoTests(SimpleTestCase):
    def test_logo_crops_are_static_files(self):
        for name in SCHOOL_LOGOS:
            with self.subTest(name=name):
                self.assertIsNotNone(finders.find(f"dist/img/brand/school/{name}"))

    def test_logo_crops_match_brand_source(self):
        source = Path(settings.BASE_DIR).parent / "docs" / "brand" / "iceberg-school" / "web"
        if not source.is_dir():
            self.skipTest("docs/brand/iceberg-school/web not present in this checkout")
        for name in SCHOOL_LOGOS:
            with self.subTest(name=name):
                shipped = Path(finders.find(f"dist/img/brand/school/{name}")).read_bytes()
                self.assertEqual(shipped, (source / name).read_bytes())
