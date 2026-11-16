"""More Study Center admin pages on the Admin UI kit (P3.9d): the group page,
collections and the payment and enrollment forms. Kit markup, no old hero,
Uzbek and Russian text, and other branches stay out of reach."""

from django.urls import reverse
from django.utils import translation

from main_app.models import CustomUser, Invoice

from . import test_admin_center_pages as base


class CenterAdminMorePagesTests(base.CenterAdminPagesTests):
    def page(self, name, *args, lang="en", query=""):
        CustomUser.objects.filter(pk=self.admin_user.pk).update(language=lang)
        response = self.client.get(reverse(name, args=args) + query)
        self.assertEqual(response.status_code, 200, name)
        return response.content.decode()

    def test_group_page_uses_the_kit(self):
        html = self.page("admin_group_detail", self.group.pk)
        self.assertIn('class="ui-table"', html)
        self.assertIn('class="page-eyebrow"', html)
        self.assertNotIn("gd-hero", html)
        self.assertIn("Kamola Test", html)  # the teacher, in the subtitle
        for student in (self.paid, self.late, self.open):
            self.assertIn(student.admin.get_full_name(), html)
        self.assertNotIn(self.far.admin.get_full_name(), html)

    def test_group_page_of_another_branch_is_out_of_reach(self):
        response = self.client.get(reverse("admin_group_detail", args=[self.group_b.pk]))
        self.assertNotEqual(response.status_code, 200)

    def test_collections_uses_the_kit_and_counts_own_branch_only(self):
        html = self.page("admin_collections")
        self.assertIn('class="ui-stats"', html)
        self.assertNotIn("ice-hero", html)
        self.assertNotIn('style="padding', html)
        self.assertIn("IELTS 6.5", html)
        self.assertNotIn("Far group", html)
        self.assertIn("Needs attention: overdue and partial payers", html)
        late = Invoice.objects.get(student=self.late)
        self.assertIn(reverse("admin_record_payment", args=[late.pk]), html)

    def test_form_pages_have_one_title_and_a_translated_button(self):
        late = Invoice.objects.get(student=self.late)
        pages = {
            "uz": {
                ("admin_generate_invoices",): "Hisob-fakturalarni yaratish",
                ("admin_add_invoice",): "Hisob-faktura yaratish",
                ("admin_record_payment", late.pk): "Qolgan qarz",
                ("add_enrollment",): "Oʻquvchini qabul qilish",
            },
            "ru": {
                ("admin_generate_invoices",): "Создать счета",
                ("admin_add_invoice",): "Создать счёт",
                ("admin_record_payment", late.pk): "Остаток",
                ("add_enrollment",): "Зачислить ученика",
            },
        }
        for lang, expected in pages.items():
            for (name, *args), text in expected.items():
                with self.subTest(lang=lang, page=name):
                    html = self.page(name, *args, lang=lang)
                    self.assertIn(text, html)
                    self.assertIn('class="page-eyebrow"', html)
                    self.assertNotIn("page-card-header", html)  # the title is in the page header
                    self.assertIn("pf-submit", html)
        translation.deactivate_all()

    def test_russian_group_page_and_collections(self):
        html = self.page("admin_group_detail", self.group.pk, lang="ru")
        self.assertIn("Зачислить ученика", html)
        self.assertIn("Дата зачисления", html)
        html = self.page("admin_collections", lang="ru")
        self.assertIn("Ожидается", html)
        self.assertIn("Доля сбора", html)
        translation.deactivate_all()

    def test_record_payment_for_another_branch_is_out_of_reach(self):
        far = Invoice.objects.get(student=self.far)
        response = self.client.get(reverse("admin_record_payment", args=[far.pk]))
        self.assertNotEqual(response.status_code, 200)
