"""Payments pages, status labels and amounts in Uzbek and Russian (web audit M2, part 2).

Needs compiled translations: run ``python manage.py compilemessages`` first (CI does).
"""

from datetime import date

from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import translation

from main_app.forms import GroupForm
from main_app.models import Course, Enrollment, Group, Invoice, Student
from main_app.payments import _uzs, format_uzs, format_uzs_number
from main_app.templatetags.uzs import uzs, uzs_plain

PASSWORD = "Pass12345!"


class LabelsTests(SimpleTestCase):
    def test_student_status_and_level_follow_the_language(self):
        statuses = dict(Student.STATUS_CHOICES)
        levels = dict(Student.LEVEL_CHOICES)
        with translation.override("uz"):
            self.assertEqual(str(statuses[Student.STATUS_SUSPENDED]), "Toʻxtatilgan")
            self.assertEqual(str(levels[3]), "3-daraja")
        with translation.override("ru"):
            self.assertEqual(str(statuses[Student.STATUS_INACTIVE]), "Неактивен")
            self.assertEqual(str(levels[3]), "Уровень 3")
        with translation.override("en"):
            self.assertEqual(str(statuses[Student.STATUS_ACTIVE]), "Active")
            self.assertEqual(str(levels[3]), "Level 3")

    def test_invoice_status_follows_the_language(self):
        statuses = dict(Invoice.STATUS_CHOICES)
        with translation.override("uz"):
            self.assertEqual(str(statuses[Invoice.STATUS_PARTIAL]), "Qisman toʻlangan")
        with translation.override("ru"):
            self.assertEqual(str(statuses[Invoice.STATUS_PAID]), "Оплачено")
            self.assertEqual(str(statuses[Invoice.STATUS_DUE]), "К оплате")

    def test_group_form_name_label(self):
        with translation.override("ru"):
            self.assertEqual(str(GroupForm.base_fields["name"].label), "Название")

    def test_uzs_filter_follows_the_language(self):
        with translation.override("ru"):
            self.assertEqual(uzs(1200000), "1.2 млн сум")
            self.assertEqual(uzs(200000), "200 тыс. сум")
            self.assertEqual(uzs_plain(10000000), "10 млн")
            self.assertEqual(format_uzs(3000000), "3 млн сум")
        with translation.override("uz"):
            self.assertEqual(uzs(1200000), "1.2 million soʻm")
            self.assertEqual(uzs(200000), "200 ming soʻm")
        with translation.override("en"):
            self.assertEqual(uzs(200000), "200 ming soʻm")
            self.assertEqual(uzs(200500), "200,500 soʻm")

    def test_stored_text_stays_the_same(self):
        # Notification texts are stored, so they don't follow the admin's language.
        with translation.override("ru"):
            self.assertEqual(format_uzs_number(3000000), "3 million")
            self.assertEqual(_uzs(200000), "200 ming soʻm")


@override_settings(SECURE_SSL_REDIRECT=False)
class PaymentsPagesTranslatedTests(TestCase):
    def setUp(self):
        users = get_user_model().objects
        self.admin = users.create_user(
            email="boss@example.com",
            password=PASSWORD,
            first_name="T",
            last_name="U",
            user_type="1",
        )
        pupil = users.create_user(
            email="pupil@example.com",
            password=PASSWORD,
            first_name="Ali",
            last_name="Valiyev",
            user_type="3",
            login_id="IC000001",
        )
        self.student = Student.objects.get(admin=pupil)
        course = Course.objects.create(name="General English", monthly_fee=600000)
        self.group = Group.objects.create(name="Alpha", course=course)
        Enrollment.objects.create(student=self.student, group=self.group, is_active=True)
        self.client.force_login(self.admin)

    def _use(self, language):
        self.admin.language = language
        self.admin.save(update_fields=["language"])

    def _messages(self, response):
        return [str(m) for m in get_messages(response.wsgi_request)]

    def _generate(self):
        return self.client.post(
            reverse("admin_generate_invoices"), {"month": "2026-10", "due_date": "2026-10-05"}
        )

    def test_page_titles(self):
        self._use("ru")
        titles = {
            "admin_collections": "Поступления",
            "admin_generate_invoices": "Создать счета за месяц",
            "admin_add_invoice": "Добавить разовый счёт",
        }
        for name, title in titles.items():
            with self.subTest(page=name):
                response = self.client.get(reverse(name))
                self.assertEqual(response.context["page_title"], title)
        self._generate()
        invoice = Invoice.objects.get(student=self.student)
        self._use("uz")
        response = self.client.get(reverse("admin_record_payment", args=[invoice.id]))
        self.assertEqual(response.context["page_title"], "Toʻlovni yozish")

    def test_generate_messages(self):
        self._use("ru")
        response = self._generate()
        self.assertIn("Создан 1 счёт за Октябрь 2026.", self._messages(response))
        response = self._generate()
        self.assertIn("1 уже существовал и пропущен.", self._messages(response))

    def test_generate_messages_in_english_keep_the_wording(self):
        self._use("en")
        response = self._generate()
        self.assertIn("Created 1 invoice for October 2026.", self._messages(response))
        response = self._generate()
        self.assertIn("1 already existed and was skipped.", self._messages(response))

    def test_record_payment_and_cancelled_messages(self):
        self._generate()
        invoice = Invoice.objects.get(student=self.student)
        self._use("ru")
        response = self.client.post(
            reverse("admin_record_payment", args=[invoice.id]),
            {"amount": "600000", "method": "cash", "paid_on": "2026-10-05", "note": ""},
        )
        self.assertIn(
            "Записан платёж 600 тыс. сум от Valiyev, Ali. Статус счёта: оплачено.",
            self._messages(response),
        )
        invoice.status = Invoice.STATUS_CANCELLED
        invoice.save(update_fields=["status"])
        self._use("uz")
        response = self.client.get(reverse("admin_record_payment", args=[invoice.id]))
        self.assertIn(
            "Bu hisob-faktura bekor qilingan — unga toʻlov yozib boʻlmaydi.",
            self._messages(response),
        )

    def test_add_invoice_message(self):
        self._use("uz")
        response = self.client.post(
            reverse("admin_add_invoice"),
            {
                "student": self.student.id,
                "month": "2026-11",
                "amount": "100000",
                "discount": "0",
                "due_date": date(2026, 11, 5).isoformat(),
                "note": "",
            },
        )
        self.assertIn("Valiyev, Ali uchun hisob-faktura yaratildi.", self._messages(response))


@override_settings(SECURE_SSL_REDIRECT=False)
class BranchLabelTests(TestCase):
    def test_add_student_branch_label_is_translated(self):
        admin = get_user_model().objects.create_user(
            email="boss@example.com",
            password=PASSWORD,
            first_name="T",
            last_name="U",
            user_type="1",
        )
        admin.language = "ru"
        admin.save(update_fields=["language"])
        self.client.force_login(admin)
        html = self.client.get(reverse("add_student")).content.decode()
        self.assertIn('<label for="id_branch">Филиал / Адрес', html)
        self.assertNotIn('<label for="id_branch">Branch<', html)
