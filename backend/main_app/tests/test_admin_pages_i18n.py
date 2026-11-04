"""Admin pages in Uzbek and Russian (web audit M2, part 1).

Dashboard, Students, Teachers, Groups, Payments and the admin profile, plus a
sample of the success and error messages on those pages. Needs compiled
translations: run ``python manage.py compilemessages`` first (CI does).
"""

from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.test import TestCase, override_settings
from django.urls import reverse

from main_app.models import Course, Enrollment, Group, Staff, Student

PASSWORD = "Pass12345!"

# page -> (uz text, ru text) that must show once the admin picks the language.
PAGES = {
    "admin_home": ("Tezkor amallar", "Быстрые действия"),
    "manage_student": ("Oʻquvchilarni qidirish", "Поиск учеников"),
    "add_student": ("Shaxsiy maʼlumotlar", "Личные данные"),
    "edit_student": ("Oʻquvchini yangilash", "Обновить ученика"),
    "manage_staff": ("Oʻqituvchilarni qidirish", "Поиск учителей"),
    "add_staff": ("Dars biriktirish", "Учебная нагрузка"),
    "edit_staff": ("Oʻqituvchini yangilash", "Обновить учителя"),
    "manage_group": ("Guruhlarni qidirish", "Поиск групп"),
    "add_group": ("Guruhni saqlash", "Сохранить группу"),
    "edit_group": ("Jadval va sigʻim", "Расписание и вместимость"),
    "admin_payments": ("Hisob-fakturalarni yaratish", "Создать счета"),
    "profile_hub": ("Mavzu tanlovi", "Выбор темы"),
}


def _user(email, user_type, **extra):
    return get_user_model().objects.create_user(
        email=email,
        password=PASSWORD,
        first_name="T",
        last_name="U",
        user_type=user_type,
        **extra,
    )


@override_settings(SECURE_SSL_REDIRECT=False)
class AdminPagesTranslatedTests(TestCase):
    def setUp(self):
        self.admin = _user("boss@example.com", "1")
        self.course = Course.objects.create(name="General English")
        teacher = _user("teacher@example.com", "2", login_id="TC000001")
        self.staff = Staff.objects.get(admin=teacher)
        pupil = _user("pupil@example.com", "3", login_id="IC000001")
        self.student = Student.objects.get(admin=pupil)
        self.group = Group.objects.create(name="Alpha", course=self.course, teacher=self.staff)
        self.client.force_login(self.admin)

    def _url(self, name):
        args = {
            "edit_student": [self.student.id],
            "edit_staff": [self.staff.id],
            "edit_group": [self.group.id],
        }.get(name, [])
        return reverse(name, args=args)

    def _use(self, language):
        self.admin.language = language
        self.admin.save(update_fields=["language"])

    def test_pages_render_in_uzbek_and_russian(self):
        for index, language in enumerate(("uz", "ru")):
            self._use(language)
            for name, texts in PAGES.items():
                with self.subTest(page=name, language=language):
                    response = self.client.get(self._url(name))
                    self.assertEqual(response.status_code, 200)
                    self.assertContains(response, texts[index])

    def test_english_stays_the_same(self):
        self._use("en")
        html = self.client.get(reverse("admin_home")).content.decode()
        self.assertIn("Quick Actions", html)
        self.assertIn("Welcome back, T U", html)
        html = self.client.get(reverse("manage_group")).content.decode()
        self.assertIn("Search groups", html)

    def test_form_labels_and_counts_are_translated(self):
        self._use("ru")
        html = self.client.get(reverse("add_student")).content.decode()
        self.assertIn("Номер телефона", html)
        self.assertIn("— Выберите программу —", html)
        Enrollment.objects.create(student=self.student, group=self.group)
        html = self.client.get(reverse("manage_group")).content.decode()
        self.assertIn("1 ученик", html)
        self._use("uz")
        html = self.client.get(reverse("add_group")).content.decode()
        self.assertIn("Filial / Manzil", html)
        html = self.client.get(reverse("admin_home")).content.decode()
        self.assertIn("Xush kelibsiz, T U", html)

    def _messages(self, response):
        return [str(m) for m in get_messages(response.wsgi_request)]

    def test_messages_are_translated(self):
        self._use("ru")
        response = self.client.post(self._url("edit_student"), {})
        self.assertIn("Заполните форму правильно!", self._messages(response))

        Enrollment.objects.create(student=self.student, group=self.group)
        self._use("uz")
        response = self.client.post(reverse("delete_group", args=[self.group.id]))
        text = " ".join(self._messages(response))
        self.assertIn("guruhini oʻchirib boʻlmaydi", text)
        self.assertIn("1 ta roʻyxatga olish", text)

        empty = Group.objects.create(name="Beta", course=self.course, teacher=self.staff)
        self._use("ru")
        response = self.client.post(reverse("delete_group", args=[empty.id]))
        self.assertIn("Группа «Beta» удалена.", self._messages(response))
