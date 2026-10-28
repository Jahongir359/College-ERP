"""Parents hear when their child is marked absent or late (plan task P2.3)."""

from main_app.models import Notification, Parent, ParentChild

from .test_register import _RegisterFixture, _user


class RegisterNoticeTests(_RegisterFixture):
    def setUp(self):
        super().setUp()
        # Aziz has two parents (``self.parent`` from the fixture and a father);
        # Bekzod has his own; Madina has none.
        self.father = _user("dad@example.com", "4")
        ParentChild.objects.create(parent=Parent.objects.get(admin=self.father), student=self.aziz)
        self.bekzod_parent = _user("bekzodmum@example.com", "4")
        ParentChild.objects.create(
            parent=Parent.objects.get(admin=self.bekzod_parent), student=self.bekzod
        )
        self.far_parent = _user("farmum@example.com", "4")
        ParentChild.objects.create(
            parent=Parent.objects.get(admin=self.far_parent), student=self.far_pupil
        )

    def notices(self):
        return list(
            Notification.objects.order_by("pk").values_list("recipient_id", "category", "message")
        )

    def test_exactly_the_linked_parents_hear_about_an_absence(self):
        res = self.save(self.homeroom.admin, [{"student_id": self.aziz.pk, "status": "absent"}])
        self.assertEqual(res.status_code, 200, res.data)
        day = self.today.strftime("%d.%m.%Y")
        message = f"Aziz Karimov {day} kuni 3-A sinfida darsda boʻlmadi."
        self.assertCountEqual(
            self.notices(),
            [
                (self.parent.pk, Notification.ATTENDANCE, message),
                (self.father.pk, Notification.ATTENDANCE, message),
            ],
        )

    def test_late_notice_names_the_arrival_time(self):
        self.save(
            self.homeroom.admin,
            [
                {"student_id": self.bekzod.pk, "status": "late", "arrival_time": "08:12"},
                {"student_id": self.madina.pk, "status": "absent"},  # no parents linked
            ],
        )
        day = self.today.strftime("%d.%m.%Y")
        self.assertEqual(
            self.notices(),
            [
                (
                    self.bekzod_parent.pk,
                    Notification.ATTENDANCE,
                    f"Bekzod Aliyev {day} kuni 3-A sinfiga kechikib keldi, soat 08:12 da.",
                )
            ],
        )

    def test_late_without_a_time(self):
        self.save(self.homeroom.admin, [{"student_id": self.bekzod.pk, "status": "late"}])
        day = self.today.strftime("%d.%m.%Y")
        self.assertEqual(
            [m for _, _, m in self.notices()],
            [f"Bekzod Aliyev {day} kuni 3-A sinfiga kechikib keldi."],
        )

    def test_saving_the_same_marks_again_sends_nothing_new(self):
        records = [
            {"student_id": self.aziz.pk, "status": "absent"},
            {"student_id": self.bekzod.pk, "status": "late", "arrival_time": "08:12"},
        ]
        self.save(self.homeroom.admin, records)
        self.assertEqual(Notification.objects.count(), 3)
        self.save(self.homeroom.admin, records)
        # A new arrival time or note on the same mark is not a new notice either.
        records[1]["arrival_time"] = "08:20"
        records[0]["note"] = "Kasal"
        self.save(self.homeroom.admin, records)
        self.assertEqual(Notification.objects.count(), 3)

    def test_a_correction_to_present_sends_nothing(self):
        self.save(self.homeroom.admin, [{"student_id": self.bekzod.pk, "status": "late"}])
        Notification.objects.all().delete()
        self.save(self.homeroom.admin, [{"student_id": self.bekzod.pk, "status": "present"}])
        self.save(self.homeroom.admin, [])  # left out means present
        self.assertEqual(Notification.objects.count(), 0)

    def test_a_change_between_late_and_absent_is_a_new_notice(self):
        self.save(self.homeroom.admin, [{"student_id": self.bekzod.pk, "status": "late"}])
        self.save(self.homeroom.admin, [{"student_id": self.bekzod.pk, "status": "absent"}])
        messages = [m for _, _, m in self.notices()]
        self.assertEqual(len(messages), 2)
        self.assertIn("darsda boʻlmadi", messages[1])

    def test_everyone_present_and_refused_saves_send_nothing(self):
        self.save(self.homeroom.admin, [])
        self.save(self.subject_teacher.admin, [{"student_id": self.aziz.pk, "status": "absent"}])
        self.save(self.homeroom.admin, [{"student_id": self.aziz.pk, "status": "nope"}])
        self.assertEqual(Notification.objects.count(), 0)

    def test_parent_reads_the_notice_in_the_app(self):
        self.save(self.homeroom.admin, [{"student_id": self.aziz.pk, "status": "absent"}])
        for parent, count in ((self.parent, 1), (self.bekzod_parent, 0), (self.far_parent, 0)):
            self.as_user(parent)
            res = self.api.get("/api/v1/notifications/")
            self.assertEqual(res.status_code, 200)
            rows = res.data["results"] if isinstance(res.data, dict) else res.data
            self.assertEqual(len(rows), count, parent.email)
