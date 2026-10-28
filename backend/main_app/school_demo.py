"""Demo data for the Iceberg School (plan task P0.6): ``manage.py seed_school_demo``.

Everything lives in its own "Iceberg School (demo)" branch and course, uses
``@demo.iceberg.internal`` emails, ``DEMO-…`` login IDs and phone numbers with
the unused "00" operator code, so it never mixes with or collides with real
families. Re-running finds what exists (by login ID) and adds only what is
missing; it never changes passwords or real data.

The timetable is a clash-free week: six bell periods and, per class, each
subject as many times as its weekly hours. Not seeded yet, because the model
doesn't exist: marks (P2.4). Add them here when that task lands.
"""

from datetime import date, time
from decimal import Decimal

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from . import parents
from .models import (
    BellPeriod,
    Branch,
    ClassSubject,
    CustomUser,
    Enrollment,
    Group,
    Invoice,
    Lesson,
    ParentChild,
    Payment,
    Session,
    Subject,
    Term,
)
from .payments import generate_invoices_for_month
from .school import seed_school_subjects

DEMO_BRANCH = "Iceberg School (demo)"
DEMO_COURSE = "Iceberg School (demo)"
DEMO_PASSWORD = "Demo12345!"
EMAIL_DOMAIN = "demo.iceberg.internal"
MONTHLY_FEE = Decimal("3000000")

# login suffix, first name, last name, gender
TEACHERS = [
    ("TC01", "Nodira", "Usmonova", "F"),  # homeroom 1-A
    ("TC02", "Jasur", "Karimov", "M"),  # homeroom 7-B, maths
    ("TC03", "Gulnora", "Rahimova", "F"),  # homeroom 11-A, Uzbek and literature
    ("TC04", "Sardor", "Aliyev", "M"),  # English
    ("TC05", "Dilfuza", "Tosheva", "F"),  # sciences
    ("TC06", "Bekzod", "Yusupov", "M"),  # history, PE, informatics
]

# name, grade, letter, homeroom teacher, [(subject, teacher, weekly hours)]
CLASSES = [
    (
        "1-A",
        1,
        "A",
        "TC01",
        [
            ("Ona tili", "TC01", 4),
            ("Oʻqish savodxonligi", "TC01", 4),
            ("Matematika", "TC01", 4),
            ("Ingliz tili", "TC04", 2),
            ("Tabiiy fanlar", "TC01", 1),
            ("Tasviriy sanʼat", "TC01", 1),
            ("Musiqa", "TC01", 1),
            ("Jismoniy tarbiya", "TC06", 2),
        ],
    ),
    (
        "7-B",
        7,
        "B",
        "TC02",
        [
            ("Ona tili", "TC03", 3),
            ("Adabiyot", "TC03", 2),
            ("Algebra", "TC02", 3),
            ("Geometriya", "TC02", 2),
            ("Ingliz tili", "TC04", 3),
            ("Rus tili", "TC03", 2),
            ("Biologiya", "TC05", 2),
            ("Fizika", "TC05", 2),
            ("Geografiya", "TC05", 2),
            ("Oʻzbekiston tarixi", "TC06", 2),
            ("Informatika", "TC06", 1),
            ("Jismoniy tarbiya", "TC06", 2),
        ],
    ),
    (
        "11-A",
        11,
        "A",
        "TC03",
        [
            ("Ona tili", "TC03", 2),
            ("Adabiyot", "TC03", 2),
            ("Algebra", "TC02", 3),
            ("Geometriya", "TC02", 2),
            ("Ingliz tili", "TC04", 3),
            ("Fizika", "TC05", 3),
            ("Kimyo", "TC05", 2),
            ("Biologiya", "TC05", 2),
            ("Jahon tarixi", "TC06", 2),
            ("Huquq", "TC06", 1),
            ("Iqtisodiy bilim asoslari", "TC06", 1),
            ("Informatika", "TC06", 2),
        ],
    ),
]

# login suffix, first, last, gender, class, date of birth
STUDENTS = [
    ("IC01", "Aziz", "Karimov", "M", "1-A", date(2019, 3, 14)),
    ("IC02", "Madina", "Rasulova", "F", "1-A", date(2019, 7, 2)),
    ("IC03", "Temur", "Ismoilov", "M", "1-A", date(2019, 11, 21)),
    ("IC04", "Sevara", "Nazarova", "F", "1-A", date(2019, 5, 9)),
    ("IC05", "Malika", "Karimova", "F", "7-B", date(2013, 4, 18)),
    ("IC06", "Javohir", "Toshmatov", "M", "7-B", date(2013, 9, 30)),
    ("IC07", "Shahzoda", "Ergasheva", "F", "7-B", date(2013, 1, 25)),
    ("IC08", "Otabek", "Saidov", "M", "7-B", date(2013, 6, 12)),
    ("IC09", "Kamola", "Yoqubova", "F", "11-A", date(2009, 2, 7)),
    ("IC10", "Doniyor", "Qodirov", "M", "11-A", date(2009, 10, 15)),
    ("IC11", "Nilufar", "Abdullayeva", "F", "11-A", date(2009, 8, 3)),
    ("IC12", "Sherzod", "Mirzayev", "M", "11-A", date(2009, 12, 19)),
]

# login suffix, first, last, phone, [(student, relation, is_primary)]
# PR01 has two children (child switcher); IC01 has both parents linked.
PARENTS = [
    (
        "PR01",
        "Dilnoza",
        "Karimova",
        "+998 00 000 01 01",
        [("IC01", "mother", True), ("IC05", "mother", True)],
    ),
    ("PR02", "Rustam", "Karimov", "+998 00 000 01 02", [("IC01", "father", False)]),
    ("PR03", "Zarina", "Rasulova", "+998 00 000 01 03", [("IC02", "mother", True)]),
    ("PR04", "Anvar", "Ismoilov", "+998 00 000 01 04", [("IC03", "father", True)]),
    ("PR05", "Feruza", "Nazarova", "+998 00 000 01 05", [("IC04", "mother", True)]),
    ("PR06", "Ulugʻbek", "Toshmatov", "+998 00 000 01 06", [("IC06", "father", True)]),
    ("PR07", "Mohira", "Ergasheva", "+998 00 000 01 07", [("IC07", "mother", True)]),
    ("PR08", "Akmal", "Saidov", "+998 00 000 01 08", [("IC08", "guardian", True)]),
    ("PR09", "Lola", "Yoqubova", "+998 00 000 01 09", [("IC09", "mother", True)]),
    ("PR10", "Bahodir", "Qodirov", "+998 00 000 01 10", [("IC10", "father", True)]),
    ("PR11", "Gulchehra", "Abdullayeva", "+998 00 000 01 11", [("IC11", "mother", True)]),
    ("PR12", "Ravshan", "Mirzayev", "+998 00 000 01 12", [("IC12", "father", True)]),
]

# Uzbek school quarters as (year offset, month, day) from the September start. The real
# 2026–27 dates: classes from 2 Sep, autumn break 4–9 Nov; winter (14 days from ~28 Dec)
# and spring (~19–29 Mar) breaks follow the 2025–26 pattern. See the plan, section 2.1.
QUARTERS = [
    (1, "1-chorak", (0, 9, 2), (0, 11, 3)),
    (2, "2-chorak", (0, 11, 10), (0, 12, 26)),
    (3, "3-chorak", (1, 1, 11), (1, 3, 18)),
    (4, "4-chorak", (1, 3, 30), (1, 5, 25)),
]


# The school day of the design mockups (screen 6): 45-minute lessons, a longer break after the third.
BELLS = [
    (1, time(8, 0), time(8, 45)),
    (2, time(8, 55), time(9, 40)),
    (3, time(9, 50), time(10, 35)),
    (4, time(10, 55), time(11, 40)),
    (5, time(11, 50), time(12, 35)),
    (6, time(12, 45), time(13, 30)),
]
WEEKDAYS = (1, 2, 3, 4, 5, 6)  # Monday to Saturday
# Subjects taught in a shared room; other lessons use the class's own room.
SPECIAL_ROOMS = {"Jismoniy tarbiya": "Sport zali", "Informatika": "Informatika xonasi"}


def _periods_per_day(grade):
    return 4 if grade <= 4 else len(BELLS)


def login_id(suffix):
    return f"DEMO-{suffix}"


def _user(suffix, first, last, user_type, gender="", dob=None, password=DEMO_PASSWORD):
    """Get or create a demo login. Returns (user, created)."""
    lid = login_id(suffix)
    user = CustomUser.objects.filter(login_id=lid).first()
    if user is not None:
        return user, False
    user = CustomUser.objects.create_user(
        email=f"{lid.lower()}@{EMAIL_DOMAIN}",
        password=password,
        user_type=user_type,
        first_name=first,
        last_name=last,
        login_id=lid,
        gender=gender,
        date_of_birth=dob,
    )
    return user, True


def _school_year(today):
    """The current academic year: the marked one, or a new Sep–May year if none."""
    session = Session.current()
    if session is not None:
        return session, False
    start = today.year if today.month >= 8 else today.year - 1
    session = Session.objects.create(
        name=f"{start}–{start + 1}",
        start_year=date(start, 9, 1),
        end_year=date(start + 1, 6, 30),
        is_current=not Session.objects.filter(is_current=True).exists(),
    )
    return session, True


def _quarters(session):
    """Add the four quarters when the year has none (a real year's quarters are kept)."""
    if session.terms.exists():
        return 0
    start = session.start_year.year
    created = 0
    for number, name, (sy, sm, sd), (ey, em, ed) in QUARTERS:
        term = Term(
            session=session,
            number=number,
            name=name,
            start_date=date(start + sy, sm, sd),
            end_date=date(start + ey, em, ed),
        )
        try:
            term.full_clean()
        except ValidationError:
            continue  # the year's dates don't fit the usual quarters; leave it to the admin
        term.save()
        created += 1
    return created


def _bell_periods(branch):
    """The demo branch's bell times. Returns ({number: BellPeriod}, number created)."""
    periods, created = {}, 0
    for number, start, end in BELLS:
        period, was_created = BellPeriod.objects.get_or_create(
            branch=branch, number=number, defaults={"start_time": start, "end_time": end}
        )
        periods[number] = period
        created += was_created
    return periods, created


def _timetable(classes, periods):
    """A clash-free week for each class that has no lessons yet. Returns lessons created.

    Every subject gets its weekly hours, one a day where it can (two at most), on the
    class's lightest day, in the first period where the class, the teacher and any
    shared room are free. Classes that already have lessons (an admin may have
    edited them) are kept.
    """
    busy = set()  # ("class"|"teacher"|"room", id or name, weekday, period number)
    for lesson in Lesson.objects.filter(period__in=periods.values()).select_related(
        "class_subject__subject", "period"
    ):
        slot = (lesson.weekday, lesson.period.number)
        busy.add(("class", lesson.group_id, *slot))
        if lesson.class_subject.teacher_id:
            busy.add(("teacher", lesson.class_subject.teacher_id, *slot))
        room = SPECIAL_ROOMS.get(lesson.class_subject.subject.name)
        if room:
            busy.add(("room", room, *slot))

    created = 0
    for group in classes.values():
        if group.lessons.exists():
            continue
        last = _periods_per_day(group.grade_level)
        todo = [
            cs
            for cs in group.class_subjects.select_related("subject").order_by(
                "-weekly_hours", "subject__name"
            )
            for _ in range(cs.weekly_hours)
        ]
        per_day = {}  # (class subject id, weekday) -> lessons that day
        load = dict.fromkeys(WEEKDAYS, 0)  # lessons this class has each day
        for cs in todo:
            room = SPECIAL_ROOMS.get(cs.subject.name, "")
            # The lightest day first, so every day of the week gets a similar number of lessons.
            days = sorted(WEEKDAYS, key=lambda day: (load[day], day))
            slot = next(
                (
                    (day, number)
                    for limit in (1, 2)
                    for day in days
                    if per_day.get((cs.pk, day), 0) < limit
                    for number in range(1, last + 1)
                    if ("class", group.pk, day, number) not in busy
                    and ("teacher", cs.teacher_id, day, number) not in busy
                    and not (room and ("room", room, day, number) in busy)
                ),
                None,
            )
            if slot is None:  # the week is full for this class or teacher; skip the lesson
                continue
            day, number = slot
            Lesson.objects.create(
                group=group, class_subject=cs, weekday=day, period=periods[number], room=room
            )
            busy.add(("class", group.pk, day, number))
            if cs.teacher_id:
                busy.add(("teacher", cs.teacher_id, day, number))
            if room:
                busy.add(("room", room, day, number))
            per_day[(cs.pk, day)] = per_day.get((cs.pk, day), 0) + 1
            load[day] += 1
            created += 1
    return created


@transaction.atomic
def seed_school_demo(password=DEMO_PASSWORD, today=None):
    """Create (or complete) the demo school. Returns a dict of counts for the report."""
    today = today or timezone.localdate()
    counts = dict.fromkeys(
        (
            "teachers",
            "classes",
            "class_subjects",
            "students",
            "parents",
            "links",
            "invoices",
            "payments",
            "bell_periods",
            "lessons",
        ),
        0,
    )

    branch, _ = Branch.objects.get_or_create(
        name=DEMO_BRANCH, defaults={"brand": Branch.BRAND_SCHOOL}
    )
    if branch.brand != Branch.BRAND_SCHOOL:
        branch.brand = Branch.BRAND_SCHOOL
        branch.save(update_fields=["brand"])
    course, _ = seed_school_subjects(DEMO_COURSE)
    session, session_created = _school_year(today)
    counts["quarters"] = _quarters(session)

    teachers = {}
    for suffix, first, last, gender in TEACHERS:
        user, created = _user(suffix, first, last, "2", gender, password=password)
        staff = user.staff
        if created:
            staff.branch = branch
            staff.course = course
            staff.save(update_fields=["branch", "course"])
            counts["teachers"] += 1
        teachers[suffix] = staff

    subjects = {s.name: s for s in Subject.objects.filter(course=course)}
    classes = {}
    for name, grade, letter, homeroom, plan in CLASSES:
        group = Group.objects.filter(  # scoping-ok: seed data, finds its own demo class
            branch=branch, kind=Group.KIND_CLASS, session=session, name=name
        ).first()
        if group is None:
            group = Group(
                name=name,
                course=course,
                branch=branch,
                kind=Group.KIND_CLASS,
                grade_level=grade,
                letter=letter,
                session=session,
                teacher=teachers[homeroom],
                monthly_fee=MONTHLY_FEE,
                capacity=25,
                room=f"Xona {grade}{letter}",
            )
            group.full_clean()
            group.save()
            counts["classes"] += 1
        classes[name] = group
        for subject_name, teacher, hours in plan:
            subject = subjects.get(subject_name)
            if subject is None:  # renamed or deleted by the school; skip it
                continue
            _, created = ClassSubject.objects.get_or_create(
                group=group,
                subject=subject,
                defaults={"teacher": teachers[teacher], "weekly_hours": hours},
            )
            counts["class_subjects"] += created

    students = {}
    for suffix, first, last, gender, class_name, dob in STUDENTS:
        user, created = _user(suffix, first, last, "3", gender, dob, password=password)
        student = user.student
        if created:
            student.branch = branch
            student.course = course
            student.save(update_fields=["branch", "course"])
            counts["students"] += 1
        group = classes[class_name]
        if not Enrollment.objects.filter(student=student, group=group).exists():
            enrollment = Enrollment(student=student, group=group)
            enrollment.full_clean()
            enrollment.save()
        students[suffix] = student

    for suffix, first, last, phone, children in PARENTS:
        user, created = _user(suffix, first, last, "4", password=password)
        parent = user.parent
        if created:
            parent.phone = phone
            parent.save(update_fields=["phone"])
            counts["parents"] += 1
        for child, relation, is_primary in children:
            student = students[child]
            if not ParentChild.objects.filter(parent=parent, student=student).exists():
                parents.link_child(parent, student, relation, is_primary)
                counts["links"] += 1

    periods, counts["bell_periods"] = _bell_periods(branch)
    counts["lessons"] = _timetable(classes, periods)

    # This month's tuition, with a few payments so all invoice states show.
    period = today.replace(day=1)
    result = generate_invoices_for_month(period, due_date=period.replace(day=10), branch=branch)
    counts["invoices"] = len(result["created"])
    demo_invoices = Invoice.objects.filter(  # scoping-ok: seed data, its own demo invoices
        group__branch=branch, period=period
    ).select_related("student__admin")
    invoices = {inv.student.admin.login_id: inv for inv in demo_invoices}
    for suffix, share in (("IC01", 1), ("IC05", 1), ("IC09", 1), ("IC06", Decimal("0.5"))):
        invoice = invoices.get(login_id(suffix))
        if invoice is None or invoice.payments.exists():
            continue
        Payment.objects.create(
            invoice=invoice,
            amount=(invoice.total_due * share).quantize(Decimal("1")),
            method=Payment.METHOD_CASH,
            paid_on=today,
            note="Demo payment",
        )
        invoice.refresh_status()
        counts["payments"] += 1

    counts["session"] = str(session)
    counts["session_created"] = session_created
    return counts
