"""Demo data for the Iceberg School (plan task P0.6): ``manage.py seed_school_demo``.

Everything lives in its own "Iceberg School (demo)" branch and course, uses
``@demo.iceberg.internal`` emails, ``DEMO-…`` login IDs and phone numbers with
the unused "00" operator code, so it never mixes with or collides with real
families. Re-running finds what exists (by login ID) and adds only what is
missing; it never changes passwords or real data.

Not seeded yet, because the models don't exist: the timetable (P2.1) and marks
(P2.4). Add them here when those tasks land.
"""

from datetime import date
from decimal import Decimal

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from . import parents
from .models import (
    Branch,
    ClassSubject,
    CustomUser,
    Enrollment,
    Group,
    Invoice,
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

# Uzbek school quarters as (month, day) offsets from the year's September start.
QUARTERS = [
    (1, "1-chorak", (0, 9, 2), (0, 10, 31)),
    (2, "2-chorak", (0, 11, 9), (0, 12, 27)),
    (3, "3-chorak", (1, 1, 8), (1, 3, 20)),
    (4, "4-chorak", (1, 3, 30), (1, 5, 25)),
]


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
        group = Group.objects.filter(
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

    # This month's tuition, with a few payments so all invoice states show.
    period = today.replace(day=1)
    result = generate_invoices_for_month(period, due_date=period.replace(day=10), branch=branch)
    counts["invoices"] = len(result["created"])
    invoices = {
        inv.student.admin.login_id: inv
        for inv in Invoice.objects.filter(group__branch=branch, period=period).select_related(
            "student__admin"
        )
    }
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
