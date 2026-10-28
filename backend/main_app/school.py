"""Iceberg School helpers that are not access rules (those live in branching.py)."""

from .models import Course, Subject

SCHOOL_COURSE_NAME = "Iceberg School"

# The usual subjects of an Uzbek general school (grades 1–11). Seeded as plain,
# editable data: the school renames, adds or deletes them in the admin.
STANDARD_SUBJECTS = (
    "Ona tili",
    "Oʻqish savodxonligi",
    "Adabiyot",
    "Matematika",
    "Algebra",
    "Geometriya",
    "Ingliz tili",
    "Rus tili",
    "Tabiiy fanlar",
    "Oʻzbekiston tarixi",
    "Jahon tarixi",
    "Geografiya",
    "Biologiya",
    "Fizika",
    "Kimyo",
    "Informatika",
    "Huquq",
    "Iqtisodiy bilim asoslari",
    "Tarbiya",
    "Texnologiya",
    "Tasviriy sanʼat",
    "Musiqa",
    "Chizmachilik",
    "Jismoniy tarbiya",
)


def seed_school_subjects(course_name=SCHOOL_COURSE_NAME):
    """Create the school course and any missing standard subjects.

    Safe to run again: existing subjects (matched by name) are left as they are.
    Returns ``(course, number_of_subjects_created)``.
    """
    course = Course.objects.filter(name=course_name).order_by("pk").first()
    if course is None:
        course = Course.objects.create(name=course_name)
    existing = set(Subject.objects.filter(course=course).values_list("name", flat=True))
    missing = [name for name in STANDARD_SUBJECTS if name not in existing]
    Subject.objects.bulk_create(Subject(name=name, course=course) for name in missing)
    return course, len(missing)


def school_course():
    """The default School course (created with the standard subjects if missing)."""
    course = Course.objects.filter(name=SCHOOL_COURSE_NAME).order_by("pk").first()
    if course is None:
        course, _ = seed_school_subjects()
    return course
