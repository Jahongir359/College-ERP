"""Create the "Iceberg School" course and the standard school subjects.

    python manage.py seed_school_subjects
    python manage.py seed_school_subjects --course "Iceberg School Chilonzor"

Safe to run again; subjects that already exist are not touched.
"""

from django.core.management.base import BaseCommand

from main_app.school import SCHOOL_COURSE_NAME, seed_school_subjects


class Command(BaseCommand):
    help = "Create the school course and its standard subject list (editable afterwards)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--course",
            default=SCHOOL_COURSE_NAME,
            help=f'Course that holds the school subjects (default "{SCHOOL_COURSE_NAME}").',
        )

    def handle(self, *args, **options):
        course, created = seed_school_subjects(options["course"])
        self.stdout.write(self.style.SUCCESS(f'"{course.name}": {created} subject(s) added.'))
