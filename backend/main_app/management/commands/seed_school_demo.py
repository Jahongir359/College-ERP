"""Seed a demo Iceberg School (plan task P0.6).

    python manage.py seed_school_demo
    python manage.py seed_school_demo --password "Other123!"
    python manage.py seed_school_demo --force      # when DEBUG=False (staging)

Safe to run again: only missing rows are added. Refuses to run when
DEBUG=False unless --force, so it isn't run on production by accident.
"""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from main_app.school_demo import DEMO_BRANCH, DEMO_PASSWORD, seed_school_demo


class Command(BaseCommand):
    help = "Create a demo school branch with classes, teachers, students, parents and invoices."

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Run even when DEBUG=False (for a staging server, never production).",
        )
        parser.add_argument(
            "--password",
            default=DEMO_PASSWORD,
            help="Password for new demo logins (existing logins keep theirs).",
        )

    def handle(self, *args, **options):
        if not settings.DEBUG and not options["force"]:
            raise CommandError(
                "DEBUG is off, so this may be production. Use --force on a staging server."
            )
        counts = seed_school_demo(password=options["password"])
        year = counts["session"] + (" (new)" if counts["session_created"] else "")
        self.stdout.write(self.style.SUCCESS(f'"{DEMO_BRANCH}" ready. Academic year: {year}.'))
        self.stdout.write(
            "Added: {teachers} teachers, {classes} classes, {class_subjects} class subjects, "
            "{students} students, {parents} parents, {links} parent links, {quarters} quarters, "
            "{invoices} invoices, {payments} payments.".format(**counts)
        )
        self.stdout.write(
            "Logins: teachers DEMO-TC01…TC06, students DEMO-IC01…IC12, parents "
            "DEMO-PR01…PR12 (DEMO-PR01 has two children). New logins use the --password value."
        )
        self.stdout.write("Not seeded yet: timetable (P2.1) and marks (P2.4).")
