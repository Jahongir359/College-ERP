"""
Null out the `image` field for DashboardStory rows whose underlying file
is missing on disk. Safe to run repeatedly; never touches stories that
have a valid file.

Why this exists:
    On ephemeral filesystems (DigitalOcean App Platform without persistent
    storage attached), any uploaded file gets wiped on redeploy. The DB
    row keeps pointing at the now-missing path, which then renders as a
    broken-image icon in the browser. This command resets those rows so
    the dashboard falls back to the emoji + colour cleanly.

    For S3-compatible backends (DigitalOcean Spaces, Amazon S3) we skip
    the check — Django can't ask `.path` of a remote file, and trusting
    the URL is the right call.

Usage:
    python manage.py cleanup_broken_stories          # write changes
    python manage.py cleanup_broken_stories --dry-run
"""
import os

from django.core.management.base import BaseCommand
from main_app.models import DashboardStory


class Command(BaseCommand):
    help = "Reset DashboardStory.image for rows whose file is missing on disk."

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='List broken rows but do not modify the database.',
        )

    def handle(self, *args, **opts):
        dry_run = opts['dry_run']

        stories_with_image = DashboardStory.objects.exclude(image='').exclude(image__isnull=True)
        total = stories_with_image.count()
        if total == 0:
            self.stdout.write('No stories with images — nothing to check.')
            return

        broken = []
        skipped_remote = 0
        for s in stories_with_image:
            try:
                path = s.image.path
            except (NotImplementedError, ValueError, AttributeError):
                # Remote storage backend — trust the URL, skip.
                skipped_remote += 1
                continue
            if not os.path.exists(path):
                broken.append(s)

        if skipped_remote:
            self.stdout.write(self.style.NOTICE(
                f'Skipped {skipped_remote} stories on remote storage (cannot check from here).'
            ))

        if not broken:
            self.stdout.write(self.style.SUCCESS(
                f'All {total} local story files are present. Nothing to fix.'
            ))
            return

        for s in broken:
            self.stdout.write(f'  ✗ #{s.id} "{s.title}" → {s.image.name}')

        if dry_run:
            self.stdout.write(self.style.WARNING(
                f'Dry run: {len(broken)} broken row(s) found — no changes made.'
            ))
            return

        # Wipe just the file reference; keep title/body/emoji/bg intact so the
        # story still renders with its fallback look.
        for s in broken:
            s.image = None
            s.save(update_fields=['image'])

        self.stdout.write(self.style.SUCCESS(
            f'Cleaned {len(broken)} broken story reference(s).'
        ))
