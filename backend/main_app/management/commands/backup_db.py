"""
Back up the database to a file (plan task P0.7).

Usage:
    python manage.py backup_db
    python manage.py backup_db --output-dir /backups --keep 14

PostgreSQL is dumped with ``pg_dump --format=custom`` (restore with
``pg_restore``); SQLite is copied with SQLite's online backup API, so the copy
is consistent even while the app is running. Files are named
``iceberg-db-<YYYYmmdd-HHMMSS>.dump`` / ``.sqlite3`` and written to
``--output-dir``, else ``$BACKUP_DIR``, else ``backend/backups/``. A file only
gets its final name once it is complete.

``--keep N`` (or ``$BACKUP_KEEP``) deletes all but the newest N backups in that
directory; 0 (the default) keeps everything. The command exits non-zero on any
failure so a cron job or systemd timer reports it. Scheduling it and copying
the files off the server are described in docs/DEPLOYMENT.md.
"""

import os
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.utils import timezone

PREFIX = "iceberg-db-"
BACKUP_NAME = re.compile(rf"^{PREFIX}\d{{8}}-\d{{6}}\.(dump|sqlite3)$")


def default_output_dir():
    return Path(os.environ.get("BACKUP_DIR") or (Path(settings.BASE_DIR) / "backups"))


def pg_dump_command(db, target, pg_dump="pg_dump"):
    """``(args, env)`` to dump the database described by ``db`` (a Django
    DATABASES entry) into ``target``. The password goes in the environment,
    never on the command line."""
    args = [pg_dump, "--format=custom", "--no-owner", "--no-acl", f"--file={target}"]
    if db.get("HOST"):
        args.append(f"--host={db['HOST']}")
    if db.get("PORT"):
        args.append(f"--port={db['PORT']}")
    if db.get("USER"):
        args.append(f"--username={db['USER']}")
    args.append(str(db["NAME"]))

    env = dict(os.environ)
    if db.get("PASSWORD"):
        env["PGPASSWORD"] = str(db["PASSWORD"])
    sslmode = (db.get("OPTIONS") or {}).get("sslmode")
    if sslmode:
        env["PGSSLMODE"] = str(sslmode)
    return args, env


def rotate(directory, keep):
    """Delete all but the newest ``keep`` backups in ``directory``; return the
    deleted paths. Only files this command names are touched."""
    if keep <= 0:
        return []
    backups = sorted(p for p in directory.iterdir() if BACKUP_NAME.match(p.name))
    old = backups[:-keep]
    for path in old:
        path.unlink()
    return old


class Command(BaseCommand):
    help = "Back up the database (pg_dump for PostgreSQL, a file copy for SQLite)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--output-dir",
            help="Directory for the backup (default: $BACKUP_DIR, else backend/backups/).",
        )
        parser.add_argument(
            "--keep",
            type=int,
            default=int(os.environ.get("BACKUP_KEEP") or 0),
            help="Keep only the newest N backups in the directory (default: $BACKUP_KEEP, "
            "else 0 = keep all).",
        )
        parser.add_argument(
            "--pg-dump",
            default=os.environ.get("PG_DUMP") or "pg_dump",
            help="pg_dump binary; its major version must be >= the server's "
            "(default: $PG_DUMP, else pg_dump on PATH).",
        )

    def handle(self, *args, **options):
        if options["keep"] < 0:
            raise CommandError("--keep must be 0 or more.")
        directory = Path(options["output_dir"]) if options["output_dir"] else default_output_dir()
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise CommandError(f"Can't create backup directory {directory}: {exc}") from exc

        vendor = connection.vendor
        stamp = timezone.now().strftime("%Y%m%d-%H%M%S")
        if vendor == "postgresql":
            target = directory / f"{PREFIX}{stamp}.dump"
        elif vendor == "sqlite":
            target = directory / f"{PREFIX}{stamp}.sqlite3"
        else:
            raise CommandError(f"Backups are not supported for the {vendor} database.")
        partial = target.with_name(target.name + ".partial")

        try:
            if vendor == "postgresql":
                self._dump_postgres(partial, options["pg_dump"])
            else:
                self._copy_sqlite(partial)
            partial.replace(target)
        except BaseException:
            partial.unlink(missing_ok=True)
            raise

        size_kb = target.stat().st_size / 1024
        self.stdout.write(self.style.SUCCESS(f"Backup written: {target} ({size_kb:.0f} KB)"))
        for path in rotate(directory, options["keep"]):
            self.stdout.write(f"Deleted old backup: {path.name}")

    def _dump_postgres(self, target, pg_dump):
        if shutil.which(pg_dump) is None:
            raise CommandError(
                f"{pg_dump} not found. Install the PostgreSQL client (same major version "
                "as the server or newer) or pass --pg-dump / set PG_DUMP."
            )
        args, env = pg_dump_command(connection.settings_dict, target, pg_dump)
        result = subprocess.run(args, env=env, capture_output=True, text=True)
        if result.returncode != 0:
            message = f"pg_dump failed ({result.returncode}): {result.stderr.strip()}"
            if "version mismatch" in result.stderr:
                message += (
                    "\npg_dump is older than the server: use a pg_dump with the server's "
                    "major version or newer (--pg-dump / PG_DUMP)."
                )
            raise CommandError(message)

    def _copy_sqlite(self, target):
        if connection.in_atomic_block:
            # SQLite's backup would wait forever on this connection's own lock.
            raise CommandError("Run backup_db outside a database transaction.")
        connection.ensure_connection()
        destination = sqlite3.connect(target)
        try:
            connection.connection.backup(destination)
        finally:
            destination.close()
