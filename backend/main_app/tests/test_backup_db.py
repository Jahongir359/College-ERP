"""``manage.py backup_db`` (plan task P0.7): a backup that restores, the
pg_dump call, and rotation."""

import shutil
import sqlite3
import tempfile
from io import StringIO
from pathlib import Path
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TransactionTestCase

from main_app.management.commands import backup_db
from main_app.models import Branch


def _tempdir(test):
    path = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, path, ignore_errors=True)
    return path


class SqliteBackupTests(TransactionTestCase):
    # A real ``manage.py backup_db`` runs outside any transaction; TestCase's
    # open transaction would keep SQLite's backup waiting on its own lock.
    def setUp(self):
        self.dir = _tempdir(self)

    def run_backup(self, *args):
        out = StringIO()
        call_command("backup_db", "--output-dir", str(self.dir), *args, stdout=out)
        return out.getvalue()

    def backups(self):
        return sorted(p.name for p in self.dir.iterdir())

    def test_backup_restores_the_data(self):
        Branch.objects.create(name="Backup test branch")
        output = self.run_backup()

        [name] = self.backups()
        self.assertRegex(name, backup_db.BACKUP_NAME)
        self.assertTrue(name.endswith(".sqlite3"))
        self.assertIn(name, output)
        # "Restore": open the copy as a database and find the row.
        restored = sqlite3.connect(self.dir / name)
        try:
            rows = restored.execute(
                f"SELECT name FROM {Branch._meta.db_table} WHERE name = ?",
                ["Backup test branch"],
            ).fetchall()
            tables = {row[0] for row in restored.execute("SELECT name FROM sqlite_master")}
        finally:
            restored.close()
        self.assertEqual(rows, [("Backup test branch",)])
        self.assertIn("django_migrations", tables)

    def test_output_dir_defaults_to_backup_dir_env(self):
        with mock.patch.dict("os.environ", {"BACKUP_DIR": str(self.dir / "env")}):
            call_command("backup_db", stdout=StringIO())
        self.assertEqual(len(list((self.dir / "env").iterdir())), 1)

    def test_keep_deletes_only_older_backups_made_by_the_command(self):
        for stamp in ("20260101-020000", "20260102-020000", "20260103-020000"):
            (self.dir / f"iceberg-db-{stamp}.sqlite3").write_text("old")
        (self.dir / "notes.txt").write_text("not a backup")
        (self.dir / "iceberg-db-20250101-020000.sqlite3.partial").write_text("broken")

        output = self.run_backup("--keep", "2")

        names = self.backups()
        self.assertNotIn("iceberg-db-20260101-020000.sqlite3", names)
        self.assertNotIn("iceberg-db-20260102-020000.sqlite3", names)
        self.assertIn("iceberg-db-20260103-020000.sqlite3", names)
        self.assertIn("notes.txt", names)
        self.assertIn("iceberg-db-20250101-020000.sqlite3.partial", names)
        self.assertEqual(sum(bool(backup_db.BACKUP_NAME.match(n)) for n in names), 2)
        self.assertIn("Deleted old backup: iceberg-db-20260101-020000.sqlite3", output)

    def test_keep_zero_keeps_everything(self):
        (self.dir / "iceberg-db-20260101-020000.sqlite3").write_text("old")
        self.run_backup()
        self.assertEqual(len(self.backups()), 2)

    def test_negative_keep_is_an_error(self):
        with self.assertRaises(CommandError):
            self.run_backup("--keep", "-1")

    def test_refuses_to_run_inside_a_transaction(self):
        from django.db import transaction

        with transaction.atomic(), self.assertRaisesMessage(CommandError, "transaction"):
            self.run_backup()
        self.assertEqual(self.backups(), [])

    def test_failed_copy_leaves_no_file(self):
        with mock.patch.object(
            backup_db.Command, "_copy_sqlite", side_effect=sqlite3.OperationalError("disk full")
        ):
            with self.assertRaises(sqlite3.OperationalError):
                self.run_backup()
        self.assertEqual(self.backups(), [])


class _FakePostgres:
    vendor = "postgresql"
    settings_dict = {
        "NAME": "iceberg",
        "USER": "iceberg_user",
        "PASSWORD": "s3cret",
        "HOST": "db.example.com",
        "PORT": 25060,
        "OPTIONS": {"sslmode": "require"},
    }


class PostgresBackupTests(SimpleTestCase):
    def setUp(self):
        self.dir = _tempdir(self)

    def test_pg_dump_command_keeps_the_password_off_the_command_line(self):
        args, env = backup_db.pg_dump_command(
            _FakePostgres.settings_dict, Path("/b/x.dump"), "pg_dump"
        )
        self.assertEqual(
            args,
            [
                "pg_dump",
                "--format=custom",
                "--no-owner",
                "--no-acl",
                "--file=/b/x.dump",
                "--host=db.example.com",
                "--port=25060",
                "--username=iceberg_user",
                "iceberg",
            ],
        )
        self.assertNotIn("s3cret", " ".join(args))
        self.assertEqual(env["PGPASSWORD"], "s3cret")
        self.assertEqual(env["PGSSLMODE"], "require")

    def run_with_fake_pg(self, returncode=0, which="/usr/bin/pg_dump", stderr="connection refused"):
        def fake_run(args, env, capture_output, text):
            target = Path(args[4].removeprefix("--file="))
            if returncode == 0:
                target.write_bytes(b"PGDMP")
            return mock.Mock(returncode=returncode, stderr=stderr)

        with (
            mock.patch.object(backup_db, "connection", _FakePostgres()),
            mock.patch.object(backup_db.shutil, "which", return_value=which),
            mock.patch.object(backup_db.subprocess, "run", side_effect=fake_run) as run,
        ):
            call_command("backup_db", "--output-dir", str(self.dir), stdout=StringIO())
        return run

    def test_postgres_backup_is_a_custom_format_dump(self):
        run = self.run_with_fake_pg()
        [name] = [p.name for p in self.dir.iterdir()]
        self.assertRegex(name, backup_db.BACKUP_NAME)
        self.assertTrue(name.endswith(".dump"))
        args = run.call_args.args[0]
        # pg_dump writes to the .partial name; it is renamed when complete.
        self.assertTrue(args[4].endswith(".dump.partial"))

    def test_pg_dump_failure_is_an_error_and_leaves_no_file(self):
        with self.assertRaisesMessage(CommandError, "connection refused"):
            self.run_with_fake_pg(returncode=1)
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_version_mismatch_is_explained(self):
        stderr = (
            "pg_dump: error: aborting because of server version mismatch\n"
            "pg_dump: detail: server version: 16.4; pg_dump version: 15.8"
        )
        with self.assertRaisesMessage(CommandError, "pg_dump is older than the server"):
            self.run_with_fake_pg(returncode=1, stderr=stderr)

    def test_missing_pg_dump_is_explained(self):
        with self.assertRaisesMessage(CommandError, "PostgreSQL client"):
            self.run_with_fake_pg(which=None)
