"""Audit #12: convert LeaveReportStudent.date and LeaveReportStaff.date
from CharField to DateField.

A direct ALTER COLUMN from varchar to date fails on Postgres without an
explicit USING clause, and pre-existing data may include partial strings
that don't parse. We do the conversion in a single migration with four
ordered steps:

  1. AddField  date_dt = DateField(null=True)  — temporary column
  2. RunPython that parses each row's old text-`date` into date_dt;
     unparseable rows leave date_dt NULL and a warning is printed.
  3. RemoveField date
  4. RenameField date_dt → date

Result: models.py and the DB both end with `date = DateField(null=True)`.
"""
from datetime import datetime
from django.db import migrations, models


_DATE_FORMATS = ('%Y-%m-%d', '%d-%m-%Y', '%d/%m/%Y', '%m/%d/%Y', '%Y/%m/%d')


def _parse(text):
    if not text:
        return None
    text = text.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def copy_dates(apps, schema_editor):
    for model_name in ('LeaveReportStudent', 'LeaveReportStaff'):
        Model = apps.get_model('main_app', model_name)
        unparseable = 0
        for row in Model.objects.all():
            parsed = _parse(row.date)
            if parsed is None and row.date:
                unparseable += 1
                continue
            row.date_dt = parsed
            row.save(update_fields=['date_dt'])
        if unparseable:
            print(f"  [{model_name}] left {unparseable} unparseable date(s) as NULL")


def noop_reverse(apps, schema_editor):
    """Reverse keeps the new DateField data — text source already removed."""
    pass


class Migration(migrations.Migration):
    dependencies = [
        ('main_app', '0013_migrate_issued_books_to_loans'),
    ]
    operations = [
        migrations.AddField(
            model_name='leavereportstudent', name='date_dt',
            field=models.DateField(null=True, blank=True),
        ),
        migrations.AddField(
            model_name='leavereportstaff', name='date_dt',
            field=models.DateField(null=True, blank=True),
        ),
        migrations.RunPython(copy_dates, noop_reverse),
        migrations.RemoveField(model_name='leavereportstudent', name='date'),
        migrations.RemoveField(model_name='leavereportstaff', name='date'),
        migrations.RenameField(
            model_name='leavereportstudent', old_name='date_dt', new_name='date',
        ),
        migrations.RenameField(
            model_name='leavereportstaff', old_name='date_dt', new_name='date',
        ),
    ]
