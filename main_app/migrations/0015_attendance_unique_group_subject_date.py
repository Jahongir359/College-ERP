"""Audit #13: enforce (group, subject, date) uniqueness on Attendance.

The previous schema let staff "Take Attendance" for the same group on
the same day twice, producing duplicate Attendance rows each with their
own chain of AttendanceReports. Adding the unique_together constraint
on existing production data would fail if any duplicates already exist.

This migration first removes duplicates (keeping the most recently
created row in each conflict group; AttendanceReports on the dropped
rows cascade automatically) and then applies the constraint.
"""
from django.db import migrations
from django.db.models import Count, Max


def dedupe_attendance(apps, schema_editor):
    Attendance = apps.get_model('main_app', 'Attendance')

    # Find every (group, subject, date) triple with more than one row.
    dupes = (
        Attendance.objects
        .values('group_id', 'subject_id', 'date')
        .annotate(n=Count('id'), latest_id=Max('id'))
        .filter(n__gt=1)
    )
    removed_total = 0
    for group in dupes:
        # Keep the row with the highest id (latest insert); delete the rest.
        keep = group['latest_id']
        to_remove = Attendance.objects.filter(
            group_id=group['group_id'],
            subject_id=group['subject_id'],
            date=group['date'],
        ).exclude(id=keep)
        n = to_remove.count()
        to_remove.delete()
        removed_total += n
        print(f"  [Attendance dedupe] group={group['group_id']} "
              f"subject={group['subject_id']} date={group['date']}: "
              f"removed {n} duplicate(s)")
    if removed_total:
        print(f"  [Attendance dedupe] total rows removed: {removed_total}")


def noop_reverse(apps, schema_editor):
    """Cannot un-dedupe; reverse is a no-op."""
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('main_app', '0014_leavereport_date_to_datefield'),
    ]

    operations = [
        migrations.RunPython(dedupe_attendance, noop_reverse),
        migrations.AlterUniqueTogether(
            name='attendance',
            unique_together={('group', 'subject', 'date')},
        ),
    ]
