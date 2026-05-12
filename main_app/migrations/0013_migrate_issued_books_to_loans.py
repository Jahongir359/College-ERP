"""Best-effort copy of legacy IssuedBook rows into the new Loan table.

The legacy table stored:
  - student_id as a CharField (we trust it parses as an int that is a Student.pk)
  - isbn as PositiveIntegerField (we look up Book by isbn — first match wins)

Rows that fail either lookup are skipped (and logged). IssuedBook itself is
not deleted yet — we keep it for one release as a safety net so admins can
sanity-check the migrated data before the table is dropped in a later PR.
"""
from django.db import migrations


def copy_issued_books(apps, schema_editor):
    IssuedBook = apps.get_model('main_app', 'IssuedBook')
    Loan = apps.get_model('main_app', 'Loan')
    Student = apps.get_model('main_app', 'Student')
    Book = apps.get_model('main_app', 'Book')

    skipped = 0
    copied = 0
    for issued in IssuedBook.objects.all():
        try:
            sid = int(issued.student_id)
        except (TypeError, ValueError):
            skipped += 1
            continue
        student = Student.objects.filter(pk=sid).first()
        book = Book.objects.filter(isbn=issued.isbn).first()
        if not student or not book:
            skipped += 1
            continue
        # Avoid duplicating active loans if migration is re-run.
        if Loan.objects.filter(student=student, book=book, returned_on__isnull=True).exists():
            continue
        Loan.objects.create(
            student=student,
            book=book,
            issued_on=issued.issued_date,
            due_on=issued.expiry_date,
        )
        copied += 1

    if copied or skipped:
        print(f"  [Loan migration] copied={copied} skipped={skipped}")


def noop_reverse(apps, schema_editor):
    """Reverse leaves Loan rows in place; IssuedBook still has the originals."""
    pass


class Migration(migrations.Migration):
    dependencies = [
        ('main_app', '0012_add_loan_model'),
    ]
    operations = [
        migrations.RunPython(copy_issued_books, noop_reverse),
    ]
