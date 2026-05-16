from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("main_app", "0024_group_start_date_student_theme"),
    ]

    operations = [
        migrations.AddField(
            model_name="customuser",
            name="avatar",
            field=models.CharField(blank=True, default="", max_length=10),
        ),
        # Drop the legacy vocabulary tables at DB level, then clean up the state.
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    "DROP TABLE IF EXISTS main_app_vocabularyprogress;",
                    reverse_sql=migrations.RunSQL.noop,
                ),
                migrations.RunSQL(
                    "DROP TABLE IF EXISTS main_app_vocabulary;",
                    reverse_sql=migrations.RunSQL.noop,
                ),
            ],
            state_operations=[
                migrations.AlterUniqueTogether(
                    name="vocabularyprogress",
                    unique_together=None,
                ),
                migrations.RemoveField(
                    model_name="vocabularyprogress",
                    name="student",
                ),
                migrations.RemoveField(
                    model_name="vocabularyprogress",
                    name="vocabulary",
                ),
                migrations.DeleteModel(name="VocabularyProgress"),
                migrations.DeleteModel(name="Vocabulary"),
            ],
        ),
    ]
