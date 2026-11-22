from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("staticscanners", "0041_staticscansdb_import_warnings")]
    operations = [
        migrations.AddField(
            model_name="staticscanfinding", name="observed_severity",
            field=models.CharField(max_length=32, blank=True, default=""),
        ),
    ]
