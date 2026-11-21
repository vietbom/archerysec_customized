from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("staticscanners", "0040_finding_identity_version")]
    operations = [migrations.AddField(
        model_name="staticscansdb", name="import_warnings",
        field=models.JSONField(default=list, blank=True),
    )]
